#!/bin/bash

# 判断是否为 root 用户
if [ "$(id -u)" != "0" ]; then
	echo "错误: 你必须以 root 用户身份运行此脚本" 1>&2
	exit 1
fi

# 判断系统是否为 Debian
if ! grep -qi "Debian" /etc/os-release; then
	echo "错误: 此脚本仅支持 Debian 系统"
	exit 1
fi

# 生成随机端口
rand_port() {
	min=10000
	max=60000
	echo $((RANDOM % (max - min) + min))
}

# 配置客户端文件
config_client() {
	cat >/etc/wireguard/client.conf <<-EOF
		[Interface]
		PrivateKey = $c1
		Address = 10.0.0.2/24
		DNS = 8.8.8.8
		MTU = 1420

		[Peer]
		PublicKey = $s2
		Endpoint = $server_ip:$port
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
}

# 安装 WireGuard
wireguard_install() {
	echo "正在更新软件包列表..."
	apt-get update

	echo "正在安装 WireGuard 及相关工具..."
	# 使用更通用的方式安装内核头文件，提高兼容性
	# linux-headers-amd64 会自动匹配并安装适用于当前架构的最新头文件
	# 这比写死 $(uname -r) 更健壮
	apt-get install -y wireguard qrencode ufw curl linux-headers-amd64

	echo "正在创建 WireGuard 目录和密钥..."
	# 尝试创建目录，并检查是否成功
	if ! mkdir -p /etc/wireguard; then
		echo "错误: 无法创建目录 /etc/wireguard。请检查权限或磁盘空间。" >&2
		exit 1
	fi
	# 设置安全权限
	chmod 700 /etc/wireguard
	cd /etc/wireguard || { echo "错误: 无法切换到目录 /etc/wireguard。请检查目录是否存在且为有效目录。" >&2; exit 1; }

	wg genkey | tee sprivatekey | wg pubkey >spublickey
	wg genkey | tee cprivatekey | wg pubkey >cpublickey
	# 设置密钥文件的权限
	chmod 600 sprivatekey cprivatekey

	s1=$(cat sprivatekey)
	s2=$(cat spublickey)
	c1=$(cat cprivatekey)
	c2=$(cat cpublickey)
	echo "服务端私钥 (s1): $s1"
	echo "服务端公钥 (s2): $s2"
	echo "客户端私钥 (c1): $c1"
	echo "客户端公钥 (c2): $c2"

	# 优先取 IPv4，没有就取 IPv6
	server_ip=$(curl -s -4 icanhazip.com || curl -s -6 icanhazip.com)
	# 如果是 IPv6，加方括号
	if [[ $server_ip == *:* ]]; then
		server_ip="[$server_ip]"
	fi
	port=$(rand_port)

	echo "配置系统网络转发..."
	sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
	if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
		echo "net.ipv4.ip_forward=1" >>/etc/sysctl.conf
	fi
	sysctl -p

	echo "配置防火墙 (UFW)..."
	ufw allow ssh
	ufw allow "$port"/udp
	ufw --force enable

	net_interface=$(ip -o -4 route show to default | awk '{print $5}')
	if [ -z "$net_interface" ]; then
		echo "错误: 无法检测到主网络接口"
		exit 1
	fi
	echo "检测到主网络接口为: $net_interface"

	if ! grep -q "POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE" /etc/ufw/before.rules; then
		sed -i "1s;^;*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE\nCOMMIT\n;" /etc/ufw/before.rules
	fi

	sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
	ufw reload

	echo "正在创建服务器配置文件 wg0.conf..."
	cat >/etc/wireguard/wg0.conf <<-EOF
		[Interface]
		PrivateKey = $s1
		Address = 10.0.0.1/24
		ListenPort = $port
		MTU = 1420

		[Peer]
		PublicKey = $c2
		AllowedIPs = 10.0.0.2/32
	EOF

	echo "正在创建客户端配置文件 client.conf..."
	config_client

	# 设置配置文件权限
	chmod 600 /etc/wireguard/*.conf

	echo "启动 WireGuard 服务..."
	# 先尝试静默关闭已存在的接口，以避免 "wg0 already exists" 的警告
	wg-quick down wg0 &>/dev/null || true
	# 启动新的 wg0 接口
	wg-quick up wg0 || { echo "错误: 启动 WireGuard 接口 wg0 失败。" >&2; exit 1; }
	systemctl enable wg-quick@wg0

	echo -e "\n=============================================================="
	echo "🎉 WireGuard 安装完成! 🎉"
	echo "=============================================================="
	echo "服务器配置: /etc/wireguard/wg0.conf"
	echo "客户端配置: /etc/wireguard/client.conf"
	echo ""
	qrencode -t ansiutf8 </etc/wireguard/client.conf
	echo "=============================================================="
}

# 卸载 WireGuard
wireguard_uninstall() {
	echo "正在停止并禁用 WireGuard 服务..."
	systemctl stop wg-quick@wg0
	systemctl disable wg-quick@wg0

	echo "正在卸载 WireGuard 及相关软件包..."
	# 使用 --purge 彻底清除配置
	apt-get remove --purge -y wireguard wireguard-tools qrencode

	echo "正在清理配置文件..."
	rm -rf /etc/wireguard

	echo "跳过防火墙重置，以避免影响宝塔面板等服务。"
	echo "请手动删除为 WireGuard 开放的端口。"
	# echo "正在重置防火墙规则 (UFW)..."
	# # ufw reset 会禁用防火墙，需要用户确认
	# ufw --force reset
	# echo "防火墙已重置并禁用。"

	echo -e "\n=============================================================="
	echo "🎉 WireGuard 已成功卸载。"
	echo "=============================================================="
}

# 添加新客户端
add_new_client() {
    # 检查 WireGuard 是否已安装
    if [ ! -f /etc/wireguard/wg0.conf ]; then
        echo "错误: WireGuard 尚未安装。请先选择选项 1 进行安装。"
        exit 1
    fi

    echo
    read -r -p "请输入新客户端的名称 (例如: phone, laptop): " client_name

    # 检查名称是否为空
    if [ -z "$client_name" ]; then
        echo "错误: 客户端名称不能为空。"
        exit 1
    fi

    # 简单的名称清理，移除特殊字符
    client_name=$(echo "$client_name" | tr -dc '[:alnum:]_-')

    # 检查配置文件是否已存在
    if [ -f "/etc/wireguard/${client_name}.conf" ]; then
        echo "错误: 名为 ${client_name} 的客户端配置已存在。"
        exit 1
    fi

    # --- 查找下一个可用的 IP 地址 ---
    # 查找 wg0.conf 中最后一个 AllowedIPs 的 IP
    last_ip=$(grep -oP 'AllowedIPs = 10.0.0.\K[0-9]+' /etc/wireguard/wg0.conf | sort -n | tail -1)
    
    # 如果没有找到 IP (比如初始安装后只有一个 peer)，则从 2 开始
    if [ -z "$last_ip" ]; then
        next_ip_octet=2
    else
        next_ip_octet=$((last_ip + 1))
    fi

    # 检查 IP 是否超出范围
    if [ "$next_ip_octet" -gt 254 ]; then
        echo "错误: IP 地址池已满 (10.0.0.2-10.0.0.254)。"
        exit 1
    fi

    new_client_ip="10.0.0.${next_ip_octet}/32"
    echo "为新客户端分配的 IP 地址: 10.0.0.${next_ip_octet}"

    # --- 生成客户端密钥 ---
    cd /etc/wireguard || exit
    new_client_private_key=$(wg genkey)
    new_client_public_key=$(echo "$new_client_private_key" | wg pubkey)
	# 临时保存密钥，并设置权限
	echo "$new_client_private_key" > "${client_name}_privatekey"
	echo "$new_client_public_key" > "${client_name}_publickey"
	chmod 600 "${client_name}_privatekey" "${client_name}_publickey"


    # --- 更新服务器配置 ---
    echo "正在更新服务器配置..."
    cat >>/etc/wireguard/wg0.conf <<-EOF

		[Peer]
		# Client: $client_name
		PublicKey = $new_client_public_key
		AllowedIPs = $new_client_ip
	EOF

    # --- 创建客户端配置文件 ---
    echo "正在创建客户端配置文件 /etc/wireguard/${client_name}.conf..."
    # 获取服务器信息
    server_public_key=$(cat /etc/wireguard/spublickey)
	# 从 wg0.conf 获取 Endpoint IP 和 Port，更可靠
    server_ip=$(grep -oP 'Endpoint = \K[^:]+' /etc/wireguard/client.conf) # 沿用初始IP
    server_port=$(grep -oP 'ListenPort = \K[0-9]+' /etc/wireguard/wg0.conf)


    cat >"/etc/wireguard/${client_name}.conf" <<-EOF
		[Interface]
		PrivateKey = $new_client_private_key
		Address = 10.0.0.${next_ip_octet}/24
		DNS = 8.8.8.8
		MTU = 1420

		[Peer]
		PublicKey = $server_public_key
		Endpoint = $server_ip:$server_port
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
	
	# 设置新配置文件的权限
	chmod 600 "/etc/wireguard/${client_name}.conf"

    # --- 重启服务并显示结果 ---
    echo "正在重新加载 WireGuard 服务..."
    systemctl restart wg-quick@wg0

    echo -e "\n=============================================================="
    echo "🎉 新客户端 '$client_name' 添加成功! 🎉"
    echo "=============================================================="
    echo "客户端配置文件: /etc/wireguard/${client_name}.conf"
    echo "扫描下面的二维码以导入配置:"
    echo ""
    qrencode -t ansiutf8 <"/etc/wireguard/${client_name}.conf"
    echo "=============================================================="
	
	# 清理临时密钥文件
	rm -f "${client_name}_privatekey" "${client_name}_publickey"
}


# 菜单
start_menu() {
	clear
	echo "=================================================="
	echo " 适用于 Debian 的 WireGuard 一键安装脚本"
	echo "=================================================="
	echo "1. 安装 WireGuard"
	echo "2. 卸载 WireGuard"
	echo "3. 添加新用户"
	echo "4. 退出脚本"
	echo
	read -r -p "请输入数字 [1-4]: " num
	case "$num" in
	1) wireguard_install ;;
	2) wireguard_uninstall ;;
	3) add_new_client ;;
	4) exit 0 ;;
	*)
		echo "错误: 请输入正确的数字"
		sleep 2
		start_menu
		;;
	esac
}

start_menu
