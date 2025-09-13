#!/bin/bash

#================================================================================
# 适用于 Debian 的 WireGuard + Udp2raw 一键安装脚本 (已修复下载问题)
#
# 功能:
# 1. 安装 WireGuard (可选集成 Udp2raw)
# 2. 卸载 WireGuard
# 3. 添加新用户
# 4. 智能安装检测，防止重复执行
#================================================================================

# --- 全局函数和变量 ---

# 判断是否为 root 用户
check_root() {
	if [ "$(id -u)" != "0" ]; then
		echo "错误: 你必须以 root 用户身份运行此脚本" 1>&2
		exit 1
	fi
}

# 判断系统是否为 Debian
check_debian() {
	if ! grep -qi "Debian" /etc/os-release; then
		echo "错误: 此脚本仅支持 Debian 系统"
		exit 1
	fi
}

# 生成随机端口
rand_port() {
	min=10000
	max=60000
	echo $((RANDOM % (max - min) + min))
}

# --- 主要功能函数 ---

# 安装 WireGuard
wireguard_install() {
	if [ -f /etc/wireguard/wg0.conf ]; then
		echo "检测到 WireGuard 已安装 (/etc/wireguard/wg0.conf 存在)。无需重复安装。"
		exit 0
	fi

	read -r -p "是否启用 TCP 伪装 (udp2raw)？[y/N]: " use_udp2raw
	use_udp2raw=$(echo "$use_udp2raw" | tr '[:upper:]' '[:lower:]')

	echo "正在更新软件包列表..."
	apt-get update
	echo "正在安装 WireGuard 及相关工具..."
	apt-get install -y wireguard qrencode ufw curl linux-headers-amd64

	echo "正在创建 WireGuard 目录和密钥..."
	mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
	cd /etc/wireguard || exit 1

	wg genkey | tee sprivatekey | wg pubkey >spublickey
	wg genkey | tee cprivatekey | wg pubkey >cpublickey
	chmod 600 sprivatekey cprivatekey

	s1=$(cat sprivatekey)
	s2=$(cat spublickey)
	c1=$(cat cprivatekey)
	c2=$(cat cpublickey)

	server_ip=$(curl -s -4 icanhazip.com || curl -s -6 icanhazip.com)
	wg_port=$(rand_port)

	echo "配置系统网络转发..."
	sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
	if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then echo "net.ipv4.ip_forward=1" >>/etc/sysctl.conf; fi
	sysctl -p

	echo "配置防火墙 (UFW)..."
	ufw allow ssh

	local client_endpoint
	if [ "$use_udp2raw" == "y" ]; then
		echo "正在为您配置 udp2raw..."
		tcp_port=$(rand_port)
		udp2raw_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)

		echo "开放 udp2raw 的 TCP 端口: $tcp_port"

		ufw allow "$tcp_port"/tcp

		echo "正在下载并安装 udp2raw..."
		# 作者已停止更新，直接使用固定链接以提高稳定性和速度
		UDP2RAW_URL="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"

		echo "使用下载链接: $UDP2RAW_URL"
		if ! curl -L -o udp2raw_binaries.tar.gz "$UDP2RAW_URL"; then
			echo "错误: 使用 curl 下载 udp2raw 失败。请检查网络或链接是否有效。"
			exit 1
		fi
		if [ ! -s udp2raw_binaries.tar.gz ] || [ "$(stat -c%s "udp2raw_binaries.tar.gz")" -lt 10000 ]; then
			echo "错误: 下载的文件大小异常，可能不是有效的压缩包。"
			rm -f udp2raw_binaries.tar.gz
			exit 1
		fi
		if ! tar -xzf udp2raw_binaries.tar.gz; then
			echo "错误: 解压 udp2raw_binaries.tar.gz 失败。"
			exit 1
		fi
		if [ -f "udp2raw_binaries/udp2raw_amd64" ]; then mv udp2raw_binaries/udp2raw_amd64 /usr/local/bin/udp2raw; else
			echo "错误: 在解压的文件中未找到 udp2raw_amd64。"
			rm -rf udp2raw_binaries*
			exit 1
		fi

		rm -rf udp2raw_binaries udp2raw_binaries.tar.gz

		echo "正在创建 udp2raw 系统服务..."
		cat >/etc/systemd/system/udp2raw.service <<-EOF
			[Unit]
			Description=udp2raw-tunnel server
			After=network.target
			[Service]
			Type=simple
			ExecStart=/usr/local/bin/udp2raw -s -l 0.0.0.0:$tcp_port -r 127.0.0.1:$wg_port -k "$udp2raw_password" --raw-mode faketcp -a
			Restart=on-failure
			[Install]
			WantedBy=multi-user.target
		EOF
		systemctl daemon-reload && systemctl enable udp2raw && systemctl start udp2raw
		client_endpoint="127.0.0.1:29999"
	else
		echo "开放 WireGuard 的 UDP 端口: $wg_port"
		ufw allow "$wg_port"/udp
		client_endpoint="$server_ip:$wg_port"
	fi

	ufw --force enable

	net_interface=$(ip -o -4 route show to default | awk '{print $5}')
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
		ListenPort = $wg_port
		MTU = 1420

		[Peer]
		# Client: client
		PublicKey = $c2
		AllowedIPs = 10.0.0.2/32
	EOF

	echo "正在创建客户端配置文件 client.conf..."
	cat >/etc/wireguard/client.conf <<-EOF
		[Interface]
		PrivateKey = $c1
		Address = 10.0.0.2/24
		DNS = 8.8.8.8
		MTU = 1420

		[Peer]
		PublicKey = $s2
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
	chmod 600 /etc/wireguard/*.conf

	echo "启动 WireGuard 服务..."
	wg-quick down wg0 &>/dev/null || true
	wg-quick up wg0 || {
		echo "错误: 启动 WireGuard 接口 wg0 失败。" >&2
		exit 1
	}
	systemctl enable wg-quick@wg0

	echo -e "\n=============================================================="
	echo "🎉 WireGuard 安装完成! 🎉"
	echo "=============================================================="
	echo "服务器配置: /etc/wireguard/wg0.conf"
	echo "客户端配置: /etc/wireguard/client.conf"
	echo ""
	qrencode -t ansiutf8 </etc/wireguard/client.conf
	echo "=============================================================="

	if [ "$use_udp2raw" == "y" ]; then
		echo -e "\n=================== 客户端 Udp2raw 设置 ==================="
		echo "伪装模式已启用，您需要在客户端上运行 udp2raw。"
		echo "服务器 TCP 端口: $tcp_port"
		echo "连接密码: $udp2raw_password"
		echo ""
		echo "在您的客户端(电脑/路由器)上，先运行以下命令："
		echo "--------------------------------------------------------------"
		echo "./udp2raw -c -l 127.0.0.1:29999 -r $server_ip:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp -a"
		echo "--------------------------------------------------------------"
		echo "然后再启动上面的 WireGuard 客户端配置。"
		echo "=============================================================="
	fi
}

# 卸载 WireGuard
wireguard_uninstall() {
	echo "正在停止并禁用 WireGuard 和 udp2raw 服务..."
	systemctl stop wg-quick@wg0 && systemctl disable wg-quick@wg0
	systemctl stop udp2raw &>/dev/null && systemctl disable udp2raw &>/dev/null

	echo "正在卸载 WireGuard 及相关软件包..."
	apt-get remove --purge -y wireguard wireguard-tools qrencode

	echo "正在清理配置文件和程序..."
	rm -rf /etc/wireguard
	rm -f /etc/systemd/system/udp2raw.service
	rm -f /usr/local/bin/udp2raw
	systemctl daemon-reload

	echo "跳过防火墙重置，以避免影响宝塔面板等服务。请手动删除相关端口。"

	echo -e "\n🎉 WireGuard 及 Udp2raw 已成功卸载。"
}

# 添加新客户端
add_new_client() {
	if [ ! -f /etc/wireguard/wg0.conf ]; then
		echo "错误: WireGuard 尚未安装。"
		exit 1
	fi

	read -r -p "请输入新客户端的名称 (例如: phone, laptop): " client_name
	if [ -z "$client_name" ]; then
		echo "错误: 客户端名称不能为空。"
		exit 1
	fi
	client_name=$(echo "$client_name" | tr -dc '[:alnum:]_-')
	if [ -f "/etc/wireguard/${client_name}.conf" ]; then
		echo "错误: 名为 ${client_name} 的客户端配置已存在。"
		exit 1
	fi

	last_ip_octet=$(grep -oP 'AllowedIPs = 10.0.0.\K[0-9]+' /etc/wireguard/wg0.conf | sort -n | tail -1)
	next_ip_octet=$((last_ip_octet + 1))
	if [ "$next_ip_octet" -gt 254 ]; then
		echo "错误: IP 地址池已满。"
		exit 1
	fi
	new_client_ip="10.0.0.${next_ip_octet}/32"
	echo "为新客户端分配的 IP 地址: 10.0.0.${next_ip_octet}"

	cd /etc/wireguard || exit
	new_client_private_key=$(wg genkey)
	new_client_public_key=$(echo "$new_client_private_key" | wg pubkey)

	echo "正在更新服务器配置..."
	echo -e "\n[Peer]\n# Client: $client_name\nPublicKey = $new_client_public_key\nAllowedIPs = $new_client_ip" >>/etc/wireguard/wg0.conf

	echo "正在创建客户端配置文件 /etc/wireguard/${client_name}.conf..."
	server_public_key=$(cat /etc/wireguard/spublickey)

	local client_endpoint
	if systemctl -q is-active udp2raw; then
		client_endpoint="127.0.0.1:29999"
	else
		server_ip=$(curl -s -4 icanhazip.com || curl -s -6 icanhazip.com)
		server_port=$(grep -oP 'ListenPort = \K[0-9]+' /etc/wireguard/wg0.conf)
		client_endpoint="$server_ip:$server_port"
	fi

	cat >"/etc/wireguard/${client_name}.conf" <<-EOF
		[Interface]
		PrivateKey = $new_client_private_key
		Address = 10.0.0.${next_ip_octet}/24
		DNS = 8.8.8.8
		MTU = 1420

		[Peer]
		PublicKey = $server_public_key
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
	chmod 600 "/etc/wireguard/${client_name}.conf"

	echo "正在重新加载 WireGuard 服务..."
	systemctl restart wg-quick@wg0

	echo -e "\n=============================================================="
	echo "🎉 新客户端 '$client_name' 添加成功! 🎉"
	echo "=============================================================="
	echo "客户端配置文件: /etc/wireguard/${client_name}.conf"
	qrencode -t ansiutf8 <"/etc/wireguard/${client_name}.conf"
	echo "=============================================================="

	if systemctl -q is-active udp2raw; then
		echo "提醒: 您的服务正在使用 udp2raw，请确保客户端也正确配置。"
	fi
}

# --- 菜单和主逻辑 ---
start_menu() {
	clear
	echo "=================================================="
	echo " 适用于 Debian 的 WireGuard 一键安装脚本"
	echo " (集成 Udp2raw 伪装功能)"
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

# --- 脚本入口 ---
check_root
check_debian
start_menu
