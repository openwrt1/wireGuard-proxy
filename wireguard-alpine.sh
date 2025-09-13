#!/bin/bash

#================================================================================
# 适用于 Alpine Linux 的 WireGuard + Udp2raw 一键安装脚本
#
# 特点:
# - 使用 apk 作为包管理器
# - 使用 iptables 并与 wg0 接口绑定，无需持久化配置
# - 完整移植原 Debian 脚本的所有功能
#================================================================================

# --- 全局函数和变量 ---

# 判断是否为 root 用户
check_root() {
	if [ "$(id -u)" != "0" ]; then
		echo "错误: 你必须以 root 用户身份运行此脚本" 1>&2
		exit 1
	fi
}

# 判断系统是否为 Alpine
check_alpine() {
	if ! grep -qi "Alpine" /etc/os-release; then
		echo "错误: 此脚本仅支持 Alpine Linux 系统"
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
    # 检查是否已安装
    if [ -f /etc/wireguard/wg0.conf ]; then
        echo "检测到 WireGuard 已安装 (/etc/wireguard/wg0.conf 存在)。"
        echo "无需重复安装。如果您想添加新用户，请选择主菜单的'添加新用户'选项。"
        exit 0
    fi

    # 询问是否启用 udp2raw
    echo
    read -r -p "是否启用 TCP 伪装 (udp2raw)？[y/N]: " use_udp2raw
    use_udp2raw=$(echo "$use_udp2raw" | tr '[:upper:]' '[:lower:]') # 转为小写

	echo "正在更新软件包列表..."
	apk update

	echo "正在安装 WireGuard 及相关工具..."
	apk add wireguard-tools qrencode curl iptables

	echo "正在创建 WireGuard 目录和密钥..."
	mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
	cd /etc/wireguard || exit 1

	wg genkey | tee sprivatekey | wg pubkey > spublickey
	wg genkey | tee cprivatekey | wg pubkey > cpublickey
	chmod 600 sprivatekey cprivatekey

	s1=$(cat sprivatekey)
	s2=$(cat spublickey)
	c1=$(cat cprivatekey)
	c2=$(cat cpublickey)

	server_ip=$(curl -s -4 icanhazip.com || curl -s -6 icanhazip.com)
    
	echo "配置系统网络转发..."
	sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
	if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
		echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	fi
	sysctl -p

    # 根据是否使用 udp2raw 配置
    local client_endpoint
    local wg_port
    local client_mtu
    local postup_rules=""
    local predown_rules=""
    net_interface=$(ip -o -4 route show to default | awk '{print $5}')
	echo "检测到主网络接口为: $net_interface"

    postup_rules="iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE;"
    predown_rules="iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE;"

    if [ "$use_udp2raw" == "y" ]; then
        read -r -p "请输入 udp2raw 的 TCP 端口 [默认: 39001]: " tcp_port
        tcp_port=${tcp_port:-39001}
        wg_port=$(rand_port) # 内部 WG 端口保持随机
        client_mtu=1200 # udp2raw 需要更小的 MTU
        udp2raw_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        
        echo "为 udp2raw 的 TCP 端口 $tcp_port 添加防火墙规则..."
        postup_rules="$postup_rules iptables -A INPUT -p tcp --dport $tcp_port -j ACCEPT;"
        predown_rules="$predown_rules iptables -D INPUT -p tcp --dport $tcp_port -j ACCEPT;"

        # --- 安装 udp2raw (已修正架构检测) ---
        echo "正在下载并安装 udp2raw..."
        UDP2RAW_URL="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"
        echo "使用下载链接: $UDP2RAW_URL"
        
        if ! curl -L -o udp2raw_binaries.tar.gz "$UDP2RAW_URL"; then
            echo "错误: 下载 udp2raw 失败。请检查网络连接。" >&2
            exit 1
        fi

        if ! tar -xzf udp2raw_binaries.tar.gz; then
            echo "错误: 解压 udp2raw_binaries.tar.gz 失败。文件可能已损坏。" >&2
            rm -f udp2raw_binaries.tar.gz
            exit 1
        fi

        # 根据系统架构选择正确的二进制文件
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)
                UDP2RAW_BINARY="udp2raw_amd64"
                ;;
            aarch64 | arm*)
                UDP2RAW_BINARY="udp2raw_arm"
                ;;
            i386 | i686)
                UDP2RAW_BINARY="udp2raw_x86"
                ;;
            *)
                echo "错误: 不支持的系统架构 '$ARCH'。无法自动安装 udp2raw。" >&2
                echo "请在 /etc/wireguard 目录中检查解压后的文件，并手动安装。" >&2
                rm -f udp2raw_* version.txt udp2raw_binaries.tar.gz
                exit 1
                ;;
        esac

        if [ ! -f "$UDP2RAW_BINARY" ]; then
            echo "错误: 在解压的文件中未找到适用于您架构 ('$ARCH') 的二进制文件 '$UDP2RAW_BINARY'。" >&2
            rm -f udp2raw_* version.txt udp2raw_binaries.tar.gz
            exit 1
        fi

        echo "检测到架构 '$ARCH'，将安装 '$UDP2RAW_BINARY'..."
        mv "$UDP2RAW_BINARY" /usr/local/bin/udp2raw
        chmod +x /usr/local/bin/udp2raw

        echo "正在清理临时文件..."
        rm -f udp2raw_* version.txt udp2raw_binaries.tar.gz
        # --- udp2raw 安装结束 ---

        # 创建 systemd 服务
        echo "正在创建 udp2raw 系统服务..."
        cat > /etc/systemd/system/udp2raw.service <<-EOF
			[Unit]
			Description=udp2raw-tunnel server
			After=network.target

			[Service]
			Type=simple
			ExecStart=/usr/local/bin/udp2raw -s -l 0.0.0.0:$tcp_port -r 127.0.0.1:$wg_port -k "$udp2raw_password" --raw-mode faketcp --cipher-mode xor -a
			Restart=on-failure
			RestartSec=5

			[Install]
			WantedBy=multi-user.target
		EOF
        
        systemctl daemon-reload
        systemctl enable udp2raw
        systemctl start udp2raw
        
        client_endpoint="127.0.0.1:29999" # 客户端本地 udp2raw 监听的端口
    else
        read -r -p "请输入 WireGuard 的 UDP 端口 [默认: 39000]: " wg_port
        wg_port=${wg_port:-39000}
        client_mtu=1420

        echo "为 WireGuard 的 UDP 端口 $wg_port 添加防火墙规则..."
        postup_rules="$postup_rules iptables -A INPUT -p udp --dport $wg_port -j ACCEPT;"
        predown_rules="$predown_rules iptables -D INPUT -p udp --dport $wg_port -j ACCEPT;"
        client_endpoint="$server_ip:$wg_port"
    fi

	echo "正在创建服务器配置文件 wg0.conf..."
	cat > /etc/wireguard/wg0.conf <<-EOF
		[Interface]
		PrivateKey = $s1
		Address = 10.0.0.1/24
		ListenPort = $wg_port
		MTU = 1420
        PostUp = $postup_rules
        PreDown = $predown_rules

		[Peer]
		# Client: client
		PublicKey = $c2
		AllowedIPs = 10.0.0.2/32
	EOF

	echo "正在创建客户端配置文件 client.conf..."
	cat > /etc/wireguard/client.conf <<-EOF
		[Interface]
		PrivateKey = $c1
		Address = 10.0.0.2/24
		DNS = 8.8.8.8
		MTU = $client_mtu

		[Peer]
		PublicKey = $s2
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
    chmod 600 /etc/wireguard/*.conf

	echo "启动 WireGuard 服务..."
	wg-quick down wg0 &>/dev/null || true
	wg-quick up wg0 || { echo "错误: 启动 WireGuard 接口 wg0 失败。" >&2; exit 1; }
	systemctl enable wg-quick@wg0

	echo -e "\n=============================================================="
	echo "🎉 WireGuard 安装完成! 🎉"
	echo "=============================================================="
	echo "服务器配置: /etc/wireguard/wg0.conf"
	echo "客户端配置: /etc/wireguard/client.conf"
	echo ""
	qrencode -t ansiutf8 < /etc/wireguard/client.conf
	echo "=============================================================="

    if [ "$use_udp2raw" == "y" ]; then
        echo -e "\n=================== 客户端 Udp2raw 设置 ==================="
        echo "伪装模式已启用，您需要在客户端上运行 udp2raw。"
        echo "请从 https://github.com/wangyu-/udp2raw/releases 下载 udp2raw 二进制文件。"
        echo "解压后，根据您的操作系统，在终端或命令行中运行对应命令："
        echo ""
        echo "服务器 TCP 端口: $tcp_port"
        echo "连接密码: $udp2raw_password"
        echo ""
        echo -e "\033[1;32m--- Linux 客户端 ---\033[0m"
        echo "(根据您的架构选择 udp2raw_amd64, udp2raw_arm 等)"
        echo "./udp2raw_amd64 -c -l 127.0.0.1:29999 -r $server_ip:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor -a"
        echo ""
        echo -e "\033[1;32m--- macOS 客户端 ---\033[0m"
        echo "(M1/M2/M3 芯片请用 udp2raw_mp_mac_m1)"
        echo "./udp2raw_mp_mac -c -l 127.0.0.1:29999 -r $server_ip:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
        echo ""
        echo -e "\033[1;32m--- Windows 客户端 (在 CMD 或 PowerShell 中运行) ---\033[0m"
        echo "(推荐使用 udp2raw_mp.exe)"
        echo "./udp2raw_mp.exe -c -l 127.0.0.1:29999 -r $server_ip:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor -a"
        echo ""
        echo "--------------------------------------------------------------"
        echo "然后再启动 WireGuard 客户端。"
        echo "=============================================================="
    fi
}

# 卸载 WireGuard
wireguard_uninstall() {
	echo "正在停止并禁用 WireGuard 和 udp2raw 服务..."
	wg-quick down wg0 &>/dev/null || true # 这会执行 PreDown 规则，移除 iptables 条目
	systemctl stop wg-quick@wg0
	systemctl disable wg-quick@wg0
    systemctl stop udp2raw &>/dev/null || true
    systemctl disable udp2raw &>/dev/null || true

	echo "正在卸载 WireGuard 及相关软件包..."
	apk del wireguard-tools qrencode iptables

	echo "正在清理配置文件和程序..."
	rm -rf /etc/wireguard
    rm -f /etc/systemd/system/udp2raw.service
    rm -f /usr/local/bin/udp2raw
    systemctl daemon-reload

	echo -e "\n=============================================================="
	echo "🎉 WireGuard 及 Udp2raw 已成功卸载。"
	echo "=============================================================="
}

# 添加新客户端
add_new_client() {
    if [ ! -f /etc/wireguard/wg0.conf ]; then
        echo "错误: WireGuard 尚未安装。请先选择选项 1 进行安装。"
        exit 1
    fi

    read -r -p "请输入新客户端的名称 (例如: phone, laptop): " client_name
    if [ -z "$client_name" ]; then echo "错误: 客户端名称不能为空。"; exit 1; fi
    client_name=$(echo "$client_name" | tr -dc '[:alnum:]_-')
    if [ -f "/etc/wireguard/${client_name}.conf" ]; then echo "错误: 名为 ${client_name} 的客户端配置已存在。"; exit 1; fi

    last_ip_octet=$(grep -oP 'AllowedIPs = 10.0.0.\K[0-9]+' /etc/wireguard/wg0.conf | sort -n | tail -1)
    next_ip_octet=$((last_ip_octet + 1))
    if [ "$next_ip_octet" -gt 254 ]; then echo "错误: IP 地址池已满。"; exit 1; fi
    new_client_ip="10.0.0.${next_ip_octet}/32"
    echo "为新客户端分配的 IP 地址: 10.0.0.${next_ip_octet}"

    cd /etc/wireguard || exit
    new_client_private_key=$(wg genkey)
    new_client_public_key=$(echo "$new_client_private_key" | wg pubkey)

    echo "正在更新服务器配置..."
    # 使用更安全的方式热添加 peer，而不是重启整个服务
    wg set wg0 peer "$new_client_public_key" allowed-ips "$new_client_ip"
    # 同时也将配置持久化到文件
    cat >> /etc/wireguard/wg0.conf <<-EOF

		[Peer]
		# Client: $client_name
		PublicKey = $new_client_public_key
		AllowedIPs = $new_client_ip
	EOF

    echo "正在创建客户端配置文件 /etc/wireguard/${client_name}.conf..."
    server_public_key=$(cat /etc/wireguard/spublickey)
    
    local client_endpoint
    local client_mtu
    if systemctl -q is-active udp2raw; then
        client_endpoint="127.0.0.1:29999"
        client_mtu=1200
    else
        server_ip=$(curl -s -4 icanhazip.com || curl -s -6 icanhazip.com)
        server_port=$(grep -oP 'ListenPort = \K[0-9]+' /etc/wireguard/wg0.conf)
        client_endpoint="$server_ip:$server_port"
        client_mtu=1420
    fi

    cat > "/etc/wireguard/${client_name}.conf" <<-EOF
		[Interface]
		PrivateKey = $new_client_private_key
		Address = 10.0.0.${next_ip_octet}/24
		DNS = 8.8.8.8
		MTU = $client_mtu

		[Peer]
		PublicKey = $server_public_key
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
	chmod 600 "/etc/wireguard/${client_name}.conf"

    echo -e "\n=============================================================="
    echo "🎉 新客户端 '$client_name' 添加成功! 🎉"
    echo "=============================================================="
    echo "客户端配置文件: /etc/wireguard/${client_name}.conf"
    qrencode -t ansiutf8 < "/etc/wireguard/${client_name}.conf"
    echo "=============================================================="
    
    if systemctl -q is-active udp2raw; then
        echo "提醒: 您的服务正在使用 udp2raw，请确保客户端也正确配置。"
    fi
}

# --- 菜单和主逻辑 ---
start_menu() {
	clear
	echo "=================================================="
	echo " 适用于 Alpine Linux 的 WireGuard 一键安装脚本"
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
check_alpine
start_menu
