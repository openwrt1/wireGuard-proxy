#!/bin/bash

#================================================================================
# 适用于 Ubuntu 的 WireGuard + Udp2raw 一键安装脚本
#
# 功能:
# 1. 安装 WireGuard (可选集成 Udp2raw)
# 2. 卸载 WireGuard
# 3. 添加新用户
# 4. 删除用户
# 5. 优化系统 (升级内核并开启 BBR)
# 6. 智能安装检测，防止重复执行
#================================================================================

# --- 全局函数和变量 ---

# 判断是否为 root 用户
check_root() {
	if [ "$(id -u)" != "0" ]; then
		echo "错误: 你必须以 root 用户身份运行此脚本" 1>&2
		exit 1
	fi
}

# 判断系统是否为 Ubuntu
check_ubuntu() {
	if ! grep -qi "Ubuntu" /etc/os-release; then
		echo "错误: 此脚本仅支持 Ubuntu 系统"
		exit 1
	fi
}

# 生成随机端口
rand_port() {
	min=10000
	max=60000
	echo $((RANDOM % (max - min) + min))
}

# 初始系统状态检查
initial_check() {
    kernel_version=$(uname -r)
    bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control)

    echo "==================== 系统状态检查 ===================="
    echo "当前内核版本: $kernel_version"
    if [[ "$kernel_version" =~ ^[5-9]\. || "$kernel_version" =~ ^[1-9][0-9]+\. ]]; then
        echo -e "状态: \033[0;32m良好 (推荐内核)\033[0m"
    else
        echo -e "状态: \033[0;33m过旧 (建议升级内核以获得最佳性能)\033[0m"
    fi

    echo "TCP 拥塞控制算法: $bbr_status"
    if [ "$bbr_status" = "bbr" ]; then
        echo -e "状态: \033[0;32mBBR 已开启\033[0m"
    else
        echo -e "状态: \033[0;33mBBR 未开启 (建议开启以优化网络)\033[0m"
    fi
    echo "======================================================"
    echo
}

# 显示 Udp2raw 客户端配置信息
display_udp2raw_info() {
    local server_ip=$1
    local tcp_port=$2
    local udp2raw_password=$3

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
    echo "udp2raw_mp.exe -c -l 127.0.0.1:29999 -r $server_ip:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor -a"
    echo ""
    echo "--------------------------------------------------------------"
    echo "然后再启动 WireGuard 客户端。"
    echo "=============================================================="
}


# --- 主要功能函数 ---

# 安装 WireGuard
wireguard_install(){
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
	apt-get update

	echo "正在安装 WireGuard 及相关工具..."
	apt-get install -y wireguard qrencode ufw curl

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

	echo "配置防火墙 (UFW)..."
	ufw allow ssh

    # 根据是否使用 udp2raw 配置防火墙和客户端
    local client_endpoint
    local wg_port
    local client_mtu
    if [ "$use_udp2raw" == "y" ]; then
        read -r -p "请输入 udp2raw 的 TCP 端口 [默认: 39001]: " tcp_port
        tcp_port=${tcp_port:-39001}
        wg_port=$(rand_port) # 内部 WG 端口保持随机
        client_mtu=1280 # udp2raw 需要更小的 MTU
        udp2raw_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)

        echo "开放 udp2raw 的 TCP 端口: $tcp_port"
        ufw allow "$tcp_port"/tcp

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
	cat > /etc/wireguard/wg0.conf <<-EOF
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
        display_udp2raw_info "$server_ip" "$tcp_port" "$udp2raw_password"
    fi
}

# 卸载 WireGuard
wireguard_uninstall() {
	echo "正在停止并禁用 WireGuard 和 udp2raw 服务..."
	systemctl stop wg-quick@wg0
	systemctl disable wg-quick@wg0
    systemctl stop udp2raw &>/dev/null || true
    systemctl disable udp2raw &>/dev/null || true

	echo "正在卸载 WireGuard 及相关软件包..."
	apt-get remove --purge -y wireguard wireguard-tools qrencode

	echo "正在清理配置文件和程序..."
	rm -rf /etc/wireguard
    rm -f /etc/systemd/system/udp2raw.service
    rm -f /usr/local/bin/udp2raw
    systemctl daemon-reload

	echo "跳过防火墙重置，以避免影响其他服务。"
	echo "请手动删除为 WireGuard 或 udp2raw 开放的端口。"

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
    if [ -z "$last_ip_octet" ]; then
        next_ip_octet=2
    else
        next_ip_octet=$((last_ip_octet + 1))
    fi

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
        client_mtu=1280
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
        # 提醒用户 udp2raw 正在运行，并显示连接信息
        echo "提醒: 您的服务正在使用 udp2raw，新客户端也需要配置。"
        
        # 从 systemd 服务文件中提取信息
        local server_ip
        local tcp_port
        local udp2raw_password
        
        server_ip=$(curl -s -4 icanhazip.com || curl -s -6 icanhazip.com)
        
        if [ -f /etc/systemd/system/udp2raw.service ]; then
            tcp_port=$(grep -oP 'ExecStart=.*-l 0\.0\.0\.0:\K[0-9]+' /etc/systemd/system/udp2raw.service)
            udp2raw_password=$(grep -oP 'ExecStart=.*-k "\K[^"]+' /etc/systemd/system/udp2raw.service)
        fi

        if [ -n "$server_ip" ] && [ -n "$tcp_port" ] && [ -n "$udp2raw_password" ]; then
            display_udp2raw_info "$server_ip" "$tcp_port" "$udp2raw_password"
        else
            echo "警告: 无法从 /etc/systemd/system/udp2raw.service 中自动提取 udp2raw 配置信息。"
            echo "请手动检查您的 udp2raw 客户端配置。"
        fi
    fi
}

# 删除客户端
delete_client() {
    if [ ! -f /etc/wireguard/wg0.conf ]; then
        echo "错误: WireGuard 尚未安装。请先选择选项 1 进行安装。"
        exit 1
    fi

    echo "可用的客户端配置:"
    CLIENTS=$(find /etc/wireguard/ -name "*.conf" -printf "%f\n" | sed 's/\.conf$//' | grep -v '^wg0$')
    
    if [ -z "$CLIENTS" ]; then
        echo "没有找到任何客户端。"
        exit 0
    fi
    echo "$CLIENTS"
    echo

    read -r -p "请输入要删除的客户端的名称: " client_name

    if [ -z "$client_name" ]; then
        echo "错误: 客户端名称不能为空。"
        exit 1
    fi

    if [ ! -f "/etc/wireguard/${client_name}.conf" ]; then
        echo "错误: 名为 ${client_name} 的客户端配置不存在。"
        exit 1
    fi

    # 从 wg0.conf 中根据注释 '# Client: client_name' 找到对应的公钥
    client_pub_key=$(grep -A 2 -E "^\s*# Client: ${client_name}\s*$" /etc/wireguard/wg0.conf | awk '/PublicKey/ {print $3}')

    if [ -z "$client_pub_key" ]; then
        echo "错误: 无法在 wg0.conf 中找到客户端 ${client_name} 的公钥。"
        echo "可能是配置文件格式问题或该用户已被手动删除。"
        exit 1
    fi

    echo "正在删除客户端: $client_name (公钥: $client_pub_key)"

    # 1. 从实时接口中移除 peer
    wg set wg0 peer "$client_pub_key" remove
    if [ $? -ne 0 ]; then
        echo "警告: 从实时接口移除 peer 失败。可能该 peer 已不存在于活动会话中。"
    fi

    # 2. 从 wg0.conf 中移除 peer 配置块
    cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak
    # 使用 awk 以段落模式（由空行分隔）来安全地删除整个 peer 块
    awk -v key_to_remove="$client_pub_key" '
        BEGIN { RS = ""; FS = "\n" }
        {
            is_target = 0
            for (i=1; i<=NF; i++) {
                if ($i ~ "PublicKey = " key_to_remove) {
                    is_target = 1
                    break
                }
            }
            if (!is_target) {
                # 打印非目标的块，并保留其后的记录分隔符（空行）
                print $0 (RT ? RT : "")
            }
        }
    ' /etc/wireguard/wg0.conf.bak > /etc/wireguard/wg0.conf

    # 3. 删除客户端的配置文件
    rm -f "/etc/wireguard/${client_name}.conf"

    echo -e "\n=============================================================="
    echo "🎉 客户端 '$client_name'  已成功删除。"
    echo "=============================================================="
}

# 优化系统
optimize_system() {
    echo "此操作将尝试升级系统内核并开启 BBR 拥塞控制算法。"
    read -r -p "这需要重启服务器才能生效。是否继续? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[yY]([eE][sS])?$ ]]; then
        echo "操作已取消。"
        exit 0
    fi

    echo "正在更新软件包列表..."
    apt-get update

    echo "正在安装最新的 HWE (Hardware Enablement) 内核..."
    # HWE 内核是 Ubuntu 官方提供的方式，用于在 LTS 版本上获取新硬件支持和新内核
    apt-get install -y --install-recommends linux-generic-hwe-$(lsb_release -rs)

    echo "正在配置 BBR..."
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi

    echo -e "\n=============================================================="
    echo "🎉 系统优化配置完成! 🎉"
    echo "内核已升级，BBR 已配置。"
    echo -e "\033[1;31m请务必重启服务器 (reboot) 以应用新的内核和设置。\033[0m"
    echo "=============================================================="
}


# --- 菜单和主逻辑 ---
start_menu(){
	clear
    initial_check
	echo "=================================================="
	echo " 适用于 Ubuntu 的 WireGuard 一键安装脚本"
	echo " (集成 Udp2raw 伪装功能)"
	echo "=================================================="
	echo "1. 安装 WireGuard"
	echo "2. 卸载 WireGuard"
	echo "3. 添加新用户"
	echo "4. 删除用户"
	echo "5. 优化系统 (升级内核并开启 BBR)"
	echo "6. 退出脚本"
	echo
	read -r -p "请输入数字 [1-6]: " num
	case "$num" in
	1) wireguard_install ;;
	2) wireguard_uninstall ;;
	3) add_new_client ;;
	4) delete_client ;;
	5) optimize_system ;;
	6) exit 0 ;;
	*)
		echo "错误: 请输入正确的数字"
		sleep 2
		start_menu
		;;
	esac
}

# --- 脚本入口 ---
check_root
check_ubuntu
start_menu
