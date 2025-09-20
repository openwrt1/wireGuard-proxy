#!/bin/bash
# 启用严格模式
set -e
set -o pipefail

#================================================================================
# 适用于 Ubuntu 的 WireGuard + Udp2raw 一键安装脚本 (功能增强版)
#
# 功能:
# 1. 安装 WireGuard (可选集成 Udp2raw, 可选 IP 模式)
# 2. 卸载 WireGuard
# 3. 添加新用户
# 4. 删除用户
# 5. 显示所有客户端配置
# 6. 显示 Udp2raw 客户端配置
# 7. 优化系统 (开启 BBR)
# 8. 智能安装检测，防止重复执行
#================================================================================

# --- 全局函数和变量 ---

# 统一错误处理函数
error_exit() {
    echo -e "\033[1;31m错误: $1 (脚本第 $2 行)\033[0m" >&2
    exit 1
}
trap 'error_exit "命令执行失败" $LINENO' ERR

# 判断是否为 root 用户
check_root() {
	if [ "$(id -u)" != "0" ]; then
        error_exit "你必须以 root 用户身份运行此脚本" $LINENO
	fi
}

# 判断系统是否为 Ubuntu
check_ubuntu() {
	if ! grep -qi "Ubuntu" /etc/os-release; then
        error_exit "此脚本仅支持 Ubuntu 系统" $LINENO
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

# 获取公网 IP 地址 (IPv4 和 IPv6)
get_public_ips() {
    ipv4_apis=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip")
    ipv6_apis=("https://api64.ipify.org" "https://ipv6.icanhazip.com")

    for api in "${ipv4_apis[@]}"; do
        public_ipv4=$(curl -s -m 5 "$api")
        if [ -n "$public_ipv4" ]; then break; fi
    done

    for api in "${ipv6_apis[@]}"; do
        public_ipv6=$(curl -s -m 5 "$api")
        if [ -n "$public_ipv6" ]; then break; fi
    done
}

# 显示 Udp2raw 客户端配置信息
display_udp2raw_info() {
    local server_ipv4=$1
    local server_ipv6=$2
    local tcp_port_v4=$3
    local tcp_port_v6=$4
    local udp2raw_password=$5

    echo -e "\n=================== 客户端 Udp2raw 设置 ==================="
    echo "伪装模式已启用，您需要在客户端上运行 udp2raw。"
    echo "提示: 以下命令已适配 udp2raw_mp 等不支持 -a 参数的客户端。"
    echo "如果您使用原版 udp2raw，请将 --raw-mode easyfaketcp 改为 --raw-mode faketcp 并添加 -a 参数。"
    echo "连接密码: $udp2raw_password"
    echo ""

    if [ -n "$tcp_port_v4" ]; then
        echo -e "\033[1;32m--- IPv4 连接命令 (服务器端口: $tcp_port_v4) ---\033[0m"
        echo "./<udp2raw_binary> -c -l 127.0.0.1:29999 -r $server_ipv4:$tcp_port_v4 -k \"$udp2raw_password\" --raw-mode easyfaketcp --cipher-mode xor --dev <物理网卡名>"
        echo ""
    fi

    if [ -n "$tcp_port_v6" ]; then
        echo -e "\033[1;32m--- IPv6 连接命令 (服务器端口: $tcp_port_v6) ---\033[0m"
        echo "./<udp2raw_binary> -c -l 127.0.0.1:29999 -r [$server_ipv6]:$tcp_port_v6 -k \"$udp2raw_password\" --raw-mode easyfaketcp --cipher-mode xor --dev <物理网卡名>"
        echo ""
    fi

    echo "--------------------------------------------------------------"
    echo "然后再启动 WireGuard 客户端。"
    echo "=============================================================="
}


# --- 主要功能函数 ---

# 安装 WireGuard
wireguard_install(){
    if [ -f /etc/wireguard/wg0.conf ]; then
        echo "检测到 WireGuard 已安装 (/etc/wireguard/wg0.conf 存在)。"
        exit 0
    fi

    # IP 模式选择
    echo "请选择服务器的 IP 模式:"
    echo "  1) IPv4 Only (仅监听 IPv4)"
    echo "  2) IPv6 Only (仅监听 IPv6)"
    echo "  3) Dual Stack (IPv4 + IPv6 混合模式)"
    read -r -p "请输入数字 [1-3]: " ip_mode_choice
    case "$ip_mode_choice" in
        1) ip_mode="ipv4" ;;
        2) ip_mode="ipv6" ;;
        3) ip_mode="dual" ;;
        *) error_exit "无效的选择" $LINENO ;;
    esac

    if [ "$ip_mode" = "dual" ]; then
        echo -e "\033[1;33m警告: 混合模式在某些网络环境下可能导致客户端连接混乱或速度不稳定。\033[0m"
    fi

    read -r -p "是否启用 TCP 伪装 (udp2raw)？[y/N]: " use_udp2raw
    use_udp2raw=$(echo "$use_udp2raw" | tr '[:upper:]' '[:lower:]')

	echo "正在更新软件包列表..."
	apt-get update

	echo "正在安装 WireGuard 及相关工具..."
	apt-get install -y wireguard qrencode curl
    echo -e "\033[0;32m✓ 核心工具安装成功。\033[0m"

	echo "正在创建 WireGuard 目录和密钥..."
	mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
	cd /etc/wireguard || exit 1

	wg genkey | tee sprivatekey | wg pubkey > spublickey
	wg genkey | tee cprivatekey | wg pubkey > cpublickey
	chmod 600 sprivatekey cprivatekey
    echo -e "\033[0;32m✓ 密钥生成成功。\033[0m"

	s1=$(cat sprivatekey)
	s2=$(cat spublickey)
	c1=$(cat cprivatekey)
	c2=$(cat cpublickey)

    echo "正在获取公网 IP 地址..."
    get_public_ips
    if [ "$ip_mode" = "ipv4" ] && [ -z "$public_ipv4" ]; then error_exit "无法获取 IPv4 地址，无法继续安装。" $LINENO; fi
    if [ "$ip_mode" = "ipv6" ] && [ -z "$public_ipv6" ]; then error_exit "无法获取 IPv6 地址，无法继续安装。" $LINENO; fi
    if [ "$ip_mode" = "dual" ] && [ -z "$public_ipv4" ] && [ -z "$public_ipv6" ]; then error_exit "无法获取任何公网 IP 地址。" $LINENO; fi
    echo "检测到 IPv4: ${public_ipv4:-N/A}"
    echo "检测到 IPv6: ${public_ipv6:-N/A}"
    
	echo "配置系统网络转发..."
    if [ "$ip_mode" = "ipv4" ] || [ "$ip_mode" = "dual" ]; then
        sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
        if ! grep -q -E "^\s*net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf; fi
    fi
    if [ "$ip_mode" = "ipv6" ] || [ "$ip_mode" = "dual" ]; then
        sed -i '/net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf
        if ! grep -q -E "^\s*net.ipv6.conf.all.forwarding\s*=\s*1" /etc/sysctl.conf; then echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf; fi
    fi
    sysctl -p >/dev/null
    echo -e "\033[0;32m✓ 网络转发配置成功。\033[0m"

    PARAMS_FILE="/etc/wireguard/params"
    {
        echo "IP_MODE=$ip_mode"
        echo "SERVER_IPV4=${public_ipv4}"
        echo "SERVER_IPV6=${public_ipv6}"
    } > "$PARAMS_FILE"

    local client_endpoint wg_port client_mtu postup_rules predown_rules tcp_port_v4 tcp_port_v6 udp2raw_password
    wg_port=$(rand_port)

    local net_interface net_interface_ipv6
    if [ "$ip_mode" = "ipv4" ] || [ "$ip_mode" = "dual" ]; then
        net_interface=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
        if [ -z "$net_interface" ]; then error_exit "无法自动检测到有效的 IPv4 主网络接口。" $LINENO; fi
        echo "检测到 IPv4 主网络接口为: $net_interface"
    fi
    if [ "$use_udp2raw" = "y" ]; then
        client_mtu=1280
        udp2raw_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        {
            echo "USE_UDP2RAW=true"
            echo "UDP2RAW_PASSWORD=$udp2raw_password"
        } >> "$PARAMS_FILE"

        echo "正在下载并安装 udp2raw..."
        UDP2RAW_URL="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"
        curl -L -o udp2raw_binaries.tar.gz "$UDP2RAW_URL"
        tar -xzf udp2raw_binaries.tar.gz
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64) UDP2RAW_BINARY="udp2raw_amd64" ;;
            aarch64 | arm*) UDP2RAW_BINARY="udp2raw_arm" ;;
            i386 | i686) UDP2RAW_BINARY="udp2raw_x86" ;;
            *) error_exit "不支持的系统架构 '$ARCH'。" $LINENO ;;
        esac
        cp "$UDP2RAW_BINARY" /usr/local/bin/udp2raw-ipv4
        cp "$UDP2RAW_BINARY" /usr/local/bin/udp2raw-ipv6
        chmod +x /usr/local/bin/udp2raw-ipv4 /usr/local/bin/udp2raw-ipv6
        rm -f udp2raw_* version.txt udp2raw_binaries.tar.gz udp2raw_amd64 udp2raw_arm udp2raw_x86
        echo -e "\033[0;32m✓ Udp2raw 安装成功。\033[0m"

        postup_rules=""
        predown_rules=""
        if [ "$ip_mode" = "ipv4" ] || [ "$ip_mode" = "dual" ]; then
            read -r -p "请输入 udp2raw 的 IPv4 TCP 端口 [默认: 39001]: " tcp_port_v4
            tcp_port_v4=${tcp_port_v4:-39001}
            echo "TCP_PORT_V4=$tcp_port_v4" >> "$PARAMS_FILE"
            cat > /etc/systemd/system/udp2raw-ipv4.service <<-EOF
[Unit]
Description=udp2raw-tunnel server (IPv4)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw-ipv4 -s -l 0.0.0.0:$tcp_port_v4 -r 127.0.0.1:$wg_port -k "$udp2raw_password" --raw-mode faketcp --cipher-mode xor -a
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
            postup_rules="${postup_rules} ! iptables -C INPUT -p tcp --dport $tcp_port_v4 -j ACCEPT 2>/dev/null && iptables -I INPUT -p tcp --dport $tcp_port_v4 -j ACCEPT;"
            predown_rules="${predown_rules} iptables -D INPUT -p tcp --dport $tcp_port_v4 -j ACCEPT 2>/dev/null || true;"
            systemctl daemon-reload
            systemctl enable udp2raw-ipv4
            systemctl start udp2raw-ipv4
            echo -e "\033[0;32m✓ Udp2raw IPv4 服务已启动并设置开机自启。\033[0m"
        fi
        if [ "$ip_mode" = "ipv6" ] || [ "$ip_mode" = "dual" ]; then
            read -r -p "请输入 udp2raw 的 IPv6 TCP 端口 [默认: 39002]: " tcp_port_v6
            tcp_port_v6=${tcp_port_v6:-39002}
            echo "TCP_PORT_V6=$tcp_port_v6" >> "$PARAMS_FILE"
            cat > /etc/systemd/system/udp2raw-ipv6.service <<-EOF
[Unit]
Description=udp2raw-tunnel server (IPv6)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw-ipv6 -s -l [::]:$tcp_port_v6 -r 127.0.0.1:$wg_port -k "$udp2raw_password" --raw-mode faketcp --cipher-mode xor -a
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
            postup_rules="${postup_rules} ! ip6tables -C INPUT -p tcp --dport $tcp_port_v6 -j ACCEPT 2>/dev/null && ip6tables -I INPUT -p tcp --dport $tcp_port_v6 -j ACCEPT;"
            predown_rules="${predown_rules} ip6tables -D INPUT -p tcp --dport $tcp_port_v6 -j ACCEPT 2>/dev/null || true;"
            systemctl daemon-reload
            systemctl enable udp2raw-ipv6
            systemctl start udp2raw-ipv6
            echo -e "\033[0;32m✓ Udp2raw IPv6 服务已启动并设置开机自启。\033[0m"
        fi
        client_endpoint="127.0.0.1:29999"
    else
        read -r -p "请输入 WireGuard 的 UDP 端口 [默认: 39000]: " wg_port
        wg_port=${wg_port:-39000}
        client_mtu=1420
        {
            echo "USE_UDP2RAW=false"
            echo "WG_PORT=$wg_port"
        } >> "$PARAMS_FILE"
        postup_rules="! iptables -C INPUT -p udp --dport $wg_port -j ACCEPT 2>/dev/null && iptables -I INPUT -p udp --dport $wg_port -j ACCEPT;"
        predown_rules="iptables -D INPUT -p udp --dport $wg_port -j ACCEPT 2>/dev/null || true;"
        
        if [ "$ip_mode" = "ipv4" ]; then client_endpoint="$public_ipv4:$wg_port"; fi
        if [ "$ip_mode" = "ipv6" ]; then client_endpoint="[$public_ipv6]:$wg_port"; fi
        if [ "$ip_mode" = "dual" ]; then
             if [ -n "$public_ipv4" ]; then client_endpoint="$public_ipv4:$wg_port"; else client_endpoint="[$public_ipv6]:$wg_port"; fi
        fi
    fi

    if [ "$ip_mode" = "ipv6" ] || [ "$ip_mode" = "dual" ]; then
        net_interface_ipv6=$(ip -o -6 route show to default | awk '{print $5}' | head -n1)
        if [ -z "$net_interface_ipv6" ]; then
            net_interface_ipv6=$(ip -6 addr show scope global | grep -oP 'dev \K[^ ]+' | head -n1)
        fi
        if [ -z "$net_interface_ipv6" ]; then error_exit "无法自动检测到有效的 IPv6 主网络接口。" $LINENO; fi
        echo "检测到 IPv6 主网络接口为: $net_interface_ipv6"
    fi

    if [ "$ip_mode" = "ipv4" ] || [ "$ip_mode" = "dual" ]; then
        postup_rules="${postup_rules} ! iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE 2>/dev/null && iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE;"
        predown_rules="${predown_rules} iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE 2>/dev/null || true;"
    fi
    if [ "$ip_mode" = "ipv6" ] || [ "$ip_mode" = "dual" ]; then
        postup_rules="${postup_rules} ! ip6tables -t nat -C POSTROUTING -s fd86:ea04:1111::/64 -o $net_interface_ipv6 -j MASQUERADE 2>/dev/null && ip6tables -t nat -A POSTROUTING -s fd86:ea04:1111::/64 -o $net_interface_ipv6 -j MASQUERADE;"
        postup_rules="${postup_rules} ! ip6tables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null && ip6tables -I FORWARD -i wg0 -j ACCEPT;"
        postup_rules="${postup_rules} ! ip6tables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && ip6tables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;"
        predown_rules="${predown_rules} ip6tables -t nat -D POSTROUTING -s fd86:ea04:1111::/64 -o $net_interface_ipv6 -j MASQUERADE 2>/dev/null || true;"
        predown_rules="${predown_rules} ip6tables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; ip6tables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true;"
    fi

    server_address=""; client_address=""; client_dns=""; peer_allowed_ips=""
    if [ "$ip_mode" = "ipv4" ] || [ "$ip_mode" = "dual" ]; then
        server_address="10.0.0.1/24"; client_address="10.0.0.2/24"; peer_allowed_ips="10.0.0.2/32"; client_dns="8.8.8.8"
    fi
    if [ "$ip_mode" = "ipv6" ] || [ "$ip_mode" = "dual" ]; then
        server_address=${server_address:+"$server_address, "}fd86:ea04:1111::1/64
        client_address=${client_address:+"$client_address, "}fd86:ea04:1111::2/64
        peer_allowed_ips=${peer_allowed_ips:+"$peer_allowed_ips, "}fd86:ea04:1111::2/128
        client_dns=${client_dns:+"$client_dns, "}2001:4860:4860::8888
    fi

    # 针对单栈模式优化客户端 AllowedIPs
    local client_allowed_ips="0.0.0.0/0, ::/0" # 默认全局隧道
    if [ "$ip_mode" = "ipv4" ]; then client_allowed_ips="0.0.0.0/0"; fi
    if [ "$ip_mode" = "ipv6" ]; then client_allowed_ips="::/0"; fi

	echo "正在创建服务器配置文件 wg0.conf..."
	cat > /etc/wireguard/wg0.conf <<-EOF
		[Interface]
		PrivateKey = $s1
		Address = $server_address
		ListenPort = $wg_port
		MTU = 1420
        PostUp = $postup_rules
        PreDown = $predown_rules
		[Peer]
		# Client: client
		PublicKey = $c2
		AllowedIPs = $peer_allowed_ips
	EOF

	echo "正在创建客户端配置文件 client.conf..."
	cat > /etc/wireguard/client.conf <<-EOF
		[Interface]
		PrivateKey = $c1
		Address = $client_address
		DNS = $client_dns
		MTU = $client_mtu
		[Peer]
		PublicKey = $s2
		Endpoint = $client_endpoint
		AllowedIPs = $client_allowed_ips
		PersistentKeepalive = 25
	EOF
    chmod 600 /etc/wireguard/*.conf
    echo -e "\033[0;32m✓ 配置文件创建成功。\033[0m"

	echo "启动并设置 WireGuard 服务开机自启..."
	wg-quick down wg0 &>/dev/null || true
	wg-quick up wg0
	systemctl enable wg-quick@wg0
    echo -e "\033[0;32m✓ WireGuard 服务已启动并设置开机自启。\033[0m"

	echo -e "\n🎉 WireGuard 安装完成! 🎉"
	echo "-------------------- 初始客户端配置 --------------------"
    echo "配置文件路径: /etc/wireguard/client.conf"
    echo "二维码:"
	qrencode -t ansiutf8 < /etc/wireguard/client.conf
    echo -e "\n配置文件内容:"
    cat "/etc/wireguard/client.conf"
    echo "------------------------------------------------------"

    if [ "$use_udp2raw" = "y" ]; then
        display_udp2raw_info "$public_ipv4" "$public_ipv6" "$tcp_port_v4" "$tcp_port_v6" "$udp2raw_password"
    fi

    printf "\n💡 \033[1;36m提示: 您可以使用以下命令检查防火墙规则是否已正确加载。\033[0m\n"
    if [ "$ip_mode" = "ipv4" ] || [ "$ip_mode" = "dual" ]; then
        printf "  - 检查 IPv4 NAT 规则:   \033[0;32miptables -t nat -L POSTROUTING -v -n\033[0m\n"
        if [ "$use_udp2raw" = "y" ]; then
            printf "  - 检查 IPv4 入站规则:   \033[0;32miptables -L INPUT -v -n | grep --color=never -E 'dpt:%s'\033[0m\n" "$tcp_port_v4"
        else
            printf "  - 检查 IPv4 入站规则:   \033[0;32miptables -L INPUT -v -n | grep --color=never -E 'dpt:%s'\033[0m\n" "$wg_port"
        fi
    fi
    if [ "$ip_mode" = "ipv6" ] || [ "$ip_mode" = "dual" ]; then
        printf "  - 检查 IPv6 NAT 规则:   \033[0;32mip6tables -t nat -L POSTROUTING -v -n\033[0m\n"
        if [ "$use_udp2raw" = "y" ] && [ -n "$tcp_port_v6" ]; then
            printf "  - 检查 IPv6 入站规则:   \033[0;32mip6tables -L INPUT -v -n | grep --color=never -E 'dpt:%s'\033[0m\n" "$tcp_port_v6"
        fi
    fi
}

# 卸载 WireGuard
wireguard_uninstall() {
    echo "正在停止并卸载 WireGuard 及相关服务..."
    set +e
    wg-quick down wg0 &>/dev/null || true
	systemctl stop wg-quick@wg0 && systemctl disable wg-quick@wg0
    systemctl stop udp2raw-ipv4 && systemctl disable udp2raw-ipv4
    systemctl stop udp2raw-ipv6 && systemctl disable udp2raw-ipv6
    set -e
	apt-get remove --purge -y wireguard wireguard-tools qrencode &>/dev/null
	rm -rf /etc/wireguard /usr/local/bin/udp2raw-ipv4 /usr/local/bin/udp2raw-ipv6 /etc/systemd/system/udp2raw-ipv4.service /etc/systemd/system/udp2raw-ipv6.service
    systemctl daemon-reload
	echo "🎉 WireGuard 及 Udp2raw 已成功卸载。"
}

# 添加新客户端
add_new_client() {
    if [ ! -f /etc/wireguard/wg0.conf ]; then error_exit "WireGuard 尚未安装。" $LINENO; fi

    local PARAMS_FILE IP_MODE SERVER_IPV4 SERVER_IPV6 USE_UDP2RAW WG_PORT TCP_PORT_V4 TCP_PORT_V6 UDP2RAW_PASSWORD
    PARAMS_FILE="/etc/wireguard/params"
    # shellcheck source=/etc/wireguard/params
    if [ -f "$PARAMS_FILE" ]; then source "$PARAMS_FILE"; else error_exit "params 文件不存在。" $LINENO; fi

    read -r -p "请输入新客户端的名称: " client_name
    if [ -z "$client_name" ]; then error_exit "客户端名称不能为空。" $LINENO; fi
    if [ -f "/etc/wireguard/${client_name}.conf" ]; then error_exit "名为 ${client_name} 的客户端已存在。" $LINENO; fi

    local new_client_ip_v4 new_client_ip_v6 peer_allowed_ips client_address

    if [ "$IP_MODE" = "ipv4" ] || [ "$IP_MODE" = "dual" ]; then
        last_ip_octet=$(grep -oP '10\.0\.0\.\K[0-9]+' /etc/wireguard/wg0.conf | sort -n | tail -1 || echo 1)
        next_ip_octet=$((last_ip_octet + 1))
        if [ "$next_ip_octet" -gt 254 ]; then error_exit "IPv4 地址池已满。" $LINENO; fi
        new_client_ip_v4="10.0.0.${next_ip_octet}"
        peer_allowed_ips="$new_client_ip_v4/32"
        client_address="$new_client_ip_v4/24"
    fi
    if [ "$IP_MODE" = "ipv6" ] || [ "$IP_MODE" = "dual" ]; then
        last_ip_octet=$(grep -oP 'fd86:ea04:1111::\K[0-9a-fA-F]+' /etc/wireguard/wg0.conf | sort -n | tail -1 || echo 1)
        next_ip_octet=$((last_ip_octet + 1))
        new_client_ip_v6="fd86:ea04:1111::${next_ip_octet}"
        peer_allowed_ips=${peer_allowed_ips:+"$peer_allowed_ips, "}"$new_client_ip_v6/128"
        client_address=${client_address:+"$client_address, "}"$new_client_ip_v6/64"
    fi
    echo "为新客户端分配的 IP: ${new_client_ip_v4:-N/A} ${new_client_ip_v6:-N/A}"

    cd /etc/wireguard || exit 1
    local new_client_private_key new_client_public_key
    new_client_private_key=$(wg genkey)
    new_client_public_key=$(echo "$new_client_private_key" | wg pubkey)

    wg set wg0 peer "$new_client_public_key" allowed-ips "$peer_allowed_ips"
    printf "\n[Peer]\n# Client: %s\nPublicKey = %s\nAllowedIPs = %s\n" "$client_name" "$new_client_public_key" "$peer_allowed_ips" >> /etc/wireguard/wg0.conf

    local server_public_key
    server_public_key=$(cat spublickey)
    
    local client_endpoint client_mtu client_dns=""
    if [ "$USE_UDP2RAW" = "true" ]; then
        client_endpoint="127.0.0.1:29999"
        client_mtu=1280
    else
        if [ "$IP_MODE" = "ipv4" ]; then client_endpoint="${SERVER_IPV4}:${WG_PORT}"; fi
        if [ "$IP_MODE" = "ipv6" ]; then client_endpoint="[${SERVER_IPV6}]:${WG_PORT}"; fi
        if [ "$IP_MODE" = "dual" ]; then
            if [ -n "$SERVER_IPV4" ]; then client_endpoint="${SERVER_IPV4}:${WG_PORT}"; else client_endpoint="[${SERVER_IPV6}]:${WG_PORT}"; fi
        fi
        client_mtu=1420
    fi

    local client_allowed_ips="0.0.0.0/0, ::/0" # 默认全局隧道
    if [ "$IP_MODE" = "ipv4" ] || [ "$IP_MODE" = "dual" ]; then client_dns="8.8.8.8"; fi
    if [ "$IP_MODE" = "ipv6" ] || [ "$IP_MODE" = "dual" ]; then
        client_dns=${client_dns:+"$client_dns, "}2001:4860:4860::8888
    fi

    # 针对单栈模式优化客户端配置
    if [ "$IP_MODE" = "ipv4" ]; then client_allowed_ips="0.0.0.0/0"; fi
    if [ "$IP_MODE" = "ipv6" ]; then client_allowed_ips="::/0"; fi


    cat > "/etc/wireguard/${client_name}.conf" <<-EOF
		[Interface]
		PrivateKey = $new_client_private_key
		Address = $client_address
		DNS = $client_dns
		MTU = $client_mtu
		[Peer]
		PublicKey = $server_public_key
		Endpoint = $client_endpoint
		AllowedIPs = $client_allowed_ips
		PersistentKeepalive = 25
	EOF
    chmod 600 "/etc/wireguard/${client_name}.conf"

    echo -e "\n🎉 新客户端 '$client_name' 添加成功!"
    echo "-------------------- 客户端配置 --------------------"
    echo "配置文件路径: /etc/wireguard/${client_name}.conf"
    echo "二维码:"
    qrencode -t ansiutf8 < "/etc/wireguard/${client_name}.conf"
    echo -e "\n配置文件内容:"
    cat "/etc/wireguard/${client_name}.conf"
    echo "------------------------------------------------------"
    
    if [ "$USE_UDP2RAW" = "true" ]; then
        echo "提醒: 您的服务正使用 udp2raw，新客户端也需按以下信息配置。"
        display_udp2raw_info "$SERVER_IPV4" "$SERVER_IPV6" "$TCP_PORT_V4" "$TCP_PORT_V6" "$UDP2RAW_PASSWORD"
    fi
}

# 删除客户端
delete_client() {
    if [ ! -f /etc/wireguard/wg0.conf ]; then error_exit "WireGuard 尚未安装。" $LINENO; fi

    echo "可用的客户端配置:"
    mapfile -t CLIENTS < <(find /etc/wireguard/ -name "*.conf" -printf "%f\n" | sed 's/\.conf$//' | grep -v '^wg0$' || true)
    if [ ${#CLIENTS[@]} -eq 0 ]; then echo "没有找到任何客户端。"; exit 0; fi
    printf '%s\n' "${CLIENTS[@]}"

    read -r -p "请输入要删除的客户端名称: " client_name
    if [ -z "$client_name" ]; then error_exit "客户端名称不能为空。" $LINENO; fi
    if [[ ! " ${CLIENTS[*]} " == *" ${client_name} "* ]]; then error_exit "客户端 ${client_name} 不存在。" $LINENO; fi

    local client_pub_key
    client_pub_key=$(awk -v client="$client_name" '/^# Client: / && $3==client {getline; print $3}' /etc/wireguard/wg0.conf)
    if [ -z "$client_pub_key" ]; then error_exit "无法在 wg0.conf 中找到客户端 ${client_name} 的公钥。" $LINENO; fi

    wg set wg0 peer "$client_pub_key" remove
    sed -i "/^# Client: ${client_name}$/,/^$/d" /etc/wireguard/wg0.conf

    rm -f "/etc/wireguard/${client_name}.conf"

    echo "🎉 客户端 '$client_name' 已成功删除。"
}

# 显示所有客户端配置
list_clients() {
    if [ ! -d /etc/wireguard ]; then error_exit "WireGuard 尚未安装。" $LINENO; fi
    mapfile -t CLIENTS < <(find /etc/wireguard/ -name "*.conf" -printf "%f\n" | sed 's/\.conf$//' | grep -v '^wg0$' || true)
    if [ ${#CLIENTS[@]} -eq 0 ]; then echo "没有找到任何客户端配置。"; exit 0; fi

    echo "==================== 所有客户端配置 ===================="
    for client in "${CLIENTS[@]}"; do
        echo -e "\n--- 客户端: \033[1;32m$client\033[0m ---"
        echo "配置文件路径: /etc/wireguard/${client}.conf"
        echo "二维码:"
        qrencode -t ansiutf8 < "/etc/wireguard/${client}.conf"
        echo -e "\n配置文件内容:"
        cat "/etc/wireguard/${client}.conf"
        echo "------------------------------------------------------"
    done
    echo "======================================================="
}

# 显示 Udp2raw 配置
show_udp2raw_config() {
    if [ ! -f /etc/wireguard/params ]; then error_exit "WireGuard 尚未安装或配置文件不完整。" $LINENO; fi
    
    local IP_MODE SERVER_IPV4 SERVER_IPV6 USE_UDP2RAW WG_PORT TCP_PORT_V4 TCP_PORT_V6 UDP2RAW_PASSWORD
    # shellcheck source=/etc/wireguard/params
    source /etc/wireguard/params
    if [ "$USE_UDP2RAW" = "true" ]; then
        display_udp2raw_info "$SERVER_IPV4" "$SERVER_IPV6" "$TCP_PORT_V4" "$TCP_PORT_V6" "$UDP2RAW_PASSWORD"
    else
        echo "Udp2raw 模式未在安装时启用。"
    fi
}

# 优化系统
optimize_system() {
    read -r -p "此操作将尝试应用 BBR 设置，可能需要更新内核并重启。是否继续? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[yY] ]]; then echo "操作已取消。"; exit 0; fi

    if ! grep -q -E "^\s*net.core.default_qdisc\s*=\s*fq" /etc/sysctl.conf; then echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; fi
    if ! grep -q -E "^\s*net.ipv4.tcp_congestion_control\s*=\s*bbr" /etc/sysctl.conf; then echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; fi
    sysctl -p >/dev/null

    echo -e "🎉 BBR 配置已写入。如果 BBR 未生效，您可能需要手动升级内核并重启。"
    initial_check
}


# --- 菜单和主逻辑 ---
start_menu(){
	clear
    initial_check
	echo "=================================================="
	echo " 适用于 Ubuntu 的 WireGuard 一键安装脚本"
	echo "=================================================="
	echo "1. 安装 WireGuard"
	echo "2. 卸载 WireGuard"
	echo "3. 添加新用户"
	echo "4. 删除用户"
    echo "5. 显示所有客户端配置"
    echo "6. 显示 Udp2raw 客户端配置"
	echo "7. 优化系统 (开启 BBR)"
	echo "8. 退出脚本"
	echo
	read -r -p "请输入数字 [1-8]: " num
    local num
	case "$num" in
	1) wireguard_install ;;
	2) wireguard_uninstall ;;
	3) add_new_client ;;
	4) delete_client ;;
    5) list_clients ;;
    6) show_udp2raw_config ;;
	7) optimize_system ;;
	8) exit 0 ;;
	*)
		echo "错误: 请输入正确的数字"; sleep 2; start_menu ;;
	esac
}

# --- 脚本入口 ---
check_root
check_ubuntu
start_menu
