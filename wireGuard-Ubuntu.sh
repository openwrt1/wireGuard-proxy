#!/bin/bash
# 启用严格模式
set -e
set -o pipefail

#================================================================================
# 适用于 Ubuntu 的 WireGuard + Udp2raw 一键安装脚本 (安全加固版)
#
# 功能:
# 1. 安装 WireGuard (可选集成 Udp2raw)
# 2. 卸载 WireGuard
# 3. 添加新用户
# 4. 删除用户
# 5. 显示所有客户端配置
# 6. 显示 Udp2raw 客户端配置
# 7. 优化系统 (升级内核并开启 BBR)
# 8. 智能安装检测，防止重复执行
#================================================================================

# --- 全局函数和变量 ---

# 统一错误处理函数
error_exit() {
    echo -e "\033[1;31m错误: $1 (脚本第 $2 行)\033[0m" >&2
    exit 1
}

# 清理函数，在脚本退出时执行
cleanup() {
    # 可以在这里添加清理逻辑，例如删除临时文件
    # echo "正在执行清理操作..."
    rm -f /etc/wireguard/udp2raw_binaries.tar.gz /etc/wireguard/version.txt
}

trap 'error_exit "命令执行失败" $LINENO' ERR
trap cleanup EXIT

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
    local tcp_port=$3
    local udp2raw_password=$4

    echo -e "\n=================== 客户端 Udp2raw 设置 ==================="
    echo "伪装模式已启用，您需要在客户端上运行 udp2raw。"
    echo "请从 https://github.com/wangyu-/udp2raw/releases 下载 udp2raw 二进制文件。"
    echo "解压后，根据您的操作系统，在终端或命令行中运行对应命令："
    echo ""
    echo "服务器 TCP 端口: $tcp_port"
    echo "连接密码: $udp2raw_password"
    echo ""

    if [ -n "$server_ipv4" ]; then
        echo -e "\033[1;32m--- IPv4 连接命令 (推荐) ---\033[0m"
        echo "Linux: ./udp2raw_amd64 -c -l 127.0.0.1:29999 -r $server_ipv4:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
        echo "macOS: ./udp2raw_mp_mac -c -l 127.0.0.1:29999 -r $server_ipv4:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
        echo "Windows: udp2raw_mp.exe -c -l 127.0.0.1:29999 -r $server_ipv4:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
        echo ""
    fi

    if [ -n "$server_ipv6" ]; then
        echo -e "\033[1;32m--- IPv6 连接命令 ---\033[0m"
        echo "Linux: ./udp2raw_amd64 -c -l 127.0.0.1:29999 -r [$server_ipv6]:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
        echo "macOS: ./udp2raw_mp_mac -c -l 127.0.0.1:29999 -r [$server_ipv6]:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
        echo "Windows: udp2raw_mp.exe -c -l 127.0.0.1:29999 -r [$server_ipv6]:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor"
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

    read -r -p "是否启用 TCP 伪装 (udp2raw)？[y/N]: " USE_UDP2RAW
    USE_UDP2RAW=$(echo "$USE_UDP2RAW" | tr '[:upper:]' '[:lower:]')

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

    echo "正在获取公网 IP 地址..."
    get_public_ips
    if [ -z "$public_ipv4" ] && [ -z "$public_ipv6" ]; then
        error_exit "无法获取公网 IP 地址。" $LINENO
    fi
    echo "检测到 IPv4: ${public_ipv4:-N/A}"
    echo "检测到 IPv6: ${public_ipv6:-N/A}"
    
	echo "配置系统网络转发..."
	sed -i -e '/net.ipv4.ip_forward=1/s/^#//' -e '/net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf
	if ! grep -q -E "^\s*net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf; fi
	if ! grep -q -E "^\s*net.ipv6.conf.all.forwarding\s*=\s*1" /etc/sysctl.conf; then echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf; fi
    
    # 验证并应用 sysctl 配置
    sysctl -p >/dev/null || error_exit "sysctl 配置加载失败，请检查 /etc/sysctl.conf 文件语法。" $LINENO

    PARAMS_FILE="/etc/wireguard/params"
    {
        echo "SERVER_IPV4=${public_ipv4}"
        echo "SERVER_IPV6=${public_ipv6}"
    } > "$PARAMS_FILE"
    [ -s "$PARAMS_FILE" ] || error_exit "创建 params 配置文件失败。" $LINENO

	echo "配置防火墙 (UFW)..."
	ufw allow ssh

    local client_endpoint
    local wg_port
    local client_mtu
    if [ "$USE_UDP2RAW" == "y" ]; then
        read -r -p "请输入 udp2raw 的 TCP 端口 [默认: 39001]: " tcp_port
        tcp_port=${tcp_port:-39001}
        wg_port=$(rand_port)
        client_mtu=1280
        udp2raw_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        
        {
            echo "USE_UDP2RAW=true"
            echo "TCP_PORT=$tcp_port"
            echo "WG_PORT=$wg_port"
            echo "UDP2RAW_PASSWORD=$udp2raw_password"
        } >> "$PARAMS_FILE"
        
        echo "开放 udp2raw 的 TCP 端口: $tcp_port"
        ufw allow "$tcp_port"/tcp

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
        mv "$UDP2RAW_BINARY" /usr/local/bin/udp2raw
        chmod +x /usr/local/bin/udp2raw
        rm -f udp2raw_* version.txt udp2raw_binaries.tar.gz

        echo "正在创建 udp2raw 系统服务..."
        cat > /etc/systemd/system/udp2raw.service <<-EOF
			[Unit]
			Description=udp2raw-tunnel server
			After=network.target
			[Service]
			Type=simple
			ExecStart=/usr/local/bin/udp2raw -s -l [::]:$tcp_port -r 127.0.0.1:$wg_port -k "$udp2raw_password" --raw-mode faketcp --cipher-mode xor
			Restart=on-failure
			[Install]
			WantedBy=multi-user.target
		EOF
        [ -s /etc/systemd/system/udp2raw.service ] || error_exit "创建 udp2raw.service 文件失败。" $LINENO
        systemctl daemon-reload
        systemctl enable udp2raw
        systemctl start udp2raw
        client_endpoint="127.0.0.1:29999"
    else
        read -r -p "请输入 WireGuard 的 UDP 端口 [默认: 39000]: " wg_port
        wg_port=${wg_port:-39000}
        client_mtu=1420
        {
            echo "USE_UDP2RAW=false"
            echo "WG_PORT=$wg_port"
        } >> "$PARAMS_FILE"
        echo "开放 WireGuard 的 UDP 端口: $wg_port"
        ufw allow "$wg_port"/udp
        if [ -n "$public_ipv4" ]; then
            client_endpoint="$public_ipv4:$wg_port"
        else
            client_endpoint="[$public_ipv6]:$wg_port"
        fi
    fi

	net_interface=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    if [ -z "$net_interface" ]; then net_interface=$(ip -o -6 route show to default | awk '{print $5}' | head -n1); fi
    if [ -z "$net_interface" ] || ! ip link show "$net_interface" > /dev/null 2>&1; then
        error_exit "无法自动检测到有效的主网络接口。" $LINENO
    fi
	echo "检测到主网络接口为: $net_interface"

    # 为 IPv4 和 IPv6 分别设置 NAT 规则
    UFW_BEFORE_RULES="/etc/ufw/before.rules"
    UFW_BEFORE6_RULES="/etc/ufw/before6.rules"

    if ! grep -q "# BEGIN WIREGUARD NAT" "$UFW_BEFORE_RULES"; then
        cp "$UFW_BEFORE_RULES" "${UFW_BEFORE_RULES}.bak"
        ( echo ""; echo "# BEGIN WIREGUARD NAT"; echo "*nat"; echo ":POSTROUTING ACCEPT [0:0]";
          echo "-A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE";
          echo "COMMIT"; echo "# END WIREGUARD NAT" ) >> "$UFW_BEFORE_RULES"
        grep -q "# END WIREGUARD NAT" "$UFW_BEFORE_RULES" || error_exit "向 $UFW_BEFORE_RULES 写入 NAT 规则失败。" $LINENO
    fi

    if [ -n "$public_ipv6" ] && ! grep -q "# BEGIN WIREGUARD NAT" "$UFW_BEFORE6_RULES"; then
        ( echo ""; echo "# BEGIN WIREGUARD NAT"; echo "*nat"; echo ":POSTROUTING ACCEPT [0:0]";
          echo "-A POSTROUTING -s fd86:ea04:1111::/64 -o $net_interface -j MASQUERADE";
          echo "COMMIT"; echo "# END WIREGUARD NAT" ) >> "$UFW_BEFORE6_RULES"
        grep -q "# END WIREGUARD NAT" "$UFW_BEFORE6_RULES" || error_exit "向 $UFW_BEFORE6_RULES 写入 NAT 规则失败。" $LINENO
    fi

    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    grep -q 'DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw || error_exit "修改 /etc/default/ufw 转发策略失败。" $LINENO

    ufw --force enable
    ufw reload || error_exit "UFW 防火墙重载失败，请检查 $UFW_BEFORE_RULES 中的规则是否存在语法错误。" $LINENO

	echo "正在创建服务器配置文件 wg0.conf..."
	cat > /etc/wireguard/wg0.conf <<-EOF
		[Interface]
		PrivateKey = $s1
		Address = 10.0.0.1/24, fd86:ea04:1111::1/64
		ListenPort = $wg_port
		MTU = 1420
		[Peer]
		# Client: client
		PublicKey = $c2
		AllowedIPs = 10.0.0.2/32, fd86:ea04:1111::2/128
	EOF
    [ -s /etc/wireguard/wg0.conf ] || error_exit "创建 wg0.conf 文件失败。" $LINENO

	echo "正在创建客户端配置文件 client.conf..."
	cat > /etc/wireguard/client.conf <<-EOF
		[Interface]
		PrivateKey = $c1
		Address = 10.0.0.2/24, fd86:ea04:1111::2/64
		DNS = 8.8.8.8, 2001:4860:4860::8888
		MTU = $client_mtu
		[Peer]
		PublicKey = $s2
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
    [ -s /etc/wireguard/client.conf ] || error_exit "创建 client.conf 文件失败。" $LINENO
    chmod 600 /etc/wireguard/*.conf

	echo "启动 WireGuard 服务..."
	wg-quick down wg0 &>/dev/null || true
	wg-quick up wg0
	systemctl enable wg-quick@wg0

	echo -e "\n🎉 WireGuard 安装完成! 🎉"
	qrencode -t ansiutf8 < /etc/wireguard/client.conf

    if [ "$USE_UDP2RAW" == "y" ]; then
        display_udp2raw_info "$public_ipv4" "$public_ipv6" "$tcp_port" "$udp2raw_password"
    fi
}

# 卸载 WireGuard
wireguard_uninstall() {
    # 卸载前禁用严格模式，以防服务不存在时脚本退出
    set +e
	systemctl stop wg-quick@wg0 && systemctl disable wg-quick@wg0
    systemctl stop udp2raw && systemctl disable udp2raw
    set -e
	apt-get remove --purge -y wireguard wireguard-tools qrencode
	rm -rf /etc/wireguard /usr/local/bin/udp2raw /etc/systemd/system/udp2raw.service
    systemctl daemon-reload
	echo "🎉 WireGuard 及 Udp2raw 已成功卸载。"
}

# 添加新客户端
add_new_client() {
    if [ ! -f /etc/wireguard/wg0.conf ]; then error_exit "WireGuard 尚未安装。" $LINENO; fi

    read -r -p "请输入新客户端的名称: " client_name
    if [ -z "$client_name" ]; then error_exit "客户端名称不能为空。" $LINENO; fi
    if [ -f "/etc/wireguard/${client_name}.conf" ]; then error_exit "名为 ${client_name} 的客户端已存在。" $LINENO; fi

    last_ip_octet=$(grep -oP '10\.0\.0\.\K[0-9]+' /etc/wireguard/wg0.conf | sort -n | tail -1 || echo 1)
    next_ip_octet=$((last_ip_octet + 1))
    if [ "$next_ip_octet" -gt 254 ]; then error_exit "IP 地址池已满。" $LINENO; fi
    
    new_client_ip="10.0.0.${next_ip_octet}"
    new_client_ipv6="fd86:ea04:1111::${next_ip_octet}"
    echo "为新客户端分配的 IP: $new_client_ip, $new_client_ipv6"

    cd /etc/wireguard || exit 1
    new_client_private_key=$(wg genkey)
    new_client_public_key=$(echo "$new_client_private_key" | wg pubkey)

    wg set wg0 peer "$new_client_public_key" allowed-ips "$new_client_ip/32, $new_client_ipv6/128"
    # 为客户端添加注释，方便删除
    echo -e "\n[Peer]\n# Client: $client_name\nPublicKey = $new_client_public_key\nAllowedIPs = $new_client_ip/32, $new_client_ipv6/128" >> /etc/wireguard/wg0.conf
    grep -q "$new_client_public_key" /etc/wireguard/wg0.conf || error_exit "向 wg0.conf 添加新客户端失败。" $LINENO

    server_public_key=$(cat /etc/wireguard/spublickey)
    
    # 声明将从 params 文件加载的变量
    local USE_UDP2RAW SERVER_IPV4 SERVER_IPV6 WG_PORT TCP_PORT UDP2RAW_PASSWORD
    PARAMS_FILE="/etc/wireguard/params"
    # shellcheck source=/dev/null # source-path=/etc/wireguard/params
    if [ -f "$PARAMS_FILE" ]; then source "$PARAMS_FILE"; else error_exit "params 文件不存在。" $LINENO; fi

    local client_endpoint
    local client_mtu
    if [ "$USE_UDP2RAW" = "true" ]; then
        client_endpoint="127.0.0.1:29999"
        client_mtu=1280
    else
        if [ -n "$SERVER_IPV4" ]; then
            client_endpoint="${SERVER_IPV4}:${WG_PORT}"
        else
            client_endpoint="[${SERVER_IPV6}]:${WG_PORT}"
        fi
        client_mtu=1420
    fi

    cat > "/etc/wireguard/${client_name}.conf" <<-EOF
		[Interface]
		PrivateKey = $new_client_private_key
		Address = $new_client_ip/24, $new_client_ipv6/64
		DNS = 8.8.8.8, 2001:4860:4860::8888
		MTU = $client_mtu
		[Peer]
		PublicKey = $server_public_key
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
    [ -s "/etc/wireguard/${client_name}.conf" ] || error_exit "创建客户端 ${client_name}.conf 文件失败。" $LINENO
	chmod 600 "/etc/wireguard/${client_name}.conf"

    echo -e "\n🎉 新客户端 '$client_name' 添加成功!"
    qrencode -t ansiutf8 < "/etc/wireguard/${client_name}.conf"
    
    if [ "$USE_UDP2RAW" = "true" ]; then
        echo "提醒: 您的服务正使用 udp2raw，新客户端也需按以下信息配置。"
        display_udp2raw_info "$SERVER_IPV4" "$SERVER_IPV6" "$TCP_PORT" "$UDP2RAW_PASSWORD"
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
    if [[ ! " ${CLIENTS[*]} " =~ \b${client_name}\b ]]; then error_exit "客户端 ${client_name} 不存在。" $LINENO; fi

    client_pub_key=$(awk -v client="$client_name" '/^# Client: / && $3==client {getline; print $3}' /etc/wireguard/wg0.conf)
    if [ -z "$client_pub_key" ]; then error_exit "无法在 wg0.conf 中找到客户端 ${client_name} 的公钥。" $LINENO; fi

    wg set wg0 peer "$client_pub_key" remove
    
    # 使用 awk 更安全地删除 peer 配置块
    awk -v key="$client_pub_key" '
        BEGIN { RS = "\n\n"; ORS = "\n\n" }
        !/PublicKey = / || $0 !~ key
    ' /etc/wireguard/wg0.conf > /etc/wireguard/wg0.conf.tmp
    mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf

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
        echo "------------------------------------------------------"
    done
    echo "======================================================="
}

# 显示 Udp2raw 配置
show_udp2raw_config() {
    # 声明将从 params 文件加载的变量
    local USE_UDP2RAW SERVER_IPV4 SERVER_IPV6 TCP_PORT UDP2RAW_PASSWORD

    if [ ! -f /etc/wireguard/params ]; then error_exit "WireGuard 尚未安装或配置文件不完整。" $LINENO; fi
    # shellcheck source=/dev/null # source-path=/etc/wireguard/params
    source /etc/wireguard/params || error_exit "无法加载 params 文件。" $LINENO
    if [ "$USE_UDP2RAW" = "true" ]; then
        display_udp2raw_info "$SERVER_IPV4" "$SERVER_IPV6" "$TCP_PORT" "$UDP2RAW_PASSWORD"
    else
        echo "Udp2raw 模式未在安装时启用。"
    fi
}

# 优化系统
optimize_system() {
    read -r -p "此操作将升级内核并开启 BBR，需要重启。是否继续? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[yY] ]]; then echo "操作已取消。"; exit 0; fi

    apt-get update
    apt-get install -y --install-recommends "linux-generic-hwe-$(lsb_release -rs)"

    if ! grep -q -E "^\s*net.core.default_qdisc\s*=\s*fq" /etc/sysctl.conf; then echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; fi
    if ! grep -q -E "^\s*net.ipv4.tcp_congestion_control\s*=\s*bbr" /etc/sysctl.conf; then echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; fi

    echo -e "🎉 系统优化配置完成! \033[1;31m请务必重启服务器 (reboot) 以应用新内核。\033[0m"
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
	echo "7. 优化系统 (升级内核并开启 BBR)"
	echo "8. 退出脚本"
	echo
	read -r -p "请输入数字 [1-8]: " num
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
