#!/bin/bash

#================================================================================
# 适用于 Alpine Linux 的 WireGuard + Udp2raw 一键安装脚本 (功能增强版)
#
# 特点:
# - 使用 apk 作为包管理器
# - 使用 OpenRC 作为服务管理器
# - 功能对齐 Debian/Ubuntu 版本，包含用户管理、BBR 优化等
# - 智能检测、安全加固
#================================================================================

# --- 全局函数和变量 ---

# 启用严格模式，任何命令失败则立即退出
set -e
set -o pipefail

# 统一错误处理函数
error_exit() {
    echo -e "\033[1;31m错误: $1 (脚本第 $2 行)\033[0m" >&2
    exit 1
}
# 设置错误陷阱，捕获未预期的错误
trap 'error_exit "命令执行失败" $LINENO' ERR

# 判断是否为 root 用户
check_root() {
	if [ "$(id -u)" != "0" ]; then
		error_exit "你必须以 root 用户身份运行此脚本" $LINENO
	fi
}

# 判断系统是否为 Alpine
check_alpine() {
	if ! grep -qi "Alpine" /etc/os-release; then
		error_exit "此脚本仅支持 Alpine Linux 系统" $LINENO
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
    bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")

    echo "==================== 系统状态检查 ===================="
    echo "当前内核版本: $kernel_version"
    if [[ "$kernel_version" =~ ^[5-9]\. || "$kernel_version" =~ ^[1-9][0-9]+\. ]]; then
        echo -e "状态: \033[0;32m良好 (内核支持 BBR)\033[0m"
    else
        echo -e "状态: \033[0;33m过旧 (可能不支持 BBR)\033[0m"
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

# 获取公网 IP 地址
get_public_ip() {
    public_ip=$(curl -s -m 5 -4 icanhazip.com || curl -s -m 5 -6 icanhazip.com)
    if [ -z "$public_ip" ]; then
        error_exit "无法获取公网 IP 地址。" $LINENO
    fi
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
    echo -e "\033[1;32m--- 通用连接命令 (请替换 <udp2raw_binary> 为对应文件名) ---\033[0m"
    echo "./<udp2raw_binary> -c -l 127.0.0.1:29999 -r $server_ip:$tcp_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor -a"
    echo ""
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

    read -r -p "是否启用 TCP 伪装 (udp2raw)？[y/N]: " use_udp2raw
    use_udp2raw=$(echo "$use_udp2raw" | tr '[:upper:]' '[:lower:]')

	echo "正在更新软件包列表..."
	apk update
	echo "正在安装 WireGuard 及相关工具..."
	apk add --no-cache wireguard-tools curl iptables

    # --- 调试代码开始 ---
    echo -e "\n\033[1;33m--- 调试信息开始 ---\033[0m"
    echo "[调试] 检查 /etc/init.d/ 目录内容:"
    ls -l /etc/init.d/
    echo "[调试] 检查 wireguard-tools 软件包安装的文件列表:"
    apk info -L wireguard-tools
    echo -e "\033[1;33m--- 调试信息结束 ---\033[0m\n"
    # --- 调试代码结束 ---

    echo "正在尝试安装 libqrencode (用于生成二维码)..."
    apk add --no-cache libqrencode &>/dev/null

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
    get_public_ip
    echo "检测到公网 IP: $public_ip"
    
	echo "配置系统网络转发..."
	if ! grep -q -E "^\s*net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf; fi
    sysctl -p >/dev/null

    PARAMS_FILE="/etc/wireguard/params"
    echo "SERVER_IP=$public_ip" > "$PARAMS_FILE"

    local client_endpoint
    local wg_port
    local client_mtu
    local postup_rules=""
    local predown_rules=""
    net_interface=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
    if [ -z "$net_interface" ]; then net_interface=$(ip route show default 2>/dev/null | awk '/default/ && /dev/ {print $2}' | head -n1); fi
    echo "检测到主网络接口为: ${net_interface:-未知}"

    if [ -n "$net_interface" ]; then
        postup_rules="iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE;"
        predown_rules="iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE;"
    fi

    if [ "$use_udp2raw" == "y" ]; then
        read -r -p "请输入 udp2raw 的 TCP 端口 [默认: 39001]: " tcp_port
        tcp_port=${tcp_port:-39001}
        wg_port=$(rand_port)
        client_mtu=1200
        udp2raw_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        
        {
            echo "USE_UDP2RAW=true"
            echo "TCP_PORT=$tcp_port"
            echo "UDP2RAW_PASSWORD=$udp2raw_password"
            echo "WG_PORT=$wg_port"
        } >> "$PARAMS_FILE"

        postup_rules="$postup_rules iptables -A INPUT -p tcp --dport $tcp_port -j ACCEPT;"
        predown_rules="$predown_rules iptables -D INPUT -p tcp --dport $tcp_port -j ACCEPT;"

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

        echo "正在创建 udp2raw OpenRC 服务..."
        cat > /etc/init.d/udp2raw <<-EOF
#!/sbin/openrc-run
description="udp2raw-tunnel server"
command="/usr/local/bin/udp2raw"
command_args="-s -l 0.0.0.0:$tcp_port -r 127.0.0.1:$wg_port -k \"$udp2raw_password\" --raw-mode faketcp --cipher-mode xor -a"
pidfile="/var/run/udp2raw.pid"
command_background=true

depend() {
    need net
    after net
}
EOF
        chmod +x /etc/init.d/udp2raw
        rc-update add udp2raw default
        rc-service udp2raw start
        client_endpoint="127.0.0.1:29999"
    else
        read -r -p "请输入 WireGuard 的 UDP 端口 [默认: 39000]: " wg_port
        wg_port=${wg_port:-39000}
        client_mtu=1420
        {
            echo "USE_UDP2RAW=false"
            echo "WG_PORT=$wg_port"
        } >> "$PARAMS_FILE"
        postup_rules="$postup_rules iptables -A INPUT -p udp --dport $wg_port -j ACCEPT;"
        predown_rules="$predown_rules iptables -D INPUT -p udp --dport $wg_port -j ACCEPT;"
        client_endpoint="$public_ip:$wg_port"
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

	echo "启动并设置 WireGuard 服务开机自启..."
    # Alpine 的 wireguard-tools 包不再创建 init.d 脚本。
    # 我们手动创建一个来包装 wg-quick 命令。
    if [ ! -f /etc/init.d/wg-quick ]; then
        echo "正在创建 /etc/init.d/wg-quick OpenRC 服务脚本..."
        cat > /etc/init.d/wg-quick <<-EOF
#!/sbin/openrc-run

description="WireGuard quick interface manager"

command="/usr/bin/wg-quick"
command_args="\$1 \$RC_SVCNAME"

depend() {
    need net
    after firewall
}
EOF
    fi

    # 确保 OpenRC 服务脚本存在且可执行
    if [ -f /etc/init.d/wg-quick ]; then
        chmod +x /etc/init.d/wg-quick
        # 强制创建服务链接
        ln -sf /etc/init.d/wg-quick /etc/init.d/wg-quick.wg0
        
        # 强制 OpenRC 更新服务依赖缓存
        rc-update -u

        # 使用 OpenRC 标准方式管理服务
        rc-service wg-quick.wg0 stop &>/dev/null || true
        rc-service wg-quick.wg0 start

        # 添加到开机启动
        rc-update add wg-quick.wg0 default
    else
        error_exit "OpenRC script /etc/init.d/wg-quick not found." $LINENO
    fi

	echo -e "\n🎉 WireGuard 安装完成! 🎉"
	if command -v qrencode &> /dev/null; then
        qrencode -t ansiutf8 < /etc/wireguard/client.conf
    else
        echo "[提示] 未安装 libqrencode，无法生成二维码。请手动使用 client.conf 文件。"
    fi

    if [ "$use_udp2raw" == "y" ]; then
        display_udp2raw_info "$public_ip" "$tcp_port" "$udp2raw_password"
    fi
}

# 卸载 WireGuard
wireguard_uninstall() {
    set +e
	rc-service wg-quick.wg0 stop &>/dev/null
	rc-update del wg-quick.wg0 default &>/dev/null
    rc-service udp2raw stop &>/dev/null
    rc-update del udp2raw default &>/dev/null
    set -e
	apk del wireguard-tools curl iptables libqrencode &>/dev/null || apk del wireguard-tools curl iptables
	rm -rf /etc/wireguard /etc/init.d/udp2raw /usr/local/bin/udp2raw /etc/init.d/wg-quick.wg0
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
    echo "为新客户端分配的 IP: $new_client_ip"

    cd /etc/wireguard || exit 1
    new_client_private_key=$(wg genkey)
    new_client_public_key=$(echo "$new_client_private_key" | wg pubkey)

    wg set wg0 peer "$new_client_public_key" allowed-ips "$new_client_ip/32"
    echo -e "\n[Peer]\n# Client: $client_name\nPublicKey = $new_client_public_key\nAllowedIPs = $new_client_ip/32" >> /etc/wireguard/wg0.conf

    server_public_key=$(cat /etc/wireguard/spublickey)
    PARAMS_FILE="/etc/wireguard/params"
    
    # 初始化变量以消除 ShellCheck 警告
    USE_UDP2RAW=""
    SERVER_IP=""
    WG_PORT=""
    TCP_PORT=""
    UDP2RAW_PASSWORD=""
    # shellcheck source=/etc/wireguard/params
    if [ -f "$PARAMS_FILE" ]; then source "$PARAMS_FILE"; else error_exit "params 文件不存在。" $LINENO; fi

    local client_endpoint
    local client_mtu
    if [ "$USE_UDP2RAW" = "true" ]; then
        client_endpoint="127.0.0.1:29999"
        client_mtu=1200
    else
        client_endpoint="${SERVER_IP}:${WG_PORT}"
        client_mtu=1420
    fi

    cat > "/etc/wireguard/${client_name}.conf" <<-EOF
		[Interface]
		PrivateKey = $new_client_private_key
		Address = $new_client_ip/24
		DNS = 8.8.8.8
		MTU = $client_mtu
		[Peer]
		PublicKey = $server_public_key
		Endpoint = $client_endpoint
		AllowedIPs = 0.0.0.0/0, ::/0
		PersistentKeepalive = 25
	EOF
    chmod 600 "/etc/wireguard/${client_name}.conf"

    echo -e "\n🎉 新客户端 '$client_name' 添加成功!"
    if command -v qrencode &> /dev/null; then
        qrencode -t ansiutf8 < "/etc/wireguard/${client_name}.conf"
    fi
    
    if [ "$USE_UDP2RAW" = "true" ]; then
        echo "提醒: 您的服务正使用 udp2raw，新客户端也需按以下信息配置。"
        display_udp2raw_info "$SERVER_IP" "$TCP_PORT" "$UDP2RAW_PASSWORD"
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
    # 使用更安全的通配符匹配来检查客户端是否存在
    if [[ ! " ${CLIENTS[*]} " == *" ${client_name} "* ]]; then error_exit "客户端 ${client_name} 不存在。" $LINENO; fi

    client_pub_key=$(awk -v client="$client_name" '/^# Client: / && $3==client {getline; print $3}' /etc/wireguard/wg0.conf)
    if [ -z "$client_pub_key" ]; then error_exit "无法在 wg0.conf 中找到客户端 ${client_name} 的公钥。" $LINENO; fi

    wg set wg0 peer "$client_pub_key" remove
    
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
        if command -v qrencode &> /dev/null; then
            qrencode -t ansiutf8 < "/etc/wireguard/${client}.conf"
        else
            echo "[配置内容]"
            cat "/etc/wireguard/${client}.conf"
        fi
        echo "------------------------------------------------------"
    done
    echo "======================================================="
}

# 显示 Udp2raw 配置
show_udp2raw_config() {
    if [ ! -f /etc/wireguard/params ]; then error_exit "WireGuard 尚未安装或配置文件不完整。" $LINENO; fi
    
    # 初始化变量以消除 ShellCheck 警告
    USE_UDP2RAW=""
    SERVER_IP=""
    TCP_PORT=""
    UDP2RAW_PASSWORD=""
    # shellcheck source=/etc/wireguard/params
    source /etc/wireguard/params

    if [ "$USE_UDP2RAW" = "true" ]; then
        display_udp2raw_info "$SERVER_IP" "$TCP_PORT" "$UDP2RAW_PASSWORD"
    else
        echo "Udp2raw 模式未在安装时启用。"
    fi
}

# 优化系统 (开启 BBR)
optimize_system() {
    echo "正在为 Alpine Linux 配置 BBR..."
    {
        echo "net.core.default_qdisc=fq"
        echo "net.ipv4.tcp_congestion_control=bbr"
    } >> /etc/sysctl.conf
    sysctl -p >/dev/null
    echo "🎉 BBR 配置完成! 设置已生效并将在重启后保持。"
}


# --- 菜单和主逻辑 ---
start_menu(){
	clear
    initial_check
	echo "=================================================="
	echo " 适用于 Alpine Linux 的 WireGuard 一键安装脚本"
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
check_alpine
start_menu
