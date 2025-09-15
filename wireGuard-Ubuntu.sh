#!/bin/bash

#================================================================================
# 适用于 Ubuntu 的 WireGuard + Udp2raw 一键安装脚本
#
# 功能:
# 1. 安装 WireGuard (可选集成 Udp2raw)
# 2. 卸载 WireGuard
# 3. 添加新用户
# 4. 删除用户
# 5. 智能安装检测，防止重复执行
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

# 获取公网 IP 地址 (IPv4 和 IPv6)，增加冗余
get_public_ips() {
    # IPv4 API Endpoints
    ipv4_apis=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip")
    # IPv6 API Endpoints
    ipv6_apis=("https://api64.ipify.org" "https://ipv6.icanhazip.com")

    # 获取 IPv4
    for api in "${ipv4_apis[@]}"; do
        public_ipv4=$(curl -s -m 5 "$api")
        if [ -n "$public_ipv4" ]; then
            break
        fi
    done

    # 获取 IPv6
    for api in "${ipv6_apis[@]}"; do
        public_ipv6=$(curl -s -m 5 "$api")
        if [ -n "$public_ipv6" ]; then
            break
        fi
    done
}

# 显示 Udp2raw 客户端配置信息
display_udp2raw_info() {
    local server_ipv4=$1
    local server_ipv6=$2
    local tcp_port=$3
    local udp2raw_password=$4

    printf "\\n=================== 客户端 Udp2raw 设置 ===================\\n"
    printf "伪装模式已启用，您需要在客户端上运行 udp2raw。\\n"
    printf "请从 https://github.com/wangyu-/udp2raw/releases 下载 udp2raw 二进制文件。\\n"
    printf "解压后，根据您的操作系统，在终端或命令行中运行对应命令：\\n"
    printf "\\n"
    printf "服务器 TCP 端口: %s\n" "$tcp_port"
    printf "连接密码: %s\n" "$udp2raw_password"
    printf "\\n"

    if [ -n "$server_ipv4" ]; then
        printf "\\033[1;32m--- IPv4 连接命令 (推荐) ---\\033[0m\\n"
        printf "Linux: ./udp2raw_amd64 -c -l 127.0.0.1:29999 -r %s:%s -k \"%s\" --raw-mode faketcp --cipher-mode xor\\n" "$server_ipv4" "$tcp_port" "$udp2raw_password"
        printf "macOS: ./udp2raw_mp_mac -c -l 127.0.0.1:29999 -r %s:%s -k \"%s\" --raw-mode faketcp --cipher-mode xor\\n" "$server_ipv4" "$tcp_port" "$udp2raw_password"
        printf "Windows: udp2raw_mp.exe -c -l 127.0.0.1:29999 -r %s:%s -k \"%s\" --raw-mode faketcp --cipher-mode xor\\n" "$server_ipv4" "$tcp_port" "$udp2raw_password"
        printf "\\n"
    fi

    if [ -n "$server_ipv6" ]; then
        printf "\\033[1;32m--- IPv6 连接命令 ---\\033[0m\\n"
        printf "Linux: ./udp2raw_amd64 -c -l 127.0.0.1:29999 -r [%s]:%s -k \"%s\" --raw-mode faketcp --cipher-mode xor\\n" "$server_ipv6" "$tcp_port" "$udp2raw_password"
        printf "macOS: ./udp2raw_mp_mac -c -l 127.0.0.1:29999 -r [%s]:%s -k \"%s\" --raw-mode faketcp --cipher-mode xor\\n" "$server_ipv6" "$tcp_port" "$udp2raw_password"
        printf "Windows: udp2raw_mp.exe -c -l 127.0.0.1:29999 -r [%s]:%s -k \"%s\" --raw-mode faketcp --cipher-mode xor\\n" "$server_ipv6" "$tcp_port" "$udp2raw_password"
        printf "\\n"
    fi

    printf "\\n"
    printf "%s\\n" "--------------------------------------------------------------"
    printf "然后再启动 WireGuard 客户端。\\n"
    printf "==============================================================\\n"
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

	echo "正在获取公网 IP 地址..."
    get_public_ips
    if [ -z "$public_ipv4" ] && [ -z "$public_ipv6" ]; then
        echo "错误: 无法获取公网 IP 地址。请检查网络连接或 DNS 设置。" >&2
        exit 1
    fi
    echo "检测到 IPv4: ${public_ipv4:-N/A}"
    echo "检测到 IPv6: ${public_ipv6:-N/A}"
    
	echo "配置系统网络转发..."
	sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
	if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
		echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	fi

	# 创建一个文件来保存关键参数，方便后续添加用户
	PARAMS_FILE="/etc/wireguard/params"
    {
        echo "SERVER_IPV4=${public_ipv4}"
        echo "SERVER_IPV6=${public_ipv6}"
    } > "$PARAMS_FILE"

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
        {
            echo "USE_UDP2RAW=true"
            echo "TCP_PORT=$tcp_port"
            echo "UDP2RAW_PASSWORD=$udp2raw_password"
        } >> "$PARAMS_FILE"

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
        {
            echo "USE_UDP2RAW=false"
            echo "WG_PORT=$wg_port"
        } >> "$PARAMS_FILE"
        client_mtu=1420

        echo "开放 WireGuard 的 UDP 端口: $wg_port"
        ufw allow "$wg_port"/udp
        # 优先使用 IPv4 作为默认 Endpoint
        if [ -n "$public_ipv4" ]; then
            client_endpoint="$public_ipv4:$wg_port"
        else
            # 如果没有 IPv4，则使用 IPv6，并用方括号括起来
            client_endpoint="[$public_ipv6]:$wg_port"
        fi
    fi

    # 智能获取主网络接口，兼容 IPv4/IPv6-only 环境
    # 优先尝试 IPv4 路由采样，然后回退到 default route，再回退到第一个非 loopback 接口
    net_interface=""
    net_interface=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
    if [ -z "$net_interface" ]; then
        # IPv4 失败，尝试默认路由解析
        net_interface=$(ip route show default 2>/dev/null | awk '/default/ && /dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
    fi
    if [ -z "$net_interface" ]; then
        # 再尝试 IPv6 路由采样
        net_interface=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
    fi

    # 最后回退到第一个非 loopback 的接口
    if [ -z "$net_interface" ]; then
        net_interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1)
    fi

    # 验证接口名有效且存在（避免把 IP 地址误当作接口名）
    if ! ip link show "$net_interface" >/dev/null 2>&1; then
        echo "警告: 无法识别接口 '$net_interface'，尝试使用第一个非 loopback 接口。"
        net_interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1)
    fi

    # 确保接口名不超过系统限制（IFNAMSIZ 通常为 15）
    if [ ${#net_interface} -ge 15 ]; then
        echo "警告: 检测到接口名过长('${net_interface}'), 这可能不是有效的接口名。尝试使用第一个非 loopback 接口。"
        net_interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1)
    fi

    echo "检测到主网络接口为: $net_interface"

    # --- 调试信息开始 ---
    echo "【调试】准备修改防火墙规则，当前 /etc/ufw/before.rules 前 10 行："
    head -n 10 /etc/ufw/before.rules 2>/dev/null || true
    # --- 调试信息结束 ---

    # 在 UFW 启动前，提前将 NAT 规则写入文件（只针对 IPv4 的 /etc/ufw/before.rules）
    UFW_BEFORE=/etc/ufw/before.rules
    MASQ_RULE="-A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE"

    # 如果已存在相同的规则，则跳过；如果存在相同源但不同出口接口，则替换为当前接口
    if grep -qF "-A POSTROUTING -s 10.0.0.0/24" "$UFW_BEFORE" 2>/dev/null; then
        if grep -qF "$MASQ_RULE" "$UFW_BEFORE" 2>/dev/null; then
            echo "【调试】已存在匹配的 NAT 规则，跳过添加。"
        else
            echo "【调试】发现已存在类似 NAT 规则但出口接口不同，正在替换为: $net_interface"
            sed -ri "s|(-A POSTROUTING -s 10\.0\.0\.0/24 -o )[^[:space:]]+(-j MASQUERADE)|\1${net_interface}\2|" "$UFW_BEFORE" || true
        fi
    else
        # 如果没有 *nat 块，则在文件顶部插入一个 nat 块
        if ! grep -q "^\*nat" "$UFW_BEFORE" 2>/dev/null; then
            # 将 nat 块插入到文件顶部，确保格式正确
            sed -i "1s;^;*nat\n:POSTROUTING ACCEPT [0:0]\n${MASQ_RULE}\nCOMMIT\n;" "$UFW_BEFORE"
            echo "【调试】已向 $UFW_BEFORE 添加新的 *nat 块和 MASQUERADE 规则。"
        else
            # 已有 nat 块但无规则，尝试在第一个 COMMIT 前插入规则
            awk -v rule="$MASQ_RULE" '
                BEGIN{in_nat=0; inserted=0}
                /^\*nat/ {print; in_nat=1; next}
                in_nat && /^COMMIT/ && !inserted {print rule; print; inserted=1; in_nat=0; next}
                {print}
            ' "$UFW_BEFORE" > "$UFW_BEFORE".tmp && mv "$UFW_BEFORE".tmp "$UFW_BEFORE"
            echo "【调试】已在现有 *nat 块中插入 MASQUERADE 规则。"
        fi
    fi

    # 确保转发策略为 ACCEPT
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    echo "【调试】已将 /etc/default/ufw 的 FORWARD_POLICY 修改为 ACCEPT。"

    # --- 调试信息开始 ---
    echo "【调试】修改后 /etc/ufw/before.rules 前 10 行："
    head -n 10 /etc/ufw/before.rules 2>/dev/null || true
    # --- 调试信息结束 ---

    # 启动/重载 UFW，并在失败时给出诊断信息
    if ! ufw --force enable 2>/tmp/ufw_enable.err || ! ufw reload 2>/tmp/ufw_reload.err; then
        echo "错误: 启动或重载 UFW 时失败。收集诊断信息..."
        echo "---- /etc/ufw/before.rules (前 200 行) ----"
        head -n 200 /etc/ufw/before.rules 2>/dev/null || true
        echo "---- ip link show ----"
        ip -o link show
        echo "---- ip -o addr show ----"
        ip -o addr show
        echo "---- ufw enable stderr ----"
        sed -n '1,200p' /tmp/ufw_enable.err || true
        echo "---- ufw reload stderr ----"
        sed -n '1,200p' /tmp/ufw_reload.err || true
        echo "提示: 常见问题是 before.rules 包含了 IPv6 地址或不兼容的条目，或某些规则被误插入到 IPv4 文件中。"
        echo "您可以手动检查 /etc/ufw/before.rules 或还原备份后重试。"
    fi

   	# 在所有网络和防火墙规则配置完成后，再应用 sysctl 设置
   	sysctl -p

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

	echo -e "\\n=============================================================="
	echo "🎉 WireGuard 安装完成! 🎉"
	echo "=============================================================="
	echo "服务器配置: /etc/wireguard/wg0.conf"
	echo "客户端配置: /etc/wireguard/client.conf"
	echo ""
	qrencode -t ansiutf8 < /etc/wireguard/client.conf
	echo "=============================================================="

    if [ "$use_udp2raw" == "y" ]; then
        display_udp2raw_info "$public_ipv4" "$public_ipv6" "$tcp_port" "$udp2raw_password"
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

	echo -e "\\n=============================================================="
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

    last_ip_octet=$(grep -oP 'AllowedIPs = 10.0.0.\\K[0-9]+' /etc/wireguard/wg0.conf | sort -n | tail -1)
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
    PARAMS_FILE="/etc/wireguard/params"

    local client_endpoint
    local client_mtu
    local USE_UDP2RAW="false" # 为变量提供默认值以提高健壮性并消除 shellcheck 警告
    local SERVER_IPV4=""      # 同上
    local SERVER_IPV6=""      # 同上
    local WG_PORT=""          # 同上
    local TCP_PORT=""         # 同上

    # 从参数文件中读取配置，而不是实时检测
    # shellcheck source=/etc/wireguard/params
    if [ -f "$PARAMS_FILE" ]; then
        source "$PARAMS_FILE"
    fi

    if [ "$USE_UDP2RAW" = "true" ]; then
        client_endpoint="127.0.0.1:29999"
        client_mtu=1280
    else
        server_port="$WG_PORT"
        # 优先使用 IPv4 作为默认 Endpoint
        if [ -n "$SERVER_IPV4" ]; then
            client_endpoint="${SERVER_IPV4}:${server_port}"
        else
            # 如果没有 IPv4，则使用 IPv6，并用方括号括起来
            client_endpoint="[${SERVER_IPV6}]:${server_port}"
        fi
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

    echo -e "\\n=============================================================="
    echo "🎉 新客户端 ${client_name} 添加成功! 🎉"
    echo "=============================================================="
    echo "客户端配置文件: /etc/wireguard/${client_name}.conf"
    qrencode -t ansiutf8 < "/etc/wireguard/${client_name}.conf"
    echo "=============================================================="

    if systemctl -q is-active udp2raw; then
        # 提醒用户 udp2raw 正在运行，并显示连接信息
        echo "提醒: 您的服务正在使用 udp2raw，新客户端也需要按以下信息配置。"

        # 直接从变量显示信息
        if [ -n "$TCP_PORT" ] && [ -n "$UDP2RAW_PASSWORD" ]; then
            display_udp2raw_info "$SERVER_IPV4" "$SERVER_IPV6" "$TCP_PORT" "$UDP2RAW_PASSWORD"
        else
            echo "警告: 无法从 /etc/wireguard/params 中自动提取 udp2raw 配置信息。"
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
    if ! wg set wg0 peer "$client_pub_key" remove; then
        echo "警告: 从实时接口移除 peer 失败。可能该 peer 已不存在于活动会话中。"
    fi

    # 2. 从 wg0.conf 中移除 peer 配置块
    cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak
    # 使用 awk 以段落模式（由空行分隔）来安全地删除整个 peer 块
    # 这种方法兼容性更好，可以避免 mawk 等 awk 实现中的 for 循环解析问题
    awk -v key_to_remove="$client_pub_key" '
        BEGIN { RS = ""; ORS = "\n\n" }
        # 如果当前记录(一个 Peer 块)不包含要移除的公钥则打印它
        ! /PublicKey = / && ! /AllowedIPs = / || $0 !~ "PublicKey = " key_to_remove
    ' /etc/wireguard/wg0.conf.bak > /etc/wireguard/wg0.conf

    # 3. 删除客户端的配置文件
    rm -f "/etc/wireguard/${client_name}.conf"

    echo -e "\\n=============================================================="
    echo "🎉 客户端 ${client_name}  已成功删除。"
    echo "=============================================================="
}


# --- 菜单和主逻辑 ---
start_menu(){
	clear
	echo "=================================================="
	echo " 适用于 Ubuntu 的 WireGuard 一键安装脚本"
	echo " (集成 Udp2raw 伪装功能)"
	echo "=================================================="
	echo "1. 安装 WireGuard"
	echo "2. 卸载 WireGuard"
	echo "3. 添加新用户"
	echo "4. 删除用户"
	echo "5. 退出脚本"
	echo
	read -r -p "请输入数字 [1-5]: " num
	case "$num" in
	1) wireguard_install ;;
	2) wireguard_uninstall ;;
	3) add_new_client ;;
	4) delete_client ;;
	5) exit 0 ;;
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
