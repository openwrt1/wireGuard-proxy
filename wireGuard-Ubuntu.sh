#!/bin/bash
# ==================================================
# 介绍：适用于 Debian/Ubuntu/CentOS 的 WireGuard 一键安装脚本
# 作者：Gemini Code Assist (融合 atrandys 的脚本逻辑)
# ==================================================
# 判断是否为 root 用户
if [ "$(id -u)" != "0" ]; then
   echo "错误: 你必须以 root 用户身份运行此脚本" 1>&2
   exit 1
fi

# --- 通用函数 ---
# 生成随机端口
rand_port(){
    min=10000
    max=60000
    echo $(($RANDOM % ($max - $min) + $min))
}
# 配置客户端文件
config_client(){
cat > /etc/wireguard/client.conf <<-EOF
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

# --- 特定系统的安装函数 ---
# Debian/Ubuntu 安装流程
install_debian() {
    echo "正在为 Debian/Ubuntu 系统安装 WireGuard..."
    apt-get update
    # 安装 wireguard, qrencode (用于生成二维码), ufw (防火墙)
    apt-get install -y wireguard qrencode ufw

    echo "配置防火墙 (UFW)..."
    ufw allow ssh
    ufw allow $port/udp
    ufw --force enable

    # 配置 UFW 的 NAT 转发规则
    if ! grep -q "POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE" /etc/ufw/before.rules; then
        sed -i "1s;^;*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE\nCOMMIT\n;" /etc/ufw/before.rules
    fi
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    ufw reload
}
# CentOS/RHEL 安装流程
install_centos() {
    echo "正在为 CentOS/RHEL 系统安装 WireGuard..."
    # 安装 EPEL 源和 WireGuard 源
    yum install -y epel-release
    curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    # 安装 wireguard 和 qrencode
    yum install -y wireguard-tools qrencode

    echo "配置防火墙 (firewalld)..."
    # 优先使用 firewalld，更现代
    systemctl start firewalld
    systemctl enable firewalld
    firewall-cmd --zone=public --add-port=$port/udp --permanent
    firewall-cmd --zone=public --add-masquerade --permanent
    firewall-cmd --reload
}
# --- 主安装逻辑 ---
wireguard_install(){
    # 1. 检测操作系统
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "错误: 无法检测到操作系统类型。"
        exit 1
    fi

    # 2. 通用准备工作
    echo "正在创建 WireGuard 目录和密钥..."
    mkdir -p /etc/wireguard
    cd /etc/wireguard

    wg genkey | tee sprivatekey | wg pubkey > spublickey
    wg genkey | tee cprivatekey | wg pubkey > cpublickey

    s1=$(cat sprivatekey)
    s2=$(cat spublickey)
    c1=$(cat cprivatekey)
    c2=$(cat cpublickey)

    server_ip=$(curl -s icanhazip.com)
    port=$(rand_port)
    net_interface=$(ip -o -4 route show to default | awk '{print $5}')
    if [ -z "$net_interface" ]; then
        echo "错误: 无法检测到主网络接口"
        exit 1
    fi
    echo "检测到主网络接口为: $net_interface"

    # 3. 开启IP转发 (通用)
    echo "配置系统网络转发..."
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -p

    # 4. 根据操作系统执行特定安装
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        install_debian
    elif [ "$OS" == "centos" ] || [ "$OS" == "rhel" ]; then
        # CentOS 7 内核版本过低，需要升级才能使用 WireGuard
        if [ "$OS" == "centos" ] && grep -q "7\." /etc/redhat-release; then
             echo "警告: CentOS 7 需要升级内核才能使用 WireGuard。此脚本暂未包含自动内核升级，请手动升级或使用 CentOS 8+。"
             # 此处可以集成之前的内核升级脚本，但为保持简洁，暂时只做提示
             # exit 1
        fi
        install_centos
    else
        echo "错误: 不支持的操作系统: $OS"
        exit 1
    fi

    # 5. 创建配置文件并启动服务 (通用)
    echo "正在创建服务器配置文件 wg0.conf..."
    # 对于CentOS，如果使用firewalld，PostUp/Down规则也不再需要
cat > /etc/wireguard/wg0.conf <<-EOF
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

    echo "启动并设置 WireGuard 开机自启..."
    wg-quick up wg0
    systemctl enable wg-quick@wg0

    # 6. 显示结果 (通用)
    echo -e "\n=============================================================="
    echo "🎉 WireGuard 安装完成! 🎉"
    echo "=============================================================="
    echo "服务器配置: /etc/wireguard/wg0.conf"
    echo "客户端配置: /etc/wireguard/client.conf"
    echo ""
    echo "你可以下载 client.conf 文件到你的设备上使用。"
    echo "你也可以扫描下面的二维码直接导入配置 (需要手机客户端支持):"
    echo "--------------------------------------------------------------"
    qrencode -t ansiutf8 < /etc/wireguard/client.conf
    echo "--------------------------------------------------------------"
}

# --- 开始菜单 ---
start_menu(){
    clear
    echo "=================================================="
    echo " 介绍：适用于 Debian/Ubuntu/CentOS 的 WireGuard 安装脚本"
    echo " 作者：Gemini Code Assist"
    echo "=================================================="
    echo "1. 安装 WireGuard"
    echo "2. 退出脚本"
    echo
    read -p "请输入数字 [1-2]: " num
    case "$num" in
    	1)
	    wireguard_install
	    ;;
	2)
	    exit 0
	    ;;
	*)
	    clear
	    echo "错误: 请输入正确的数字"
	    sleep 2s
	    start_menu
	    ;;
    esac
}
# 运行开始菜单
start_menu

