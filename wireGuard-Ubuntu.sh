#!/bin/bash

# ==================================================
# 介绍：适用于 Ubuntu 18.04+ 的 WireGuard 一键安装脚本
# 作者：Gemini Code Assist (参照 atrandys 的 CentOS 脚本)
# ==================================================

# 判断是否为 root 用户
if [ "$(id -u)" != "0" ]; then
   echo "错误: 你必须以 root 用户身份运行此脚本" 1>&2
   exit 1
fi

# 判断系统是否为 Ubuntu
if ! grep -q "Ubuntu" /etc/issue; then
    echo "错误: 此脚本仅支持 Ubuntu 系统"
    exit 1
fi

# 生成随机端口
rand_port(){
    min=10000
    max=60000
    # 使用系统内置的 $RANDOM 变量，更简单
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

# Ubuntu 安装 WireGuard
wireguard_install(){
    echo "正在更新软件包列表..."
    apt-get update

    echo "正在安装 WireGuard 及相关工具..."
    # Ubuntu 20.04+ 自带 wireguard 包，18.04 需要 PPA，但 apt 会自动处理
    apt-get install -y wireguard qrencode

    echo "正在创建 WireGuard 目录和密钥..."
    mkdir -p /etc/wireguard
    cd /etc/wireguard

    # 生成服务器和客户端密钥
    wg genkey | tee sprivatekey | wg pubkey > spublickey
    wg genkey | tee cprivatekey | wg pubkey > cpublickey

    # 读取密钥到变量
    s1=$(cat sprivatekey)
    s2=$(cat spublickey)
    c1=$(cat cprivatekey)
    c2=$(cat cpublickey)

    # 获取服务器公网 IP 和随机端口
    server_ip=$(curl -s icanhazip.com)
    port=$(rand_port)

    echo "配置系统网络转发..."
    # 开启 IPv4 转发
    sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -p

    echo "配置防火墙 (UFW)..."
    # 安装 UFW (如果未安装)
    apt-get install -y ufw
    
    # 允许 SSH, WireGuard 端口，并开启防火墙
    ufw allow ssh
    ufw allow $port/udp
    ufw --force enable

    # 自动检测主网络接口 (如 eth0, ens3)
    net_interface=$(ip -o -4 route show to default | awk '{print $5}')
    if [ -z "$net_interface" ]; then
        echo "错误: 无法检测到主网络接口"
        exit 1
    fi
    echo "检测到主网络接口为: $net_interface"

    # 配置 UFW 的 NAT 转发规则
    # 在 /etc/ufw/before.rules 文件顶部添加 NAT 配置
    if ! grep -q "POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE" /etc/ufw/before.rules; then
        sed -i "1s;^;*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.0.0.0/24 -o $net_interface -j MASQUERADE\nCOMMIT\n;" /etc/ufw/before.rules
    fi

    # 确保 UFW 默认转发策略为 ACCEPT
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # 重启 UFW 使配置生效
    ufw reload

    echo "正在创建服务器配置文件 wg0.conf..."
cat > /etc/wireguard/wg0.conf <<-EOF
[Interface]
PrivateKey = $s1
Address = 10.0.0.1/24
ListenPort = $port
MTU = 1420
# PostUp/PostDown 规则由 UFW 处理，这里不再需要
# PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $net_interface -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $net_interface -j MASQUERADE

[Peer]
PublicKey = $c2
AllowedIPs = 10.0.0.2/32
EOF

    echo "正在创建客户端配置文件 client.conf..."
    config_client

    echo "启动 WireGuard 服务..."
    wg-quick up wg0
    
    echo "设置 WireGuard 开机自启..."
    systemctl enable wg-quick@wg0

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

# 开始菜单
start_menu(){
    clear
    echo "=================================================="
    echo " 介绍：适用于 Ubuntu 的 WireGuard 一键安装脚本"
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
