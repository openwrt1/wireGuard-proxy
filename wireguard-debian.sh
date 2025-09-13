#!/bin/bash

# ==================================================
# 介绍：适用于 Debian 10+/11+/12+ 的 WireGuard 一键安装脚本
# 作者：Gemini Code Assist（Debian 专用版）
# ==================================================

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
	echo $(($RANDOM % ($max - $min) + $min))
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
	apt-get install -y wireguard qrencode ufw curl linux-headers-$(uname -r)

	echo "正在创建 WireGuard 目录和密钥..."
	mkdir -p /etc/wireguard
	cd /etc/wireguard

	wg genkey | tee sprivatekey | wg pubkey >spublickey
	wg genkey | tee cprivatekey | wg pubkey >cpublickey

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
	ufw allow $port/udp
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

	echo "启动 WireGuard 服务..."
	wg-quick up wg0
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

# 菜单
start_menu() {
	clear
	echo "=================================================="
	echo " 适用于 Debian 的 WireGuard 一键安装脚本"
	echo "=================================================="
	echo "1. 安装 WireGuard"
	echo "2. 退出脚本"
	echo
	read -p "请输入数字 [1-2]: " num
	case "$num" in
	1) wireguard_install ;;
	2) exit 0 ;;
	*)
		echo "错误: 请输入正确的数字"
		sleep 2
		start_menu
		;;
	esac
}

start_menu
