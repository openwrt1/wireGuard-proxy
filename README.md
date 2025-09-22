# WireGuard-Proxy 一键安装脚本

这个仓库包含了一键安装脚本，用于在主流 Linux 发行版上快速部署 WireGuard，并可选择性地安装 Udp2raw 进行流量混淆。

---

## 适用于 Alpine Linux

在您的 **Alpine Linux** 服务器上，复制并粘贴以下命令来下载并运行脚本。这一行命令将完成下载脚本、赋予执行权限并启动交互式安装菜单的全部操作。

```bash
wget -O wireguard-alpine.sh https://raw.githubusercontent.com/openwrt1/wireGuard-proxy/main/wireguard-alpine.sh && chmod +x wireguard-alpine.sh && ./wireguard-alpine.sh
```

---

## 适用于 Debian

在您的 **Debian** 服务器上，使用以下命令来下载并运行脚本。

```bash
wget -O wireguard-debian.sh https://raw.githubusercontent.com/openwrt1/wireGuard-proxy/main/wireguard-debian.sh && chmod +x wireguard-debian.sh && ./wireguard-debian.sh
```

---

## 适用于 Ubuntu

在您的 **Ubuntu** 服务器上，使用以下命令来下载并运行脚本。

```bash
wget -O wireguard-debian.sh https://raw.githubusercontent.com/openwrt1/wireGuard-proxy/main/wireguard-debian.sh && chmod +x wireguard-debian.sh && ./wireguard-debian.sh
```

---

### 功能特性

*   **一键安装**：轻松部署 WireGuard。
*   **多系统支持**：支持 Alpine、Debian 和 Ubuntu。
*   **流量混淆**：可选择通过 Udp2raw 实现 TCP 流量伪装。
*   **用户管理**：自动化管理客户端（添加/删除用户）。
*   **系统优化**：自动开启 BBR 拥塞控制算法。
*   **智能网卡检测**：强大且多层次的网络接口检测机制，确保在复杂网络环境下的可靠性。
