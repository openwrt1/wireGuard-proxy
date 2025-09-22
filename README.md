# WireGuard-Proxy Scripts

This repository contains one-click installation scripts for setting up WireGuard and optionally Udp2raw on major Linux distributions.

---

## For Alpine Linux

To download and run the script on your **Alpine Linux** server, copy and paste the following command. This single line will download the script, make it executable, and start the interactive installation menu.

**Note:** Please replace `YOUR_USERNAME` with your actual GitHub username.

```bash
wget -O wireguard-alpine.sh https://raw.githubusercontent.com/YOUR_USERNAME/wireGuard-proxy/main/wireguard-alpine.sh && chmod +x wireguard-alpine.sh && ./wireguard-alpine.sh
```

---

## For Debian / Ubuntu

To download and run the script on your **Debian or Ubuntu** server, use the following command.

**Note:** Please replace `YOUR_USERNAME` with your actual GitHub username.

```bash
wget -O wireguard-debian.sh https://raw.githubusercontent.com/YOUR_USERNAME/wireGuard-proxy/main/wireguard-debian.sh && chmod +x wireguard-debian.sh && ./wireguard-debian.sh
```

---

### Features

*   One-click installation for WireGuard.
*   Supports Alpine, Debian, and Ubuntu.
*   Optional TCP obfuscation with Udp2raw.
*   Automatic user management (add/delete clients).
*   System optimization (enables BBR).
*   Robust, multi-layered network interface detection for reliability in complex environments.
