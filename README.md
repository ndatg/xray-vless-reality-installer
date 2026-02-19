# Xray VLESS + REALITY Installer

One script to install and manage a VLESS + REALITY VPN server on any Linux VPS. No domain, no certificates, no Docker — works out of the box in under 2 minutes.

## Quick Start

```bash
wget https://raw.githubusercontent.com/ndatg/xray-vless-reality-installer/main/xray-install.sh && sudo bash xray-install.sh
```

To manage clients later, just re-run `sudo bash xray-install.sh`.

## What It Does

**First run** — interactive installation:
- Installs Xray-core (latest version, auto-detects architecture)
- Generates REALITY keys, UUID, Short ID
- Lets you choose DNS (Google, Cloudflare, Quad9, AdGuard, OpenDNS)
- Configures systemd service on port 443
- Sets up nginx camouflage on port 80
- Enables TCP BBR for better speed
- Prints connection URI + QR code

**Every next run** — management menu:

```
Xray VLESS+REALITY is already installed.

Select an option:
   1) Add a new client
   2) Remove an existing client
   3) Remove Xray
   4) Exit
```

## Requirements

- Linux VPS (Debian, Ubuntu, CentOS, Fedora, Arch)
- Root access
- Ports 443 and 80 open

The script installs all dependencies automatically.

## How It Works

REALITY is a next-gen transport protocol by the Xray team. It makes your VPN traffic indistinguishable from a regular HTTPS connection to a real website (e.g. `www.google.com`). Unlike traditional TLS proxies, REALITY requires no certificates and no domain — just a VPS with a public IP.

## Client Apps

Import the generated URI or scan the QR code:

| Platform | App |
|----------|-----|
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118), [V2BOX](https://apps.apple.com/app/v2box-v2ray-client/id6446814690) |
| macOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118), [V2BOX](https://apps.apple.com/app/v2box-v2ray-client/id6446814690) |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG), [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid) |
| Windows | [v2rayN](https://github.com/2dust/v2rayN) |
| Linux | [v2rayA](https://github.com/v2rayA/v2rayA), [Nekoray](https://github.com/Mahdi-zarei/nekoray), [Hiddify](https://github.com/hiddify/hiddify-app) |

## File Locations

| Path | Description |
|------|-------------|
| `/usr/local/bin/xray` | Xray-core binary |
| `/etc/xray/config.json` | Server configuration |
| `/etc/xray/public.key` | REALITY public key |
| `/etc/xray/vless-*.png` | QR code images |

## License

MIT
