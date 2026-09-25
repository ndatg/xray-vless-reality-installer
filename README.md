# Xray VLESS + REALITY Installer

One script to install and manage a VLESS + REALITY VPN server on any Linux VPS. No domain, no certificates, no Docker — works out of the box in under 2 minutes.

## Quick Start

```bash
wget https://raw.githubusercontent.com/ndatg/xray-vless-reality-installer/main/xray-install.sh && sudo bash xray-install.sh
```

To manage clients later, just re-run `sudo bash xray-install.sh`.

### Running in Docker (no systemd)

Use `xray-install-docker.sh` inside a Docker container (Debian/Ubuntu, Fedora, Alpine, Arch images). Run it as root; bash is required:

```bash
wget https://raw.githubusercontent.com/ndatg/xray-vless-reality-installer/main/xray-install-docker.sh && bash xray-install-docker.sh
```

Differences from the host script:
- Xray runs as a background process; log in `/var/log/xray.log`
- No systemd unit, no dedicated user, no BBR, no nginx
- Publish port 443 of the container (e.g. `docker run -p 443:443 ...`)
- The process is not supervised: after a container restart, re-run the script and choose **Start / restart Xray**

## What It Does

**First run** — interactive installation:
- Installs Xray-core (latest version, auto-detects architecture)
- Detects the server's public IP — you can keep it or enter a domain instead
- Generates REALITY keys, UUID, Short ID
- Lets you choose DNS (Google, Cloudflare, Quad9, AdGuard, OpenDNS)
- Configures systemd service on port 443 with autostart at boot
- Validates the config and checks that Xray actually started (shows logs if not)
- Optionally sets up nginx on port 80 (redirect to the SNI site)
- Enables TCP BBR for better speed (persistent across reboots)
- Prints connection URI + QR code

**Every next run** — service status and management menu:

```
Xray VLESS+REALITY is already installed.

   Service  : active (since Thu 2026-09-25 21:00:00 MSK)
   Autostart: enabled
   Version  : 26.3.27
   Address  : 203.0.113.10
   SNI      : www.cloudflare.com
   Clients  : 3
   Log      : journalctl -u xray

Select an option:
   1) Add a new client
   2) Remove an existing client
   3) Start / restart Xray
   4) Remove Xray
   5) Exit
```

If autostart at boot was turned off, the script re-enables it. Config changes
(adding/removing clients) are validated before they replace the running config.

**Remove Xray** deletes the binary, configuration, service and BBR settings.
If the script set up nginx, it also offers to restore the original nginx config.

## Requirements

- Linux VPS (Debian, Ubuntu, CentOS, Fedora, Arch)
- Root access
- Port 443 open (and port 80 if you enable the nginx redirect)

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
| `/etc/xray/server.addr` | Server address (IP or domain) used in client links |
| `/etc/xray/vless-*.png` | QR code images |
| `/etc/systemd/system/xray.service` | Systemd service unit |
| `/etc/sysctl.d/99-xray-bbr.conf` | TCP BBR settings |
| `/etc/nginx/sites-available/default` or `/etc/nginx/conf.d/default.conf` | nginx redirect (only if enabled; original saved as `*.orig`) |

## License

MIT
