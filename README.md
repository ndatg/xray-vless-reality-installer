# Xray VLESS + REALITY Installer

One script to install and manage a VLESS + REALITY VPN server on any Linux VPS, with a choice of TCP + XTLS Vision or XHTTP transport. No domain, no certificates — works out of the box in under 2 minutes. A separate script is available for Docker containers without systemd.

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
- No systemd unit, no dedicated user, no BBR
- Publish port 443 of the container (e.g. `docker run -p 443:443 ...`)
- Autostart without systemd, detected automatically:
  - **cron** (if a cron daemon runs in the container): checks every minute, so Xray comes back after a container restart *and* after a crash
  - otherwise **OpenRC** (`/etc/local.d`) or **`/etc/rc.local`**: starts Xray at container boot
  - if none is available, set your provider's startup command to `/usr/local/bin/xray-autostart`, or start Xray from the menu (**Start / restart Xray**)

## What It Does

**First run** — interactive installation:
- Installs Xray-core (latest version, auto-detects architecture)
- Detects the server's public IP — you can keep it or enter a domain instead
- Generates REALITY keys, UUID, Short ID
- Lets you choose the transport: **TCP + XTLS Vision** (default, supported by all clients) or **XHTTP** (see below)
- Checks the SNI site against REALITY target requirements (TLS 1.3, HTTP/2, no redirect to another domain) and warns before continuing
- Lets you choose DNS (Google, Cloudflare, Quad9, AdGuard, OpenDNS)
- Configures systemd service on port 443 with autostart at boot
- Validates the config and checks that Xray actually started (shows logs if not)
- Blocks clients from reaching the server's local and private addresses (see below)
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
   Transport: TCP + XTLS Vision
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
If the config was created by an older version without the private-address block,
the script offers to add it.

**Remove Xray** deletes the binary, configuration, service and BBR settings.

## Requirements

- Linux VPS (Debian, Ubuntu, CentOS, Fedora, Arch)
- Root access
- Port 443 open

The script installs all dependencies automatically.

## How It Works

REALITY is a next-gen security layer by the Xray team. It makes your VPN traffic indistinguishable from a regular HTTPS connection to a real website (the SNI site, e.g. `www.cloudflare.com`). Unlike traditional TLS proxies, REALITY requires no certificates and no domain — just a VPS with a public IP. On top of REALITY the traffic is carried either over TCP with XTLS Vision or over XHTTP (see below).

### Choosing the SNI site

The SNI site should be a foreign site that supports TLS 1.3 and HTTP/2 (required for XHTTP) and does not redirect to another domain — the script checks this during installation. Prefer a site hosted in the same network as your VPS over popular domains (Google, Microsoft, Apple): a VPS IP claiming to be one of them is easy to spot. Some sites pass the check but still fail with REALITY (e.g. `www.microsoft.com` with its very large certificate chain), so test a connection after installing.

## Transport: TCP + Vision or XHTTP

| | TCP + XTLS Vision | XHTTP |
|---|---|---|
| Client support | All apps | Apps with a recent Xray-core; see [Client Apps](#client-apps) |
| How it looks | One long TLS connection | HTTP requests (harder to fingerprint by connection pattern) |
| Flow | `xtls-rprx-vision` | none (Vision works only over TCP) |

XHTTP follows the [official Project X example](https://github.com/XTLS/Xray-examples/tree/main/VLESS-XHTTP-Reality):
only a random `path` is set, `mode` is `auto` (the client picks `stream-one` with REALITY),
everything else uses Xray defaults. Requires Xray-core v25.3.6 or newer. Do **not** enable
Mux (mux.cool) in the client app when using XHTTP.

The transport is chosen at install time; to switch, reinstall (clients get new links).

## Private Address Blocking

Clients can use the server only to reach the internet. Connections to the
server's own and internal addresses are dropped:

- `127.0.0.0/8`, `::1` — services on the server itself (databases, admin panels, APIs listening on localhost)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7` — provider/LAN networks, Docker host
- `169.254.0.0/16`, `fe80::/10` — link-local, including the cloud metadata service `169.254.169.254`

This also covers hostnames that resolve to these addresses (`localhost`, entries
from `/etc/hosts`, public domains pointing to `127.0.0.1`). Xray's own DNS queries
are routed directly, so a local system resolver keeps working. To allow access,
remove the `"outboundTag": "block"` rule from `routing.rules` in `/etc/xray/config.json`
and restart Xray.

## Client Apps

Import the generated URI or scan the QR code. All apps below support **TCP + XTLS Vision**.
**XHTTP** is an Xray-core feature: apps built on a recent Xray-core (v25.3.6+) support it,
apps built on sing-box usually do not.

| Platform | App | XHTTP |
|----------|-----|-------|
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118), [V2BOX](https://apps.apple.com/app/v2box-v2ray-client/id6446814690) | check the app version |
| macOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118), [V2BOX](https://apps.apple.com/app/v2box-v2ray-client/id6446814690) | check the app version |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | yes (Xray-core) |
| Android | [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid) | no (sing-box core) |
| Windows | [v2rayN](https://github.com/2dust/v2rayN) | yes (Xray-core) |
| Linux | [v2rayA](https://github.com/v2rayA/v2rayA) | yes, with Xray-core |
| Linux | [Nekoray](https://github.com/Mahdi-zarei/nekoray), [Hiddify](https://github.com/hiddify/hiddify-app) | usually no (sing-box core) |

With XHTTP, keep **Mux** disabled in the app.

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

## License

MIT
