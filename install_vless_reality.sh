#!/usr/bin/env bash

# ==============================================================================
# Xray-Core VLESS + REALITY Automated Installer
# ------------------------------------------------------------------------------
# This script installs a secure, obfuscated VLESS VPN server using Xray-core’s
# REALITY transport. It mirrors the UX of the other installers in this repo.
#
#   Required parameters:
#     --sni     <domain>          The fake site domain (e.g. www.cloudflare.com)
#
#   Optional parameters:
#     --uuid    <uuid>            Client UUID (defaults to uuidgen)
#     --short   <hex>            Short ID (1-16 hex, defaults random)
#     --fp      <fingerprint>     Client fingerprint (default chrome) – URI only
#
# Example:
#   sudo bash install_vless_reality.sh \
#       --sni www.cloudflare.com \
#       --uuid 11111111-1111-1111-1111-111111111111 \
#       --short abcd
# ------------------------------------------------------------------------------
# Features:
#   • Listens on TCP/443 using REALITY (no public certificate needed)
#   • Randomised private/public key pair (X25519)
#   • Generates shareable VLESS+REALITY URI and QR code
#   • Minimal systemd service under user nobody
#   • Optional Nginx site on port 80 for camouflage
# ==============================================================================

set -euo pipefail

##############################
# 1. Parse user parameters   #
##############################

SNI=""
SERVER=""
UUID=""
SHORT_ID=""
FINGERPRINT="chrome"
XRAY_VERSION=""

usage() {
    echo -e "\nUsage: sudo $0 --sni <fake-site.com> [--server <real-server-domain-or-ip>] [--uuid <uuid>] [--short <hex>] [--fp <fingerprint>] [--version <xray-version>]\n" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sni)
            SNI="$2"; shift 2;;
        --server)
            SERVER="$2"; shift 2;;
        --uuid)
            UUID="$2"; shift 2;;
        --short)
            SHORT_ID="$2"; shift 2;;
        --fp)
            FINGERPRINT="$2"; shift 2;;
        --version)
            XRAY_VERSION="$2"; shift 2;;
        -h|--help)
            usage;;
        *)
            echo "Unknown option: $1" >&2; usage;;
    esac
done

if [[ -z "$SNI" ]]; then
    usage
fi

# Fetch latest Xray-core version from GitHub if not specified
if [[ -z "$XRAY_VERSION" ]]; then
    XRAY_VERSION="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -Po '"tag_name":\s*"\K[^"]+' || true)"
    if [[ -z "$XRAY_VERSION" ]]; then
        echo "Unable to fetch latest Xray-core version from GitHub. Please pass --version <tag>." >&2
        exit 1
    fi
    echo ">>> Latest Xray-core version: $XRAY_VERSION"
fi

# Determine SERVER if not provided (use public IPv4)
if [[ -z "$SERVER" ]]; then
    SERVER="$(curl -s https://api.ipify.org || true)"
    if [[ -z "$SERVER" ]]; then
        echo "Unable to auto-detect public IP. Please pass --server <ip/domain>." >&2
        exit 1
    fi
fi

# Generate UUID if missing
if [[ -z "$UUID" ]]; then
    if command -v uuidgen &>/dev/null; then
        UUID="$(uuidgen)"
    else
        UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N | sha256sum | cut -c1-32 | sed 's/\(..\)/\1-/g; s/-$//')"
    fi
fi

# Generate Short ID (1-16 hex chars) if missing
if [[ -z "$SHORT_ID" ]]; then
    SHORT_ID="$(openssl rand -hex 4 2>/dev/null || echo abcd)"
fi

##############################
# 2. Install dependencies    #
##############################

install_deps() {
    if command -v apt &>/dev/null; then
        apt update -y
        DEBIAN_FRONTEND=noninteractive apt install -y curl unzip tar uuid-runtime nginx qrencode
    elif command -v dnf &>/dev/null; then
        dnf install -y curl unzip tar nginx qrencode
    elif command -v yum &>/dev/null; then
        yum install -y curl unzip tar nginx qrencode
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm curl unzip tar nginx qrencode
    else
        echo "Unsupported package manager. Install curl and unzip manually." >&2
        exit 1
    fi
}

# Enable TCP BBR if not already active
enable_bbr() {
    if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q '^bbr$'; then
        echo "✓ BBR congestion control already enabled."
    else
        echo -e "\n>>> Enabling TCP BBR congestion control..."
        # Apply settings only if they are not yet present
        grep -qF 'net.core.default_qdisc=fq' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
        grep -qF 'net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
        sysctl -p
    fi
}

install_deps
enable_bbr

############################################
# 3. Download & install latest Xray-core   #
############################################

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH_PKG="xray-linux-64"   ;;
    aarch64|arm64)  ARCH_PKG="xray-linux-arm64-v8a" ;;
    armv7l|armv6l)  ARCH_PKG="xray-linux-arm32-v7a" ;;
    *) echo "Unsupported CPU architecture: $ARCH" >&2; exit 1;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
TAR_NAME="${ARCH_PKG}.zip"
DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${TAR_NAME}"

echo -e "\n>>> Downloading Xray-core ${XRAY_VERSION} (${ARCH_PKG})..."
curl -L "$DOWNLOAD_URL" -o "$TMP_DIR/${TAR_NAME}"

install -d /usr/local/bin /etc/xray
unzip -qo "$TMP_DIR/${TAR_NAME}" -d "$TMP_DIR"
install -m 755 "$TMP_DIR/xray" /usr/local/bin/xray

##############################
# 4. Generate REALITY keys   #
##############################

KEY_OUTPUT=$(/usr/local/bin/xray x25519)

# v25.3.6+: "PrivateKey: <val>" / "Password: <val>"
# older:    "Private key: <val>" / "Public key: <val>"
PRIVATE_KEY=$(echo "$KEY_OUTPUT" | awk '/PrivateKey:/{print $2}')
if [[ -z "$PRIVATE_KEY" ]]; then
    PRIVATE_KEY=$(echo "$KEY_OUTPUT" | awk '/Private key:/{print $3}')
fi

PUBLIC_KEY=$(echo "$KEY_OUTPUT" | awk '/Password:/{print $2}')
if [[ -z "$PUBLIC_KEY" ]]; then
    PUBLIC_KEY=$(echo "$KEY_OUTPUT" | awk '/Public key:/{print $3}')
fi

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo "Failed to generate X25519 keys. Output was:" >&2
    echo "$KEY_OUTPUT" >&2
    exit 1
fi

# Persist public key for future user additions
echo "$PUBLIC_KEY" > /etc/xray/public.key

##############################
# 5. Create config.json      #
##############################

CONFIG_PATH="/etc/xray/config.json"
cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$SNI:443",
          "xver": 0,
          "serverNames": [
            "$SNI"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} }
  ]
}
EOF

# Allow nobody (nogroup on Debian, nobody on RHEL) to read the config
if getent group nogroup &>/dev/null; then
    chown root:nogroup "$CONFIG_PATH"
else
    chown root:nobody "$CONFIG_PATH"
fi
chmod 640 "$CONFIG_PATH"

##############################
# 6. systemd service         #
##############################

# Determine nobody's group (nogroup on Debian, nobody on RHEL)
if getent group nogroup &>/dev/null; then
    NOBODY_GROUP="nogroup"
else
    NOBODY_GROUP="nobody"
fi

SERVICE_FILE="/etc/systemd/system/xray.service"
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Xray Service (VLESS + REALITY)
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
Type=simple
User=nobody
Group=${NOBODY_GROUP}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

################################
# 7. Optional Nginx on port 80 #
################################

WEBROOT="/var/www/html"
mkdir -p "$WEBROOT"

NGINX_CONF_CONTENT="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    return 301 https://${SNI}\$request_uri;
}"

# Debian/Ubuntu style (sites-available + sites-enabled)
if [[ -d /etc/nginx/sites-available ]]; then
    DEFAULT_SITE="/etc/nginx/sites-available/default"
    if [[ -f "$DEFAULT_SITE" && ! -f "${DEFAULT_SITE}.orig" ]]; then
        cp "$DEFAULT_SITE" "${DEFAULT_SITE}.orig"
    fi
    echo "$NGINX_CONF_CONTENT" > "$DEFAULT_SITE"
    if [[ -d /etc/nginx/sites-enabled ]]; then
        ln -sf "$DEFAULT_SITE" /etc/nginx/sites-enabled/default
    fi
# RHEL/Fedora/Arch style (conf.d)
elif [[ -d /etc/nginx/conf.d ]]; then
    DEFAULT_SITE="/etc/nginx/conf.d/default.conf"
    if [[ -f "$DEFAULT_SITE" && ! -f "${DEFAULT_SITE}.orig" ]]; then
        cp "$DEFAULT_SITE" "${DEFAULT_SITE}.orig"
    fi
    echo "$NGINX_CONF_CONTENT" > "$DEFAULT_SITE"
fi

systemctl enable --now nginx
systemctl reload nginx

################################
# 8. Generate URI + QR code   #
################################

URI="vless://${UUID}@${SERVER}:443?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=${FINGERPRINT}&sni=${SNI}#${SHORT_ID}-${SNI}"

cat <<GENERATE

Generated VLESS+REALITY URI (copy or scan):
$URI
GENERATE

# Ensure qrencode is installed (should be from dependencies, but double-check)
if command -v qrencode &>/dev/null; then
    QR_OUTPUT="/etc/xray/vless-${UUID}.png"
    qrencode -o "$QR_OUTPUT" -l H -t png -- "$URI"

    # Show ASCII QR for quick scan
    qrencode -t ANSIUTF8 -- "$URI"

    echo -e "\nQR code saved to: $QR_OUTPUT"
else
    echo -e "\nqrencode not available - QR code generation skipped"
fi

################################
# 9. Completion message        #
################################

cat <<EOF

✔ Xray-core VLESS + REALITY installation completed!

Configuration file : $CONFIG_PATH
Systemd service    : xray (running)
Fake SNI           : $SNI
Connect to host    : $SERVER
Public key         : $PUBLIC_KEY (also saved to /etc/xray/public.key)
Short ID           : $SHORT_ID
UUID               : $UUID

To add more users later run:  sudo bash add_vless_reality_user.sh

Share the above URI or QR with your client.

Check service status with: systemctl status xray
EOF
