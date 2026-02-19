#!/usr/bin/env bash

# ==============================================================================
# Xray VLESS + REALITY — Universal Management Script
# ------------------------------------------------------------------------------
# A single interactive script that handles the full lifecycle:
#   - First run  : installs Xray-core with VLESS+REALITY (interactive prompts)
#   - Re-run     : management menu (add/remove clients, uninstall)
#
# Usage:
#   sudo bash xray-install.sh
# ==============================================================================

set -euo pipefail

CONFIG="/etc/xray/config.json"

# ==============================================================================
# Utility functions
# ==============================================================================

# Check whether a previous installation exists and is active
is_xray_installed() {
    [[ -f /usr/local/bin/xray ]] && \
    [[ -f "$CONFIG" ]] && \
    systemctl is-enabled xray &>/dev/null
}

# Resolve the server's public IPv4 address (multiple fallbacks)
detect_public_ip() {
    curl -4s https://api.ipify.org 2>/dev/null \
        || curl -4s https://ifconfig.me 2>/dev/null \
        || hostname -I 2>/dev/null | awk '{print $1}' \
        || true
}

# Generate a random UUID using the best available method
generate_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null \
            || date +%s%N | sha256sum | cut -c1-32 \
               | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
    fi
}

# Generate an 8-char hex Short ID that does not collide with existing ones
# $1 — space-separated list of existing Short IDs (optional)
generate_short_id() {
    local existing="${1:-}"
    local sid=""
    for _ in {1..10}; do
        if command -v openssl &>/dev/null; then
            sid="$(openssl rand -hex 4)"
        else
            sid="$(head -c 4 /dev/urandom 2>/dev/null | xxd -p || printf '%08x' $((RANDOM * RANDOM)))"
        fi
        # Return immediately if unique
        if [[ ! " $existing " =~ " $sid " ]]; then
            echo "$sid"; return 0
        fi
    done
    echo "$sid"  # last resort after 10 collisions
}

# Set ownership and permissions on config.json (readable by the nobody service)
set_config_permissions() {
    local path="${1:-$CONFIG}"
    if getent group nogroup &>/dev/null; then
        chown root:nogroup "$path"
    else
        chown root:nobody "$path"
    fi
    chmod 640 "$path"
}

# Return the correct unprivileged group name for the current distro
get_nobody_group() {
    if getent group nogroup &>/dev/null; then
        echo "nogroup"
    else
        echo "nobody"
    fi
}

# Install jq if it is not already present
ensure_jq() {
    command -v jq &>/dev/null && return 0
    echo ">>> Installing jq..."
    if command -v apt &>/dev/null; then
        apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y jq
    elif command -v dnf &>/dev/null; then
        dnf install -y jq
    elif command -v yum &>/dev/null; then
        yum install -y epel-release && yum install -y jq
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm jq
    else
        echo "Please install 'jq' manually." >&2; exit 1
    fi
}

# Install all required packages for a fresh installation
install_deps() {
    echo -e "\n>>> Installing dependencies..."
    if command -v apt &>/dev/null; then
        apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            curl unzip tar uuid-runtime nginx qrencode jq
    elif command -v dnf &>/dev/null; then
        dnf install -y curl unzip tar nginx qrencode jq
    elif command -v yum &>/dev/null; then
        yum install -y curl unzip tar nginx qrencode epel-release
        yum install -y jq
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm curl unzip tar nginx qrencode jq
    else
        echo "Unsupported package manager. Install dependencies manually." >&2
        exit 1
    fi
}

# Enable TCP BBR congestion control for better throughput
enable_bbr() {
    if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q '^bbr$'; then
        echo ">>> BBR congestion control already enabled."
    else
        echo -e "\n>>> Enabling TCP BBR congestion control..."
        grep -qF 'net.core.default_qdisc=fq' /etc/sysctl.conf \
            || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
        grep -qF 'net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf \
            || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
        sysctl -p
    fi
}

# Build a VLESS+REALITY URI and display it along with a QR code
# Arguments: uuid server public_key short_id sni [fingerprint]
show_connection_info() {
    local uuid="$1" server="$2" pbk="$3" sid="$4" sni="$5" fp="${6:-chrome}"
    local uri="vless://${uuid}@${server}:443?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&pbk=${pbk}&sid=${sid}&fp=${fp}&sni=${sni}#${sid}-${sni}"

    echo ""
    echo "Generated VLESS+REALITY URI (copy or scan):"
    echo "$uri"

    if command -v qrencode &>/dev/null; then
        local png="/etc/xray/vless-${uuid}.png"
        qrencode -o "$png" -l H -t png -- "$uri"
        qrencode -t ANSIUTF8 -- "$uri"
        echo -e "\nQR code saved to: $png"
    else
        echo -e "\nqrencode not available — QR code generation skipped."
    fi
}

# ==============================================================================
# Fresh installation (interactive)
# ==============================================================================

new_install() {
    echo ""
    echo "Welcome to the Xray VLESS+REALITY installer!"
    echo ""

    # ---- Public IP ----
    local server
    server="$(detect_public_ip)"
    if [[ -z "$server" ]]; then
        echo "Unable to auto-detect public IP." >&2
        read -rp "Enter the server's public IP or domain: " server
        [[ -z "$server" ]] && { echo "Server address is required." >&2; exit 1; }
    fi
    echo "Detected public IP: $server"

    # ---- SNI domain (required) ----
    local sni
    echo ""
    read -rp "Enter the SNI domain (e.g. www.cloudflare.com): " sni
    while [[ -z "$sni" ]]; do
        read -rp "SNI domain cannot be empty. Try again: " sni
    done

    # ---- DNS selection ----
    echo ""
    echo "Select a DNS server for Xray:"
    echo "   1) Current system resolvers"
    echo "   2) Google        (8.8.8.8, 8.8.4.4)"
    echo "   3) Cloudflare    (1.1.1.1, 1.0.0.1)"
    echo "   4) OpenDNS       (208.67.222.222, 208.67.220.220)"
    echo "   5) Quad9         (9.9.9.9, 149.112.112.112)"
    echo "   6) AdGuard DNS   (94.140.14.14, 94.140.15.15)"
    local dns_choice dns1 dns2
    read -rp "DNS [1-6, default 2]: " dns_choice
    case "${dns_choice:-2}" in
        1)
            dns1="$(grep -m1 '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true)"
            dns2="$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk 'NR==2{print $2}' || true)"
            if [[ -z "$dns1" ]]; then
                dns1="8.8.8.8"; dns2="8.8.4.4"
                echo "No system resolvers found. Falling back to Google DNS."
            fi
            ;;
        3)  dns1="1.1.1.1";         dns2="1.0.0.1" ;;
        4)  dns1="208.67.222.222";   dns2="208.67.220.220" ;;
        5)  dns1="9.9.9.9";         dns2="149.112.112.112" ;;
        6)  dns1="94.140.14.14";    dns2="94.140.15.15" ;;
        *)  dns1="8.8.8.8";         dns2="8.8.4.4" ;;
    esac

    # ---- Confirmation summary ----
    echo ""
    echo "Xray VLESS+REALITY will be installed with these settings:"
    echo ""
    echo "   Server IP  : $server"
    echo "   SNI domain : $sni"
    echo "   DNS servers: $dns1${dns2:+, $dns2}"
    echo ""
    read -rp "Press Enter to continue or Ctrl+C to abort..."

    # ---- Install system packages ----
    install_deps
    enable_bbr

    # ---- Download latest Xray-core binary ----
    local xray_version
    xray_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest \
        | grep -Po '"tag_name":\s*"\K[^"]+' || true)"
    if [[ -z "$xray_version" ]]; then
        echo "Unable to fetch latest Xray-core version from GitHub." >&2
        exit 1
    fi
    echo -e "\n>>> Latest Xray-core version: $xray_version"

    local arch_pkg
    case "$(uname -m)" in
        x86_64|amd64)   arch_pkg="xray-linux-64" ;;
        aarch64|arm64)  arch_pkg="xray-linux-arm64-v8a" ;;
        armv7l|armv6l)  arch_pkg="xray-linux-arm32-v7a" ;;
        *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
    esac

    local tmp_dir
    tmp_dir=$(mktemp -d)

    local zip_name="${arch_pkg}.zip"
    local download_url="https://github.com/XTLS/Xray-core/releases/download/${xray_version}/${zip_name}"
    echo ">>> Downloading Xray-core ${xray_version} (${arch_pkg})..."
    curl -L "$download_url" -o "$tmp_dir/$zip_name"

    install -d /usr/local/bin /etc/xray
    unzip -qo "$tmp_dir/$zip_name" -d "$tmp_dir"
    install -m 755 "$tmp_dir/xray" /usr/local/bin/xray
    rm -rf "$tmp_dir"

    # ---- Generate X25519 key pair for REALITY ----
    local key_output private_key public_key
    key_output=$(/usr/local/bin/xray x25519)

    # Support both old ("Private key: / Public key:") and new ("PrivateKey: / Password:") formats
    private_key=$(echo "$key_output" | awk '/PrivateKey:/{print $2}')
    [[ -z "$private_key" ]] && private_key=$(echo "$key_output" | awk '/Private key:/{print $3}')

    public_key=$(echo "$key_output" | awk '/Password:/{print $2}')
    [[ -z "$public_key" ]] && public_key=$(echo "$key_output" | awk '/Public key:/{print $3}')

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        echo "Failed to generate X25519 keys. Raw output:" >&2
        echo "$key_output" >&2
        exit 1
    fi

    # Persist public key for future client additions
    echo "$public_key" > /etc/xray/public.key

    # ---- Generate first client credentials ----
    local uuid short_id
    uuid="$(generate_uuid)"
    short_id="$(generate_short_id)"

    # ---- Write config.json (with DNS section) ----
    local dns_json="\"$dns1\""
    [[ -n "$dns2" ]] && dns_json="\"$dns1\", \"$dns2\""

    cat > "$CONFIG" <<EOF
{
  "dns": {
    "servers": [$dns_json]
  },
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
            "id": "$uuid",
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
          "dest": "$sni:443",
          "xver": 0,
          "serverNames": [
            "$sni"
          ],
          "privateKey": "$private_key",
          "shortIds": [
            "$short_id"
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": { "domainStrategy": "UseIP" } }
  ]
}
EOF
    set_config_permissions

    # ---- Create and start systemd service ----
    local nobody_group
    nobody_group="$(get_nobody_group)"

    cat > /etc/systemd/system/xray.service <<SERVICE
[Unit]
Description=Xray Service (VLESS + REALITY)
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
Type=simple
User=nobody
Group=${nobody_group}
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

    # ---- Configure nginx on port 80 (camouflage redirect to SNI) ----
    mkdir -p /var/www/html

    local nginx_conf="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    return 301 https://${sni}\$request_uri;
}"

    if [[ -d /etc/nginx/sites-available ]]; then
        local site="/etc/nginx/sites-available/default"
        [[ -f "$site" && ! -f "${site}.orig" ]] && cp "$site" "${site}.orig"
        echo "$nginx_conf" > "$site"
        [[ -d /etc/nginx/sites-enabled ]] && ln -sf "$site" /etc/nginx/sites-enabled/default
    elif [[ -d /etc/nginx/conf.d ]]; then
        local site="/etc/nginx/conf.d/default.conf"
        [[ -f "$site" && ! -f "${site}.orig" ]] && cp "$site" "${site}.orig"
        echo "$nginx_conf" > "$site"
    fi

    systemctl enable --now nginx
    systemctl reload nginx

    # ---- Display connection info ----
    show_connection_info "$uuid" "$server" "$public_key" "$short_id" "$sni"

    cat <<EOF

Xray-core VLESS + REALITY installation completed!

Configuration file : $CONFIG
Systemd service    : xray (running)
Fake SNI           : $sni
Connect to host    : $server
Public key         : $public_key (saved to /etc/xray/public.key)
Short ID           : $short_id
UUID               : $uuid

To manage clients or remove Xray, run this script again.
EOF
}

# ==============================================================================
# Add a new client to the running server
# ==============================================================================

add_client() {
    ensure_jq

    # Generate unique credentials
    local uuid short_id existing_sids
    uuid="$(generate_uuid)"
    existing_sids=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[]? // empty' "$CONFIG" 2>/dev/null | tr '\n' ' ' || echo "")
    short_id="$(generate_short_id "$existing_sids")"

    echo ""
    echo "Adding new client..."
    echo "  UUID     : $uuid"
    echo "  Short ID : $short_id"

    # Append client and Short ID atomically (write to temp, then mv)
    local tmp
    tmp=$(mktemp)
    jq --arg uid "$uuid" --arg sid "$short_id" '
        (.inbounds[0].settings.clients //= []) |
        .inbounds[0].settings.clients += [{"id":$uid,"flow":"xtls-rprx-vision"}] |
        (.inbounds[0].streamSettings.realitySettings.shortIds //= []) |
        .inbounds[0].streamSettings.realitySettings.shortIds += [$sid]
    ' "$CONFIG" > "$tmp"
    mv "$tmp" "$CONFIG"

    set_config_permissions
    systemctl restart xray

    # Build and display the connection URI
    local pbk sni server
    pbk="$(cat /etc/xray/public.key 2>/dev/null || echo "")"
    sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // empty' "$CONFIG")"
    [[ -z "$sni" ]] && sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" | cut -d: -f1)"
    server="$(detect_public_ip)"

    show_connection_info "$uuid" "$server" "$pbk" "$short_id" "$sni"

    echo ""
    echo "Client added successfully! Xray has been restarted."
}

# ==============================================================================
# Remove an existing client from the server
# ==============================================================================

remove_client() {
    ensure_jq

    local num_clients
    num_clients=$(jq '.inbounds[0].settings.clients | length' "$CONFIG")

    # Refuse to remove the last remaining client
    if [[ "$num_clients" -le 1 ]]; then
        echo ""
        echo "There is only one client configured."
        echo "Cannot remove the last client — use option 3 to remove Xray entirely."
        return
    fi

    echo ""
    echo "Current clients:"
    echo ""

    # List every client with its positional Short ID
    local i=0
    local uuids=()
    while IFS= read -r uid; do
        uuids+=("$uid")
        local sid
        sid=$(jq -r --argjson idx "$i" \
            '.inbounds[0].streamSettings.realitySettings.shortIds[$idx] // "N/A"' "$CONFIG")
        echo "   $((i + 1))) $uid  (Short ID: $sid)"
        i=$((i + 1))
    done < <(jq -r '.inbounds[0].settings.clients[].id' "$CONFIG")

    echo ""
    read -rp "Select the client to remove [1-$num_clients]: " choice

    # Validate the selection
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > num_clients )); then
        echo "Invalid selection." >&2
        return
    fi

    local idx=$(( choice - 1 ))
    local target_uuid="${uuids[$idx]}"

    echo ""
    read -rp "Confirm removal of client $target_uuid? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo "Aborted."; return; }

    # Remove both the client object and its corresponding Short ID by index
    jq --argjson idx "$idx" '
        .inbounds[0].settings.clients |= del(.[$idx]) |
        .inbounds[0].streamSettings.realitySettings.shortIds |= del(.[$idx])
    ' "$CONFIG" > "${CONFIG}.tmp"
    mv "${CONFIG}.tmp" "$CONFIG"

    set_config_permissions
    systemctl restart xray

    # Clean up QR code image if it exists
    rm -f "/etc/xray/vless-${target_uuid}.png"

    echo "Client removed. Xray has been restarted."
}

# ==============================================================================
# Completely uninstall Xray and clean up all related files
# ==============================================================================

remove_xray() {
    echo ""
    read -rp "Are you sure you want to completely remove Xray? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo "Aborted."; return; }

    echo ""
    echo ">>> Stopping and disabling Xray service..."
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true

    echo ">>> Removing Xray binary, configuration and service unit..."
    rm -f /usr/local/bin/xray
    rm -rf /etc/xray
    rm -f /etc/systemd/system/xray.service
    systemctl daemon-reload

    # Offer to revert nginx changes
    echo ""
    read -rp "Also stop and disable nginx? [y/N]: " remove_nginx
    if [[ "$remove_nginx" =~ ^[Yy]$ ]]; then
        systemctl stop nginx 2>/dev/null || true
        systemctl disable nginx 2>/dev/null || true
        # Restore the original nginx config from backup if available
        for orig in /etc/nginx/sites-available/default.orig /etc/nginx/conf.d/default.conf.orig; do
            if [[ -f "$orig" ]]; then
                mv "$orig" "${orig%.orig}"
                echo "Restored original nginx config from $orig"
            fi
        done
    fi

    echo ""
    echo "Xray has been completely removed."
}

# ==============================================================================
# Management menu (shown when Xray is already installed)
# ==============================================================================

manage_menu() {
    echo ""
    echo "Xray VLESS+REALITY is already installed."
    echo ""
    echo "Select an option:"
    echo "   1) Add a new client"
    echo "   2) Remove an existing client"
    echo "   3) Remove Xray"
    echo "   4) Exit"

    local option
    read -rp "Option [1-4]: " option
    case "$option" in
        1) add_client ;;
        2) remove_client ;;
        3) remove_xray ;;
        4) exit 0 ;;
        *) echo "Invalid option." >&2; exit 1 ;;
    esac
}

# ==============================================================================
# Entry point
# ==============================================================================

# This script must be executed as root
if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root. Use: sudo bash $0" >&2
    exit 1
fi

if is_xray_installed; then
    manage_menu
else
    new_install
fi
