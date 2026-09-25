#!/usr/bin/env bash

# ==============================================================================
# Xray VLESS + REALITY — Docker Management Script (no systemd)
# ------------------------------------------------------------------------------
# Same lifecycle as xray-install.sh, adapted for Docker containers without systemd:
#   - First run  : installs Xray-core with VLESS+REALITY (interactive prompts)
#   - Re-run     : management menu (status, add/remove clients, restart, uninstall)
#
# Differences from xray-install.sh:
#   - Xray runs as a background process (nohup), log in /var/log/xray.log
#   - No systemd unit, no dedicated user, no BBR (sysctl), no nginx
#   - Autostart without systemd: a cron check every minute (also restarts
#     Xray after a crash), else OpenRC local.d or /etc/rc.local at boot.
#     If none is available, start Xray from the menu after a container restart
#     or set your provider's startup command to /usr/local/bin/xray-autostart
#
# Publish port 443 of the container (e.g. docker run -p 443:443 ...).
#
# Usage (as root inside the container):
#   bash xray-install-docker.sh
# ==============================================================================

set -euo pipefail

CONFIG="/etc/xray/config.json"
SERVER_ADDR_FILE="/etc/xray/server.addr"
# Private/local destinations clients must not reach through the proxy
# (server's localhost, LAN/provider networks, cloud metadata 169.254.169.254)
PRIVATE_IPS_JSON='["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]'
XRAY_BIN="/usr/local/bin/xray"
XRAY_LOG="/var/log/xray.log"
# pgrep/pkill pattern for our Xray process only (not other Xray instances
# or "xray run -test" validation runs)
XRAY_MATCH="$XRAY_BIN run -config $CONFIG"

# ==============================================================================
# Utility functions
# ==============================================================================

# Check whether a previous installation exists
is_xray_installed() {
    [[ -f "$XRAY_BIN" ]] && [[ -f "$CONFIG" ]]
}

# Resolve the server's public IPv4 address (multiple fallbacks)
detect_public_ip() {
    local url ip
    for url in https://api.ipify.org https://ifconfig.me; do
        ip="$(curl -4fsS --connect-timeout 5 --max-time 10 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
        # Accept only something that looks like an IPv4 address (not an error page)
        if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            echo "$ip"; return 0
        fi
    done
    hostname -I 2>/dev/null | awk '{print $1}' || true
}

# Return the server address clients connect to.
# Uses the address saved at install time; if it is missing,
# auto-detects (or asks) and saves it for next time.
get_server_address() {
    local server=""
    [[ -f "$SERVER_ADDR_FILE" ]] && server="$(head -n1 "$SERVER_ADDR_FILE")"
    if [[ -z "$server" ]]; then
        server="$(detect_public_ip)"
        if [[ -z "$server" ]]; then
            echo "Unable to auto-detect public IP." >&2
            read -rp "Enter the server's public IP or domain: " server
            [[ -z "$server" ]] && { echo "Server address is required." >&2; exit 1; }
        fi
        echo "$server" > "$SERVER_ADDR_FILE"
    fi
    echo "$server"
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

# Restrict permissions on config.json and /etc/xray/ (Xray runs as root here)
set_config_permissions() {
    local path="${1:-$CONFIG}"
    chmod 750 "$(dirname "$path")"
    chmod 640 "$path"
}

# Validate an Xray config file; print Xray's output and fail if it is invalid
# $1 — path to config (optional, defaults to $CONFIG)
validate_config() {
    local path="${1:-$CONFIG}" output
    if ! output=$("$XRAY_BIN" run -test -format json -config "$path" 2>&1); then
        echo "Xray config validation failed ($path):" >&2
        echo "$output" >&2
        return 1
    fi
}

# Check whether the config already blocks private destinations
has_private_block() {
    jq -e '[.routing.rules[]? | select(.outboundTag == "block")] | length > 0' "$CONFIG" &>/dev/null
}

# Add the private-address block to an existing config (older installs):
# tag DNS and outbounds, route Xray's own DNS queries directly (the system
# resolver may be 127.0.0.53 / 127.0.0.11), send private IPs to blackhole.
# freedom uses ForceIP: with UseIP, names Xray's DNS can't resolve (localhost,
# entries from /etc/hosts) fall back to the system resolver and bypass the block.
add_private_block() {
    local tmp
    tmp=$(mktemp)
    jq --argjson ips "$PRIVATE_IPS_JSON" '
        .dns.tag = "dns-internal" |
        .outbounds = ((.outbounds // []) | map(if .protocol == "freedom" then (.tag //= "direct") | .settings.domainStrategy = "ForceIP" else . end)) |
        (if any(.outbounds[]; .tag == "block") then . else .outbounds += [{"tag": "block", "protocol": "blackhole"}] end) |
        .routing.domainStrategy = "IPIfNonMatch" |
        .routing.rules = [
            {"type": "field", "inboundTag": ["dns-internal"], "outboundTag": "direct"},
            {"type": "field", "ip": $ips, "outboundTag": "block"}
        ] + ((.routing.rules // []) | map(select(.outboundTag != "block" and .inboundTag != ["dns-internal"])))
    ' "$CONFIG" > "$tmp"
    validate_config "$tmp" || { rm -f "$tmp"; exit 1; }
    mv "$tmp" "$CONFIG"
    set_config_permissions
    restart_xray
    echo ">>> Access to private/local addresses is now blocked."
}

# Offer the private-address block if the config does not have it yet
offer_private_block() {
    command -v jq &>/dev/null || return 0
    # Only touch a config Xray accepts; a broken one is reported by start/restart
    validate_config &>/dev/null || return 0
    has_private_block && return 0
    echo ""
    echo "Your config lets clients reach the server's local and private addresses"
    echo "(localhost services, internal networks, cloud metadata)."
    local answer
    read -rp "Block them now? [Y/n]: " answer
    [[ "$answer" =~ ^[Nn]$ ]] || add_private_block
}

# ==============================================================================
# Process management (no systemd)
# ==============================================================================

xray_pid() {
    pgrep -f "$XRAY_MATCH" 2>/dev/null | head -n1 || true
}

is_xray_running() {
    [[ -n "$(xray_pid)" ]]
}

# Start Xray in the background and make sure it is actually running
start_xray() {
    if is_xray_running; then
        echo ">>> Xray is already running (PID $(xray_pid))."
        return 0
    fi
    validate_config || exit 1
    echo ">>> Starting Xray..."
    nohup "$XRAY_BIN" run -config "$CONFIG" < /dev/null >> "$XRAY_LOG" 2>&1 &
    sleep 2
    if is_xray_running; then
        echo ">>> Xray started (PID $(xray_pid))."
    else
        echo "Xray failed to start. Recent log ($XRAY_LOG):" >&2
        tail -n 20 "$XRAY_LOG" >&2 2>/dev/null || true
        exit 1
    fi
}

# Stop Xray and wait until it has exited (so port 443 is free for a restart)
stop_xray() {
    is_xray_running || return 0
    echo ">>> Stopping Xray..."
    pkill -f "$XRAY_MATCH" 2>/dev/null || true
    for _ in {1..10}; do
        is_xray_running || { echo ">>> Xray stopped."; return 0; }
        sleep 0.5
    done
    pkill -9 -f "$XRAY_MATCH" 2>/dev/null || true
    sleep 0.5
    echo ">>> Xray killed."
}

restart_xray() {
    stop_xray
    start_xray
}

# ==============================================================================
# Autostart (no systemd): cron watchdog, OpenRC local.d or rc.local
# ==============================================================================

AUTOSTART_BIN="/usr/local/bin/xray-autostart"
AUTOSTART_MARKER="# xray-autostart"
OPENRC_LOCAL="/etc/local.d/xray.start"

# Standalone launcher used by every autostart hook: starts Xray if it is
# installed and not running. Independent of where this script lives.
write_autostart_launcher() {
    cat > "$AUTOSTART_BIN" <<LAUNCHER
#!/bin/sh
$AUTOSTART_MARKER — managed by xray-install-docker.sh
# Starts Xray if it is installed and not already running.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[ -x "$XRAY_BIN" ] && [ -f "$CONFIG" ] || exit 0
pgrep -f "$XRAY_MATCH" >/dev/null 2>&1 && exit 0
nohup "$XRAY_BIN" run -config "$CONFIG" < /dev/null >> "$XRAY_LOG" 2>&1 &
LAUNCHER
    chmod 755 "$AUTOSTART_BIN"
}

# Is a cron daemon running in this container right now?
cron_running() {
    command -v crontab &>/dev/null || return 1
    pgrep -x cron &>/dev/null || pgrep -x crond &>/dev/null || pgrep -f 'busybox crond' &>/dev/null
}

# Print the autostart hook that is currently installed: cron|openrc|rc.local|none
autostart_mechanism() {
    if crontab -l 2>/dev/null | grep -qF "$AUTOSTART_MARKER"; then
        echo "cron"
    elif [[ -f "$OPENRC_LOCAL" ]]; then
        echo "openrc"
    elif grep -qF "$AUTOSTART_BIN" /etc/rc.local 2>/dev/null; then
        echo "rc.local"
    else
        echo "none"
    fi
}

# Can any autostart hook be installed in this container?
autostart_available() {
    cron_running || [[ -d /run/openrc ]] || \
        { [[ -f /etc/rc.local ]] && [[ "$(cat /proc/1/comm 2>/dev/null)" == "init" ]]; }
}

# Install the first working autostart hook (no-op if one is already installed)
setup_autostart() {
    [[ "$(autostart_mechanism)" != "none" ]] && return 0
    write_autostart_launcher

    if cron_running; then
        # Every minute: covers container restarts and Xray crashes.
        # (busybox crond has no @reboot, so a per-minute check is used everywhere)
        { crontab -l 2>/dev/null || true; echo "* * * * * $AUTOSTART_BIN $AUTOSTART_MARKER"; } | crontab -
        echo ">>> Autostart: cron checks Xray every minute and starts it if needed."
    elif [[ -d /run/openrc ]] && command -v rc-update &>/dev/null; then
        mkdir -p /etc/local.d
        printf '#!/bin/sh\n%s\n%s\n' "$AUTOSTART_MARKER" "$AUTOSTART_BIN" > "$OPENRC_LOCAL"
        chmod 755 "$OPENRC_LOCAL"
        rc-update add local default &>/dev/null || true
        echo ">>> Autostart: OpenRC starts Xray at container boot ($OPENRC_LOCAL)."
    elif [[ -f /etc/rc.local ]] && [[ "$(cat /proc/1/comm 2>/dev/null)" == "init" ]]; then
        if grep -q '^exit 0' /etc/rc.local; then
            sed -i "0,/^exit 0/s|^exit 0|$AUTOSTART_BIN $AUTOSTART_MARKER\nexit 0|" /etc/rc.local
        else
            echo "$AUTOSTART_BIN $AUTOSTART_MARKER" >> /etc/rc.local
        fi
        chmod +x /etc/rc.local
        echo ">>> Autostart: /etc/rc.local starts Xray at container boot."
    else
        echo "Warning: no cron, OpenRC or rc.local found — Xray will not start automatically." >&2
        echo "If your provider's panel has a startup command, set it to: $AUTOSTART_BIN" >&2
        return 0
    fi
}

# Remove every autostart hook and the launcher
remove_autostart() {
    if crontab -l 2>/dev/null | grep -qF "$AUTOSTART_MARKER"; then
        # grep -v exits 1 when our line was the only one — that is fine
        crontab -l 2>/dev/null | { grep -vF "$AUTOSTART_MARKER" || true; } | crontab -
    fi
    rm -f "$OPENRC_LOCAL"
    [[ -f /etc/rc.local ]] && sed -i "\|$AUTOSTART_BIN|d" /etc/rc.local
    rm -f "$AUTOSTART_BIN"
}

# Human-readable autostart state for the status block
autostart_status() {
    case "$(autostart_mechanism)" in
        cron)     echo "cron (checks every minute)" ;;
        openrc)   echo "OpenRC (at container boot)" ;;
        rc.local) echo "rc.local (at container boot)" ;;
        *)        echo "none (start from the menu after a container restart)" ;;
    esac
}

# ==============================================================================
# Packages
# ==============================================================================

# Install jq if it is not already present
ensure_jq() {
    command -v jq &>/dev/null && return 0
    echo ">>> Installing jq..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y jq
    elif command -v dnf &>/dev/null; then
        dnf install -y jq
    elif command -v yum &>/dev/null; then
        yum install -y epel-release && yum install -y jq
    elif command -v apk &>/dev/null; then
        apk add --no-cache jq
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm jq
    else
        echo "Please install 'jq' manually." >&2; exit 1
    fi
}

# Install all required packages for a fresh installation
# (procps provides pgrep/pkill, which minimal images often lack)
install_deps() {
    echo -e "\n>>> Installing dependencies..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            curl unzip tar uuid-runtime qrencode jq openssl procps
    elif command -v dnf &>/dev/null; then
        dnf install -y curl unzip tar qrencode jq openssl procps-ng
    elif command -v yum &>/dev/null; then
        yum install -y epel-release
        yum install -y curl unzip tar qrencode jq openssl procps-ng
    elif command -v apk &>/dev/null; then
        apk add --no-cache curl unzip tar libqrencode-tools jq openssl procps-ng
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm curl unzip tar qrencode jq openssl procps-ng
    else
        echo "Unsupported package manager. Install dependencies manually." >&2
        exit 1
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
    echo "Welcome to the Xray VLESS+REALITY installer (Docker mode, no systemd)!"
    echo ""

    # ---- Public IP ----
    local server
    local detected input
    detected="$(detect_public_ip)"
    if [[ -n "$detected" ]]; then
        echo "Detected public IP: $detected"
        read -rp "Server address for clients (IP or domain) [$detected]: " input
        server="${input:-$detected}"
    else
        echo "Unable to auto-detect public IP." >&2
        read -rp "Enter the server's public IP or domain: " server
    fi
    [[ -z "$server" ]] && { echo "Server address is required." >&2; exit 1; }

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

    # ---- Download latest Xray-core binary (skipped if already present) ----
    if [[ -f "$XRAY_BIN" ]]; then
        echo -e "\n>>> Using existing Xray binary: $XRAY_BIN"
    else
        local xray_version
        # jq instead of grep -P: busybox grep (Alpine) has no PCRE support
        xray_version="$(curl -fsSL --connect-timeout 10 --max-time 30 https://api.github.com/repos/XTLS/Xray-core/releases/latest \
            | jq -r '.tag_name // empty' || true)"
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
        # Clean up the temp dir even if download/unzip fails and set -e aborts the script
        # shellcheck disable=SC2064  # expand now: tmp_dir is local
        trap "rm -rf '$tmp_dir'" EXIT

        local zip_name="${arch_pkg}.zip"
        local download_url="https://github.com/XTLS/Xray-core/releases/download/${xray_version}/${zip_name}"
        echo ">>> Downloading Xray-core ${xray_version} (${arch_pkg})..."
        curl -fL --connect-timeout 10 --max-time 300 "$download_url" -o "$tmp_dir/$zip_name"

        install -d /usr/local/bin
        unzip -qo "$tmp_dir/$zip_name" -d "$tmp_dir"
        install -m 755 "$tmp_dir/xray" "$XRAY_BIN"
        rm -rf "$tmp_dir"
        trap - EXIT
    fi
    install -d /etc/xray

    # ---- Generate X25519 key pair for REALITY ----
    local key_output private_key public_key
    key_output=$("$XRAY_BIN" x25519)

    # Use $NF (last field) to handle varying output formats across Xray versions
    # Support both old ("Private key: / Public key:") and new ("PrivateKey: / Password:") formats
    private_key=$(echo "$key_output" | awk '/PrivateKey/{print $NF}')
    [[ -z "$private_key" ]] && private_key=$(echo "$key_output" | awk '/Private key:/{print $3}')

    public_key=$(echo "$key_output" | awk '/Password/{print $NF}')
    [[ -z "$public_key" ]] && public_key=$(echo "$key_output" | awk '/Public key:/{print $3}')

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        echo "Failed to generate X25519 keys. Raw output:" >&2
        echo "$key_output" >&2
        exit 1
    fi

    # Persist public key and server address for future client additions
    echo "$public_key" > /etc/xray/public.key
    echo "$server" > "$SERVER_ADDR_FILE"

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
    "servers": [$dns_json],
    "tag": "dns-internal"
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
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["dns-internal"], "outboundTag": "direct" },
      { "type": "field", "ip": $PRIVATE_IPS_JSON, "outboundTag": "block" }
    ]
  },
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "ForceIP" } },
    { "tag": "block", "protocol": "blackhole" }
  ]
}
EOF
    set_config_permissions

    # ---- Start Xray (validates the config first) and set up autostart ----
    restart_xray
    setup_autostart

    # ---- Display connection info ----
    show_connection_info "$uuid" "$server" "$public_key" "$short_id" "$sni"

    cat <<EOF

Xray-core VLESS + REALITY installation completed!

Configuration file : $CONFIG
Xray process       : running (PID $(xray_pid)), log: $XRAY_LOG
Fake SNI           : $sni
Connect to host    : $server
Public key         : $public_key (saved to /etc/xray/public.key)
Server address     : saved to $SERVER_ADDR_FILE
Short ID           : $short_id
UUID               : $uuid

Autostart          : $(autostart_status)
Make sure port 443 of the container is published.
EOF
}

# ==============================================================================
# Add a new client to the running server
# ==============================================================================

add_client() {
    ensure_jq

    local server
    server="$(get_server_address)"

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
    validate_config "$tmp" || { rm -f "$tmp"; exit 1; }
    mv "$tmp" "$CONFIG"

    set_config_permissions
    restart_xray

    # Build and display the connection URI
    local pbk sni
    pbk="$(cat /etc/xray/public.key 2>/dev/null || echo "")"
    sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // empty' "$CONFIG")"
    [[ -z "$sni" ]] && sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" | cut -d: -f1)"

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
        echo "Cannot remove the last client — use option 4 to remove Xray entirely."
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
    validate_config "${CONFIG}.tmp" || { rm -f "${CONFIG}.tmp"; exit 1; }
    mv "${CONFIG}.tmp" "$CONFIG"

    set_config_permissions
    restart_xray

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
    # Remove autostart first so a cron check can't start Xray again
    remove_autostart
    stop_xray

    echo ">>> Removing Xray binary, configuration, log and autostart..."
    rm -f "$XRAY_BIN"
    rm -rf /etc/xray
    rm -f "$XRAY_LOG"

    echo ""
    echo "Xray has been completely removed."
}

# ==============================================================================
# Management menu (shown when Xray is already installed)
# ==============================================================================

# Print a short summary of the process state and configuration
show_status() {
    local pid state version server clients sni
    pid="$(xray_pid)"
    if [[ -n "$pid" ]]; then state="running (PID $pid)"; else state="stopped"; fi
    version="$("$XRAY_BIN" version 2>/dev/null | awk 'NR==1{print $2}' || true)"
    server="$(head -n1 "$SERVER_ADDR_FILE" 2>/dev/null || true)"

    # Don't install jq just to show the menu — print "?" if it is missing
    clients="?"; sni="?"
    if command -v jq &>/dev/null; then
        clients="$(jq '.inbounds[0].settings.clients | length' "$CONFIG" 2>/dev/null || echo "?")"
        sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // "?"' "$CONFIG" 2>/dev/null || echo "?")"
    fi

    echo ""
    echo "   Service  : $state"
    echo "   Autostart: $(autostart_status)"
    echo "   Version  : ${version:-unknown}"
    echo "   Address  : ${server:-not saved}"
    echo "   SNI      : $sni"
    echo "   Clients  : $clients"
    echo "   Log      : $XRAY_LOG"
}

manage_menu() {
    echo ""
    echo "Xray VLESS+REALITY is already installed (Docker mode)."
    show_status
    echo ""
    echo "Select an option:"
    echo "   1) Add a new client"
    echo "   2) Remove an existing client"
    echo "   3) Start / restart Xray"
    echo "   4) Remove Xray"
    echo "   5) Exit"

    local option
    read -rp "Option [1-5]: " option
    case "$option" in
        1) add_client ;;
        2) remove_client ;;
        3) restart_xray ;;
        4) remove_xray ;;
        5) exit 0 ;;
        *) echo "Invalid option." >&2; exit 1 ;;
    esac
}

# ==============================================================================
# Entry point
# ==============================================================================

# This script must be executed as root
if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if is_xray_installed; then
    # Older installs had no autostart: add it if the container supports it
    if [[ "$(autostart_mechanism)" == "none" ]] && autostart_available; then
        setup_autostart
    fi
    offer_private_block
    manage_menu
else
    new_install
fi
