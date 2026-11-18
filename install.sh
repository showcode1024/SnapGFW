#!/usr/bin/env bash
# natgfw installer / upgrader / uninstaller for KVM hosts (Debian / Ubuntu / RHEL family)
#
# Examples:
#   bash install.sh --from-bin ./natgfw-linux-amd64 --disable-rfw --with-geo
#   bash install.sh --listen 127.0.0.1:9090 --bridge rmbr0 --low-mem
#   bash install.sh --uninstall [--purge]
set -euo pipefail

BIN="/usr/local/bin/natgfw"
CFG_DIR="/etc/natgfw"
CFG_FILE="${CFG_DIR}/config.json"
DATA_DIR="/var/lib/natgfw"
SERVICE_FILE="/etc/systemd/system/natgfw.service"

LISTEN="0.0.0.0:9090"
BRIDGE="rmbr0"
LOW_MEM=0
DISABLE_RFW=0
WITH_GEO=0
FROM_BIN=""
RELEASE_URL="${NATGFW_RELEASE_URL:-https://github.com/showcode1024/natgfw/releases/latest/download}"
UNINSTALL=0
PURGE=0

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --from-bin PATH       Install using a prebuilt local binary (recommended for custom builds)
  --release-url URL     Download natgfw-linux-<arch> and SHA256SUMS from URL
  --listen ADDR         Web panel listen address (default: 0.0.0.0:9090)
  --bridge IFACE        Container bridge interface to protect (default: rmbr0)
  --low-mem             Enable low-memory tuning (GOMEMLIMIT=64MiB)
  --disable-rfw         Stop and disable runman's built-in rfw.service to avoid overlap
  --with-geo            Download latest geosite.dat and geoip.dat into /var/lib/natgfw/
  --uninstall           Stop service, clean nft table and remove binary/unit (keeps data)
  --purge               With --uninstall: also delete /etc/natgfw and /var/lib/natgfw
  -h, --help            Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-bin)    FROM_BIN="${2:?}"; shift 2 ;;
    --release-url) RELEASE_URL="${2:?}"; shift 2 ;;
    --listen)      LISTEN="${2:?}"; shift 2 ;;
    --bridge)      BRIDGE="${2:?}"; shift 2 ;;
    --low-mem)     LOW_MEM=1; shift ;;
    --disable-rfw) DISABLE_RFW=1; shift ;;
    --with-geo)    WITH_GEO=1; shift ;;
    --uninstall)   UNINSTALL=1; shift ;;
    --purge)       PURGE=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             usage >&2; die "unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "must run as root"
[[ -d /run/systemd/system ]] || die "systemd is required"

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)             die "unsupported architecture: $(uname -m)" ;;
esac

uninstall() {
  log "stopping natgfw service"
  systemctl disable --now natgfw.service 2>/dev/null || true
  nft delete table inet natgfw 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$BIN"
  systemctl daemon-reload
  if [[ "$PURGE" -eq 1 ]]; then
    log "purging $CFG_DIR and $DATA_DIR"
    rm -rf "$CFG_DIR" "$DATA_DIR"
  fi
  log "natgfw uninstalled"
}

if [[ "$UNINSTALL" -eq 1 ]]; then
  uninstall
  exit 0
fi

# 1. Install minimal host dependencies (nftables + conntrack CLI + curl)
log "checking system dependencies"
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -qq
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq --no-install-recommends nftables conntrack curl ca-certificates
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q nftables conntrack-tools curl ca-certificates
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q nftables conntrack-tools curl ca-certificates
fi

# 2. Verify kernel Netfilter capabilities (avoids silent failure on restricted containers)
log "checking kernel netfilter capabilities"
for mod in nf_tables nf_conntrack nfnetlink_queue; do
  modprobe "$mod" 2>/dev/null || true
done
nft list tables >/dev/null 2>&1 || die "nftables is unavailable in this kernel/environment"
[[ -e /proc/net/netfilter/nfnetlink_queue || -d /proc/sys/net/netfilter ]] || warn "netfilter sysfs entries missing; verify nfnetlink_queue support"

if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
  warn "bridge interface '$BRIDGE' not found yet (normal if runman-agent has not created instances yet)"
fi

# 3. Install or atomically upgrade binary
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [[ -n "$FROM_BIN" ]]; then
  [[ -f "$FROM_BIN" ]] || die "binary not found: $FROM_BIN"
  cp "$FROM_BIN" "$WORK/natgfw"
elif [[ -n "$RELEASE_URL" ]]; then
  asset="natgfw-linux-${ARCH}"
  log "downloading $asset"
  curl -fsSL --retry 3 -o "$WORK/SHA256SUMS" "${RELEASE_URL}/SHA256SUMS" || die "failed downloading SHA256SUMS"
  curl -fsSL --retry 3 -o "$WORK/natgfw" "${RELEASE_URL}/${asset}" || die "failed downloading ${asset}"
  (cd "$WORK" && grep -E "  \*?${asset}\$" SHA256SUMS | awk '{print $1 "  natgfw"}' | sha256sum -c --quiet -) \
    || die "SHA256 verification failed for ${asset}"
else
  die "provide --from-bin <path> or --release-url <url> (or build locally with GOOS=linux GOARCH=${ARCH} go build ./cmd/natgfw)"
fi

chmod 755 "$WORK/natgfw"
"$WORK/natgfw" version >/dev/null || die "downloaded binary is not executable on this host"
install -m 755 "$WORK/natgfw" "${BIN}.new"
mv -f "${BIN}.new" "$BIN"
log "installed $($BIN version)"

# 4. Initialize config without overwriting existing customizations
install -d -m 700 "$CFG_DIR" "$DATA_DIR"
FRESH=0
PASSWORD=""
if [[ ! -f "$CFG_FILE" ]]; then
  FRESH=1
  LOW_MEM_JSON="false"
  [[ "$LOW_MEM" -eq 1 ]] && LOW_MEM_JSON="true"
  cat > "$CFG_FILE" <<EOF
{
  "listen_addr": "${LISTEN}",
  "admin_user": "admin",
  "data_dir": "${DATA_DIR}",
  "runman_data_dir": "/var/lib/runman-agent",
  "bridge_iface": "${BRIDGE}",
  "nft_table": "natgfw",
  "queue_base": 200,
  "conn_mark_accept": 2001,
  "conn_mark_drop": 2002,
  "low_mem_mode": ${LOW_MEM_JSON}
}
EOF
  chmod 600 "$CFG_FILE"
  PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true)
  printf '%s\n' "$PASSWORD" | "$BIN" set-password -config "$CFG_FILE" >/dev/null
else
  log "keeping existing $CFG_FILE"
fi

# 5. Optional GeoSite & GeoIP download
if [[ "$WITH_GEO" -eq 1 ]]; then
  log "downloading geosite.dat and geoip.dat"
  curl -fsSL --retry 3 -o "${DATA_DIR}/geosite.dat.tmp" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
    && mv -f "${DATA_DIR}/geosite.dat.tmp" "${DATA_DIR}/geosite.dat" || warn "failed downloading geosite.dat (builtin CN fallback active)"
  curl -fsSL --retry 3 -o "${DATA_DIR}/geoip.dat.tmp" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
    && mv -f "${DATA_DIR}/geoip.dat.tmp" "${DATA_DIR}/geoip.dat" || warn "failed downloading geoip.dat"
fi

# 6. Optionally disable runman's built-in rfw to avoid duplicate filtering
if [[ "$DISABLE_RFW" -eq 1 ]] && systemctl list-unit-files | grep -q '^rfw\.service'; then
  log "disabling built-in rfw.service"
  systemctl disable --now rfw.service 2>/dev/null || true
fi

# 7. Write systemd service with bounded memory limits
GOMEM="128MiB"
MEMMAX="256M"
if [[ "$LOW_MEM" -eq 1 ]]; then
  GOMEM="64MiB"
  MEMMAX="128M"
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=natgfw NAT DPI Firewall & Panel
After=network-online.target nftables.service runman-agent.service
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=GOMEMLIMIT=${GOMEM}
ExecStart=${BIN} serve -config ${CFG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
ExecStopPost=-/usr/sbin/nft delete table inet natgfw
Restart=always
RestartSec=3s
LimitNOFILE=1048576
MemoryMax=${MEMMAX}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now natgfw.service
sleep 1
systemctl is-active --quiet natgfw.service || die "natgfw failed to start; inspect: journalctl -u natgfw -e"

echo
log "natgfw is active"
echo "  panel:  http://${LISTEN}"
if [[ "$FRESH" -eq 1 ]]; then
  echo "  login:  admin / ${PASSWORD}"
fi
echo "  logs:   journalctl -u natgfw -f"
echo "  nft:    nft list table inet natgfw"
