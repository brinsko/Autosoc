#!/bin/bash
# =============================================================================
# setup-server.sh - One-command DNS + Remote Syslog Server (RHEL/CentOS/Rocky/Alma)
# GitHub: https://github.com/brisnko/Autosoc
# Author: brisnko
# Version: 3.0 - FINAL (November 2025) - 100% original code preserved
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

log()     { echo -e "${BLUE}[*] $*${NC}"; }
success() { echo -e "${GREEN}Success: $*${NC}"; }
error()   { echo -e "${RED}ERROR: $*${NC}" >&2; }
die()     { error "$1"; exit 1; }

TARGET="/usr/local/bin/setup-my-dns-and-logging-server.sh"
ADDCLIENT="/usr/local/bin/add-client.sh"

# ───── Install your EXACT original script (100% untouched) ─────
if [[ ! -f "$TARGET" || "$1" == "--force-reinstall" ]]; then
    log "Deploying your full original DNS + Logging server engine..."
    cat > "$TARGET" <<'YOUR_ORIGINAL_SCRIPT_EXACTLY'
#!/bin/bash
# setup-my-dns-and-logging-server.sh
# Wrapper (preserves your original installer) + mandatory RHEL local-repo config (BaseOS+AppStream) when RHEL-like detected.
set -euo pipefail
IFS=$'\n\t'

LOG=/var/log/setup-my-dns-and-logging-server.wrapper.log
exec > >(tee -a "$LOG") 2>&1

usage(){ cat <<USG
Usage: sudo $0 [--non-interactive] [--force] <server-ip> <fqdn> <domain>
Example: sudo $0 192.168.29.206 server.cst.com cst.com
USG
exit 1; }

# parse basic flags
NONINTER=0; FORCE=0; ARGS=()
while [ $# -gt 0 ]; do
case "$1" in
--non-interactive) NONINTER=1; shift ;;
--force) FORCE=1; shift ;;
--help) usage ;;
--*) echo "Unknown flag: $1"; usage ;;
*) ARGS+=("$1"); shift ;;
esac
done
[ ${#ARGS[@]} -eq 3 ] || usage
IP="${ARGS[0]}"; FQDN="${ARGS[1]}"; DOMAIN="${ARGS[2]}"

prompt_yes_no(){ local p="$1"; local d="${2:-Y}"; if [ "$NONINTER" -eq 1 ]; then [ "$d" = "Y" ] && return 0 || return 1; fi
while true; do read -r -p "$p [Y/n]: " a; a="${a:-$d}"; case "$a" in [Yy]*) return 0;; [Nn]*) return 1;; *) echo "Y or N";; esac; done; }

echo "Wrapper start — log: $LOG"

# detect rhel-like
IS_RHEL=0
if [ -f /etc/os-release ]; then
. /etc/os-release
idstr="$(printf "%s %s" "${ID:-}" "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
if echo "$idstr" | grep -E -q 'rhel|redhat|centos|rocky|almalinux|centosstream'; then IS_RHEL=1; fi
fi
echo "RHEL-like: $IS_RHEL"

# helper: create repo files from a mounted ISO mountpoint (checks BaseOS/AppStream)
create_repos_from_mount() {
mp="$1"
created=0
if [ -d "$mp/BaseOS" ]; then
cat > /etc/yum.repos.d/local-iso-BaseOS.repo <<EOF
[local-iso-BaseOS]
name=Local ISO BaseOS
baseurl=file://$mp/BaseOS
enabled=1
gpgcheck=0
EOF
created=1
echo "Created local-iso-BaseOS -> $mp/BaseOS"
fi
if [ -d "$mp/AppStream" ]; then
cat > /etc/yum.repos.d/local-iso-AppStream.repo <<EOF
[local-iso-AppStream]
name=Local ISO AppStream
baseurl=file://$mp/AppStream
enabled=1
gpgcheck=0
EOF
created=1
echo "Created local-iso-AppStream -> $mp/AppStream"
fi
if [ $created -eq 0 ] && [ -d "$mp/repodata" ]; then
cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso]
name=Local ISO
baseurl=file://$mp
enabled=1
gpgcheck=0
EOF
created=1
echo "Created fallback local-iso -> $mp"
fi
if [ $created -eq 1 ]; then
if command -v dnf >/dev/null 2>&1; then dnf makecache --refresh || true; elif command -v yum >/dev/null 2>&1; then yum makecache || true; fi
return 0
fi
return 2
}

# On RHEL-like: ensure BaseOS+AppStream exist (try mounted ISOs first)
if [ "$IS_RHEL" -eq 1 ]; then
have_base=0; have_app=0
if grep -riq "baseurl.*BaseOS" /etc/yum.repos.d 2>/dev/null; then have_base=1; fi
if grep -riq "baseurl.*AppStream" /etc/yum.repos.d 2>/dev/null; then have_app=1; fi

if [ $have_base -eq 1 ] && [ $have_app -eq 1 ]; then
echo "BaseOS and AppStream already present."
else
echo "BaseOS/AppStream not found — attempting to configure from mounted ISO(s) (mandatory)."
mapfile -t MPS < <(mount | awk '/iso9660/ { for(i=3;i<=NF;i++){ if($i ~ /^\//){ print $i; break } } }' | sort -u)
success=0
for mp in "${MPS[@]}"; do
mp=$(readlink -f "$mp")
echo "Checking mounted ISO at $mp ..."
if create_repos_from_mount "$mp"; then success=1; break; fi
done
if [ $success -eq 0 ]; then
echo "No mounted ISO provided usable repos — scanning for ISO files (shallow) ..."
CAND=""
for p in /run/media /media /root /home /mnt /var/tmp /tmp; do
[ -d "$p" ] || continue
for f in "$p"/*.iso "$p"/*/*.iso; do [ -f "$f" ] && CAND="$CAND $f"; done
done
if [ -z "$CAND" ]; then
while IFS= read -r f; do CAND="$CAND $f"; done < <(find / -maxdepth 4 -type f -iname '*.iso' 2>/dev/null || true)
fi
if [ -z "$CAND" ]; then
echo "ERROR: No RHEL-style ISO found on system and no mounted ISO provided. Cannot continue on RHEL-like host."
echo "Place a RHEL8-style DVD ISO on the system (e.g. /root/RHEL-8-dvd.iso) or mount the ISO and re-run."
exit 1
fi
MBASE="/mnt/local-iso"
mkdir -p "$MBASE"
idx=0
for iso in $CAND; do
idx=$((idx+1)); mp="$MBASE/$idx"; mkdir -p "$mp"
if mount -o loop,ro "$iso" "$mp" 2>/dev/null; then
echo "Mounted $iso -> $mp"
if create_repos_from_mount "$mp"; then success=1; break; else umount "$mp" 2>/dev/null || true; fi
else
rm -rf "$mp" 2>/dev/null || true
fi
done
if [ $success -eq 0 ]; then
echo "ERROR: Could not configure BaseOS/AppStream from discovered ISOs."
exit 1
fi
fi
fi
fi

# helper: add server PTR if needed
add_server_ptr() {
local ip="$1" fqdn="$2" domain="$3"
IFS='.' read -r a b c d <<<"$ip"
rev="${c}.${b}.${a}.in-addr.arpa"
revfile="/var/named/${rev}.zone"
mkdir -p /var/named
if [ ! -f "$revfile" ]; then
cat > "$revfile" <<RZ
\$TTL 86400
@ IN SOA ${fqdn}. root.${domain}. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS ${fqdn}.
; PTR records
RZ
chown named:named "$revfile" 2>/dev/null || true
fi
last="$d"
if ! grep -qE "^[[:space:]]*${last}[[:space:]]+IN[[:space:]]+PTR" "$revfile" 2>/dev/null; then
printf "%s IN PTR %s.\n" "$last" "$fqdn" >> "$revfile"
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$revfile" || true
echo "Added PTR $ip -> $fqdn in $revfile"
else
echo "Server PTR already present"
fi
}

# Preserve original server installer block verbatim (for audit) and make executable
cat > /usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block <<'ORIG' && chmod +x /usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block
#!/bin/bash
IP="$1"
FQDN="$2"
DOMAIN="$3"

[ -z "$IP" ] || [ -z "$FQDN" ] || [ -z "$DOMAIN" ] && {
echo "Usage: sudo $0 <server-ip> <fqdn> <domain>"
echo "Example: sudo $0 192.168.29.206 server.cst.com cst.com"
exit 1
}

echo "Setting up DNS + Remote Syslog Server — MERGED VERSION (hostname logs + green + zero noise + admin-block)..."

# === FORCE TAKE PORT 514 ===
echo "Force-killing anything using port 514..."
for proto in udp tcp; do
ss -lpn "sport = :514" 2>/dev/null | awk '{print $6}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u | xargs -r kill -9 2>/dev/null
done
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true
sleep 2

# === DNS ===
dnf install -y bind bind-utils &>/dev/null || true
hostnamectl set-hostname "$FQDN"

cat > /etc/named.conf <<EON
options {
listen-on port 53 { any; };
allow-query { any; };
recursion yes;
forwarders { 8.8.8.8; 8.8.4.4; };
directory "/var/named";
};
zone "$DOMAIN" { type master; file "$DOMAIN.zone"; };
include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
EON

cat > /var/named/$DOMAIN.zone <<EOZ
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $FQDN.
$(echo $FQDN | cut -d. -f1) IN A $IP
EOZ

chown -R named:named /var/named
systemctl enable --now named
firewall-cmd --add-service=dns --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

# === FINAL RSYSLOG CONFIG ===
dnf install -y rsyslog &>/dev/null || true
mkdir -p /var/log/remote
chmod 750 /var/log/remote

cat > /etc/rsyslog.d/50-remote-logger.conf <<'RSYS'
module(load="imuxsock")
module(load="imjournal")

$ModLoad imudp
$UDPServerRun 514
$ModLoad imtcp
$InputTCPServerRun 514

$PreserveFQDN on

$template HostFile,"/var/log/remote/%hostname%.logs"
$template GreenCmd,"\033[1;32m%timestamp:::date-rfc3339% %msg:F,58:2%@%hostname% %msg:R,ERE,0,FIELD:: (.*)--end%\033[0m\n"

if $syslogtag == 'remote-cmd:' and $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then {
action(type="omfile" dynaFile="HostFile" template="GreenCmd")
stop
}

if $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then {
action(type="omfile" dynaFile="HostFile")
}
RSYS

cat > /etc/logrotate.d/remote-logs <<'LR'
/var/log/remote/*.logs {
daily
rotate 7
compress
missingok
create 0640 root adm
sharedscripts
postrotate
systemctl restart rsyslog &>/dev/null || true
endscript
}
LR

firewall-cmd --add-port=514/tcp --add-port=514/udp --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

[ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ] && {
semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' 2>/dev/null || true
restorecon -R /var/log/remote 2>/dev/null || true
}

systemctl restart rsyslog
systemctl enable --now rsyslog

# === ADMIN BLOCK HELPER ===
cat > /usr/local/bin/admin-block-client.sh <<'AB'
#!/usr/bin/env bash
ACTION="$1"; IP="$2"; DROP_MARKER_DIR="/var/lib/admin-block-client"; mkdir -p "$DROP_MARKER_DIR"
if [ -z "$ACTION" ] || [ -z "$IP" ]; then echo "Usage: sudo $0 <block|unblock|status> <client-ip>"; exit 2; fi
case "$ACTION" in
block)
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$IP' drop" >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true
else iptables -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 || iptables -I INPUT -s "$IP" -j DROP 2>/dev/null || true; fi
touch "$DROP_MARKER_DIR/$IP.blocked"; echo "Blocked $IP";;
unblock)
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$IP' drop" >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true
else iptables -D INPUT -s "$IP" -j DROP 2>/dev/null || true; fi
rm -f "$DROP_MARKER_DIR/$IP.blocked" 2>/dev/null || true; echo "Unblocked $IP";;
status)
[ -f "$DROP_MARKER_DIR/$IP.blocked" ] && echo "$IP is marked blocked" || echo "No marker for $IP"
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --list-rich-rules | grep "$IP" || true; else iptables -S | grep "$IP" || true; fi;;
*) echo "Unknown action"; exit 3;;
esac
AB
chmod +x /usr/local/bin/admin-block-client.sh
ORIG

# run original installer block
/usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block "$IP" "$FQDN" "$DOMAIN" || true

# ensure server PTR
add_server_ptr "$IP" "$FQDN" "$DOMAIN" || true

# final beautiful banner
echo
echo -e "\033[1;32m╔══════════════════════════════════════════╗\033[0m"
echo -e "\033[1;32m║          SERVER SETUP COMPLETE!          ║\033[0m"
echo -e "\033[1;32m║  Server ready: $FQDN\033[0m"
echo -e "\033[1;32m║  IP:           $IP\033[0m"
echo -e "\033[1;32m║  Domain:       $DOMAIN\033[0m"
echo -e "\033[1;32m╚══════════════════════════════════════════╝\033[0m"
echo
echo "Client one-liner (run on every client):"
echo "sudo bash -c 'echo \"*.* @@$IP:514\" > /etc/rsyslog.d/10-remote.conf && systemctl restart rsyslog'"
echo
exit 0
YOUR_ORIGINAL_SCRIPT_EXACTLY

    chmod +x "$TARGET"
    success "Your full original engine installed → $TARGET"
fi

# ───── Run it ─────
clear
echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║    DNS + Remote Syslog Server Setup      ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo

[[ $# -ne 3 ]] && die "Usage: sudo $(basename "$0") <server-ip> <fqdn> <domain>"

log "Server IP : $1"
log "FQDN      : $2"
log "Domain    : $3"
echo

exec sudo "$TARGET" "$@"
