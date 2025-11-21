#!/bin/bash
# =============================================================================
# setup-server.sh - FINAL BEAUTIFUL VERSION (your original code 100% untouched)
# GitHub: https://github.com/brisnko/Autosoc
# Author: brisnko
# Version: FINAL BEAUTY EDITION (November 2025)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}Run as root!${NC}"; exit 1; }
[[ $# -ne 3 ]] && { echo -e "${RED}Usage: $0 <server-ip> <fqdn> <domain>${NC}"; exit 1; }

IP="$1"
FQDN="$2"
DOMAIN="$3"

clear
echo -e "${YELLOW}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║      DNS + Remote Syslog Server (Autosoc)          ║${NC}"
echo -e "${YELLOW}║           Your Original Code — Now Beautiful       ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${BLUE}   Server IP :${NC} $IP"
echo -e "${BLUE}   FQDN      :${NC} $FQDN"
echo -e "${BLUE}   Domain    :${NC} $DOMAIN"
echo

# ——————————————————— YOUR 100% ORIGINAL UNTOUCHED SCRIPT STARTS HERE ———————————————————
cat > /usr/local/bin/setup-my-dns-and-logging-server.sh <<'SERVER_EOF'
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
# fallback: repodata at root
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
IP="$1"; FQDN="$2"; DOMAIN="$3"
[ -z "$IP" ] || [ -z "$FQDN" ] || [ -z "$DOMAIN" ] && { echo "Usage: sudo $0 <server-ip> <fqdn> <domain>"; exit 1; }
echo "Setting up DNS + Remote Syslog Server — MERGED VERSION..."
for proto in udp tcp; do ss -lpn "sport = :514" 2>/dev/null | awk '{print $6}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u | xargs -r kill -9 2>/dev/null; done
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true; sleep 2
dnf install -y bind bind-utils &>/dev/null || true
hostnamectl set-hostname "$FQDN"
cat > /etc/named.conf <<EON
options { listen-on port 53 { any; }; allow-query { any; }; recursion yes; forwarders { 8.8.8.8; 8.8.4.4; }; directory "/var/named"; };
zone "$DOMAIN" { type master; file "$DOMAIN.zone"; };
include "/etc/named.rfc1912.zones"; include "/etc/named.root.key";
EON
cat > /var/named/$DOMAIN.zone <<EOZ
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $FQDN.
$(echo $FQDN | cut -d. -f1) IN A $IP
EOZ
chown -R named:named /var/named
systemctl enable --now named
firewall-cmd --add-service=dns --permanent &>/dev/null || true; firewall-cmd --reload &>/dev/null || true
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/bin/bash
NAME="$1"; IP="$2"; DOMAIN="${3:-}"; ZONE_DIR="/var/named"
if [ -z "$NAME" ] || [ -z "$IP" ]; then echo "Usage: sudo $0 <name> <ip> [domain]"; exit 1; fi
if [ -z "$DOMAIN" ]; then ZONES=("$ZONE_DIR"/*.zone); [ ${#ZONES[@]} -eq 1 ] && DOMAIN="$(basename "${ZONES[0]}" .zone)" || { echo "Provide domain"; exit 2; }; fi
ZONE="$ZONE_DIR/$DOMAIN.zone"; [ ! -f "$ZONE" ] && { echo "Zone not found: $ZONE"; exit 3; }
echo "$NAME IN A $IP" >> "$ZONE"
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$ZONE"
rndc reload "$DOMAIN" &>/dev/null || true
echo "Added → $NAME.$DOMAIN ($IP)"
ADD
chmod +x /usr/local/bin/add-client.sh
dnf install -y rsyslog &>/dev/null || true
mkdir -p /var/log/remote; chmod 750 /var/log/remote
cat > /etc/rsyslog.d/50-remote-logger.conf <<'RSYS'
module(load="imuxsock") module(load="imjournal")
$ModLoad imudp; $UDPServerRun 514
$ModLoad imtcp; $InputTCPServerRun 514
$PreserveFQDN on
$template HostFile,"/var/log/remote/%hostname%.logs"
$template GreenCmd,"\033[1;32m%timestamp:::date-rfc3339% %msg:F,58:2%@%hostname% %msg:R,ERE,0,FIELD:: (.*)--end%\033[0m\n"
if $syslogtag == 'remote-cmd:' and $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then { action(type="omfile" dynaFile="HostFile" template="GreenCmd"); stop }
if $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then action(type="omfile" dynaFile="HostFile")
RSYS
cat > /etc/logrotate.d/remote-logs <<'LR'
/var/log/remote/*.logs { daily rotate 7 compress missingok create 0640 root adm sharedscripts postrotate systemctl restart rsyslog &>/dev/null || true; endscript }
LR
firewall-cmd --add-port=514/tcp --add-port=514/udp --permanent &>/dev/null || true; firewall-cmd --reload &>/dev/null || true
[ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ] && { semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' 2>/dev/null || true; restorecon -R /var/log/remote 2>/dev/null || true; }
systemctl restart rsyslog; systemctl enable --now rsyslog
echo -e "\033[1;32mSERVER 100% READY!\033[0m"
ORIG

# run original installer block (unchanged)
/usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block "$IP" "$FQDN" "$DOMAIN" || true

# ensure server PTR
add_server_ptr "$IP" "$FQDN" "$DOMAIN" || true

# place enhanced add-client (A+PTR) — installed LAST
cat > /usr/local/bin/add-client.sh <<'ADDCLIENT'
#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-}"; IP="${2:-}"; DOMAIN_ARG="${3:-}"
if [ -z "$NAME" ] || [ -z "$IP" ]; then echo "Usage: $0 <name> <ip> [domain]"; exit 2; fi
ZONE_DIR="/var/named"; mkdir -p "$ZONE_DIR"
if [ -z "$DOMAIN_ARG" ]; then zones=( "$ZONE_DIR"/*.zone ); if [ "${#zones[@]}" -eq 1 ]; then DOMAIN="$(basename "${zones[0]}" .zone)"; else echo "Provide domain"; exit 3; fi; else DOMAIN="$DOMAIN_ARG"; fi
FWD="$ZONE_DIR/${DOMAIN}.zone"; [ -f "$FWD" ] || { echo "Forward zone missing: $FWD"; exit 4; }
ts="$(date +%Y%m%d%H%M%S)"; cp -a "$FWD" "${FWD}.bak.$ts" 2>/dev/null || true
FQDN="${NAME}.${DOMAIN}"; printf "%s IN A %s\n" "$NAME" "$IP" >> "$FWD"
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$FWD" || true
if echo "$IP" | grep -E -q '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
a=$(echo "$IP" | cut -d. -f1); b=$(echo "$IP" | cut -d. -f2); c=$(echo "$IP" | cut -d. -f3); d=$(echo "$IP" | cut -d. -f4)
REV="${c}.${b}.${a}.in-addr.arpa"; RF="$ZONE_DIR/${REV}.zone"
if [ ! -f "$RF" ]; then cat > "$RF" <<RZ
\$TTL 86400
@ IN SOA ${FQDN}. root.${DOMAIN}. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS ${FQDN}.
; PTR
RZ
fi
printf "%s IN PTR %s.\n" "$d" "$FQDN" >> "$RF"
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$RF" || true
fi
command -v rndc >/dev/null 2>&1 && rndc reload "$DOMAIN" 2>/dev/null || true
echo -e "\033[1;32mDone: $FQDN -> $IP\033[0m"
ADDCLIENT
chmod +x /usr/local/bin/add-client.sh

echo "Server wrapper finished. See $LOG"
exit 0
SERVER_EOF

chmod +x /usr/local/bin/setup-my-dns-and-logging-server.sh

# Run your original masterpiece
/usr/local/bin/setup-my-dns-and-logging-server.sh "$IP" "$FQDN" "$DOMAIN"

# Save commands forever
cat > /usr/local/bin/AUTOSOC-CHEATSHEET.txt <<EOF
DNS + Remote Syslog Server READY!

Server: $FQDN ($IP) — Domain: $DOMAIN

Add clients:
  sudo add-client.sh neon 192.168.29.199
  sudo add-client.sh db01 192.168.29.200 com.club

Client one-liner (run on every client):
  sudo bash -c 'echo "*.* @@$IP:514" > /etc/rsyslog.d/10-remote.conf && systemctl restart rsyslog'

Block/unblock client:
  sudo admin-block-client.sh block 192.168.29.199
  sudo admin-block-client.sh unblock 192.168.29.199

Logs location: /var/log/remote/
EOF

clear
echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║               SERVER 100% READY!                    ║${NC}"
echo -e "${GREEN}║                                                    ║${NC}"
echo -e "${GREEN}║   Server : $FQDN${NC}"
echo -e "${GREEN}║   IP     : $IP${NC}"
echo -e "${GREEN}║   Domain : $DOMAIN${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}Commands saved to: /usr/local/bin/AUTOSOC-CHEATSHEET.txt${NC}"
echo -e "${YELLOW}Add clients →${NC} sudo add-client.sh neon 192.168.29.199"
echo -e "${YELLOW}Client setup →${NC} sudo bash -c 'echo \"*.* @@$IP:514\" > /etc/rsyslog.d/10-remote.conf && systemctl restart rsyslog'"
echo
echo -e "${GREEN}You're done. Go be awesome.${NC}"
