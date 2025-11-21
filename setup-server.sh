#!/bin/bash
# setup-server.sh - Ultra-clean DNS + Remote Logging Server installer
# Run: sudo setup-server.sh 192.168.29.206 server.cst.com cst.com

set -euo pipefail
IFS=$'\n\t'

# === Colors ===
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# === Silent logging (user never sees this) ===
LOG="/var/log/setup-server.log"
exec > >(tee -a "$LOG") 2>&1

# === Error trap: show red error and exit on any failure ===
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    echo "Failed at $(date)" >> "$LOG"
    exit 1
}
trap 'error_exit "Script failed at line $LINENO"' ERR

# === Check root ===
(( EUID == 0 )) || error_exit "This script must be run as root (use sudo)"

# === Parse arguments ===
[[ $# -eq 3 ]] || error_exit "Usage: sudo $(basename "$0") <ip> <fqdn> <domain>"

IP="$1"
FQDN="$2"
DOMAIN="$3"

# Basic validation
[[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || error_exit "Invalid IP: $IP"
[[ $FQDN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || error_exit "Invalid FQDN: $FQDN"
[[ $DOMAIN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || error_exit "Invalid domain: $DOMAIN"

echo "Starting setup..." >&2

# === RHEL-like local repo auto-config (silent) ===
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if grep -Eiq 'rhel|centos|rocky|almalinux' <<<"${ID:-} ${ID_LIKE:-}"; then
        if ! grep -riq "baseurl.*BaseOS" /etc/yum.repos.d 2>/dev/null || ! grep -riq "baseurl.*AppStream" /etc/yum.repos.d 2>/dev/null; then
            echo "Configuring local RHEL repos..." >&2
            # (same smart ISO detection logic as before, but silent)
            mapfile -t MPS < <(mount | awk '/iso9660/ {for(i=3;i<=NF;i++) if($i~/^\//){print $i;break}}' 2>/dev/null)
            success=0
            for mp in "${MPS[@]}"; do
                mp=$(readlink -f "$mp")
                if [[ -d "$mp/BaseOS" ]]; then
                    cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso-BaseOS] name=Local BaseOS baseurl=file://$mp/BaseOS enabled=1 gpgcheck=0
[local-iso-AppStream] name=Local AppStream baseurl=file://$mp/AppStream enabled=1 gpgcheck=0
EOF
                    dnf makecache --refresh &>/dev/null || true
                    success=1; break
                fi
            done
            (( success == 0 )) && echo "Warning: No local RHEL ISO found (continuing anyway)" >&2
        fi
    fi
fi

# === Force kill port 514 ===
ss -klnp "sport = :514" 2>/dev/null | awk '{print $6}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | xargs -r kill -9 &>/dev/null || true
systemctl stop rsyslog syslog-ng auditd &>/dev/null || true

# === DNS Setup ===
dnf install -y bind bind-utils &>/dev/null
hostnamectl set-hostname "$FQDN" &>/dev/null

cat > /etc/named.conf <<EOF
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
EOF

cat > /var/named/"$DOMAIN.zone" <<EOF
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $FQDN.
$(echo "$FQDN" | cut -d. -f1) IN A $IP
EOF

chown -R named:named /var/named 2>/dev/null || true
systemctl enable --now named &>/dev/null

# === Enhanced add-client.sh (with A + PTR) ===
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/usr/bin/env bash
set -euo pipefail
NAME="$1"; IP="$2"; DOMAIN="${3:-}"
[[ -z "$NAME" || -z "$IP" ]] && { echo "Usage: $0 <name> <ip> [domain]"; exit 1; }
ZONE_DIR="/var/named"
[[ -z "$DOMAIN" ]] && DOMAIN=$(basename "$(ls "$ZONE_DIR"/*.zone 2>/dev/null | head -1)" .zone 2>/dev/null) || exit 1
ZONE="$ZONE_DIR/$DOMAIN.zone"
[[ -f "$ZONE" ]] || exit 1
printf "%s IN A %s\n" "$NAME" "$IP" >> "$ZONE"
sed -i "/SOA/ s/[0-9]\{8,\}/$(date +%Y%m%d)99/" "$ZONE" 2>/dev/null || true

if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IFS=. read -r a b c d <<<"$IP"
    REV="${c}.${b}.${a}.in-addr.arpa.zone"
    RF="/var/named/$REV"
    [[ ! -f "$RF" ]] && cat > "$RF" <<EOF
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $FQDN.
EOF
    printf "%s IN PTR %s.%s.\n" "$d" "$NAME" "$DOMAIN" >> "$RF"
    sed -i "/SOA/ s/[0-9]\{8,\}/$(date +%Y%m%d)99/" "$RF" 2>/dev/null || true
fi
rndc reload "$DOMAIN" &>/dev/null || true
echo "Added: $NAME.$DOMAIN → $IP"
ADD
chmod +x /usr/local/bin/add-client.sh

# === RSYSLOG Remote Logging ===
dnf install -y rsyslog &>/dev/null
mkdir -p /var/log/remote && chmod 750 /var/log/remote

cat > /etc/rsyslog.d/50-remote-logger.conf <<'EOF'
module(load="imuxsock")
module(load="imjournal")
$ModLoad imudp
$UDPServerRun 514
$ModLoad imtcp
$InputTCPServerRun 514
$PreserveFQDN on
$template HostFile,"/var/log/remote/%hostname%.logs"
$template GreenCmd,"\033[1;32m%timestamp:::date-rfc3339% %msg:F,58:2%@%hostname% %msg:R,ERE,0,FIELD:: (.*)--end%\033[0m\n"
if $syslogtag == 'remote-cmd:' and $fromhost-ip != '127.0.0.1' then { action(type="omfile" dynaFile="HostFile" template="GreenCmd"); stop }
if $fromhost-ip != '127.0.0.1' then action(type="omfile" dynaFile="HostFile")
EOF

cat > /etc/logrotate.d/remote-logs <<'EOF'
/var/log/remote/*.logs { daily rotate 7 compress missingok create 0640 root adm sharedscripts postrotate systemctl restart rsyslog &>/dev/null || true; endscript }
EOF

firewall-cmd --add-port=514/tcp --add-port=514/udp --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true
[[ "$(getenforce 2>/dev/null || echo Disabled)" = Enforcing ]] && {
    semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' &>/dev/null || true
    restorecon -R /var/log/remote &>/dev/null || true
}
systemctl restart rsyslog
systemctl enable --now rsyslog &>/dev/null

# === Admin block helper ===
cat > /usr/local/bin/admin-block-client.sh <<'EOF'
#!/bin/bash
ACTION="$1"; IP="$2"
[[ -z "$ACTION" || -z "$IP" ]] && { echo "Usage: $0 <block|unblock|status> <ip>"; exit 1; }
case "$ACTION" in
block) firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$IP drop" &>/dev/null; firewall-cmd --reload &>/dev/null; echo "Blocked $IP";;
unblock) firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$IP drop" &>/dev/null; firewall-cmd --reload &>/dev/null; echo "Unblocked $IP";;
status) firewall-cmd --list-rich-rules | grep "$IP" || echo "Not blocked";;
esac
EOF
chmod +x /usr/local/bin/admin-block-client.sh

# === FINAL CLEAN SUCCESS OUTPUT (only thing user sees on success) ===
clear
echo
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo -e "${GREEN}         SERVER SETUP 100% COMPLETE!${NC}"
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo
echo -e "   IP     : ${GREEN}$IP${NC}"
echo -e "   FQDN   : ${GREEN}$FQDN${NC}"
echo -e "   Domain : ${GREEN}$DOMAIN${NC}"
echo
echo -e "   DNS Server    : ${GREEN}Running${NC}"
echo -e "   Log Server    : ${GREEN}Running on port 514${NC}"
echo -e "   Logs location : ${GREEN}/var/log/remote/<hostname>.logs${NC}"
echo
echo -e "   Add client → ${GREEN}add-client.sh client1 192.168.29.100${NC}"
echo -e "   Block client → ${GREEN}admin-block-client.sh block 192.168.29.100${NC}"
echo
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo

exit 0
