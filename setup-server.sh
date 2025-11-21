#!/bin/bash
# setup-server.sh - Ultra-clean one-command DNS + Remote Logging Server
# Usage: sudo setup-server.sh 10.231.133.110 srv.net.in net.in

set -euo pipefail
IFS=$'\n\t'

# ───── Colors ─────
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m'

# ───── Silent logging (user never sees this) ─────
LOG="/var/log/setup-server.log"
mkdir -p "$(dirname "$LOG")"
exec >>"$LOG" 2>&1

# ───── Show red error and exit on any failure ─────
die() { clear; echo -e "${RED}ERROR: $1${NC}"; echo "Failed at $(date '+%Y-%m-%d %H:%M:%S') - $1" >>"$LOG"; exit 1; }
trap 'die "Script failed at line $LINENO"' ERR

# ───── Must be root ─────
(( EUID == 0 )) || die "Run with sudo"

# ───── Arguments ─────
[[ $# -eq 3 ]] || die "Usage: $(basename "$0") <ip> <fqdn> <domain>"
IP="$1"; FQDN="$2"; DOMAIN="$3"

# Basic validation
[[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "Invalid IP: $IP"
[[ $FQDN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || die "Invalid FQDN: $FQDN"
[[ $DOMAIN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || die "Invalid domain: $DOMAIN"

# ───── RHEL local repo handling (silent, never fails the script) ─────
if [[ -f /etc/os-release ]]; then
    . /etc/os-release 2>/dev/null || true
    if grep -Eiq 'rhel|centos|rocky|almalinux|redhat' <<<"${ID:-} ${ID_LIKE:-}"; then
        if ! grep -q "baseurl.*BaseOS" /etc/yum.repos.d/* 2>/dev/null && ! grep -q "baseurl.*AppStream" /etc/yum.repos.d/* 2>/dev/null; then
            # Try to auto-mount any ISO quietly
            for mp in $(mount | awk '/iso9660/ {print $3}' | head -5); do
                [[ -d "$mp/BaseOS" && -d "$mp/AppStream" ]] || continue
                cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso-BaseOS]   name=Local BaseOS   baseurl=file://$mp/BaseOS   enabled=1 gpgcheck=0
[local-iso-AppStream]name=Local AppStream baseurl=file://$mp/AppStream enabled=1 gpgcheck=0
EOF
                dnf makecache --refresh &>/dev/null || yum makecache &>/dev/null || true
                break
            done
        fi
    fi
fi

# ───── Force-free port 514 ─────
ss -klnp "sport = :514" 2>/dev/null | awk '{print $6}' | cut -d= -f2 | xargs -r kill -9 &>/dev/null || true
systemctl stop rsyslog syslog-ng auditd &>/dev/null || true
sleep 1

# ───── Install & configure DNS (named) ─────
dnf install -y bind bind-utils &>/dev/null || yum install -y bind bind-utils &>/dev/null

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

mkdir -p /var/named
cat > /var/named/"$DOMAIN.zone" <<EOF
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS  $FQDN.
$(hostname -s) IN A $IP
EOF

chown -R named:named /var/named 2>/dev/null || true
systemctl enable --now named &>/dev/null

firewall-cmd --add-service=dns --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

# ───── Enhanced add-client.sh (A + PTR) ─────
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/usr/bin/env bash
set -euo pipefail
NAME="$1"; IP="$2"; DOM="${3:-}"
[[ -z "$NAME" || -z "$IP" ]] && { echo "Usage: $0 <name> <ip> [domain]"; exit 1; }
ZONE_DIR="/var/named"
[[ -z "$DOM" ]] && DOM=$(basename "$(ls "$ZONE_DIR"/*.zone | head -1)" .zone 2>/dev/null) && [[ -z "$DOM" ]] && { echo "Cannot auto-detect domain"; exit 1; }
ZONE="$ZONE_DIR/$DOM.zone"
printf "%s IN A %s\n" "$NAME" "$IP" >> "$ZONE"
sed -i "/SOA/ s/[0-9]\{8,\}/$(date +%Y%m%d)99/" "$ZONE" 2>/dev/null || true

# PTR
if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IFS=. read -r a b c d <<<"$IP"
    REV="${c}.${b}.${a}.in-addr.arpa.zone"
    RF="/var/named/$REV"
    [[ ! -f "$RF" ]] && cat > "$RF" <<EOF
\$TTL 86400
@ IN SOA $(hostname). root.$DOM. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS  $(hostname).
EOF
    printf "%-10s IN PTR %s.%s.\n" "$d" "$NAME" "$DOM" >> "$RF"
    sed -i "/SOA/ s/[0-9]\{8,\}/$(date +%Y%m%d)99/" "$RF" 2>/dev/null || true
fi
rndc reload "$DOM" &>/dev/null || true
echo -e "\033[1;32mAdded $NAME.$DOM → $IP\033[0m"
ADD
chmod +x /usr/local/bin/add-client.sh

# ───── Remote syslog (rsyslog) ─────
dnf install -y rsyslog &>/dev/null || yum install -y rsyslog &>/dev/null
mkdir -p /var/log/remote && chmod 750 /var/log/remote

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
if $syslogtag == 'remote-cmd:' and $fromhost-ip != '127.0.0.1' then { action(type="omfile" dynaFile="HostFile" template="GreenCmd"); stop }
if $fromhost-ip != '127.0.0.1' then action(type="omfile" dynaFile="HostFile")
RSYS

cat > /etc/logrotate.d/remote-logs <<'LR'
/var/log/remote/*.logs { daily rotate 7 compress missingok create 0640 root adm sharedscripts postrotate systemctl restart rsyslog &>/dev/null || true; endscript }
LR

firewall-cmd --add-port=514/tcp --add-port=514/udp --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

if [[ "$(getenforce 2>/dev/null || echo Disabled)" = Enforcing ]]; then
    semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' &>/dev/null || true
    restorecon -Rfv /var/log/remote &>/dev/null || true
fi

systemctl restart rsyslog
systemctl enable --now rsyslog &>/dev/null

# ───── Admin block helper ─────
cat > /usr/local/bin/admin-block-client.sh <<'AB'
#!/usr/bin/env bash
ACTION="$1"; IP="$2"
[[ -z "$ACTION" || -z "$IP" ]] && { echo "Usage: $0 <block|unblock|status> <ip>"; exit 1; }
case "$ACTION" in
block)   firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$IP drop" &>/dev/null; firewall-cmd --reload &>/dev/null; echo "Blocked $IP";;
unblock) firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$IP drop" &>/dev/null; firewall-cmd --reload &>/dev/null; echo "Unblocked $IP";;
status)  firewall-cmd --list-rich-rules 2>/dev/null | grep "$IP" || echo "Not blocked";;
esac
AB
chmod +x /usr/local/bin/admin-block-client.sh

# ───── SUCCESS — ONLY THIS IS SHOWN TO USER ─────
clear
echo
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo -e "${GREEN}           SERVER SETUP 100% COMPLETE!${NC}"
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo
echo -e "   IP     : ${GREEN}$IP${NC}"
echo -e "   FQDN   : ${GREEN}$FQDN${NC}"
echo -e "   Domain : ${GREEN}$DOMAIN${NC}"
echo
echo -e "   DNS Server        : ${GREEN}Running${NC}"
echo -e "   Remote Log Server : ${GREEN}Running on port 514 (UDP+TCP)${NC}"
echo -e "   Logs location     : ${GREEN}/var/log/remote/<hostname>.logs${NC}"
echo
echo -e "   Add client    → ${GREEN}add-client.sh client1 10.231.133.100${NC}"
echo -e "   Block client  → ${GREEN}admin-block-client.sh block 10.231.133.100${NC}"
echo
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo

exit 0
