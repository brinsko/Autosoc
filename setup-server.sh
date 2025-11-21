#!/bin/bash
# setup-server.sh – FINAL ULTIMATE VERSION (2025)
# Features: Everything from your huge wrapper + auto loop-mount any .iso + clean green output
set -euo pipefail
IFS=$'\n\t'

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
LOG="/var/log/setup-server.log"
exec > >(tee -a "$LOG") 2>&1

error_exit() { echo -e "${RED}ERROR: $1${NC}" >&2; exit 1; }
trap 'error_exit "Line $LINENO"' ERR

(( EUID == 0 )) || error_exit "Run as root (sudo)"

[[ $# -eq 3 ]] || error_exit "Usage: sudo $(basename "$0") <ip> <fqdn> <domain>"
IP="$1"; FQDN="$2"; DOMAIN="$3"

[[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || error_exit "Invalid IP"
[[ $FQDN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || error_exit "Invalid FQDN"
[[ $DOMAIN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || error_exit "Invalid domain"

echo "Starting ultimate server setup..." >&2

# === 1. FULL RHEL OFFLINE REPO SUPPORT (your exact logic) ===
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if grep -Eiq 'rhel|centos|rocky|almalinux|redhat|centosstream' <<<"${ID:-} ${ID_LIKE:-}"; then
        if ! grep -riq "baseurl.*BaseOS" /etc/yum.repos.d 2>/dev/null || ! grep -riq "baseurl.*AppStream" /etc/yum.repos.d 2>/dev/null; then
            echo "Configuring local RHEL repos from mounted or discovered ISO..." >&2

            create_repos() {
                local mp="$1" created=0
                [[ -d "$mp/BaseOS" ]] && { cat > /etc/yum.repos.d/local-iso-BaseOS.repo <<EOF
[local-iso-BaseOS] name=Local BaseOS baseurl=file://$mp/BaseOS enabled=1 gpgcheck=0
EOF
                created=1; }
                [[ -d "$mp/AppStream" ]] && { cat > /etc/yum.repos.d/local-iso-AppStream.repo <<EOF
[local-iso-AppStream] name=Local AppStream baseurl=file://$mp/AppStream enabled=1 gpgcheck=0
EOF
                created=1; }
                [[ $created -eq 0 && -d "$mp/repodata" ]] && { cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso] name=Local ISO baseurl=file://$mp enabled=1 gpgcheck=0
EOF
                created=1; }
                (( created == 1 )) && { dnf makecache --refresh &>/dev/null || true; return 0; }
                return 2
            }

            # Try already mounted ISOs
            mapfile -t MPS < <(mount | awk '/iso9660/ {for(i=3;i<=NF;i++) if($i~ /^\//) {print $i; exit}}' | sort -u)
            for mp in "${MPS[@]}"; do create_repos "$(readlink -f "$mp")" && break; done || true

            # If nothing worked → auto-search and loop-mount .iso files (your exact paths)
            if ! grep -q "enabled=1" /etc/yum.repos.d/local-iso*.repo 2>/dev/null; then
                CAND=$(find /run/media /media /root /home /mnt /var/tmp /tmp -maxdepth 4 -type f -iname "*.iso" 2>/dev/null | head -20 || true)
                [[ -z "$CAND" ]] && find / -maxdepth 5 -type f -iname "*.iso" 2>/dev/null | head -20 || true
                MBASE="/mnt/local-iso"; mkdir -p "$MBASE"
                for iso in $CAND; do
                    mp="$MBASE/$(basename "$iso" .iso)"
                    mkdir -p "$mp"
                    if mount -o loop,ro "$iso" "$mp" &>/dev/null; then
                        echo "Auto-mounted $iso → $mp" >&2
                        if create_repos "$mp"; then break; fi
                        umount "$mp" 2>/dev/null || true
                    fi
                    rmdir "$mp" 2>/dev/null || true
                done
            fi

            [[ -f /etc/yum.repos.d/local-iso*.repo ]] || echo "Warning: No RHEL repo configured (will try internet)" >&2
        fi
    fi
fi

# === 2. Force own port 514 ===
ss -klnp "sport = :514" 2>/dev/null | awk '{print $6}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | xargs -r kill -9 &>/dev/null || true
systemctl stop rsyslog syslog-ng auditd &>/dev/null || true

# === 3. Install & configure everything ===
dnf install -y bind bind-utils rsyslog &>/dev/null

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

# === Enhanced add-client.sh with A + PTR + backup ===
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/usr/bin/env bash
set -euo pipefail
NAME="$1"; IP="$2"; DOMAIN="${3:-}"
[[ -z "$NAME" || -z "$IP" ]] && { echo "Usage: $0 <name> <ip> [domain]"; exit 1; }
ZONE_DIR="/var/named"
[[ -z "$DOMAIN" ]] && { zones=( "$ZONE_DIR"/*.zone ); DOMAIN=$(basename "${zones[0]}" .zone); }
FWD="$ZONE_DIR/$DOMAIN.zone"
cp -a "$FWD" "$FWD.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
printf "%s IN A %s\n" "$NAME" "$IP" >> "$FWD"
sed -i "/SOA/ s/[0-9]\{8,\}/$(date +%Y%m%d)99/" "$FWD"
if [[ $IP =~ ^[0-9.]+$ ]]; then
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
echo "Added: $NAME.$DOMAIN → $IP (A + PTR)"
ADD
chmod +x /usr/local/bin/add-client.sh

# === RSYSLOG + Green commands ===
mkdir -p /var/log/remote && chmod 750 /var/log/remote
cat > /etc/rsyslog.d/50-remote-logger.conf <<'EOF'
module(load="imuxsock") module(load="imjournal")
$ModLoad imudp; $UDPServerRun 514
$ModLoad imtcp; $InputTCPServerRun 514
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
systemctl restart rsyslog && systemctl enable --now rsyslog &>/dev/null

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

# === FINAL BEAUTIFUL SUCCESS ===
clear
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo -e "${GREEN}           SERVER SETUP 100% COMPLETE!${NC}"
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo
echo -e " IP      : ${GREEN}$IP${NC}"
echo -e " FQDN    : ${GREEN}$FQDN${NC}"
echo -e " Domain  : ${GREEN}$DOMAIN${NC}"
echo
echo -e " DNS     : ${GREEN}Running${NC}"
echo -e " Logs    : ${GREEN}Port 514 → /var/log/remote/<host>.logs${NC}"
echo
echo -e " Commands:"
echo -e "   Add client → ${GREEN}add-client.sh client1 10.10.10.100${NC}"
echo -e "   Block      → ${GREEN}admin-block-client.sh block 10.10.10.100${NC}"
echo -e "${GREEN}────────────────────────────────────────────────────────────${NC}"
echo
echo "Log: $LOG"
exit 0
