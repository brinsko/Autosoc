#!/bin/bash
# server-setup.sh
# Wrapper with added features (distro detection, ISO -> yum/apt repo config, auto-troubleshoot, PTR best-effort)
# IMPORTANT: Your original server block is inserted verbatim later and is not modified.

set -euo pipefail

IP="$1"
FQDN="$2"
DOMAIN="$3"

[ -z "$IP" ] || [ -z "$FQDN" ] || [ -z "$DOMAIN" ] && {
    echo "Usage: sudo $0 <server-ip> <fqdn> <domain>"
    echo "Example: sudo $0 192.168.29.206 server.cst.com cst.com"
    exit 1
}

# -------------------------
# Helper functions
# -------------------------
log() { echo -e "\033[1;32m$*\033[0m"; }
err() { echo -e "\033[1;31m$*\033[0m" >&2; }

detect_pkg_mgr() {
    if command -v dnf >/dev/null 2>&1; then echo "dnf"; return; fi
    if command -v yum >/dev/null 2>&1; then echo "yum"; return; fi
    if command -v apt-get >/dev/null 2>&1; then echo "apt"; return; fi
    echo "unknown"
}

is_rhel_family() {
    [ -f /etc/os-release ] && grep -qiE 'rhel|centos|fedora|rocky|almalinux' /etc/os-release 2>/dev/null
    return $?
}

# find mounted iso-like locations: prefer iso9660 mounts, otherwise detect repodata/pool/dists
find_iso_mounts() {
    # iso9660 type mounts
    mnts=$(mount | awk '$5 ~ /iso9660/ {print $3}' | sort -u)
    if [ -n "$mnts" ]; then
        echo "$mnts"
        return
    fi
    # otherwise any mount point containing repodata/pool/dists
    mount | awk '{print $3}' | while read -r mp; do
        [ -d "$mp/repodata" ] || [ -d "$mp/pool" ] || [ -d "$mp/dists" ] && echo "$mp"
    done | sort -u
}

# configure YUM from iso for RHEL family (BaseOS/AppStream best-effort)
configure_yum_from_iso() {
    if ! is_rhel_family; then
        log "Not RHEL-family - skipping yum-from-iso configuration"
        return 0
    fi

    mounts=$(find_iso_mounts)
    if [ -z "$mounts" ]; then
        log "No mounted ISO found. If you have the installation ISO file, mount it (mount -o loop /path/to.iso /mnt) and re-run."
        return 0
    fi

    for m in $mounts; do
        [ -d "$m" ] || continue
        if [ -d "$m/repodata" ]; then
            log "Creating /etc/yum.repos.d/local-iso.repo pointing to $m"
            cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso]
name=Local ISO repo ($m)
baseurl=file://$m
enabled=1
gpgcheck=0
EOF
            # Refresh cache
            if command -v dnf >/dev/null 2>&1; then
                dnf clean all >/dev/null 2>&1 || true
                dnf makecache --refresh >/dev/null 2>&1 || true
            elif command -v yum >/dev/null 2>&1; then
                yum makecache >/dev/null 2>&1 || true
            fi
            log "Local yum repo created."
            return 0
        fi
    done

    log "No usable repodata found in mounted ISOs."
    return 0
}

# configure apt from iso for Debian-family (best-effort)
configure_apt_from_iso() {
    pm=$(detect_pkg_mgr)
    if [ "$pm" != "apt" ]; then
        return 0
    fi
    mounts=$(find_iso_mounts)
    if [ -z "$mounts" ]; then
        log "No mounted ISO found for apt repo."
        return 0
    fi
    for m in $mounts; do
        [ -d "$m" ] || continue
        if [ -d "$m/pool" ] || [ -d "$m/dists" ]; then
            log "Creating /etc/apt/sources.list.d/local-iso.list pointing to $m"
            echo "deb [trusted=yes] file:$m ./ " >/etc/apt/sources.list.d/local-iso.list
            apt-get update -o Dir::Etc::sourcelist="sources.list.d/local-iso.list" -o Dir::Etc::sourceparts="-" 2>/dev/null || true
            log "Local apt repo added."
            return 0
        fi
    done
    log "No usable apt layout found in mounted ISOs."
    return 0
}

# Basic server troubleshooting & healing (best-effort)
troubleshoot_and_heal_server() {
    log "Running automatic troubleshooting (best-effort)..."

    # Ensure common packages exist
    pm=$(detect_pkg_mgr)
    if [ "$pm" = "dnf" ] || [ "$pm" = "yum" ]; then
        $pm install -y bind rsyslog bind-utils &>/dev/null || true
    elif [ "$pm" = "apt" ]; then
        apt-get update -y &>/dev/null || true
        apt-get install -y bind9 rsyslog dnsutils &>/dev/null || true
    fi

    # firewall adjustments
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=dns &>/dev/null || true
        firewall-cmd --permanent --add-port=514/tcp &>/dev/null || true
        firewall-cmd --permanent --add-port=514/udp &>/dev/null || true
        firewall-cmd --reload &>/dev/null || true
        log "firewalld: allowed dns and port 514 (tcp/udp)"
    else
        if command -v iptables >/dev/null 2>&1; then
            iptables -C INPUT -p udp --dport 514 -j ACCEPT &>/dev/null || iptables -I INPUT -p udp --dport 514 -j ACCEPT 2>/dev/null || true
            iptables -C INPUT -p tcp --dport 514 -j ACCEPT &>/dev/null || iptables -I INPUT -p tcp --dport 514 -j ACCEPT 2>/dev/null || true
            log "iptables: ensured port 514 allowed"
        fi
    fi

    # SELinux contexts
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
        semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' 2>/dev/null || true
        restorecon -R /var/log/remote 2>/dev/null || true
        log "SELinux: adjusted contexts for /var/log/remote"
    fi

    # start/enable services if present
    systemctl enable --now named rsyslog >/dev/null 2>&1 || true

    log "Troubleshooting done (best-effort)."
}

# Add PTR record to reverse zone in /var/named (best-effort) — will create reverse zone file if missing
add_ptr_to_zonefile_best_effort() {
    zonefile="$1"
    ip="$2"
    host="$3"
    [ -f "$zonefile" ] || { err "Zonefile $zonefile not found"; return 1; }
    last_octet=$(echo "$ip" | awk -F. '{print $4}')
    rev_zone=$(echo "$ip" | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')
    dir=$(dirname "$zonefile")
    revfile="$dir/$rev_zone.zone"
    if [ ! -f "$revfile" ]; then
        cat > "$revfile" <<EOF
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $FQDN.
$last_octet IN PTR $host.
EOF
        chown -R named:named "$dir" 2>/dev/null || true
        log "Created reverse zone file $revfile"
    else
        if grep -qE "^\s*$last_octet\s+IN\s+PTR\s+" "$revfile"; then
            sed -i "s/^\s*$last_octet\s\+IN\s\+PTR.*/$last_octet IN PTR $host./" "$revfile"
        else
            echo "$last_octet IN PTR $host." >> "$revfile"
        fi
        log "Updated PTR $last_octet -> $host in $revfile"
    fi
    return 0
}

# ------------------------
# PRE-RUN: configure local repos from any detected ISO and run troubleshooting
# ------------------------
configure_yum_from_iso || true
configure_apt_from_iso || true
troubleshoot_and_heal_server || true

# ------------------------
# === BEGIN: your ORIGINAL server block (exactly untouched) ===
# Everything between the markers below is your original content — unchanged.
# ------------------------
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

# === add-client.sh (FIXED VERSION) ===
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/bin/bash

NAME="$1"
IP="$2"
DOMAIN="${3:-}"
ZONE_DIR="/var/named"

# Validate inputs
if [ -z "$NAME" ] || [ -z "$IP" ]; then
    echo "Usage: sudo $0 <name> <ip> [domain]"
    exit 1
fi

# Auto-detect domain if not passed
if [ -z "$DOMAIN" ]; then
    shopt -s nullglob
    ZONES=("$ZONE_DIR"/*.zone)
    if [ ${#ZONES[@]} -eq 1 ]; then
        DOMAIN="$(basename "${ZONES[0]}" .zone)"
    else
        echo "Multiple or no zone files found — provide domain manually."
        exit 2
    fi
fi

ZONE="$ZONE_DIR/$DOMAIN.zone"

if [ ! -f "$ZONE" ]; then
    echo "Zone file does not exist: $ZONE"
    exit 3
fi

# Add A record
echo "$NAME IN A $IP" >> "$ZONE"

# Fix SOA serial
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$ZONE"

# Reload DNS zone
rndc reload "$DOMAIN" &>/dev/null || true

echo "Added → $NAME.$DOMAIN ($IP)"
ADD

chmod +x /usr/local/bin/add-client.sh

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
$template GreenCmd,"\033[1;32m%timestamp:::date-rfc3339%  %msg:F,58:2%@%hostname%  %msg:R,ERE,0,FIELD:: (.*)--end%\033[0m\n"

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

echo
echo -e "\033[1;32mSERVER 100% READY!\033[0m"
echo -e "\033[1;32mPort 514: FORCE OWNED\033[0m"
echo -e "\033[1;32mLogs: /var/log/remote/<hostname>.logs\033[0m"
echo
echo "Add clients:"
echo "   sudo add-client.sh client1 192.168.29.210"
echo "   sudo add-client.sh db01    192.168.29.215"
echo

# === ADMIN BLOCK HELPER (ADDED FEATURE) ===
# This is additive: creates /usr/local/bin/admin-block-client.sh to block/unblock client IPs.
cat > /usr/local/bin/admin-block-client.sh <<'AB'
#!/usr/bin/env bash
# Usage:
#   sudo admin-block-client.sh block 192.168.29.210
#   sudo admin-block-client.sh unblock 192.168.29.210
#   sudo admin-block-client.sh status 192.168.29.210
ACTION="$1"
IP="$2"
DROP_MARKER_DIR="/var/lib/admin-block-client"
mkdir -p "$DROP_MARKER_DIR"

if [ -z "$ACTION" ] || [ -z "$IP" ]; then
  echo "Usage: sudo $0 <block|unblock|status> <client-ip>"
  exit 2
fi

case "$ACTION" in
  block)
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$IP' drop" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    else
      iptables -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 || iptables -I INPUT -s "$IP" -j DROP 2>/dev/null || true
      ip6tables -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 || ip6tables -I INPUT -s "$IP" -j DROP 2>/dev/null || true
    fi
    touch "$DROP_MARKER_DIR/$IP.blocked"
    echo "Blocked $IP on this server."
    ;;
  unblock)
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$IP' drop" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    else
      iptables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
      ip6tables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
    fi
    rm -f "$DROP_MARKER_DIR/$IP.blocked" 2>/dev/null || true
    echo "Unblocked $IP on this server."
    ;;
  status)
    if [ -f "$DROP_MARKER_DIR/$IP.blocked" ]; then
      echo "$IP is marked blocked (marker present)."
    else
      echo "No marker for $IP. Check firewall rules."
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --list-rich-rules | grep "$IP" || true
    else
      iptables -S | grep "$IP" || true
    fi
    ;;
  *)
    echo "Unknown action. Use block|unblock|status"
    exit 3
    ;;
esac
AB

chmod +x /usr/local/bin/admin-block-client.sh
echo "Admin helper installed: /usr/local/bin/admin-block-client.sh"
echo "Use: sudo /usr/local/bin/admin-block-client.sh block|unblock|status <client-ip>"

# ensure marker dir exists
mkdir -p /var/lib/admin-block-client


echo "Created /usr/local/bin/setup-my-dns-and-logging-server.sh and made it executable."
# ------------------------
# === END of original server block (unchanged) ===
# ------------------------

# ------------------------
# POST: best-effort PTR creation + rndc reload
# ------------------------
if [ -d /var/named ] && [ -f "/var/named/$DOMAIN.zone" ]; then
    add_ptr_to_zonefile_best_effort "/var/named/$DOMAIN.zone" "$IP" "$FQDN" || true
    if command -v rndc >/dev/null 2>&1; then
        rndc reload "$DOMAIN" &>/dev/null || true
    fi
fi

# Re-run iso/apt configuration + troubleshooting to ensure final state
configure_yum_from_iso || true
configure_apt_from_iso || true
troubleshoot_and_heal_server || true

# Final helpful summary
echo
log "SERVER SCRIPT: final status/helpful hints"
echo " - Zone file (if bind): /var/named/$DOMAIN.zone"
echo " - Reverse zone (if created): /var/named/<reversed>.zone"
echo " - Add clients: sudo /usr/local/bin/add-client.sh <name> <ip> [domain]"
echo " - Admin block: /usr/local/bin/admin-block-client.sh"
echo " - Logs: /var/log/remote/<hostname>.logs"
echo " - If mounted ISO found, local repo may be at /etc/yum.repos.d/local-iso.repo or /etc/apt/sources.list.d/local-iso.list"
echo
log "If automatic DNS dynamic updates are required from clients and your named configuration restricts updates,"
log "use the server /usr/local/bin/add-client.sh or adjust BIND allow-update/TSIG keys as appropriate."
log "Server setup complete."
