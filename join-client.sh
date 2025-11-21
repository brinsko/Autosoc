#!/bin/bash
# join-client.sh
# Wrapper with added features:
# - auto-detect distro & package manager
# - auto-configure apt/yum from mounted ISO (mandatory yum configuration if RHEL-family and ISO found)
# - zero-noise interactive logger (your original client block inserted verbatim below)
# - client-side best-effort nsupdate (no SSH) to add A + PTR to DNS server (works only if server allows dynamic updates)
# - watchdog + systemd (your original block inserted verbatim below)
#
# Usage: sudo ./join-client.sh <server-ip> <domain> <client-name>

set -euo pipefail

DNS_IP="$1"
DOMAIN="$2"
CLIENT_NAME="$3"

[ -z "$DNS_IP" ] || [ -z "$DOMAIN" ] || [ -z "$CLIENT_NAME" ] && {
    echo "Usage: sudo $0 <server-ip> <domain> <client-name>"
    echo "Example: sudo $0 192.168.29.206 cst.com client1"
    exit 1
}

# -------------------------
# Helpers
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

# find mounted ISO-like path
find_iso_mounts() {
    mnts=$(mount | awk '$5 ~ /iso9660/ {print $3}' | sort -u)
    if [ -n "$mnts" ]; then
        echo "$mnts"
        return
    fi
    mount | awk '{print $3}' | while read -r mp; do
        [ -d "$mp/repodata" ] || [ -d "$mp/pool" ] || [ -d "$mp/dists" ] && echo "$mp"
    done | sort -u
}

configure_yum_from_iso() {
    if ! is_rhel_family; then
        log "Not RHEL-family: skipping yum-from-iso on client"
        return 0
    fi
    mounts=$(find_iso_mounts)
    if [ -z "$mounts" ]; then
        log "No ISO mounted for client yum config"
        return 0
    fi
    for m in $mounts; do
        [ -d "$m" ] || continue
        if [ -d "$m/repodata" ]; then
            log "Creating /etc/yum.repos.d/local-iso.repo for client pointing to $m"
            cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso]
name=Local ISO repo ($m)
baseurl=file://$m
enabled=1
gpgcheck=0
EOF
            if command -v dnf >/dev/null 2>&1; then
                dnf clean all &>/dev/null || true
                dnf makecache --refresh &>/dev/null || true
            elif command -v yum >/dev/null 2>&1; then
                yum makecache &>/dev/null || true
            fi
            log "Local YUM repo created on client"
            return 0
        fi
    done
    log "No usable repodata found on client for local iso"
    return 0
}

configure_apt_from_iso() {
    pm=$(detect_pkg_mgr)
    [ "$pm" = "apt" ] || return 0
    mounts=$(find_iso_mounts)
    if [ -z "$mounts" ]; then
        log "No ISO found for apt client"
        return 0
    fi
    for m in $mounts; do
        [ -d "$m" ] || continue
        if [ -d "$m/pool" ] || [ -d "$m/dists" ]; then
            echo "deb [trusted=yes] file:$m ./ " >/etc/apt/sources.list.d/local-iso.list
            apt-get update -o Dir::Etc::sourcelist="sources.list.d/local-iso.list" -o Dir::Etc::sourceparts="-" 2>/dev/null || true
            log "Local APT repo created on client"
            return 0
        fi
    done
    return 0
}

# Best-effort nsupdate to add A + PTR records on the DNS server (no SSH)
# This requires the DNS server to accept dynamic updates from the client or to have a TSIG key configured.
# If update fails, script prints a clear message and does not retry endlessly.
try_nsupdate_add() {
    server_ip="$1"
    domain="$2"
    client_name="$3"
    client_ip="$4"

    # construct zone (the domain) and reverse zone based on client_ip
    reverse_zone=$(echo "$client_ip" | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')
    last_oct=$(echo "$client_ip" | awk -F. '{print $4}')
    fqdn="${client_name}.${domain}."

    # Prepare nsupdate commands
    tmpf=$(mktemp)
    cat > "$tmpf" <<EOF
server $server_ip
zone $domain
update add $fqdn 86400 A $client_ip
send
zone $reverse_zone
update add $last_oct.$reverse_zone. 86400 PTR $fqdn
send
EOF

    if command -v nsupdate >/dev/null 2>&1; then
        if nsupdate -v "$tmpf" 2>&1 | tee /tmp/nsupdate.out | grep -qiE 'failed|error|REFUSED|NOTIMP|NOTAUTH'; then
            err "nsupdate attempt had errors — server likely not accepting dynamic updates from this client."
            err "nsupdate output (first 200 chars):"
            head -n60 /tmp/nsupdate.out || true
            rm -f "$tmpf" /tmp/nsupdate.out
            return 1
        else
            log "nsupdate succeeded (best-effort) — A and PTR requested to $server_ip"
            rm -f "$tmpf" /tmp/nsupdate.out
            return 0
        fi
    else
        err "nsupdate is not installed; cannot attempt dynamic DNS update."
        rm -f "$tmpf" || true
        return 1
    fi
}

# ------------------------
# PRE: configure local repos from detected iso (mandatory for RHEL-family clients if ISO present)
configure_yum_from_iso || true
configure_apt_from_iso || true

# ------------------------
# === BEGIN: your ORIGINAL client block (exactly untouched) ===
# Inserted verbatim below.
# ------------------------
SYSLOG_SERVER="$DNS_IP"
PORT="514"

# === FORCE FREE PORT 514 (kill anything using it) ===
echo "Checking and freeing port $PORT if in use..."
for proto in tcp udp; do
    pids=$(ss -lpn "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]\+' | grep -o '[0-9]\+' | sort -u)
    [ -n "$pids" ] && {
        echo "Port $PORT/$proto used by PID(s): $pids → killing them..."
        kill -9 $pids 2>/dev/null || true
    }
done
# Extra safety: stop common services that might bind to 514
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true
sleep 2

# === DNS + hostname ===
nmcli con show --active 2>/dev/null | awk '{print $1}' | while read c; do
    nmcli con mod "$c" ipv4.dns "$DNS_IP" ipv4.dns-search "$DOMAIN" ipv4.ignore-auto-dns yes &>/dev/null
    nmcli con up "$c" &>/dev/null
done
printf "search %s\nnameserver %s\n" "$DOMAIN" "$DNS_IP" > /etc/resolv.conf
hostnamectl set-hostname "$CLIENT_NAME.$DOMAIN"

# === Install packages ===
dnf install -y audit rsyslog &>/dev/null || yum install -y audit rsyslog &>/dev/null || \
apt install -y auditd rsyslog &>/dev/null || true

# === BULLETPROOF clean command logger (zero noise, zero errors) ===
cat > /etc/profile.d/remote-cmd-log.sh <<'EOD'
export REMOTE_SYSLOG_HOST="__IP__"
export REMOTE_SYSLOG_PORT="514"

_remote_cmd_logger() {
    # Skip profile/bashrc loading
    [[ "${BASH_SOURCE[1]:-}" == *"/etc/profile"* || "${BASH_SOURCE[1]:-}" == *"/etc/bash"* ]] && return

    # Skip known noise
    case "$BASH_COMMAND" in
        "" | *__vte_* | resize | history* | "set +o "* | "set -o "* ) return ;;
    esac

    # Only interactive shells
    [[ -n "$PS1" ]] || return

    logger -n "$REMOTE_SYSLOG_HOST" -P 514 -t "remote-cmd" -p local0.notice \
        "$(whoami)@$(hostname -f 2>/dev/null || hostname): $BASH_COMMAND" 2>/dev/null || true
}
trap '_remote_cmd_logger' DEBUG
EOD

sed -i "s|__IP__|$SYSLOG_SERVER|g" /etc/profile.d/remote-cmd-log.sh
chmod 644 /etc/profile.d/remote-cmd-log.sh

# === Audit rules ===
cat > /etc/audit/rules.d/99-execve.rules <<'AR'
-a always,exit -F arch=b64 -S execve,execveat -k exec_log
-a always,exit -F arch=b32 -S execve,execveat -k exec_log
-w /bin/ -p x -k exec_log
-w /sbin/ -p x -k exec_log
-w /usr/bin/ -p x -k exec_log
-w /usr/sbin/ -p x -k exec_log
AR
augenrules --load &>/dev/null || systemctl restart auditd &>/dev/null

# === Forward audit + interactive commands ===
cat > /etc/rsyslog.d/99-forward.conf <<RSY
module(load="imfile" mode="inotify")
input(type="imfile" File="/var/log/audit/audit.log" Tag="auditd:" Severity="info" Facility="local0")
local0.* @@$SYSLOG_SERVER:514
RSY

# === Final start (now port 514 is 100% free) ===
systemctl restart rsyslog auditd &>/dev/null
systemctl enable --now rsyslog auditd &>/dev/null

# === Only ONE green line ===
echo -e "\033[1;32mCLIENT 100% READY!\033[0m"

# === WATCHDOG FEATURE (ADDED) ===
# Adds client watchdog script and systemd service to enforce:
#  - first outage -> 40s grace then poweroff
#  - after first enforced poweroff -> 15s grace on next boot
# It reads REMOTE_SYSLOG_HOST from /etc/profile.d/remote-cmd-log.sh (already created above).

cat > /usr/local/bin/client-watchdog.sh <<'CW'
#!/usr/bin/env bash
# client-watchdog.sh
# Monitors reachability to REMOTE_SYSLOG_HOST (port 514). Enforces:
#  - first enforced poweroff: 40 seconds grace
#  - after first enforced poweroff (marker): 15 seconds grace on next boots

set -euo pipefail

STATE_DIR="/var/lib/client-watchdog"
mkdir -p "$STATE_DIR"
touch "$STATE_DIR/.watchdog-ok"

# Read REMOTE_SYSLOG_HOST from existing profile script if present
REMOTE=""
if [ -f /etc/profile.d/remote-cmd-log.sh ]; then
  REMOTE="$(grep -Eo 'REMOTE_SYSLOG_HOST=[^ ]+' /etc/profile.d/remote-cmd-log.sh 2>/dev/null | cut -d= -f2 | tr -d '\"')"
fi

# Allow passing IP as first arg if not found
if [ -z "$REMOTE" ]; then
  REMOTE="${1:-}"
fi

if [ -z "$REMOTE" ]; then
  echo "Client watchdog: REMOTE_SYSLOG_HOST not found. Usage: /usr/local/bin/client-watchdog.sh <server-ip>"
  exit 2
fi

TCP_PORT=514
CHECK_INTERVAL=4
FIRST_GRACE=40
FOLLOWUP_GRACE=15

if [ -f "$STATE_DIR/first_off_happened" ]; then
  ACTIVE_GRACE=$FOLLOWUP_GRACE
else
  ACTIVE_GRACE=$FIRST_GRACE
fi

log() {
  logger -t client-watchdog "$1" || true
  echo "$(date -Is) - $1"
}

is_reachable() {
  timeout 2 bash -c "cat < /dev/null > /dev/tcp/$REMOTE/$TCP_PORT" >/dev/null 2>&1 && return 0
  ping -c1 -W1 "$REMOTE" >/dev/null 2>&1 && return 0
  return 1
}

lost_since=0
while true; do
  if is_reachable; then
    if [ "$lost_since" -ne 0 ]; then
      log "Connectivity restored to $REMOTE. Cancelling shutdown timer."
    fi
    lost_since=0
    if [ -f "$STATE_DIR/first_off_happened" ]; then
      ACTIVE_GRACE=$FOLLOWUP_GRACE
    else
      ACTIVE_GRACE=$FIRST_GRACE
    fi
  else
    if [ "$lost_since" -eq 0 ]; then
      lost_since=$(date +%s)
      log "Lost connectivity to $REMOTE — starting $ACTIVE_GRACE second grace timer."
    else
      now=$(date +%s)
      elapsed=$((now - lost_since))
      remain=$((ACTIVE_GRACE - elapsed))
      if [ "$remain" -le 0 ]; then
        if ! is_reachable; then
          log "Grace period elapsed and $REMOTE still unreachable -> powering off NOW."
          touch "$STATE_DIR/first_off_happened"
          sync
          systemctl poweroff -i || shutdown -h now || poweroff -f
          break
        else
          log "Connectivity returned just before timeout — cancelling shutdown."
          lost_since=0
        fi
      else
        log "Server $REMOTE still unreachable — $remain sec remaining before enforced poweroff."
      fi
    fi
  fi
  sleep "$CHECK_INTERVAL"
done
CW

chmod +x /usr/local/bin/client-watchdog.sh

# systemd service for watchdog
cat > /etc/systemd/system/client-watchdog.service <<'UNIT'
[Unit]
Description=Client Watchdog: poweroff if syslog server unreachable
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/client-watchdog.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now client-watchdog.service
# ------------------------
# === END of original client block (unchanged) ===
# ------------------------

# POST: best-effort nsupdate to add A + PTR on DNS server (no SSH)
# Determine client primary IP (best-effort)
client_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
if [ -z "$client_ip" ]; then
    # fallback to ip route
    client_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || true)
fi

if [ -z "$client_ip" ]; then
    err "Could not determine client IP automatically for DNS update. Please supply client IP when running add-client on server."
else
    log "Attempting best-effort dynamic DNS update (nsupdate) to $DNS_IP for $CLIENT_NAME.$DOMAIN -> $client_ip"
    # ensure nsupdate available, if not install (best-effort)
    if ! command -v nsupdate >/dev/null 2>&1; then
        pm=$(detect_pkg_mgr)
        if [ "$pm" = "dnf" ] || [ "$pm" = "yum" ]; then
            $pm install -y bind-utils 2>/dev/null || true
        elif [ "$pm" = "apt" ]; then
            apt-get update -y 2>/dev/null || true
            apt-get install -y dnsutils 2>/dev/null || true
        fi
    fi

    if try_nsupdate_add "$DNS_IP" "$DOMAIN" "$CLIENT_NAME" "$client_ip"; then
        log "Client requested DNS server to add A+PTR (best-effort). If server allowed dynamic updates, records were updated."
    else
        err "Dynamic update failed or was refused. To add DNS entries manually on server use:"
        echo "   sudo /usr/local/bin/add-client.sh $CLIENT_NAME $client_ip $DOMAIN"
        echo "Or ssh into the server and run add-client.sh (if you later enable ssh)."
    fi
fi

# Final client hints
echo
log "CLIENT: final hints"
echo " - Forwarding logs to $DNS_IP:514"
echo " - Hostname: $CLIENT_NAME.$DOMAIN"
echo " - Watchdog service: systemctl status client-watchdog.service"
echo " - If dynamic DNS was refused, run on server: sudo /usr/local/bin/add-client.sh $CLIENT_NAME $client_ip $DOMAIN"
echo
log "Client join finished."
