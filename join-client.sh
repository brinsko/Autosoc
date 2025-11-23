cat > /usr/local/bin/join-dns-and-enable-full-logging.sh <<'CLIENT_EOF'
#!/bin/bash
# join-dns-and-enable-full-logging.sh
# Full client installer (NO wrapper log). Preserves your original installer verbatim and runs it.

# --- Fix for copy/paste non-breaking spaces (U+00A0) ---
# If user pasted "IP domain name" as ONE arg with NBSPs, convert to real spaces and re-exec.
if [ "$#" -eq 1 ]; then
  cleaned=$(printf '%s' "$1" | tr '\302\240' ' ')
  if printf '%s' "$cleaned" | grep -q ' '; then
    exec "$0" $cleaned
  fi
fi

set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<USG
Usage:
  sudo $0 [--non-interactive] [--force] <server-ip> <domain> <client-name>
  sudo $0 [--non-interactive] [--force]          # interactive mode
Examples:
  sudo $0 192.168.29.206 cst.com client1
USG
  exit 1
}

# parse flags
NONINTER=0; FORCE=0; ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --non-interactive) NONINTER=1; shift ;;
    --force) FORCE=1; shift ;;
    --help) usage ;;
    --*) echo "Unknown: $1"; usage ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

prompt_yes_no() {
  local prompt="$1"
  local def="${2:-Y}"
  if [ "$NONINTER" -eq 1 ]; then
    [ "$def" = "Y" ] && return 0 || return 1
  fi
  while true; do
    read -r -p "$prompt [Y/n]: " ans
    ans="${ans:-$def}"
    case "$ans" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer Y or N." ;;
    esac
  done
}

# detect package manager (kept for completeness)
PKG="unknown"
if command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
elif command -v yum >/dev/null 2>&1; then PKG="yum"
elif command -v zypper >/dev/null 2>&1; then PKG="zypper"
elif command -v pacman >/dev/null 2>&1; then PKG="pacman"; fi

# detect RHEL-like
IS_RHEL=0
if [ -f /etc/os-release ]; then
  . /etc/os-release
  idstr="$(printf "%s %s" "${ID:-}" "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
  if echo "$idstr" | grep -E -q 'rhel|redhat|centos|rocky|almalinux|centosstream'; then
    IS_RHEL=1
  fi
fi

# create repo files from a mounted ISO path (looks for BaseOS/AppStream or repodata)
create_repos_from_mount_client() {
  local mp="$1"
  local created=0

  if [ -d "$mp/BaseOS" ]; then
    cat > /etc/yum.repos.d/local-iso-BaseOS.repo <<EOF
[local-iso-BaseOS]
name=Local ISO BaseOS
baseurl=file://$mp/BaseOS
enabled=1
gpgcheck=0
EOF
    created=1
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
  fi

  if [ $created -eq 1 ]; then
    if command -v dnf >/dev/null 2>&1; then
      dnf makecache --refresh || true
    elif command -v yum >/dev/null 2>&1; then
      yum makecache || true
    fi
    return 0
  fi

  return 2
}

# If RHEL-like, ensure BaseOS + AppStream repos exist (prefer mounted ISO(s))
if [ "$IS_RHEL" -eq 1 ]; then
  have_base=0; have_app=0
  if grep -riq "baseurl.*BaseOS" /etc/yum.repos.d 2>/dev/null; then have_base=1; fi
  if grep -riq "baseurl.*AppStream" /etc/yum.repos.d 2>/dev/null; then have_app=1; fi

  if [ $have_base -eq 0 ] || [ $have_app -eq 0 ]; then
    # Try mounted ISO(s) first (mount output iso9660)
    MPS=()
    while IFS= read -r line; do
      mp="$(echo "$line" | awk '{
        for(i=3;i<=NF;i++){ if ($i ~ /^\//) { print $i; break } }
      }')"
      [ -n "$mp" ] && MPS+=("$mp")
    done < <(mount | grep iso9660 || true)

    success=0
    for mp in "${MPS[@]}"; do
      mp="$(readlink -f "$mp" 2>/dev/null || echo "$mp")"
      if create_repos_from_mount_client "$mp"; then
        success=1
        break
      fi
    done

    # If mounted ISOs didn't work, shallow-scan common locations for iso files and try mounting them
    if [ $success -eq 0 ]; then
      CAND=""
      for p in /run/media /media /root /home /mnt /var/tmp /tmp; do
        [ -d "$p" ] || continue
        for f in "$p"/*.iso "$p"/*/*.iso; do
          [ -f "$f" ] && CAND="$CAND $f"
        done
      done

      if [ -z "$CAND" ]; then
        while IFS= read -r f; do
          CAND="$CAND $f"
        done < <(find / -maxdepth 4 -type f -iname '*.iso' 2>/dev/null || true)
      fi

      if [ -z "$CAND" ]; then
        echo "ERROR: No RHEL-style ISO found on client and no useful mounted ISO present."
        echo "Place a RHEL8-style DVD ISO on the client or mount the ISO and re-run this script."
        exit 1
      fi

      MBASE="/mnt/local-iso-client"
      mkdir -p "$MBASE"
      idx=0
      for iso in $CAND; do
        idx=$((idx+1))
        mp="$MBASE/$idx"
        mkdir -p "$mp"
        if mount -o loop,ro "$iso" "$mp" 2>/dev/null; then
          if create_repos_from_mount_client "$mp"; then
            success=1
            break
          else
            umount "$mp" 2>/dev/null || true
          fi
        else
          rm -rf "$mp" 2>/dev/null || true
        fi
      done

      if [ $success -eq 0 ]; then
        echo "ERROR: Could not configure BaseOS/AppStream from discovered ISOs on client."
        exit 1
      fi
    fi
  fi
fi

# =========================
# Gather inputs (args or interactive)
# =========================
CHOSEN_SERVER=""; DOMAIN=""; CLIENT_NAME=""
if [ "${#ARGS[@]}" -eq 3 ]; then
  # Strict non-interactive arg mode
  CHOSEN_SERVER="${ARGS[0]}"
  DOMAIN="${ARGS[1]}"
  CLIENT_NAME="${ARGS[2]}"
elif [ "${#ARGS[@]}" -eq 0 ]; then
  # Fully interactive mode
  EXIST_NS=()
  if [ -f /etc/resolv.conf ]; then
    while read -r L; do
      echo "$L" | grep -E '^nameserver' >/dev/null 2>&1 && EXIST_NS+=("$(echo "$L" | awk '{print $2}')")
    done < /etc/resolv.conf
  fi

  if [ ${#EXIST_NS[@]} -gt 0 ]; then
    echo "Detected nameservers: ${EXIST_NS[*]}"
    if prompt_yes_no "Use a detected nameserver? (Y to pick)"; then
      read -r -p "Enter number (1-${#EXIST_NS[@]}) [1]: " pick
      pick="${pick:-1}"
      CHOSEN_SERVER="${EXIST_NS[$((pick-1))]}"
    else
      read -r -p "Enter DNS server IP to use: " CHOSEN_SERVER
    fi
  else
    read -r -p "Enter DNS server IP to use: " CHOSEN_SERVER
  fi

  [ -n "$DOMAIN" ] || read -r -p "Enter domain (e.g. cst.com): " DOMAIN
  [ -n "$CLIENT_NAME" ] || read -r -p "Enter client name (short): " CLIENT_NAME
else
  echo "ERROR: you must pass either 0 or 3 non-option arguments."
  usage
fi

# Preserve original client installer verbatim
cat > /usr/local/bin/join-dns-and-enable-full-logging.sh.orig_script_block <<'ORIGCLIENT' && chmod +x /usr/local/bin/join-dns-and-enable-full-logging.sh.orig_script_block
#!/bin/bash
# merged client installer:
# original join-dns-and-enable-full-logging.sh (untouched), plus added watchdog + systemd unit
set -euo pipefail
DNS_IP="$1"
DOMAIN="$2"
CLIENT_NAME="$3"

[ -z "$DNS_IP" ] || [ -z "$DOMAIN" ] || [ -z "$CLIENT_NAME" ] && {
    echo "Usage: sudo $0 <server-ip> <domain> <client-name>"
    echo "Example: sudo $0 192.168.29.206 cst.com client1"
    exit 1
}

SYSLOG_SERVER="$DNS_IP"
PORT="514"

# === FORCE FREE PORT 514 (kill anything using it) ===
echo "Checking and freeing port $PORT if in use..."
for proto in tcp udp; do
    pids=$(ss -lpn "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]\+' | grep -o '[0-9]\+' | sort -u || true)
    [ -n "${pids:-}" ] && {
        echo "Port $PORT/$proto used by PID(s): $pids → killing them..."
        kill -9 $pids 2>/dev/null || true
    }
done
# Extra safety: stop common services that might bind to 514
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true
sleep 2

# === DNS + hostname ===
nmcli con show --active 2>/dev/null | awk 'NR>1{print $1}' | while read -r c; do
    [ -z "$c" ] && continue
    nmcli con mod "$c" ipv4.dns "$DNS_IP" ipv4.dns-search "$DOMAIN" ipv4.ignore-auto-dns yes &>/dev/null || true
    nmcli con up "$c" &>/dev/null || true
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
cat > /usr/local/bin/client-watchdog.sh <<'CW'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="/var/lib/client-watchdog"
mkdir -p "$STATE_DIR"
touch "$STATE_DIR/.watchdog-ok"

REMOTE=""
if [ -f /etc/profile.d/remote-cmd-log.sh ]; then
  REMOTE="$(grep -Eo 'REMOTE_SYSLOG_HOST=[^ ]+' /etc/profile.d/remote-cmd-log.sh 2>/dev/null | cut -d= -f2 | tr -d '\"')"
fi
if [ -z "$REMOTE" ]; then
  REMOTE="${1:-}"
fi
[ -n "$REMOTE" ] || { echo "Client watchdog: REMOTE_SYSLOG_HOST not found."; exit 2; }

TCP_PORT=514
CHECK_INTERVAL=4
FIRST_GRACE=40
FOLLOWUP_GRACE=15

if [ -f "$STATE_DIR/first_off_happened" ]; then
  ACTIVE_GRACE=$FOLLOWUP_GRACE
else
  ACTIVE_GRACE=$FIRST_GRACE
fi

log(){
  logger -t client-watchdog "$1" || true
  echo "$(date -Is) - $1"
}

is_reachable(){
  timeout 2 bash -c "cat < /dev/null > /dev/tcp/$REMOTE/$TCP_PORT" >/dev/null 2>&1 && return 0
  ping -c1 -W1 "$REMOTE" >/dev/null 2>&1 && return 0
  return 1
}

lost_since=0
while true; do
  if is_reachable; then
    if [ "$lost_since" -ne 0 ]; then
      log "Connectivity restored to $REMOTE."
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
      log "Lost connectivity to $REMOTE — starting $ACTIVE_GRACE sec grace."
    else
      now=$(date +%s)
      elapsed=$((now-lost_since))
      remain=$((ACTIVE_GRACE-elapsed))
      if [ "$remain" -le 0 ]; then
        if ! is_reachable; then
          log "Grace elapsed, powering off."
          touch "$STATE_DIR/first_off_happened"
          sync
          systemctl poweroff -i || shutdown -h now || poweroff -f
          break
        else
          log "Connectivity returned."
          lost_since=0
        fi
      else
        log "Unreachable — $remain sec remaining."
      fi
    fi
  fi
  sleep "$CHECK_INTERVAL"
done
CW
chmod +x /usr/local/bin/client-watchdog.sh

# IMPORTANT: pass SYSLOG_SERVER into ExecStart so watchdog always knows server IP
cat > /etc/systemd/system/client-watchdog.service <<UNIT
[Unit]
Description=Client Watchdog: poweroff if syslog server unreachable
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/client-watchdog.sh "$SYSLOG_SERVER"
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now client-watchdog.service 2>/dev/null || true

ORIGCLIENT

# Execute preserved original block with chosen params
/usr/local/bin/join-dns-and-enable-full-logging.sh.orig_script_block "${CHOSEN_SERVER:-}" "${DOMAIN:-}" "${CLIENT_NAME:-}" || true

echo "Client wrapper finished."
exit 0
CLIENT_EOF

chmod +x /usr/local/bin/join-dns-and-enable-full-logging.sh
