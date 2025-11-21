#!/bin/bash
# setup-my-dns-and-logging-server.sh
# Wrapper (preserves your original installer) + mandatory RHEL local-repo config (BaseOS+AppStream) when RHEL-like detected.
set -euo pipefail
IFS=$'\n\t'

# ────────────── Colors ──────────────
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

error() { echo -e "${RED}ERROR: $*${NC}" >&2; }
info()  { echo -e "${GREEN}$*${NC}"; }
warn()  { echo -e "${YELLOW}WARNING: $*${NC}"; }

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
    --*) error "Unknown flag: $1"; usage ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
[ ${#ARGS[@]} -eq 3 ] || usage
IP="${ARGS[0]}"; FQDN="${ARGS[1]}"; DOMAIN="${ARGS[2]}"

prompt_yes_no(){
  local p="$1"; local d="${2:-Y}"
  if [ "$NONINTER" -eq 1 ]; then [ "$d" = "Y" ] && return 0 || return 1; fi
  while true; do
    read -r -p "$p [Y/n]: " a
    a="${a:-$d}"
    case "$a" in [Yy]*) return 0;; [Nn]*) return 1;; *) echo "Please answer Y or N";; esac
  done
}

echo "Wrapper start — log: $LOG"

# detect rhel-like
IS_RHEL=0
if [ -f /etc/os-release ]; then
  . /etc/os-release
  idstr="$(printf "%s %s" "${ID:-}" "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
  if echo "$idstr" | grep -E -q 'rhel|redhat|centos|rocky|almalinux|centosstream'; then IS_RHEL=1; fi
fi
echo "RHEL-like detected: $IS_RHEL"

# ────────────── Repo helper ──────────────
create_repos_from_mount() {
  mp="$1"; created=0
  if [ -d "$mp/BaseOS" ]; then
    cat > /etc/yum.repos.d/local-iso-BaseOS.repo <<EOF
[local-iso-BaseOS]
name=Local ISO BaseOS
baseurl=file://$mp/BaseOS
enabled=1
gpgcheck=0
EOF
    created=1; echo "Created local-iso-BaseOS -> $mp/BaseOS"
  fi
  if [ -d "$mp/AppStream" ]; then
    cat > /etc/yum.repos.d/local-iso-AppStream.repo <<EOF
[local-iso-AppStream]
name=Local ISO AppStream
baseurl=file://$mp/AppStream
enabled=1
gpgcheck=0
EOF
    created=1; echo "Created local-iso-AppStream -> $mp/AppStream"
  fi
  if [ $created -eq 0 ] && [ -d "$mp/repodata" ]; then
    cat > /etc/yum.repos.d/local-iso.repo <<EOF
[local-iso]
name=Local ISO
baseurl=file://$mp
enabled=1
gpgcheck=0
EOF
    created=1; echo "Created fallback local-iso -> $mp"
  fi
  if [ $created -eq 1 ]; then
    command -v dnf >/dev/null 2>&1 && dnf makecache --refresh || true
    command -v yum >/dev/null 2>&1 && yum makecache || true
    return 0
  fi
  return 2
}

# ────────────── RHEL repo fix (mandatory) ──────────────
if [ "$IS_RHEL" -eq 1 ]; then
  have_base=0; have_app=0
  grep -riq "baseurl.*BaseOS" /etc/yum.repos.d 2>/dev/null && have_base=1
  grep -riq "baseurl.*AppStream" /etc/yum.repos.d 2>/dev/null && have_app=1

  if [ $have_base -eq 1 ] && [ $have_app -eq 1 ]; then
    echo "BaseOS and AppStream repos already present."
  else
    info "BaseOS/AppStream missing → trying to auto-configure from ISO..."
    mapfile -t MPS < <(mount | awk '/iso9660/ {for(i=3;i<=NF;i++) if($i~/^\//) {print $i; exit}}' | sort -u)
    success=0
    for mp in "${MPS[@]}"; do
      mp=$(readlink -f "$mp")
      echo "Checking mounted ISO: $mp"
      if create_repos_from_mount "$mp"; then success=1; break; fi
    done

    if [ $success -eq 0 ]; then
      CAND=""
      for p in /run/media /media /root /home /mnt /var/tmp /tmp; do
        [ -d "$p" ] || continue
        for f in "$p"/*.iso "$p"/*/*.iso; do [ -f "$f" ] && CAND="$CAND $f"; done
      done
      [ -z "$CAND" ] && while IFS= read -r f; do CAND="$CAND $f"; done < <(find / -maxdepth 4 -type f -iname '*.iso' 2>/dev/null || true)

      if [ -z "$CAND" ]; then
        error "No RHEL ISO found! Place a RHEL 8/9 DVD ISO (e.g. /root/rhel-8.10-dvd.iso) or mount it and re-run."
        exit 1
      fi

      MBASE="/mnt/local-iso"; mkdir -p "$MBASE"; idx=0
      for iso in $CAND; do
        idx=$((idx+1)); mp="$MBASE/$idx"; mkdir -p "$mp"
        if mount -o loop,ro "$iso" "$mp" 2>/dev/null; then
          echo "Mounted $iso → $mp"
          if create_repos_from_mount "$mp"; then success=1; break; else umount "$mp" || true; fi
        else
          rmdir "$mp" 2>/dev/null || true
        fi
      done
      [ $success -eq 0 ] && { error "Failed to configure repos from any discovered ISO."; exit 1; }
    fi
  fi
fi

# ────────────── PTR helper ──────────────
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
  if ! grep -qE "^[[:space:]]*${d}[[:space:]]+IN[[:space:]]+PTR" "$revfile" 2>/dev/null; then
    printf "%-10s IN PTR %s.\n" "$d" "$fqdn" >> "$revfile"
    sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$revfile" || true
    echo "Added reverse PTR: $ip → $fqdn"
  fi
}

# ────────────── Preserve original installer block ──────────────
cat > /usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block <<'ORIG' && chmod +x /usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block
#!/bin/bash
IP="$1"; FQDN="$2"; DOMAIN="$3"
[ -z "$IP" ] || [ -z "$FQDN" ] || [ -z "$DOMAIN" ] && { echo "Usage: $0 <ip> <fqdn> <domain>"; exit 1; }

echo "Setting up DNS + Remote Syslog Server..."

# Force take port 514
for proto in udp tcp; do
  ss -lpn "sport = :514" 2>/dev/null | awk '{print $6}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u | xargs -r kill -9 2>/dev/null
done
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true; sleep 2

# DNS
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

# add-client.sh (basic version)
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/bin/bash
NAME="$1"; IP="$2"; DOMAIN="${3:-}"
ZONE_DIR="/var/named"
if [ -z "$NAME" ] || [ -z "$IP" ]; then echo "Usage: $0 <name> <ip> [domain]"; exit 1; fi
if [ -z "$DOMAIN" ]; then
  ZONES=("$ZONE_DIR"/*.zone); [ ${#ZONES[@]} -eq 1 ] && DOMAIN="$(basename "${ZONES[0]}" .zone)" || { echo "Provide domain"; exit 2; }
fi
ZONE="$ZONE_DIR/$DOMAIN.zone"
[ -f "$ZONE" ] || { echo "Zone $ZONE missing"; exit 3; }
echo "$NAME IN A $IP" >> "$ZONE"
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$ZONE"
rndc reload "$DOMAIN" &>/dev/null || true
echo "Added → $NAME.$DOMAIN ($IP)"
ADD
chmod +x /usr/local/bin/add-client.sh

# rsyslog
dnf install -y rsyslog &>/dev/null || true
mkdir -p /var/log/remote; chmod 750 /var/log/remote

cat > /etc/rsyslog.d/50-remote-logger.conf <<'RSYS'
module(load="imuxsock")
module(load="imjournal")
$ModLoad imudp; $UDPServerRun 514
$ModLoad imtcp; $InputTCPServerRun 514
$PreserveFQDN on
$template HostFile,"/var/log/remote/%hostname%.logs"
$template GreenCmd,"\033[1;32m%timestamp:::date-rfc3339% %msg:F,58:2%@%hostname% %msg:R,ERE,0,FIELD:: (.*)--end%\033[0m\n"
if $syslogtag == 'remote-cmd:' and $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then { action(type="omfile" dynaFile="HostFile" template="GreenCmd"); stop }
if $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then { action(type="omfile" dynaFile="HostFile") }
RSYS

cat > /etc/logrotate.d/remote-logs <<'LR'
/var/log/remote/*.logs { daily rotate 7 compress missingok create 0640 root adm sharedscripts postrotate systemctl restart rsyslog &>/dev/null || true; endscript }
LR

firewall-cmd --add-port=514/tcp --add-port=514/udp --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

[ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ] && {
  semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' 2>/dev/null || true
  restorecon -R /var/log/remote 2>/dev/null || true
}

systemctl restart rsyslog
systemctl enable --now rsyslog

# admin block helper
cat > /usr/local/bin/admin-block-client.sh <<'AB'
#!/usr/bin/env bash
ACTION="$1"; IP="$2"; D="/var/lib/admin-block-client"; mkdir -p "$D"
[ -z "$ACTION" ] || [ -z "$IP" ] && { echo "Usage: $0 <block|unblock|status> <ip>"; exit 2; }
case "$ACTION" in
  block)   firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$IP' drop" &>/dev/null || true; firewall-cmd --reload &>/dev/null || true; touch "$D/$IP.blocked"; echo "Blocked $IP";;
  unblock) firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$IP' drop" &>/dev/null || true; firewall-cmd --reload &>/dev/null || true; rm -f "$D/$IP.blocked"; echo "Unblocked $IP";;
  status)  [ -f "$D/$IP.blocked" ] && echo "$IP blocked" || echo "$IP not blocked"; firewall-cmd --list-rich-rules 2>/dev/null | grep "$IP" || true;;
esac
AB
chmod +x /usr/local/bin/admin-block-client.sh
ORIG

# ────────────── Run original installer ──────────────
echo "Executing original installer block..."
/usr/local/bin/setup-my-dns-and-logging-server.sh.orig_script_block "$IP" "$FQDN" "$DOMAIN" || true

# ────────────── Add server reverse PTR ──────────────
add_server_ptr "$IP" "$FQDN" "$DOMAIN" || true

# ────────────── Enhanced add-client.sh (with colors + PTR) ──────────────
cat > /usr/local/bin/add-client.sh <<'ADDCLIENT'
#!/usr/bin/env bash
set -euo pipefail
RED='\033[1;31m'; GREEN='\033[1;32m'; NC='\033[0m'
NAME="${1:-}"; IP="${2:-}"; DOMAIN_ARG="${3:-}"
if [ -z "$NAME" ] || [ -z "$IP" ]; then echo "Usage: $0 <name> <ip> [domain]"; exit 2; fi
ZONE_DIR="/var/named"; mkdir -p "$ZONE_DIR"
if [ -z "$DOMAIN_ARG" ]; then
  zones=( "$ZONE_DIR"/*.zone )
  [ "${#zones[@]}" -eq 1 ] && DOMAIN="$(basename "${zones[0]}" .zone)" || { echo -e "${RED}Provide domain name${NC}"; exit 3; }
else
  DOMAIN="$DOMAIN_ARG"
fi
FWD="$ZONE_DIR/${DOMAIN}.zone"
[ -f "$FWD" ] || { echo -e "${RED}Forward zone missing: $FWD${NC}"; exit 4; }
ts="$(date +%Y%m%d%H%M%S)"; cp -a "$FWD" "${FWD}.bak.$ts" 2>/dev/null || true
printf "%-15s IN A %s\n" "$NAME" "$IP" >> "$FWD"
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$FWD" || true

# Reverse PTR if IPv4
if echo "$IP" | grep -E -q '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  a=$(echo "$IP"|cut -d. -f1); b=$(echo "$IP"|cut -d. -f2); c=$(echo "$IP"|cut -d. -f3); d=$(echo "$IP"|cut -d. -f4)
  REV="${c}.${b}.${a}.in-addr.arpa"; RF="$ZONE_DIR/${REV}.zone"
  FQDN="${NAME}.${DOMAIN}"
  if [ ! -f "$RF" ]; then
    cat > "$RF" <<RZ
\$TTL 86400
@ IN SOA $(hostname). root.${DOMAIN}. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $(hostname).
RZ
  fi
  printf "%-10s IN PTR %s.\n" "$d" "$FQDN" >> "$RF"
  sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$RF" || true
fi

named-checkzone "$DOMAIN" "$FWD" >/dev/null 2>&1 || echo -e "${RED}Zone check warning (continuing)${NC}"
rndc reload "$DOMAIN" 2>/dev/null || true
echo -e "${GREEN}Added → ${NAME}.${DOMAIN} (${IP})${NC}"
ADDCLIENT
chmod +x /usr/local/bin/add-client.sh

# ────────────── Final success message with colors ──────────────
echo
info "╔══════════════════════════════════════════════════╗"
info "║            SERVER SETUP COMPLETE!                ║"
info "║                                                  ║"
info "║  Server IP   : $IP                     ║"
info "║  FQDN        : $FQDN             ║"
info "║  Domain      : $DOMAIN                         ║"
info "║                                                  ║"
info "║  Logs        → /var/log/remote/<hostname>.logs   ║"
info "║  Add client  → sudo add-client.sh client99 192.168.29.199 cst.com ║"
info "╚══════════════════════════════════════════════════╝"
echo

exit 0
