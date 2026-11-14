#!/usr/bin/env bash
# chemin-de-ronde: one read-only security round on a Linux server.
#
#   sudo bash ronde.sh [--out DIR] [--roots "/opt /srv /home /root /var/www"]
#
# Writes DIR/findings.tsv, one line per check:
#   ID  STATUS  SEVERITY  TOWER  TITLE  EVIDENCE
# STATUS   pass | fail | warn | info | skip
# SEVERITY critical | high | medium | low | info   (meaningful when fail or warn)
#
# READ ONLY. This script never writes outside DIR, never changes a setting,
# never restarts a service, never prints a secret value (paths and counts only).
# Without root it still runs, and marks what it could not see as skip.
set -u   # no pipefail: many checks are "cmd | grep -q", and grep -q exiting early must not turn a match into a failure
export LC_ALL=C

OUT=""
ROOTS="/opt /srv /home /root /var/www"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --roots) ROOTS="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$OUT" ] || OUT="$(mktemp -d "${TMPDIR:-/tmp}/ronde.XXXXXX")"
mkdir -p "$OUT"
TSV="$OUT/findings.tsv"
: >"$TSV"

ROOT=0; [ "$(id -u)" -eq 0 ] && ROOT=1
have() { command -v "$1" >/dev/null 2>&1; }
clean() { tr '\t\n\r' '   ' <<<"$*" | sed 's/  */ /g; s/^ //; s/ $//' | cut -c1-600; }
f() { # f ID STATUS SEVERITY TOWER TITLE EVIDENCE
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$(clean "$5")" "$(clean "$6")" >>"$TSV"
}
needroot() { # needroot ID TOWER TITLE -> returns 1 and logs skip when not root
  [ "$ROOT" -eq 1 ] && return 0
  f "$1" skip info "$2" "$3" "needs root"; return 1
}
# Existing search roots only, so find does not complain.
ROOTS_OK=""; for r in $ROOTS; do [ -d "$r" ] && ROOTS_OK="$ROOTS_OK $r"; done
PRUNE=( -path '*/node_modules' -o -path '*/.git' -o -path '*/site-packages' -o -path '*/.cache' -o -path '*/venv' -o -path '*/.venv' -o -path '*/dist-packages' -o -path '*/proc' -o -path '/var/lib/docker' -o -path '*/.npm' -o -path '*/.local/share/Trash' -o -path '*/snap' -o -path '*/Android/Sdk' -o -path '*/.rustup' -o -path '*/.cargo' -o -path '*/go/pkg' -o -path '*/.gradle' -o -path '*/.m2' -o -path '*/.nvm' )

host_info() {
  . /etc/os-release 2>/dev/null
  printf 'hostname\t%s\nos\t%s\nkernel\t%s\nroot\t%s\ndate\t%s\n' \
    "$(hostname)" "${PRETTY_NAME:-unknown}" "$(uname -r)" "$ROOT" "$(date -u +%FT%TZ)" >"$OUT/host.tsv"
}

# ---------------------------------------------------------------- ACCESS tower
SSHD_PA=unknown; SSHD_RL=unknown
tower_access() {
  local T=access t
  if have sshd && [ "$ROOT" -eq 1 ]; then
    t=$(sshd -T -C user=root,host=ronde,addr=203.0.113.9 2>/dev/null)
    if [ -n "$t" ]; then
      SSHD_PA=$(awk '$1=="passwordauthentication"{print $2}' <<<"$t")
      local ki rl mat x11 af
      ki=$(awk '$1=="kbdinteractiveauthentication"{print $2}' <<<"$t")
      rl=$(awk '$1=="permitrootlogin"{print $2}' <<<"$t"); SSHD_RL=$rl
      mat=$(awk '$1=="maxauthtries"{print $2}' <<<"$t")
      x11=$(awk '$1=="x11forwarding"{print $2}' <<<"$t")
      af=$(awk '$1=="allowagentforwarding"{print $2}' <<<"$t")
      if [ "$SSHD_PA" = yes ] || [ "$ki" = yes ]; then
        sev=high; [ "$rl" = yes ] && sev=critical
        f A01 fail "$sev" $T "SSH accepts passwords" "passwordauthentication=$SSHD_PA kbdinteractive=$ki permitrootlogin=$rl"
      else f A01 pass info $T "SSH accepts keys only" "passwordauthentication=$SSHD_PA kbdinteractive=$ki"; fi
      if [ "$rl" = yes ]; then f A02 fail high $T "root may log in over SSH with a password" "permitrootlogin=yes"
      else f A02 pass info $T "root SSH login restricted" "permitrootlogin=$rl"; fi
      if [ "${mat:-6}" -gt 4 ] || [ "$x11" = yes ] || [ "$af" = yes ]; then
        f A07 warn low $T "SSH options looser than needed" "maxauthtries=$mat x11forwarding=$x11 allowagentforwarding=$af"
      else f A07 pass info $T "SSH options tight" "maxauthtries=$mat x11forwarding=$x11"; fi
    else f A01 skip info $T "SSH configuration" "sshd -T returned nothing"; fi
  elif ! have sshd; then f A01 info info $T "no OpenSSH server installed" "sshd not found"
  else f A01 skip info $T "SSH configuration" "needs root"; fi

  local uid0; uid0=$(awk -F: '$3==0{print $1}' /etc/passwd | paste -sd, -)
  if [ "$uid0" = root ]; then f A03 pass info $T "only root has uid 0" "$uid0"
  else f A03 fail critical $T "accounts other than root have uid 0" "$uid0"; fi

  if needroot A04 $T "sudo rules"; then
    local rules; rules=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*(#|Defaults|$)' | grep NOPASSWD | grep -vE '^\s*root\s')
    local all shells
    all=$(grep -E 'NOPASSWD:\s*ALL\s*$' <<<"$rules" | awk '{print $1}' | sort -u | paste -sd, -)
    shells=$(grep -oE '/(usr/)?s?bin/(bash|sh|su|python3?|node|perl|vi|vim|nano|tee|cp|mv|chmod|chown|find|docker|systemctl|env|npm|npx|git)\b' <<<"$rules" | sort -u | paste -sd' ' -)
    if [ -n "$all" ]; then f A04 fail high $T "passwordless sudo to everything" "NOPASSWD ALL for: $all"
    elif [ -n "$shells" ]; then f A04 fail medium $T "passwordless sudo to commands that give a root shell" "$shells"
    else f A04 pass info $T "no passwordless sudo equivalent to root" ""; fi
  fi

  local dock; dock=$(getent group docker 2>/dev/null | cut -d: -f4)
  if [ -n "$dock" ]; then f A05 warn medium $T "members of the docker group are root in practice" "docker group: $dock"
  else f A05 pass info $T "docker group empty or absent" ""; fi

  if needroot A06 $T "SSH keys inventory"; then
    local inv="" n c fc=""
    for k in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
      [ -f "$k" ] || continue
      n=$(grep -cvE '^\s*(#|$)' "$k"); c=$(grep -cE '^\s*(command|.*,command)=' "$k")
      inv="$inv $(basename "$(dirname "$(dirname "$k")")")=$n"
      [ "$c" -gt 0 ] && fc="$fc $(basename "$(dirname "$(dirname "$k")")")=$c"
      [ "$(stat -c %a "$k")" -gt 644 ] 2>/dev/null && f A08 fail high $T "authorized_keys writable by others" "$k mode $(stat -c %a "$k")"
    done
    f A06 info info $T "authorized SSH keys per account (compare with who should have access)" "${inv:- none}${fc:+ ; forced commands:$fc}"
  fi
}

# ----------------------------------------------------------------- WALLS tower
FW=none
tower_walls() {
  local T=walls
  if needroot W01 $T "host firewall"; then
    if have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
      if ufw status verbose 2>/dev/null | grep -qE 'deny \(incoming\)|reject \(incoming\)'; then FW=ufw; f W01 pass info $T "UFW active, incoming denied by default" ""
      else f W01 fail high $T "UFW active but incoming not denied by default" "$(ufw status verbose | grep Default)"; fi
    elif have nft && nft list ruleset 2>/dev/null | grep -qE 'hook input .*policy (drop|reject)'; then
      FW=nft; f W01 pass info $T "nftables input policy drops by default" ""
    elif have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then
      FW=iptables; f W01 pass info $T "iptables INPUT policy drops by default" ""
    else f W01 fail high $T "no host firewall denies incoming traffic" "ufw/nftables/iptables: no default deny on input"; fi
  fi

  have ss || { f W02 skip info $T "listening ports" "ss not found"; return; }
  local lines; lines=$(ss -tulnpH 2>/dev/null | awk '{d=($0 ~ /docker-proxy/)?"d":"-"; print $1"|"$5"|"d}')
  # What really filters before a listener. raw PREROUTING drops come first of all;
  # DOCKER-USER drops apply to ports published by Docker (DNAT, IPv4); and Tailscale
  # accepts everything on tailscale0 in ts-input, ahead of UFW.
  local RAWDROP RAWTS EDGE=0 TSUP=0 ext="" i dur
  RAWDROP=" $( { iptables -t raw -S PREROUTING; ip6tables -t raw -S PREROUTING; } 2>/dev/null | grep -E -- '-j (DROP|REJECT)' | grep -v -- ' -i ' | grep -oE -- '--dport [0-9]+' | awk '{print $2}' | sort -u | paste -sd' ' -) "
  RAWTS=" $( { iptables -t raw -S PREROUTING; ip6tables -t raw -S PREROUTING; } 2>/dev/null | grep -E -- '-i tailscale0 .*-j (DROP|REJECT)' | grep -oE -- '--dport [0-9]+' | awk '{print $2}' | sort -u | paste -sd' ' -) "
  have ip && ip -o link show up 2>/dev/null | grep -q ' tailscale0:' && TSUP=1
  if have ip && have iptables; then
    dur=$(iptables -S DOCKER-USER 2>/dev/null | grep -E -- '^-A DOCKER-USER -i [^ ]+ (-m conntrack --ctstate NEW )?-j (DROP|REJECT)$' | awk '{print $4}')
    ext=$(ip -o link show up 2>/dev/null | awk -F': ' '{sub(/@.*/,"",$2); print $2}' | grep -vE '^(lo|docker|br-|veth|cni|flannel|virbr|lxdbr|tailscale)')
    if [ -n "$ext" ] && [ -n "$dur" ]; then
      EDGE=1
      for i in $ext; do
        local hit=0 r
        for r in $dur; do case "$r" in *+) [[ "$i" == "${r%+}"* ]] && hit=1 ;; *) [ "$i" = "$r" ] && hit=1 ;; esac; done
        [ $hit = 1 ] || EDGE=0
      done
    fi
  fi
  local tn=""
  # addresses of container bridges: only containers on this host reach them
  local BRIDGE=" "; have ip && BRIDGE=" $(ip -o addr show 2>/dev/null | awk '$2 ~ /^(docker|br-|veth|cni|flannel|virbr|lxdbr)/ {split($4,a,"/"); print a[1]; if ($5=="brd") print $6}' | paste -sd' ' -) " 
  local crit="" hi="" other="" lan=""
  # db, cache, search, container API, admin consoles, dev servers
  local CRIT_PORTS=" 2375 2376 3306 33060 5432 6543 6379 27017 27018 9200 9300 11211 5984 8086 9042 1433 1521 5433 54322 "
  local HIGH_PORTS=" 8000 8443 9000 9443 54323 5173 5174 4200 8888 15672 5601 3001 8081 10000 "
  while IFS='|' read -r proto addr dp; do
    [ -n "$addr" ] || continue
    local port=${addr##*:} ip=${addr%:*}
    ip=${ip%%%*}; ip=${ip#[}; ip=${ip%]}
    case "$ip" in 127.*|::1|localhost) continue ;; esac
    [ "$proto" = udp ] && case "$port" in 68|546|5353|41641) continue ;; esac
    case "$ip" in
      0.0.0.0|::|'*'|'') scope=all ;;
      fd7a:115c:a1e0:*) scope=tailnet ;;
      10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|fe80*|fd*|169.254.*) scope=lan ;;
      100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) scope=tailnet ;;
      *) scope=all ;;
    esac
    [[ "$BRIDGE" == *" $ip "* ]] && continue
    local tag="$proto/$port"
    [[ "$RAWDROP" == *" $port "* ]] && continue
    # published by Docker while DOCKER-USER drops every external interface, with a
    # default-deny firewall for the IPv6 the proxy serves: only the tailnet is left
    [ "$scope" = all ] && [ "$dp" = d ] && [ "$EDGE" = 1 ] && [ "$FW" != none ] && scope=tailnet
    if [ "$scope" = tailnet ]; then
      [ "$TSUP" = 1 ] && [[ "$RAWTS" != *" $port "* ]] && { [[ "$CRIT_PORTS$HIGH_PORTS" == *" $port "* ]] && tn="$tn $tag"; }
      continue
    fi
    if [ "$scope" = lan ]; then lan="$lan $tag@$ip"; continue; fi
    if [[ "$CRIT_PORTS" == *" $port "* ]]; then crit="$crit $tag"
    elif [[ "$HIGH_PORTS" == *" $port "* ]]; then hi="$hi $tag"
    elif [[ " 22 80 443 " != *" $port "* ]]; then other="$other $tag"; fi
  done <<<"$lines"
  crit=$(tr ' ' '\n' <<<"$crit" | sort -u | paste -sd' ' -); hi=$(tr ' ' '\n' <<<"$hi" | sort -u | paste -sd' ' -)
  other=$(tr ' ' '\n' <<<"$other" | sort -u | paste -sd' ' -); lan=$(tr ' ' '\n' <<<"$lan" | sort -u | paste -sd' ' -)
  local note=""; [ "$FW" != none ] && note=" (a firewall is active: confirm reachability with an external scan; Docker-published ports bypass UFW)"
  if [ -n "$crit" ]; then f W02 fail critical $T "database, cache or container API listening on every interface" "$crit$note"
  else f W02 pass info $T "no database or container API on a public interface" ""; fi
  if [ -n "$hi" ]; then f W03 fail high $T "admin console or dev server listening on every interface" "$hi$note"
  else f W03 pass info $T "no known admin or dev port on a public interface" ""; fi
  if [ -n "$other" ]; then f W04 warn medium $T "other ports listening on every interface (expected: 22, 80, 443)" "$other$note"
  else f W04 pass info $T "only 22, 80 and 443 listen publicly" ""; fi
  [ -n "$lan" ] && f W05 warn low $T "services bound to a local-network address (reachable by every device on that network)" "$lan"
  tn=$(tr ' ' '\n' <<<"$tn" | sort -u | paste -sd' ' -)
  [ -n "$tn" ] && f W09 warn medium $T "database or admin console reachable from every device of the tailnet (Tailscale accepts tailscale0 before UFW)" "$tn"

  if have docker && docker info >/dev/null 2>&1; then
    local pub; pub=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '(0\.0\.0\.0|\[::\]|:::):[0-9]' | awk '{print $1}' | paste -sd' ' -)
    if [ -n "$pub" ] && [ "$EDGE" = 1 ]; then f W06 pass info $T "containers publish on 0.0.0.0, but DOCKER-USER drops new connections from every external interface" "$pub"
    elif [ -n "$pub" ]; then f W06 fail high $T "containers publish ports on 0.0.0.0, which bypasses UFW" "$pub"
    else f W06 pass info $T "no container publishes on 0.0.0.0" ""; fi
  fi

  if have curl && have nginx; then
    local c80 c443
    c80=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1/ 2>/dev/null)
    c443=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 https://127.0.0.1/ 2>/dev/null)
    if [ "$c80" = 000 ] && [ "$c443" = 000 ] || [ "$c80" = 444 ]; then f W07 pass info $T "nginx answers nothing on the raw IP" ""
    else f W07 warn low $T "nginx serves a site on the raw IP (scanners find it without the domain)" "http=$c80 https=$c443"; fi
  fi

  if [ "$ROOT" -eq 1 ] && [ -d /etc/letsencrypt/live ] && have openssl; then
    local soon="" exp=""
    for c in /etc/letsencrypt/live/*/cert.pem; do
      [ -f "$c" ] || continue
      local d; d=$(basename "$(dirname "$c")")
      openssl x509 -checkend 0 -noout -in "$c" >/dev/null 2>&1 || { exp="$exp $d"; continue; }
      openssl x509 -checkend 1209600 -noout -in "$c" >/dev/null 2>&1 || soon="$soon $d"
    done
    if [ -n "$exp" ]; then f W08 fail high $T "TLS certificates expired" "$exp"
    elif [ -n "$soon" ]; then f W08 warn medium $T "TLS certificates expire within 14 days (renewal may be failing)" "$soon"
    else f W08 pass info $T "TLS certificates valid for 14 days or more" ""; fi
  fi
}

# ----------------------------------------------------------------- WATCH tower
active() { # active <service> <process>
  if have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; then return 0; fi
  pgrep -x "$2" >/dev/null 2>&1
}
tower_watch() {
  local T=watch
  if active fail2ban fail2ban-server || active crowdsec crowdsec; then
    f G01 pass info $T "brute-force guard running" "$(active fail2ban fail2ban-server && echo fail2ban) $(active crowdsec crowdsec && echo crowdsec)"
  else
    local sev=medium; [ "$SSHD_PA" = yes ] && sev=high
    f G01 fail "$sev" $T "no brute-force guard (fail2ban or CrowdSec)" "ssh passwords=$SSHD_PA"
  fi
  if active auditd auditd; then f G02 pass info $T "auditd running" ""
  else f G02 warn low $T "auditd not running (no record of who changed what)" ""; fi
  local fim=""
  for s in falco wazuh-agent ossec aide osqueryd; do have "$s" || [ -d "/var/ossec" -a "$s" = wazuh-agent ] && fim="$fim $s"; done
  [ -f /etc/cron.daily/aide ] && fim="$fim aide-cron"
  if [ -n "$fim" ]; then f G03 pass info $T "intrusion or file-integrity detection present" "$fim"
  else f G03 warn low $T "no intrusion or file-integrity detection (Falco, Wazuh, AIDE, osquery)" ""; fi
  if [ -d /var/log/journal ] || grep -qE '^\s*Storage=persistent' /etc/systemd/journald.conf 2>/dev/null; then
    f G04 pass info $T "system journal kept across reboots" ""
  elif have journalctl; then f G04 warn low $T "system journal lost at each reboot" "no /var/log/journal"; fi
  if [ "$ROOT" -eq 1 ]; then
    local n=""
    if have journalctl; then n=$(journalctl -u ssh -u sshd --since '-24h' --no-pager -q 2>/dev/null | grep -cE 'Failed password|Invalid user')
    elif [ -f /var/log/auth.log ]; then n=$(grep -cE 'Failed password|Invalid user' /var/log/auth.log 2>/dev/null); fi
    [ -n "$n" ] && f G05 info info $T "failed SSH logins in the last 24 hours" "$n"
  fi
}

# --------------------------------------------------------------- PATCHES tower
tower_patches() {
  local T=patches uu=off
  if grep -qsE 'Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/*auto-upgrades 2>/dev/null && [ -x /usr/bin/unattended-upgrade ]; then uu=on; fi
  if have apt-get; then
    if [ "$uu" = on ]; then f P01 pass info $T "automatic security updates enabled" ""
    else f P01 fail medium $T "automatic security updates not enabled" "unattended-upgrades off or missing"; fi
    local sec; sec=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -E '^Inst ' | grep -ciE 'security')
    if [ "${sec:-0}" -gt 0 ]; then
      local sev=high; [ "$uu" = on ] && sev=medium
      f P02 fail "$sev" $T "security updates waiting to be installed" "$sec packages (from the last apt update)"
    else f P02 pass info $T "no pending security update in the apt cache" "apt cache age: $(( ( $(date +%s) - $(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0) ) / 86400 )) days"; fi
  fi
  if [ -f /var/run/reboot-required ]; then f P03 warn medium $T "a reboot is required to finish updates (new kernel or libraries not loaded)" "$(head -c 200 /var/run/reboot-required.pkgs 2>/dev/null | paste -sd' ' -)"
  else f P03 pass info $T "no reboot pending" ""; fi
  if have dpkg-query; then
    local run old
    run=$(uname -r | sed -E 's/-[a-z]+$//')
    old=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 'linux-modules-[0-9]*' 2>/dev/null \
          | awk '$1 ~ /^ii/ {print $2}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-[0-9]+' | sort -uV | grep -vx "$run")
    local n; n=$(grep -c . <<<"$old")
    if [ "$n" -gt 1 ]; then f P05 warn medium $T "old kernels still installed (their known flaws count in every vulnerability scan, and they fill /boot)" "running $run; also installed: $(paste -sd' ' - <<<"$old")"
    else f P05 pass info $T "at most one fallback kernel installed" "running $run"; fi
  fi
  . /etc/os-release 2>/dev/null
  local eol=no
  case "${ID:-}" in
    ubuntu) case "${VERSION_ID:-}" in 14.*|16.*|18.*|20.*|21.*|22.10|23.*) eol=yes ;; esac ;;
    debian) [ "${VERSION_ID:-99}" -lt 11 ] 2>/dev/null && eol=yes ;;
  esac
  if [ "$eol" = yes ]; then f P04 fail high $T "operating system out of standard support" "${PRETTY_NAME:-}"
  else f P04 pass info $T "operating system supported" "${PRETTY_NAME:-unknown}"; fi
}

# --------------------------------------------------------------- SECRETS tower
SECRET_RE='(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|SERVICE_ROLE|CREDENTIAL)[A-Z_]*\s*[=:]\s*["'"'"']?[^\s"'"'"'$]{8,}'
tower_secrets() {
  local T=secrets
  [ -n "$ROOTS_OK" ] || { f K01 skip info $T "secret files" "no search root exists"; return; }
  local wr; wr=$(find $ROOTS_OK -xdev \( "${PRUNE[@]}" \) -prune -o -type f \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.p12' -o -name '*.pfx' -o -name 'credentials.json' -o -name '.pgpass' \) \
     -perm -o+r ! -name '*.example' ! -name '*.sample' ! -name '*.template' ! -name '*.dist' ! -name '*.exemple' ! -name '*.pub' ! -path '*/fixtures/*' ! -path '*/test/*' ! -path '*/tests/*' -print 2>/dev/null \
     | while read -r x; do case "$x" in *.pem|*.key) grep -qs 'PRIVATE KEY' "$x" && echo "$x" ;; *) echo "$x" ;; esac; done | head -50)
  if [ -n "$wr" ]; then f K01 fail high $T "secret files readable by every account" "$(wc -l <<<"$wr") files: $(head -5 <<<"$wr" | paste -sd' ' -)"
  else f K01 pass info $T "no secret file readable by every account" "under$ROOTS_OK"; fi

  local named; named=$(find $ROOTS_OK -xdev \( "${PRUNE[@]}" \) -prune -o -type f \( -iname '*credential*' -o -iname '*secret*' -o -iname '*password*' -o -iname '*passwd*' -o -iname '*identifiant*' -o -iname '*mot*de*passe*' \) \
     \( -iname '*.txt' -o -iname '*.md' -o -iname '*.csv' -o -iname '*.json' -o -iname '*.yml' -o -iname '*.yaml' -o -iname '*.ini' -o -iname '*.conf' \) -size -1M -print 2>/dev/null | grep -vE '/(docs?|test|tests|fixtures|examples?|node_modules)/' | head -50)
  if [ -n "$named" ]; then f K02 fail high $T "files whose name says they hold credentials in plain text" "$(wc -l <<<"$named") files: $(head -5 <<<"$named" | paste -sd' ' -)"
  else f K02 pass info $T "no plain-text credential file found by name" ""; fi

  local units=""
  for u in /etc/systemd/system/*.service /etc/systemd/system/*/*.conf /lib/systemd/system/*.service; do
    [ -f "$u" ] || continue
    if grep -qE "^\s*(Environment|ExecStart).*$SECRET_RE" "$u" 2>/dev/null || grep -qiE '^\s*ExecStart=.*--token[= ][A-Za-z0-9_.-]{20,}' "$u"; then units="$units $u"; fi
  done
  local crons=""
  [ "$ROOT" -eq 1 ] && crons=$(grep -lE "$SECRET_RE" /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | paste -sd' ' -)
  if [ -n "$units$crons" ]; then f K03 fail high $T "secrets written inside systemd units or crontabs (unit files are readable by every account)" "$units $crons"
  else f K03 pass info $T "no secret inside systemd units or crontabs" ""; fi

  if [ "$ROOT" -eq 1 ]; then
    local hist=""
    for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history /root/.psql_history /home/*/.psql_history; do
      [ -f "$h" ] || continue
      local c; c=$(grep -cE "$SECRET_RE|PGPASSWORD=|mysql .*-p[^ ]{4,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}" "$h" 2>/dev/null)
      [ "${c:-0}" -gt 0 ] && hist="$hist $h($c)"
    done
    if [ -n "$hist" ]; then f K04 warn medium $T "shell histories contain lines that look like secrets (counts only, values not read out)" "$hist"
    else f K04 pass info $T "no secret-looking line in shell histories" ""; fi
  fi
}

# ---------------------------------------------------------- SUPPLY tower
# Is a path writable by someone other than root? (file or any parent dir)
user_writable() {
  local p; p=$(readlink -f "$1" 2>/dev/null) || return 1
  [ -e "$p" ] || return 1
  while [ "$p" != / ] && [ -n "$p" ]; do
    local o m; o=$(stat -c %u "$p" 2>/dev/null) m=$(stat -c %a "$p" 2>/dev/null)
    [ -z "$o" ] && return 1
    [ "$o" != 0 ] && { echo "$p owned by uid $o"; return 0; }
    # group or other write bit, but a sticky /tmp-like dir does not count for the dir itself
    if [ -d "$p" ] && [ $(( 0$m & 01000 )) -ne 0 ]; then :; elif [ $(( 0$m & 022 )) -ne 0 ]; then echo "$p mode $m"; return 0; fi
    p=$(dirname "$p")
  done
  return 1
}
exec_paths() { # extract absolute paths of executables or scripts from a command line
  grep -oE '(^|[ "=;|&(])/[A-Za-z0-9_./@+-]+' <<<"$1" | sed -E 's/^[ "=;|&(]//' | grep -vE '^/(dev|proc|tmp/\.X|var/log)' | sort -u
}
tower_supply() {
  local T=supply
  needroot C01 $T "root jobs" || return
  local cronsrc; cronsrc=$( { cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -vE '^\s*#' | awk 'NF>6 && $6=="root"{ $1=$2=$3=$4=$5=$6=""; print }';
     cat /var/spool/cron/crontabs/root 2>/dev/null | grep -vE '^\s*(#|$)' | awk '{ if ($1 ~ /^@/) {$1=""} else {$1=$2=$3=$4=$5=""}; print }'; } )
  # Exec lines of the units that run as root. With systemd running, read the
  # effective configuration (drop-ins included: they can reset ExecStart= or set
  # User=); without it (container, chroot), fall back to the unit files.
  local rootexec="" u n usr
  for u in /etc/systemd/system/*.service; do
    [ -f "$u" ] || continue
    if [ -d /run/systemd/system ]; then
      n=$(basename "$u"); usr=$(systemctl show -p User --value "$n" 2>/dev/null)
      [ -n "$usr" ] && [ "$usr" != root ] && [ "$usr" != 0 ] && continue
      rootexec="$rootexec
$(systemctl show -p ExecStart -p ExecStartPre -p ExecStartPost "$n" 2>/dev/null | grep -oE 'argv\[\]=[^;]*' | sed -E 's/^argv\[\]=//')"
    else
      grep -qE '^\s*User=' "$u" && ! grep -qE '^\s*User=(root|0)\s*$' "$u" && continue
      rootexec="$rootexec
$(grep -hE '^\s*Exec(Start|StartPre|StartPost)=' "$u" | sed -E 's/^\s*Exec[A-Za-z]*=[-@+!:]*//')"
    fi
  done

  local pipe; pipe=$(grep -E '(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b' <<<"$cronsrc
$rootexec" | head -3)
  if [ -n "$pipe" ]; then f C01 fail high $T "root downloads and runs code from the internet on a schedule (whoever controls that URL controls this server)" "$(head -c 300 <<<"$pipe")"
  else f C01 pass info $T "no curl|bash run by root on a schedule" ""; fi

  local bad="" p w
  while read -r p; do
    [ -n "$p" ] || continue
    w=$(user_writable "$p") && bad="$bad [$w]"
  done < <( { while read -r l; do exec_paths "$l"; done <<<"$cronsrc"; while read -r l; do exec_paths "$l"; done <<<"$rootexec"; } | sort -u)
  if [ -n "$bad" ]; then f C02 fail critical $T "root runs files that another account can modify (that account becomes root)" "$bad"
  else f C02 pass info $T "every file run by root is owned and writable by root only" ""; fi

  local wu=""
  for u in /etc/systemd/system /etc/systemd/system/* /etc/cron.d /etc/cron.d/* /etc/crontab /etc/sudoers.d /etc/sudoers.d/*; do
    [ -e "$u" ] || continue; [ -L "$u" ] && continue
    w=$(user_writable "$u") && wu="$wu [$w]"
  done
  if [ -n "$wu" ]; then f C03 fail critical $T "system units, cron or sudoers files modifiable by a non-root account" "$wu"
  else f C03 pass info $T "units, cron and sudoers files belong to root" ""; fi

  local suid; suid=$(find /usr/local /opt /home /srv /tmp /var/tmp /var/www -xdev -type f -perm -4000 ! -name chrome-sandbox 2>/dev/null | head -10 | paste -sd' ' -)
  if [ -n "$suid" ]; then f C04 fail high $T "setuid programs outside system directories" "$suid"
  else f C04 pass info $T "no setuid program outside system directories" ""; fi

  local ww; ww=$(find /etc /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin -xdev -type f -perm -o+w ! -type l 2>/dev/null | head -10 | paste -sd' ' -)
  if [ -n "$ww" ]; then f C05 fail critical $T "system files writable by every account" "$ww"
  else f C05 pass info $T "no world-writable file in system directories" ""; fi
}

# ------------------------------------------------------------------ APPS tower
tower_apps() {
  local T=apps
  local procs; procs=$(ps -eo user=,comm= 2>/dev/null | awk '$1=="root" && $2 ~ /^(node|next-server|python3?|python3\.[0-9]+|ruby|java|php|php-fpm.*|gunicorn|uvicorn|PM2.*|deno|bun|dotnet)$/ {print $2}' | sort | uniq -c | awk '{print $2"x"$1}' | paste -sd' ' -)
  if [ -n "$procs" ]; then f R01 warn medium $T "application processes run as root (a bug in the app gives root)" "$procs"
  else f R01 pass info $T "no application process runs as root" ""; fi
  if have docker && docker info >/dev/null 2>&1; then
    local priv="" sock="" hostnet=""
    for id in $(docker ps -q 2>/dev/null); do
      local n i; n=$(docker inspect -f '{{.Name}}' "$id" | tr -d /)
      i=$(docker inspect -f '{{.HostConfig.Privileged}} {{.HostConfig.NetworkMode}} {{range .Mounts}}{{.Source}} {{end}}' "$id")
      [[ "$i" == true* ]] && priv="$priv $n"
      [[ "$i" == *docker.sock* ]] && sock="$sock $n"
      [[ "$i" == *" host "* ]] && hostnet="$hostnet $n"
    done
    if [ -n "$priv$sock" ]; then f R02 fail high $T "containers with full control of the host (privileged or docker.sock mounted)" "privileged:${priv:- none} ; docker.sock:${sock:- none}"
    else f R02 pass info $T "no privileged container and no docker.sock mount" ""; fi
    [ -n "$hostnet" ] && f R03 warn low $T "containers on the host network (their ports skip Docker isolation)" "$hostnet"
  fi
  if [ -S /var/run/docker.sock ]; then
    local m; m=$(stat -c %a /var/run/docker.sock)
    if [ $(( 0$m & 06 )) -ne 0 ]; then f R04 fail critical $T "Docker socket open to every account (any local account is root)" "/var/run/docker.sock mode $m"
    else f R04 pass info $T "Docker socket restricted" "mode $m"; fi
  fi
}

# ---------------------------------------------------------------- KERNEL tower
tower_kernel() {
  local T=kernel bad="" k want v
  while read -r k want; do
    v=$(sysctl -n "$k" 2>/dev/null) || continue
    [ -z "$v" ] && continue
    case "$want" in
      ">="*) [ "$v" -ge "${want#>=}" ] 2>/dev/null || bad="$bad $k=$v" ;;
      *) [ "$v" = "$want" ] || bad="$bad $k=$v" ;;
    esac
  done <<'EOF'
net.ipv4.tcp_syncookies 1
net.ipv4.conf.all.accept_redirects 0
net.ipv4.conf.all.send_redirects 0
net.ipv4.conf.all.accept_source_route 0
net.ipv4.conf.all.rp_filter >=1
net.ipv4.conf.all.log_martians 1
kernel.kptr_restrict >=1
kernel.dmesg_restrict 1
kernel.unprivileged_bpf_disabled >=1
kernel.yama.ptrace_scope >=1
fs.protected_symlinks 1
fs.protected_hardlinks 1
fs.suid_dumpable 0
EOF
  if [ -n "$bad" ]; then f N01 warn low $T "kernel network and memory protections below the usual baseline" "$bad"
  else f N01 pass info $T "kernel protections at baseline" ""; fi
}

# ----------------------------------------------------------------- VAULT tower
tower_vault() {
  local T=vault
  local timers="" crons=""
  have systemctl && timers=$(systemctl list-timers --all --no-legend 2>/dev/null | grep -iE 'backup|sauvegarde|restic|borg|dump|kopia|duplicati|rclone' | grep -v dpkg-db-backup | awk '{print $(NF-1)}' | paste -sd' ' -)
  crons=$(grep -lE 'pg_dump|pg_dumpall|pg_basebackup|mysqldump|mariadb-dump|mongodump|restic|borg |rclone|kopia|duplicity|rsync .*:' /etc/crontab /etc/cron.d/* /etc/cron.daily/* /var/spool/cron/crontabs/* 2>/dev/null | paste -sd' ' -)
  if [ -z "$timers$crons" ]; then f D01 fail high $T "no scheduled backup found on this machine" "searched timers and crontabs"
  else f D01 pass info $T "backups are scheduled" "$timers $crons"; fi
  local off=""
  for t in restic borg rclone kopia duplicity; do have "$t" && off="$off $t"; done
  if [ -z "$off" ] && ! grep -qsE 'rsync .*[a-z0-9]@[a-z0-9.-]+:|scp ' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null; then
    f D02 warn medium $T "no off-site backup tool found (a backup on the same disk dies with it)" ""
  else f D02 info info $T "off-site backup tool present, restore never proven by this round" "$off"; fi
  local full; full=$(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1 && $5+0>=90 {print $6"="$5}' | paste -sd' ' -)
  if [ -n "$full" ]; then
    local sev=medium; grep -qE '=(9[89]|100)%' <<<"$full" && sev=high
    f D03 fail "$sev" $T "disk almost full (logs, databases and backups stop writing)" "$full"
  else f D03 pass info $T "every disk below 90 percent" ""; fi
  local enc=no; have lsblk && lsblk -o TYPE 2>/dev/null | grep -q crypt && enc=yes
  f D04 info info $T "disk encryption at rest" "luks=$enc (on a rented VPS the provider can read an unencrypted disk; sensitive files need application-level encryption)"
}

host_info
tower_access
tower_walls
tower_watch
tower_patches
tower_secrets
tower_supply
tower_apps
tower_kernel
tower_vault

fails=$(awk -F'\t' '$2=="fail"' "$TSV" | wc -l)
echo "round done: $(wc -l <"$TSV") checks, $fails failed -> $TSV"
exit 0
