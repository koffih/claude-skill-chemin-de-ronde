#!/usr/bin/env bash
# Test bench: runs the round inside throwaway Ubuntu 24.04 containers.
#
#   bash tests/banc.sh detection      weak host: every planted fault is reported with its severity
#   bash tests/banc.sh lecture-seule  weak host: the full round (checks + report) changes no file
#   bash tests/banc.sh propre         hardened host: no critical and no high finding
#   bash tests/banc.sh all
#
# Needs Docker. Images are built once (tag chemin-de-ronde-banc:*), containers removed after use.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FAILS=0
ok()  { echo "  ok   $*"; }
ko()  { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }

build() {
  docker image inspect "chemin-de-ronde-banc:$1" >/dev/null 2>&1 && [ -z "${REBUILD:-}" ] && return 0
  echo "building chemin-de-ronde-banc:$1"
  docker build -q -t "chemin-de-ronde-banc:$1" - >/dev/null <<<"$2" || { echo "build failed: $1"; exit 1; }
}

WEAK='FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get install -yq --no-install-recommends openssh-server sudo cron python3 iproute2 procps curl ca-certificates >/dev/null
RUN ssh-keygen -A && mkdir -p /run/sshd \
 && printf "PasswordAuthentication yes\nPermitRootLogin yes\n" > /etc/ssh/sshd_config.d/00-weak.conf \
 && useradd -m -s /bin/bash dev && echo "dev:dev" | chpasswd \
 && echo "dev ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/dev && chmod 440 /etc/sudoers.d/dev \
 && echo "15 4 * * * root curl -fsSL https://example.invalid/install.sh | bash" > /etc/cron.d/maj \
 && mkdir -p /opt/app && printf "DATABASE_PASSWORD=not-a-real-secret-for-test-bench\n" > /opt/app/.env && chmod 644 /opt/app/.env \
 && printf "#!/bin/sh\nexec sleep 1\n" > /home/dev/run.sh && chown dev:dev /home/dev/run.sh && chmod 755 /home/dev/run.sh \
 && printf "[Service]\nExecStart=/home/dev/run.sh\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/app.service'

STRONG='FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get upgrade -yq >/dev/null && apt-get install -yq --no-install-recommends openssh-server cron python3 iproute2 procps nftables unattended-upgrades curl ca-certificates >/dev/null
RUN ssh-keygen -A && mkdir -p /run/sshd \
 && printf "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nMaxAuthTries 3\nX11Forwarding no\nAllowAgentForwarding no\n" > /etc/ssh/sshd_config.d/00-strong.conf \
 && printf "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" > /etc/apt/apt.conf.d/20auto-upgrades \
 && echo "30 2 * * * root pg_dump -Fc app > /var/backups/app.dump" > /etc/cron.d/sauvegarde \
 && mkdir -p /var/log/journal'

# The round runs as root inside the container; scripts are mounted read-only.
run_in() { # run_in <image> <extra docker args> -- <shell script>
  local img="$1"; shift; local args=(); while [ "$1" != -- ]; do args+=("$1"); shift; done; shift
  docker run --rm "${args[@]}" -v "$HERE/scripts:/ronde:ro" "chemin-de-ronde-banc:$img" bash -c "$*"
}

detection() {
  echo "detection (weak host)"
  build weak "$WEAK"
  local tsv
  tsv=$(run_in weak -- '
    python3 -c "import socket,time,os; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"0.0.0.0\",5432)); s.listen(); time.sleep(600)" &
    python3 -c "import socket,os,time; p=\"/var/run/docker.sock\"; s=socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p,0o666); time.sleep(600)" &
    sleep 1.5; bash /ronde/ronde.sh --out /tmp/r >/dev/null 2>&1; cat /tmp/r/findings.tsv')
  [ -n "$tsv" ] || { ko "round produced nothing"; return; }
  local id st sev
  while read -r id st sev what; do
    if awk -F'\t' -v i="$id" -v s="$st" -v v="$sev" '$1==i && $2==s && $3==v {f=1} END {exit !f}' <<<"$tsv"; then ok "$id $st $sev ($what)"
    else ko "$id expected $st $sev ($what), got: $(awk -F'\t' -v i="$id" '$1==i {print $2, $3, $6}' <<<"$tsv")"; fi
  done <<'EOF'
A01 fail critical SSH password login, root allowed
A02 fail high root login with password
A04 fail high sudo NOPASSWD ALL
W01 fail high no firewall
W02 fail critical database port 5432 on 0.0.0.0
K01 fail high world-readable .env
C01 fail high curl|bash in root cron
C02 fail critical root unit runs a script owned by dev
R04 fail critical docker socket mode 666
EOF
  # a secret value must never appear in the findings
  if grep -q 'not-a-real-secret-for-test-bench' <<<"$tsv"; then ko "a secret value leaked into findings.tsv"; else ok "no secret value in findings"; fi
}

lecture_seule() {
  echo "lecture-seule (weak host, full round with report)"
  build weak "$WEAK"
  local out
  out=$(run_in weak -- '
    snap() { find /etc /root /opt /home /var/spool/cron /usr/local /var/www /srv -xdev \( -type f -o -type d -o -type l \) -printf "%p %m %u %g %s %T@\n" 2>/dev/null | sort; \
             find /etc /root /opt /home /var/spool/cron /usr/local -xdev -type f -exec sha256sum {} + 2>/dev/null | sort; }
    snap > /tmp/before
    RONDE_STATE=/tmp/state bash /ronde/chemin-de-ronde.sh --out /tmp/round >/tmp/log 2>&1; echo "exit=$?"
    snap > /tmp/after
    if cmp -s /tmp/before /tmp/after; then echo SAME; else echo DIFF; diff /tmp/before /tmp/after | head -20; fi
    echo "lines=$(wc -l </tmp/before)"
    chmod 600 /opt/app/.env; snap > /tmp/control; cmp -s /tmp/after /tmp/control && echo CONTROL_BLIND || echo CONTROL_SEES
    test -s /tmp/round/rapport.md && echo REPORT')
  grep -q '^exit=0' <<<"$out" && ok "full round exit 0" || ko "full round failed: $out"
  grep -q '^REPORT' <<<"$out" && ok "report written in the round folder" || ko "no report"
  local n; n=$(sed -n 's/^lines=//p' <<<"$out")
  [ "${n:-0}" -gt 300 ] && ok "snapshot covers $n entries" || ko "snapshot too small ($n): proof would be vacuous"
  grep -q '^CONTROL_SEES' <<<"$out" && ok "positive control: a deliberate chmod is detected by the snapshot" || ko "the snapshot does not detect a deliberate change"
  if grep -q '^SAME' <<<"$out"; then ok "no file, mode, owner or timestamp changed"; else ko "the round changed files: $(sed -n '/^DIFF/,$p' <<<"$out")"; fi
}

propre() {
  echo "propre (hardened host)"
  build strong "$STRONG"
  local tsv
  tsv=$(run_in strong --cap-add NET_ADMIN -- '
    nft add table inet f && nft "add chain inet f input { type filter hook input priority 0; policy drop; }" && nft add rule inet f input ct state established,related accept && nft add rule inet f input iif lo accept && nft add rule inet f input tcp dport { 22, 80, 443 } accept
    bash /ronde/ronde.sh --out /tmp/r >/dev/null 2>&1; cat /tmp/r/findings.tsv')
  [ -n "$tsv" ] || { ko "round produced nothing"; return; }
  local bad; bad=$(awk -F'\t' '($2=="fail"||$2=="warn") && ($3=="critical"||$3=="high") {print $1, $3, $5, $6}' <<<"$tsv")
  if [ -z "$bad" ]; then ok "no critical or high finding ($(awk -F'\t' '$2=="pass"' <<<"$tsv" | wc -l) checks pass)"
  else ko "unexpected findings on the hardened host:"; echo "$bad" | sed 's/^/       /'; fi
  awk -F'\t' '$1=="W01" && $2=="pass" {f=1} END {exit !f}' <<<"$tsv" && ok "nftables default drop recognised" || ko "W01 did not see the nftables policy"
  awk -F'\t' '$1=="A01" && $2=="pass" {f=1} END {exit !f}' <<<"$tsv" && ok "key-only SSH recognised" || ko "A01 did not pass"
}

case "${1:-all}" in
  detection) detection ;;
  lecture-seule) lecture_seule ;;
  propre) propre ;;
  all) detection; lecture_seule; propre ;;
  *) echo "usage: $0 detection|lecture-seule|propre|all" >&2; exit 2 ;;
esac
echo "failures: $FAILS"
[ "$FAILS" -eq 0 ]
