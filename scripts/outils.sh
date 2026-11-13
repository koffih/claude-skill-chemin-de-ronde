#!/usr/bin/env bash
# chemin-de-ronde: the specialist tools a round can call on top of its own checks.
#
#   outils.sh detect                       which tools are present
#   outils.sh install [lynis|trivy|gitleaks|all]
#                                          download pinned versions into $STATE/bin,
#                                          verify a SHA-256 written in this file, nothing else
#   sudo outils.sh run --out DIR [--roots "/opt /srv"] [--images] [--only lynis,trivy,gitleaks]
#                                          run them read-only, write DIR/tools.tsv
#
# The tools are never installed system-wide and never configured to change the
# host: Lynis audits, Trivy and Gitleaks scan. Their raw reports stay in DIR.
# Gitleaks always runs with --redact: no secret value reaches a report.
set -uo pipefail
export LC_ALL=C

if [ "$(id -u)" -eq 0 ]; then STATE="${RONDE_STATE:-/var/lib/chemin-de-ronde}"; else STATE="${RONDE_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/chemin-de-ronde}"; fi
BIN="$STATE/bin"

# Pinned versions. Change the version AND the hash together, after checking the
# release is at least two weeks old (a compromised release is usually pulled within days).
LYNIS_V=3.1.7;     LYNIS_SHA=48d829d0dc2c583a3e838cc09a7190b69a3af844bcb913c7cf9c0226b04b95c5
TRIVY_V=0.76.1;    TRIVY_SHA=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
GITLEAKS_V=8.30.1; GITLEAKS_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

have() { command -v "$1" >/dev/null 2>&1; }
tool_path() { # prefer our pinned copy, then the system one
  case "$1" in
    lynis) [ -x "$BIN/lynis/lynis" ] && { echo "$BIN/lynis/lynis"; return; }; have lynis && command -v lynis ;;
    *) [ -x "$BIN/$1" ] && { echo "$BIN/$1"; return; }; have "$1" && command -v "$1" ;;
  esac
}

fetch() { # fetch URL SHA DEST
  local tmp; tmp=$(mktemp)
  curl -fsSL --max-time 300 -o "$tmp" "$1" || { echo "download failed: $1" >&2; rm -f "$tmp"; return 1; }
  local got; got=$(sha256sum "$tmp" | awk '{print $1}')
  if [ "$got" != "$2" ]; then echo "SHA-256 mismatch for $1 (got $got): refused" >&2; rm -f "$tmp"; return 1; fi
  mv "$tmp" "$3"
}

install_one() {
  [ "$(uname -m)" = x86_64 ] || { echo "$1: pinned binaries are x86_64 only; on $(uname -m) use the distribution package" >&2; return 1; }
  mkdir -p "$BIN"; chmod 700 "$STATE" 2>/dev/null
  local t; t=$(mktemp -d)
  case "$1" in
    lynis)
      fetch "https://github.com/CISOfy/lynis/archive/refs/tags/$LYNIS_V.tar.gz" "$LYNIS_SHA" "$t/l.tgz" || return 1
      rm -rf "$BIN/lynis"; mkdir -p "$BIN/lynis"; tar -xzf "$t/l.tgz" -C "$BIN/lynis" --strip-components=1 ;;
    trivy)
      fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_V/trivy_${TRIVY_V}_Linux-64bit.tar.gz" "$TRIVY_SHA" "$t/t.tgz" || return 1
      tar -xzf "$t/t.tgz" -C "$t" trivy && install -m 755 "$t/trivy" "$BIN/trivy" ;;
    gitleaks)
      fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_V/gitleaks_${GITLEAKS_V}_linux_x64.tar.gz" "$GITLEAKS_SHA" "$t/g.tgz" || return 1
      tar -xzf "$t/g.tgz" -C "$t" gitleaks && install -m 755 "$t/gitleaks" "$BIN/gitleaks" ;;
    *) echo "unknown tool: $1" >&2; return 2 ;;
  esac
  # Lynis refuses to run as root from files root does not own.
  [ "$(id -u)" -eq 0 ] && chown -R root:root "$BIN"
  rm -rf "$t"; echo "installed $1 in $BIN"
}

clean() { tr '\t\n\r' '   ' <<<"$*" | sed 's/  */ /g; s/^ //; s/ $//' | cut -c1-600; }
f() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$(clean "$5")" "$(clean "$6")" >>"$TSV"; }

run_lynis() {
  local L; L=$(tool_path lynis) || { f X-LYNIS skip info tools "Lynis not installed" "outils.sh install lynis"; return; }
  [ "$(id -u)" -eq 0 ] || { f X-LYNIS skip info tools "Lynis needs root" ""; return; }
  local d; d=$(dirname "$L")
  ( cd "$d" && timeout 900 "$L" audit system --quick --no-colors --no-log --report-file "$OUT/lynis-report.dat" >"$OUT/lynis.txt" 2>&1 )
  [ -s "$OUT/lynis-report.dat" ] || { f X-LYNIS skip info tools "Lynis produced no report" "see lynis.txt"; return; }
  local hi; hi=$(awk -F= '$1=="hardening_index"{print $2}' "$OUT/lynis-report.dat")
  local nw ns; nw=$(grep -c '^warning\[\]=' "$OUT/lynis-report.dat"); ns=$(grep -c '^suggestion\[\]=' "$OUT/lynis-report.dat")
  f X-LYNIS info info tools "Lynis hardening index (0-100, a trend to follow, not a goal)" "index=$hi warnings=$nw suggestions=$ns version=$("$L" show version 2>/dev/null)"
  grep '^warning\[\]=' "$OUT/lynis-report.dat" | cut -d= -f2- | while IFS='|' read -r code text _; do
    f "L-$code" fail medium tools "Lynis warning: $text" "lynis show details $code"
  done
}

run_trivy() {
  local T; T=$(tool_path trivy) || { f X-TRIVY skip info tools "Trivy not installed" "outils.sh install trivy"; return; }
  export TRIVY_CACHE_DIR="$STATE/trivy-cache"
  timeout 1800 "$T" rootfs --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --format json \
    --skip-dirs /proc --skip-dirs /sys --skip-dirs /var/lib/docker --skip-dirs /home --skip-dirs /snap \
    --output "$OUT/trivy-rootfs.json" / >"$OUT/trivy.txt" 2>&1
  summarize_trivy "$OUT/trivy-rootfs.json" T-ROOTFS "operating system and installed language packages"
  if [ "${IMAGES:-0}" -eq 1 ] && have docker && docker info >/dev/null 2>&1; then
    local i=0
    for img in $(docker ps --format '{{.Image}}' | sort -u); do
      i=$((i+1))
      timeout 900 "$T" image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --format json --output "$OUT/trivy-image-$i.json" "$img" >>"$OUT/trivy.txt" 2>&1
      summarize_trivy "$OUT/trivy-image-$i.json" "T-IMG$i" "image $img"
    done
  fi
}
summarize_trivy() { # file id label
  [ -s "$1" ] || { f "$2" skip info tools "Trivy scan of $3 failed" "see trivy.txt"; return; }
  local s; s=$(python3 -I - "$1" <<'PY'
import json,sys,collections
d=json.load(open(sys.argv[1])); c=collections.Counter(); pk=collections.Counter()
for r in d.get("Results") or []:
    for v in r.get("Vulnerabilities") or []:
        c[v["Severity"]]+=1; pk[v["PkgName"]]+=1
top=" ".join(f"{p}({n})" for p,n in pk.most_common(6))
print(c["CRITICAL"], c["HIGH"], top)
PY
)
  local cr hi top; read -r cr hi top <<<"$s"
  if [ "${cr:-0}" -gt 0 ]; then f "$2" fail high tools "Trivy: fixable critical vulnerabilities in $3" "critical=$cr high=$hi, packages: $top"
  elif [ "${hi:-0}" -gt 0 ]; then f "$2" fail medium tools "Trivy: fixable high vulnerabilities in $3" "high=$hi, packages: $top"
  else f "$2" pass info tools "Trivy: no fixable high or critical vulnerability in $3" ""; fi
}

run_gitleaks() {
  local G; G=$(tool_path gitleaks) || { f X-GITLEAKS skip info tools "Gitleaks not installed" "outils.sh install gitleaks"; return; }
  local n=0 r
  : >"$OUT/gitleaks-summary.txt"
  for r in $ROOTS; do
    [ -d "$r" ] || continue
    n=$((n+1))
    timeout 1200 "$G" dir "$r" --redact --no-banner --exit-code 0 --max-target-megabytes 2 \
      --report-format json --report-path "$OUT/gitleaks-$n.json" >/dev/null 2>>"$OUT/gitleaks.txt"
  done
  local s; s=$(python3 -I - "$OUT"/gitleaks-*.json <<'PY'
import json,sys,collections
files=collections.Counter(); rules=collections.Counter()
skip=("/node_modules/","/.git/","/site-packages/","/test/","/tests/","/fixtures/","/examples/",".example",".sample",".exemple")
for p in sys.argv[1:]:
    try: d=json.load(open(p))
    except Exception: continue
    for x in d or []:
        fn=x.get("File","")
        if any(s in fn for s in skip): continue
        files[fn]+=1; rules[x.get("RuleID","?")]+=1
print(len(files), sum(files.values()), " ".join(f"{r}({n})" for r,n in rules.most_common(5)), "|", " ".join(f for f,_ in files.most_common(6)))
PY
)
  local nf nl rest; read -r nf nl rest <<<"$s"
  if [ "${nf:-0}" -gt 0 ]; then f X-GITLEAKS fail high tools "Gitleaks: secrets written in files under $ROOTS (values redacted)" "$nl findings in $nf files; rules: $rest"
  else f X-GITLEAKS pass info tools "Gitleaks: no secret found in files under $ROOTS" ""; fi
}

cmd="${1:-detect}"; shift || true
case "$cmd" in
  detect)
    for t in lynis trivy gitleaks; do p=$(tool_path $t) && echo "$t: $p" || echo "$t: absent"; done
    for t in crowdsec fail2ban-client falco aide osqueryi wazuh-agentd nmap; do have $t && echo "$t: present" ; done; exit 0 ;;
  install)
    what="${1:-all}"; [ "$what" = all ] && what="lynis trivy gitleaks"
    rc=0; for t in $what; do install_one "$t" || rc=1; done; exit $rc ;;
  run)
    OUT=""; ROOTS="/opt /srv /home /root /var/www"; IMAGES=0; ONLY="lynis,trivy,gitleaks"
    while [ $# -gt 0 ]; do case "$1" in
      --out) OUT="$2"; shift 2 ;; --roots) ROOTS="$2"; shift 2 ;; --images) IMAGES=1; shift ;; --only) ONLY="$2"; shift 2 ;;
      *) echo "unknown option: $1" >&2; exit 2 ;; esac; done
    [ -n "$OUT" ] || { echo "--out DIR is required" >&2; exit 2; }
    mkdir -p "$OUT"; TSV="$OUT/tools.tsv"; : >"$TSV"
    [[ ",$ONLY," == *,lynis,* ]] && run_lynis
    [[ ",$ONLY," == *,trivy,* ]] && run_trivy
    [[ ",$ONLY," == *,gitleaks,* ]] && run_gitleaks
    echo "tools done -> $TSV"; exit 0 ;;
  -h|--help) sed -n '2,14p' "$0" ;;
  *) echo "unknown command: $cmd (detect, install, run)" >&2; exit 2 ;;
esac
