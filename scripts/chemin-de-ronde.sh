#!/usr/bin/env bash
# chemin-de-ronde: one full round = own checks + specialist tools present + report.
#
#   sudo bash chemin-de-ronde.sh [--roots "/opt /srv /home /root /var/www"] [--no-tools] [--images] [--out DIR]
#
# Read only. The round folder (default: $STATE/rounds/<UTC timestamp>) holds
# findings.tsv, tools.tsv, raw tool reports, rapport.md and rapport.json.
# Exit code: 0 always when the round ran; 3 if the report could not be built.
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
if [ "$(id -u)" -eq 0 ]; then STATE="${RONDE_STATE:-/var/lib/chemin-de-ronde}"; else STATE="${RONDE_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/chemin-de-ronde}"; fi
export RONDE_STATE="$STATE"

ROOTS="/opt /srv /home /root /var/www"; TOOLS=1; IMAGES=""; OUT=""
while [ $# -gt 0 ]; do case "$1" in
  --roots) ROOTS="$2"; shift 2 ;; --no-tools) TOOLS=0; shift ;; --images) IMAGES=--images; shift ;;
  --out) OUT="$2"; shift 2 ;; -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;; esac; done

umask 077
[ -n "$OUT" ] || OUT="$STATE/rounds/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
[ "$(id -u)" -eq 0 ] || echo "not root: SSH, sudo, firewall, root jobs and some secrets checks will be skipped" >&2

bash "$HERE/ronde.sh" --out "$OUT" --roots "$ROOTS"
if [ "$TOOLS" -eq 1 ]; then
  present=""; detected=$(bash "$HERE/outils.sh" detect)
  for t in lynis trivy gitleaks; do grep -q "^$t: /" <<<"$detected" && present="$present,$t"; done
  if [ -n "$present" ]; then bash "$HERE/outils.sh" run --out "$OUT" --roots "$ROOTS" $IMAGES --only "${present#,}"
  else echo "no specialist tool installed (bash $HERE/outils.sh install all): own checks only"; fi
fi
python3 -I "$HERE/rapport.py" "$OUT" --state "$STATE" || exit 3
