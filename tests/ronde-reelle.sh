#!/usr/bin/env bash
# A real round on the machine this runs on, as root, with whatever specialist tools are installed.
# Passes when the report exists, has a score, and covers at least 30 checks.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
sudo bash "$HERE/scripts/chemin-de-ronde.sh" --out "$OUT/round"
sudo python3 -I -c '
import json,sys
r=json.load(open(sys.argv[1]))
assert r["as_root"], "not run as root"
assert isinstance(r["score"], int) and 0 <= r["score"] <= 100, "no score"
assert r["checks"] >= 30, "only %d checks" % r["checks"]
print("report ok: %s %d/100 %s, %d checks, open %s" % (r["host"], r["score"], r["grade"], r["checks"], r["counts"]))
' "$OUT/round/rapport.json"
sudo test -s "$OUT/round/rapport.md"
echo "round folder: $OUT/round"
