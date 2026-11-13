#!/usr/bin/env python3
"""Two rounds on the same host: the report scores, sorts, gives a fix, and states the delta."""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RAPPORT = os.path.join(HERE, "..", "scripts", "rapport.py")
fails = 0


def check(cond, what):
    global fails
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        fails += 1


def round_dir(base, name, rows):
    d = os.path.join(base, name)
    os.makedirs(d)
    with open(os.path.join(d, "findings.tsv"), "w") as f:
        for r in rows:
            f.write("\t".join(r) + "\n")
    with open(os.path.join(d, "host.tsv"), "w") as f:
        f.write("hostname\tbanc-host\nos\tUbuntu 24.04\nkernel\t6.8\nroot\t1\ndate\t2026-11-13T00:00:00Z\n")
    return d


with tempfile.TemporaryDirectory() as t:
    state = os.path.join(t, "state")
    r1 = round_dir(t, "r1", [
        ("A01", "fail", "critical", "access", "SSH accepts passwords", "passwordauthentication=yes"),
        ("N01", "warn", "low", "kernel", "kernel protections", "fs.suid_dumpable=2"),
        ("K01", "fail", "high", "secrets", "secret files readable", "/opt/app/.env"),
        ("P04", "pass", "info", "patches", "os supported", ""),
    ])
    p = subprocess.run([sys.executable, "-I", RAPPORT, r1, "--state", state], capture_output=True, text=True)
    check(p.returncode == 0, "first report exits 0")
    j1 = json.load(open(os.path.join(r1, "rapport.json")))
    check(j1["score"] == 100 - 25 - 10 - 1, f"score is 100 minus weights (got {j1['score']})")
    check(j1["grade"] == "Open breach", "a critical finding forces the lowest grade")
    check([f["id"] for f in j1["open"]] == ["A01", "K01", "N01"], "findings sorted critical, high, low")
    check(all(f.get("fix") for f in j1["open"]), "every open finding carries a fix")
    check(j1["delta"] is None, "first round has no delta")
    md1 = open(os.path.join(r1, "rapport.md")).read()
    check(md1.startswith("# Round on banc-host: 64/100"), "markdown title gives host and score")
    check("First round recorded" in md1, "markdown says it is the first round")

    r2 = round_dir(t, "r2", [
        ("A01", "pass", "info", "access", "SSH keys only", ""),
        ("K01", "fail", "high", "secrets", "secret files readable", "/opt/app/.env"),
        ("W06", "fail", "high", "walls", "containers publish on 0.0.0.0", "db"),
        ("N01", "warn", "low", "kernel", "kernel protections", "fs.suid_dumpable=2"),
    ])
    p = subprocess.run([sys.executable, "-I", RAPPORT, r2, "--state", state], capture_output=True, text=True)
    check(p.returncode == 0, "second report exits 0")
    j2 = json.load(open(os.path.join(r2, "rapport.json")))
    d = j2["delta"] or {}
    check(d.get("fixed") == ["A01"], f"delta: A01 fixed (got {d.get('fixed')})")
    check(d.get("new") == ["W06"], f"delta: W06 new (got {d.get('new')})")
    check(d.get("still_open") == ["K01", "N01"], f"delta: K01 and N01 still open (got {d.get('still_open')})")
    check(d.get("previous_score") == 64, "delta carries the previous score")
    md2 = open(os.path.join(r2, "rapport.md")).read()
    check("- Fixed: A01" in md2 and "- New: W06" in md2, "markdown shows new and fixed")
    hist = os.path.join(state, "history", "banc-host")
    check(len(os.listdir(hist)) == 2, "both rounds filed in the history")
    check(oct(os.stat(state).st_mode & 0o777) == "0o700", "state folder is private (700)")

print(f"failures: {fails}")
sys.exit(1 if fails else 0)
