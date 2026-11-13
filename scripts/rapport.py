#!/usr/bin/env python3
"""chemin-de-ronde: turn one round into a report, and compare it with the last one.

    python3 -I rapport.py ROUND_DIR [--state DIR] [--no-history]

Reads ROUND_DIR/findings.tsv, ROUND_DIR/tools.tsv (optional) and ROUND_DIR/host.tsv.
Writes ROUND_DIR/rapport.md and ROUND_DIR/rapport.json, then files the round in
STATE/history/<hostname>/<UTC timestamp>/ so the next round can say what is new,
what was fixed and what is still open. Standard library only.
"""
import argparse, json, os, shutil, sys
from datetime import datetime, timezone

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

# One line per check: what to do. The why and the safe order are in references/fixes.md.
FIX = {
    "A01": "Set PasswordAuthentication no and KbdInteractiveAuthentication no in sshd, after a key login was proven in a second session.",
    "A02": "Set PermitRootLogin prohibit-password (or no) in sshd.",
    "A03": "Remove or renumber every uid-0 account other than root (an extra uid 0 is a classic backdoor: find who created it).",
    "A04": "Replace NOPASSWD ALL with the few exact commands the account needs, or require the password.",
    "A05": "Keep the docker group to accounts that are already trusted as root; deploy through a script run by sudo instead.",
    "A06": "Compare each key with the people and machines that should have access; remove the rest.",
    "A07": "Set MaxAuthTries 3, X11Forwarding no, AllowAgentForwarding no unless needed.",
    "A08": "chmod 600 the authorized_keys file and chown it to its account.",
    "W01": "Enable a host firewall with incoming denied by default (ufw default deny incoming; allow 22, 80, 443), with a timed rollback.",
    "W02": "Bind the database or API to 127.0.0.1 (or a private network) and reach it through an SSH tunnel or a VPN; never rely on the firewall alone.",
    "W03": "Bind admin consoles and dev servers to 127.0.0.1 and put them behind the reverse proxy with authentication, or a VPN.",
    "W04": "For each port: know which program it is, then bind it to 127.0.0.1 or close it.",
    "W05": "Bind to 127.0.0.1 or the VPN address instead of the local network address.",
    "W06": "Publish container ports as 127.0.0.1:PORT:PORT in compose files, or filter the DOCKER-USER chain: UFW does not see Docker NAT.",
    "W07": "Add a default nginx server that returns 444 for unknown hosts on 80 and 443.",
    "W08": "Check the certbot timer and its last log; renew by hand once and fix the cause.",
    "G01": "Install CrowdSec (behavioural, shared blocklists) or fail2ban with an sshd jail.",
    "G02": "Install auditd with rules on identity files, sudoers, SSH and cron.",
    "G03": "Add Falco or Wazuh (central alerts), or at least AIDE for file integrity.",
    "G04": "mkdir -p /var/log/journal and restart systemd-journald (or Storage=persistent).",
    "P01": "apt install unattended-upgrades and enable it (dpkg-reconfigure -plow unattended-upgrades).",
    "P02": "apt update && apt upgrade during a quiet hour, then check the services.",
    "P03": "Reboot during a quiet hour, after checking every service restarts on its own.",
    "P04": "Plan the move to a supported release (do-release-upgrade on a copy first).",
    "K01": "chmod 600 each file (owner only); if the file was ever world-readable on a shared host, rotate what it holds.",
    "K02": "Move the content to a password manager or an encrypted file (sops, age), delete the plain copy, rotate if it left the box.",
    "K03": "Move secrets to an EnvironmentFile= owned by root with mode 600 (or systemd credentials), then rotate them: unit files are world-readable.",
    "K04": "Rotate the secrets that were typed on the command line, then clear those history lines; pass secrets through files or prompts.",
    "C01": "Pin what is installed: clone at a fixed commit or verify a checksum, run it as the account that needs it, not root.",
    "C02": "chown root:root and chmod 755 each file root runs (and its parent folders), or run the job as the account that owns it.",
    "C03": "chown root:root and chmod 644 (units, cron) or 440 (sudoers) these files; then find out how they became writable.",
    "C04": "Check where each setuid file comes from; remove the setuid bit (chmod u-s) unless a known package needs it.",
    "C05": "chmod o-w each file and find which install made it world-writable.",
    "R01": "Run each application under its own unprivileged account (User= in systemd, or pm2 under a service account).",
    "R02": "Drop privileged: true; mount the docker socket only into tools that must manage Docker, read-only, or use a socket proxy.",
    "R03": "Use bridge networking with 127.0.0.1-bound ports unless host networking is really needed.",
    "R04": "chmod 660 /var/run/docker.sock (root:docker).",
    "N01": "Write the missing values in /etc/sysctl.d/90-hardening.conf and run sysctl --system.",
    "D01": "Schedule a database dump and a file backup, then prove a restore on another machine.",
    "D02": "Copy backups off the machine (restic or borg to another provider), encrypted, and test a restore each month.",
    "D03": "Find what grows (du -xh --max-depth=2 /), clean caches and logs, and add log rotation.",
    "D04": "For identity documents and other sensitive files, encrypt at the application level with a key that does not live on this disk.",
    "T-ROOTFS": "apt upgrade for system packages; update the listed language packages in their project and redeploy.",
    "X-GITLEAKS": "Open the raw gitleaks report in the round folder, rotate each real secret, then move it out of the files (env file mode 600, sops, a vault).",
}
GRADES = [(90, "Citadel"), (75, "Stronghold"), (50, "Cracked walls"), (0, "Open breach")]


def read_tsv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    for line in open(path, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 6:
            continue
        rows.append(dict(zip(["id", "status", "severity", "tower", "title", "evidence"], parts[:6])))
    return rows


def fix_for(fid):
    if fid in FIX:
        return FIX[fid]
    if fid.startswith("L-"):
        return f"Run `lynis show details {fid[2:]}` for the test and its advice."
    if fid.startswith("T-IMG"):
        return "Rebuild the image on an updated base and redeploy the container."
    return ""


def score_of(findings):
    lost = sum(WEIGHT.get(f["severity"], 0) for f in findings if f["status"] in ("fail", "warn"))
    s = max(0, 100 - lost)
    grade = next(g for t, g in GRADES if s >= t)
    if any(f["status"] == "fail" and f["severity"] == "critical" for f in findings):
        grade = "Open breach"
    return s, grade


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("round_dir")
    ap.add_argument("--state", default=None)
    ap.add_argument("--no-history", action="store_true")
    a = ap.parse_args()
    d = a.round_dir
    state = a.state or ("/var/lib/chemin-de-ronde" if os.geteuid() == 0 else
                        os.path.join(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")), "chemin-de-ronde"))

    host = {}
    if os.path.exists(os.path.join(d, "host.tsv")):
        for line in open(os.path.join(d, "host.tsv")):
            k, _, v = line.rstrip("\n").partition("\t")
            host[k] = v
    hostname = host.get("hostname", "unknown")
    findings = read_tsv(os.path.join(d, "findings.tsv")) + read_tsv(os.path.join(d, "tools.tsv"))
    if not findings:
        print("no findings.tsv in " + d, file=sys.stderr)
        return 2
    open_ = [f for f in findings if f["status"] in ("fail", "warn")]
    open_.sort(key=lambda f: (SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9, f["id"]))
    for f in open_:
        f["fix"] = fix_for(f["id"])
    score, grade = score_of(findings)

    # previous round of the same host
    hist = os.path.join(state, "history", hostname)
    prev = None
    if os.path.isdir(hist):
        rounds = sorted(x for x in os.listdir(hist) if os.path.exists(os.path.join(hist, x, "rapport.json")))
        if rounds:
            prev = json.load(open(os.path.join(hist, rounds[-1], "rapport.json")))
    now_ids = {f["id"] for f in open_}
    delta = None
    if prev:
        prev_ids = {f["id"] for f in prev.get("open", [])}
        delta = {
            "previous_date": prev.get("date"), "previous_score": prev.get("score"),
            "new": sorted(now_ids - prev_ids), "fixed": sorted(prev_ids - now_ids),
            "still_open": sorted(now_ids & prev_ids),
        }

    counts = {s: sum(1 for f in open_ if f["severity"] == s) for s in SEV_ORDER}
    report = {
        "host": hostname, "os": host.get("os"), "kernel": host.get("kernel"),
        "as_root": host.get("root") == "1", "date": host.get("date") or datetime.now(timezone.utc).isoformat(),
        "score": score, "grade": grade, "counts": counts, "checks": len(findings),
        "skipped": [f["id"] for f in findings if f["status"] == "skip"],
        "open": open_, "info": [f for f in findings if f["status"] == "info"], "delta": delta,
    }
    json.dump(report, open(os.path.join(d, "rapport.json"), "w"), indent=2, ensure_ascii=False)

    L = []
    L.append(f"# Round on {hostname}: {score}/100, {grade}")
    L.append("")
    L.append(f"{report['date']} . {report['os']} . kernel {report['kernel']} . "
             f"{'as root' if report['as_root'] else 'WITHOUT root: partial view'} . {len(findings)} checks")
    L.append("")
    L.append("| critical | high | medium | low |")
    L.append("|---|---|---|---|")
    L.append(f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |")
    L.append("")
    if delta:
        L.append(f"## Since the last round ({delta['previous_date']}, {delta['previous_score']}/100)")
        L.append("")
        L.append(f"- New: {', '.join(delta['new']) or 'none'}")
        L.append(f"- Fixed: {', '.join(delta['fixed']) or 'none'}")
        L.append(f"- Still open: {', '.join(delta['still_open']) or 'none'}")
        L.append("")
    else:
        L.append("First round recorded for this host: the next one will show what changed.")
        L.append("")
    L.append("## Findings, most severe first")
    L.append("")
    if not open_:
        L.append("Nothing open.")
    for f in open_:
        L.append(f"### {f['id']} [{f['severity']}] {f['title']}")
        if f["evidence"]:
            L.append(f"- Seen: {f['evidence']}")
        if f.get("fix"):
            L.append(f"- Fix: {f['fix']}")
        L.append("")
    if report["info"]:
        L.append("## For the record")
        L.append("")
        for f in report["info"]:
            L.append(f"- {f['id']} {f['title']}: {f['evidence']}")
        L.append("")
    if report["skipped"]:
        L.append(f"Not checked: {', '.join(report['skipped'])} (see findings.tsv for why).")
        L.append("")
    L.append("This round reads the machine from the inside. It does not see the provider firewall: "
             "confirm the open ports with a scan from another machine (`nmap -Pn -p- <ip>`).")
    open(os.path.join(d, "rapport.md"), "w").write("\n".join(L) + "\n")

    if not a.no_history:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        dest = os.path.join(hist, stamp)
        os.makedirs(dest, exist_ok=True)
        os.chmod(state, 0o700) if os.path.isdir(state) else None
        for n in ("findings.tsv", "tools.tsv", "host.tsv", "rapport.md", "rapport.json"):
            if os.path.exists(os.path.join(d, n)):
                shutil.copy2(os.path.join(d, n), dest)
    print(f"{hostname}: {score}/100 {grade} . critical={counts['critical']} high={counts['high']} "
          f"medium={counts['medium']} low={counts['low']} -> {os.path.join(d, 'rapport.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
