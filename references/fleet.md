# Rounds across a fleet

## Principle

Each server runs its own round; reports travel, root access does not. An agent machine that holds root SSH keys to every server, to audit them, becomes the single best target of the fleet. So:

- install the skill on each server, in the account that runs Claude Code there (the catalog installer does it, and its daily cron keeps it up to date);
- run the round there as root (`sudo`), by hand or from that server's own Claude Code session;
- if you must start rounds from one machine, use an account that can run exactly one command with sudo, the round script, owned by root:
  `ops ALL=(root) NOPASSWD: /usr/bin/bash /opt/chemin-de-ronde/scripts/chemin-de-ronde.sh *`
  with a root-owned copy of the scripts, not the copy in a user's home (otherwise C02 applies to the round itself).

## Cadence

- Monthly round on every server, and after every big change (new app, new domain, new container).
- Weekly on servers holding sensitive data.
- Right after an incident, and again after the fixes, to see them in the delta.

## Collecting

Each round leaves `rapport.json` in `/var/lib/chemin-de-ronde/rounds/<timestamp>/`. To build a fleet table, copy those files to one place (pull them with scp as an unprivileged account allowed to read only that folder, or have each server push them), then for example:

```bash
python3 - <<'PY'
import json, glob
rows = [json.load(open(p)) for p in sorted(glob.glob("reports/*/rapport.json"))]
rows.sort(key=lambda r: r["score"])
print("| host | score | grade | critical | high | since last |")
print("|---|---|---|---|---|---|")
for r in rows:
    d = r.get("delta") or {}
    print(f"| {r['host']} | {r['score']} | {r['grade']} | {r['counts']['critical']} | {r['counts']['high']} | "
          f"+{len(d.get('new', []))} / -{len(d.get('fixed', []))} |")
PY
```

Work the fleet table from the top: the servers with a critical first, then the findings that come back on many servers (those are the ones worth a shared Ansible role or a change in the server template).

## Outside view

Once per round, from a machine outside the provider network: `nmap -Pn -p- --open <ip>` per server. Keep the result next to the report; the inside and the outside views together are the real picture.
