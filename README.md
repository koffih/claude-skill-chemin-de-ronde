# claude-skill-chemin-de-ronde

A [Claude Code](https://claude.com/claude-code) skill that walks a periodic,
**read-only** security round on a Linux server and tells you what to harden.

The *chemin de ronde* is the walkway along the top of a castle wall, where the
watch makes its rounds tower by tower. This skill does the same on a server: it
looks everywhere, touches nothing, and reports what is cracked.

- **Never changes the server.** No setting, restart or system package; a test
  bench proves that no file, mode or owner changes during a round.
- **Nine towers, 40 native checks** chosen from real audits of small fleets:
  SSH and accounts, exposed databases and consoles, Docker ports that bypass
  UFW, secrets in clear (files, units, crontabs, histories), root jobs that
  another account can modify, `curl | bash` as root, patches, kernel, backups.
- **Calls the specialists** when present: Lynis (hardening), Trivy
  (vulnerabilities in packages and images), Gitleaks (secrets, always redacted).
  Pinned versions, SHA-256 written in the script, installed only in the skill's
  state folder.
- **One report**: a score, findings sorted by severity with one fix each, a mark
  on fixes that can lock you out, and the delta since the last round (new,
  fixed, still open).
- **Never prints a secret value**: files and counts only.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/koffih/claude-skill-chemin-de-ronde/main/install.sh | bash
```

Options after `bash -s --`: `--project`, `--uninstall`. Or through the catalog
[koffih/claude-skills](https://github.com/koffih/claude-skills):
`install.sh chemin-de-ronde`.

Then ask Claude Code: "walk the security round on this server", "is this server
secure?", "what should I harden here?", or in French "fais la ronde".

## Use the scripts directly

```bash
cd ~/.claude/skills/chemin-de-ronde/scripts
sudo bash outils.sh install all          # optional: Lynis, Trivy, Gitleaks (pinned)
sudo bash chemin-de-ronde.sh             # full round, report in /var/lib/chemin-de-ronde/rounds/<time>/
sudo bash chemin-de-ronde.sh --images    # also scan the images of running containers
sudo bash ronde.sh --out /tmp/r          # native checks only, findings.tsv
```

Without root the round still runs and marks what it could not see.

## What it does not do

Apply fixes (see `references/fixes.md` for each one, with the precautions for
SSH and firewall changes), scan from outside (run `nmap` from another machine),
test web applications (ZAP and Nuclei only on your own sites), or replace a
compliance assessment (`references/sensitive-data.md` lists what a server
holding identity documents also needs).

## Tests

```bash
bash tests/banc.sh all          # throwaway Ubuntu 24.04 containers: detection, read-only proof, hardened host
python3 -I tests/test_rapport.py
```

## Licence

MIT. The tools it calls keep their own licences (Lynis GPL-3.0, Trivy
Apache-2.0, Gitleaks MIT); they are downloaded from their own releases, not
redistributed here.
