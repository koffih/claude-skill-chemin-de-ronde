---
name: chemin-de-ronde
description: Walk a periodic, read-only security round on a Linux server (Ubuntu, Debian, Docker, Nginx, Supabase or PostgreSQL) and report what to harden, without changing anything. Native checks across nine towers (SSH and accounts, exposed ports and firewall, Docker bypassing UFW, secrets in clear, root jobs another account can modify, curl|bash, patches, kernel, backups), plus Lynis, Trivy and Gitleaks when present, then a scored report with one fix per finding and the delta since the last round. Use for a security audit of a server, a periodic review of a fleet of VPS, before putting sensitive data (identity documents, client files) on a server, after an incident, or to check that earlier fixes held. French triggers (audit de securite du serveur, fais la ronde, passe la ronde sur ce serveur, est-ce que ce serveur est securise, durcissement a recommander, preconise les ameliorations de securite, revue de securite des VPS, scan de vulnerabilites, chemin de ronde). Local routing (this skill only observes and recommends; to build a new server use vauban, to apply the fixes use durcissement-vps where it exists).
---

# Chemin de ronde

The *chemin de ronde* is the walkway along the top of a castle wall: the watch walks it on a schedule, looks at every tower, and reports what is cracked. It never repairs the wall itself.

This skill does the same on a Linux server: one **read-only** round, a scored report, a fix for each finding, and the difference with the previous round.

## The rule

**The round never changes the server.** No setting, no restart, no package installed in the system, no file written outside its own state folder. A fix is a recommendation in the report, applied later by a human or a hardening tool, with a way back. This is what makes the round safe to run on every production server, often.

Two corollaries:
- Never print a secret value. Findings name files and count lines; Gitleaks runs with `--redact`.
- A recommendation that touches access (SSH, firewall) is always flagged as such, with the precautions in [references/fixes.md](references/fixes.md).

## Where things are

`scripts/` in this skill's folder (usually `~/.claude/skills/chemin-de-ronde/scripts`):

| Script | What it does |
|---|---|
| `chemin-de-ronde.sh` | one full round: own checks, the specialist tools present, the report |
| `ronde.sh` | the native checks only, writes `findings.tsv` |
| `outils.sh` | `detect`, `install` (pinned versions, SHA-256 checked, into the state folder), `run` |
| `rapport.py` | score, sorted findings with fixes, delta with the last round, history |

State and history: `/var/lib/chemin-de-ronde` as root (mode 700), else `~/.local/state/chemin-de-ronde`.

## The round, step by step

1. **Which server.** By default, the machine you run on. For a remote server where the skill is installed, run it there over SSH: `ssh <host> 'sudo bash ~/.claude/skills/chemin-de-ronde/scripts/chemin-de-ronde.sh'`. Run as root: without root, a third of the checks are skipped and the report says so.
2. **Specialist tools.** `bash scripts/outils.sh detect`. If Lynis, Trivy or Gitleaks are missing, offer once to install them (`sudo bash scripts/outils.sh install all`: pinned releases, hash written in the script, installed only in the state folder). They are optional: the native checks stand alone. What each tool adds, and what the skill deliberately does not run, is in [references/tools.md](references/tools.md).
3. **Walk.** `sudo bash scripts/chemin-de-ronde.sh` (add `--images` to scan the images of running containers with Trivy, `--roots "/opt /srv"` to narrow where secrets are searched, `--no-tools` for a quick round). The native checks take about a minute; Lynis adds several minutes and Trivy up to half an hour on a large host (its first run also downloads its database). Run it in the background.
4. **Look from outside.** The round sees the server from inside. If another machine is available, scan the public IP from there (`nmap -Pn -p- --open <ip>`) and compare with W02 to W04: a port the inside sees and the outside does not is closed by the provider firewall; the opposite means the inside view missed something.
5. **Check before reporting.** Open `rapport.md` in the round folder. For each critical and high finding, confirm it with one command of your own (the evidence line says where to look). Drop a false positive explicitly in your answer rather than repeating it.
6. **Report to the user**, in their language:
   - the score and grade, and the delta since the last round (new, fixed, still open);
   - the first five actions, ordered by risk removed for effort spent, each with its fix and a mark when it **touches access**;
   - what was not checked (skipped checks, no external scan) so the score is not read as more than it is.
   If the server holds or will hold sensitive personal data (identity documents, health, payment), add the review from [references/sensitive-data.md](references/sensitive-data.md): a hardened server is necessary, not sufficient.
7. **Hand over the fixes.** This skill stops at the recommendation. Applying is a separate, explicit request, done one change at a time with a rollback, following [references/fixes.md](references/fixes.md). Log each applied fix in the server's journal (format at the end of fixes.md), then run the round again to see it move to fixed.

## Many servers

Install the skill on each server and run the round there; collect the reports. Do not give an agent machine root SSH access to the whole fleet for the sake of auditing it. Cadence, collection and a fleet table are in [references/fleet.md](references/fleet.md).

## Reading the score

100 minus 25 per critical, 10 per high, 4 per medium, 1 per low. Any critical forces the grade to **Open breach** whatever the number. Grades: Citadel (90+), Stronghold (75+), Cracked walls (50+), Open breach. The score is for following one server over time, not for comparing servers with different roles, and a high score says nothing about the application code or the provider account.

## What the round does not see

The provider firewall and console, the application code (use Semgrep or a code review), the web application from outside (ZAP or Nuclei, only on your own sites, with written permission), the cloud accounts, DNS and mail settings, and whether backups really restore. The report says so every time.
