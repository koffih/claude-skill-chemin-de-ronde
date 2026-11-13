# Fixes, check by check

Each check of the round, why it matters, how to fix it, and how to prove the fix. A mark **ACCESS** means the change can lock you out: never apply it without a second session open, and arm a rollback first.

## Before touching access (SSH, firewall)

1. Open a second SSH session and keep it open until the end.
2. Arm a timed rollback before the change, for example:
   `systemd-run --on-active=15min --unit=rollback-ssh bash -c 'cp /root/sshd.bak /etc/ssh/sshd_config && systemctl reload ssh'`
   (or `ufw disable` for the firewall).
3. Apply, then open a **new** connection from outside. Only if it works: `systemctl stop rollback-ssh.timer`.
4. Never `ufw limit` SSH on a server that agents reach often: it bans the agent, and the banned address is often also the admin's.
5. Never lock the root password: the provider's rescue console needs it. Refuse passwords **in SSH**, not on the account.

## access

| ID | Why | Fix | Proof |
|---|---|---|---|
| A01 **ACCESS** | Password SSH is brute-forced all day; with root allowed, one guessed password is the server. | `PasswordAuthentication no`, `KbdInteractiveAuthentication no` in `/etc/ssh/sshd_config.d/00-hardening.conf`, after a key login was proven. Check that no file in `sshd_config.d` sets it back (first value wins). | `sshd -T \| grep -i passwordauth`; `ssh -o PubkeyAuthentication=no host` is refused. |
| A02 **ACCESS** | Root is the one account every bot tries. | `PermitRootLogin prohibit-password` (keys only) or `no` with a sudo account. | `sshd -T \| grep permitrootlogin` |
| A03 | A second uid 0 account is a classic backdoor. | Find who created it (`grep <name> /var/log/auth.log*`), remove it; treat as an incident if unknown. | `awk -F: '$3==0' /etc/passwd` |
| A04 | `NOPASSWD: ALL` turns any compromise of that account (a leaked key, an app bug) into root. | List the commands the account really needs, give only those, or require the password. Agents that need root can use a narrow wrapper script owned by root. | `sudo -l -U <user>` |
| A05 | The docker group can mount `/` into a container: it is root. | Keep it to trusted admins; deploy through a root-owned script allowed by sudo. | `getent group docker` |
| A06 | Old keys from past contractors and machines stay valid forever. | Name every key (comment field), remove the unknown ones. | count per account in the next round |
| A07 | Extra attempts and forwarding widen what a stolen session can do. | `MaxAuthTries 3`, `X11Forwarding no`, `AllowAgentForwarding no`. | `sshd -T` |
| A08 | Anyone who can write `authorized_keys` can add their key. | `chmod 600`, `chown <user>:<user>`. | `stat -c %a` |

## walls

| ID | Why | Fix | Proof |
|---|---|---|---|
| W01 **ACCESS** | Without a default deny, every service that binds to 0.0.0.0 by mistake is public. | `ufw default deny incoming; ufw allow 22/tcp; ufw allow 80,443/tcp; ufw enable` with the rollback armed. Also close what you can at the provider firewall. | `ufw status verbose`; external `nmap`. |
| W02 | A database, Redis, Elasticsearch or the Docker API on the internet is the most common cause of full data leaks. | Bind it to `127.0.0.1` (Postgres `listen_addresses`, compose `127.0.0.1:5432:5432`), reach it by SSH tunnel or VPN. Do not rely on the firewall alone. If it was exposed, read its logs for foreign connections and rotate its passwords. | `ss -tlnp`; external `nmap -p 5432`. |
| W03 | Admin consoles (Supabase Studio, Kong, Portainer, RabbitMQ, Kibana) and dev servers (Vite, Next dev) are not built to face the internet. | Bind to `127.0.0.1`, publish through nginx with authentication, or only over a VPN (WireGuard, Tailscale). | same |
| W04 | Each unknown port is a program nobody watches. | `ss -tlnp` names the program; bind it to `127.0.0.1` or stop it. | next round |
| W05 | A local-network address is reachable by every device on that network (office, home, provider private network). | Bind to `127.0.0.1` or the VPN address. | `ss -tlnp` |
| W06 | Docker writes its own NAT rules before UFW: a port published as `5432:5432` is public even when UFW says deny. | In compose: `"127.0.0.1:5432:5432"`. Or filter in the `DOCKER-USER` chain. Recreate the container. | `docker ps`; external `nmap`. |
| W07 | Scanners find sites by IP; a default site leaks the stack and old apps. | A default nginx server: `listen 80 default_server; listen 443 ssl default_server; ssl_reject_handshake on; return 444;` | `curl -k https://<ip>` gives nothing. |
| W08 | An expired certificate breaks the site and teaches users to click through warnings. | `systemctl list-timers \| grep certbot`, `certbot renew --dry-run`, fix the cause. | the next round |

## watch

| ID | Why | Fix |
|---|---|---|
| G01 | Without a guard, brute force runs unthrottled and fills the logs. | CrowdSec (behaviour scenarios, shared blocklist, nginx and SSH) or fail2ban with an `sshd` jail. Both can coexist. |
| G02 | Without auditd there is no record of who changed sudoers, SSH or cron. | `apt install auditd` with rules on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*`, `/etc/ssh`, `/etc/cron*`. |
| G03 | Nothing notices a dropped binary or a shell spawned by a web process. | Falco (runtime detection, alerts by mail), Wazuh agent (central SIEM, file integrity), or at least AIDE in a daily cron. |
| G04 | A volatile journal loses the evidence at the first reboot. | `mkdir -p /var/log/journal && systemctl restart systemd-journald`. |

## patches

| ID | Why | Fix |
|---|---|---|
| P01 | Most break-ins use flaws patched weeks earlier. | `apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`. |
| P02 | Same. | `apt update && apt upgrade` at a quiet hour; check services after. |
| P03 | A patched kernel or libc is not in effect until the reboot. | Reboot at a quiet hour, after checking that every service is enabled to start on its own (`systemctl is-enabled`, containers with `restart: unless-stopped`). |
| P05 | Old kernels are never booted but stay on disk; every vulnerability scan counts their flaws, and they fill `/boot` until an update fails. | `apt autoremove --purge` keeps the running kernel and one fallback. Reboot first if a newer kernel is pending (P03). |
| P04 | No more security updates at all. | Plan the release upgrade on a copy of the server first. |

## secrets

| ID | Why | Fix |
|---|---|---|
| K01 | Any account (a compromised app user, a contractor) reads the keys. | `chmod 600` and the right owner. If the host is shared or was compromised, rotate the secrets. |
| K02 | "credentials.txt" files are the first thing an intruder greps for. | Move to a password manager or an encrypted file (`sops`, `age`), delete the plain copy (`shred -u`), rotate what left the machine. |
| K03 | Unit files and crontabs are world-readable by design. | `EnvironmentFile=/etc/<app>/env` (root, 600) or `LoadCredential=`; then rotate, since the old value was readable. |
| K04 | Shell histories keep secrets typed on the command line, often for years. | Rotate those secrets, delete the lines, use `read -s` or files. Values are never shown by the round: open the history yourself. |
| X-GITLEAKS | Keys committed or copied into code folders end up in backups, images and public repos. | Read the raw report in the round folder (values redacted), rotate each real secret, move it out of the code; add gitleaks as a pre-commit hook. |

## supply

| ID | Why | Fix |
|---|---|---|
| C01 | `curl ... \| bash` as root on a schedule gives root to whoever controls that URL or that repository, on every server that runs it. | Clone at a pinned commit or verify a checksum, and run it as the account that needs it, not root. |
| C02 | If root runs a file another account can modify, that account is root: it edits the file and waits. | `chown root:root` and `chmod 755` the file and every parent folder, or run the job as the owning account (`User=` in the unit, the user's crontab). |
| C03 | Same, one level up: whoever writes a unit, a cron file or sudoers decides what root runs. | `chown root:root`, `chmod 644` (units, cron) or `440` (sudoers). Find out how it became writable. |
| C04 | A setuid program outside system folders is a ready-made privilege escalation. | Identify its origin; `chmod u-s` unless a known package needs it. |
| C05 | A world-writable system file can be replaced by anyone. | `chmod o-w`, find which install did it. |

## apps

| ID | Why | Fix |
|---|---|---|
| R01 | A bug in an app running as root (path traversal, RCE in a dependency) gives root. | One unprivileged account per app (`User=` in systemd, `pm2` started by that account). |
| R02 | A privileged container or one with `docker.sock` can take the host. | Remove `privileged: true`; give the socket only to tools that must manage Docker, through a read-only socket proxy. |
| R03 | Host networking removes Docker's isolation of ports. | Bridge network with `127.0.0.1`-bound ports. |
| R04 | An open Docker socket makes every local account root. | `chmod 660 /var/run/docker.sock` (root:docker), find what changed it. |

## kernel

| ID | Why | Fix |
|---|---|---|
| N01 | Defaults leave room for ICMP redirects, spoofed sources, kernel address leaks and core dumps of setuid programs. | `/etc/sysctl.d/90-hardening.conf` with the values listed in the evidence, then `sysctl --system`. Inside a container these are set by the host. |

## vault

| ID | Why | Fix |
|---|---|---|
| D01 | No backup, no recovery from ransomware, a bad migration or a lost disk. | A scheduled database dump and file backup. |
| D02 | A backup on the same disk or provider dies with it. | restic or borg to another provider, encrypted, retention set, and a monthly restore test on another machine: an untested backup is a hope. |
| D03 | A full disk stops databases and logs, sometimes corrupts them. | `du -xh --max-depth=2 /`, log rotation, Docker image cleanup. |
| D04 | On a rented VPS the provider can read an unencrypted disk and its snapshots. | For sensitive files, encrypt in the application with a key held elsewhere (see sensitive-data.md). |

## tools

| ID | Fix |
|---|---|
| X-LYNIS / L-xxxx | `lynis show details <code>` gives the test and its advice. The hardening index is a trend to follow on one server, not a target. |
| T-ROOTFS | `apt upgrade` for system packages; language packages are updated in their project and redeployed. |
| T-IMGn | Rebuild the image on an updated base and redeploy. |
