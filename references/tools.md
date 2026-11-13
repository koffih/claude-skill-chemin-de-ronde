# The specialist tools: what the round runs, and what it does not

The round is a conductor, not a fusion. Lynis, Trivy, Wazuh or ZAP are each maintained by teams who update their rules every week; copying their logic into one script would freeze it on the day it was copied. So the round:

- runs **its own checks** for what matters most on small fleets and that general tools miss or bury (Docker bypassing UFW, root jobs another account can modify, curl|bash as root, secrets in units, a database on 0.0.0.0);
- **calls** three read-only specialists when they are installed, and folds their results into the same report;
- **recommends** the others, which are infrastructure to deploy once, not something to run during a round.

## Run by the round (read-only)

| Tool | What it adds | How the round uses it |
|---|---|---|
| [Lynis](https://github.com/CISOfy/lynis) | ~300 hardening tests (boot, auth, PAM, file permissions, services, kernel, logging) and a hardening index. | `lynis audit system --quick --no-log`, report written in the round folder; each warning becomes an `L-` finding. |
| [Trivy](https://github.com/aquasecurity/trivy) | Known vulnerabilities (CVE) in OS packages and language dependencies on disk, and in container images. | `trivy rootfs` on `/` (fixable high and critical only), `--images` adds running images. Its database lands in the state folder. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 150+ secret patterns (cloud keys, tokens, private keys) in files. | `gitleaks dir` on the search roots, always `--redact`. |

`outils.sh install` downloads pinned versions and checks a SHA-256 written in the script, not one read from the same release page: a compromised release (it happened to Trivy's distribution in 2026) does not pass. To update: pick a release at least two weeks old, change the version and the hash together.

## Recommended, deployed once (not run by the round)

| Need | Tool | When to recommend it |
|---|---|---|
| Brute force and bad bots | [CrowdSec](https://github.com/crowdsecurity/crowdsec), [Fail2ban](https://github.com/fail2ban/fail2ban) | G01 open. CrowdSec for behaviour and shared blocklists; fail2ban for simple local bans; both can coexist. |
| Runtime detection | [Falco](https://github.com/falcosecurity/falco) | G03 open on a server running containers. |
| Central logs, file integrity, alerts across a fleet | [Wazuh](https://github.com/wazuh/wazuh) | Fleet of more than a few servers or sensitive data. It is a server plus agents: a project of its own, not a round. |
| File integrity on one box | AIDE, [osquery](https://github.com/osquery/osquery) | G03 open and Wazuh not planned. |
| Compliance profiles (CIS, DISA STIG) | [OpenSCAP](https://github.com/OpenSCAP/openscap), Ubuntu Security Guide (`usg`, Ubuntu Pro) | A client or an auditor asks for a named benchmark. Audit first; never apply a full profile blindly, it can cut SSH or break services. |
| The same baseline on many servers | [dev-sec ansible-collection-hardening](https://github.com/dev-sec/ansible-collection-hardening), Ansible | The same findings come back on many servers. Test each role on a throwaway VPS first. |
| Secrets management | [SOPS](https://github.com/getsops/sops), [age](https://github.com/FiloSottile/age), [HashiCorp Vault](https://github.com/hashicorp/vault) | K01 to K04 or X-GITLEAKS keep coming back. |
| Secrets before they land | Gitleaks, [TruffleHog](https://github.com/trufflesecurity/trufflehog), [detect-secrets](https://github.com/Yelp/detect-secrets) as pre-commit or CI | X-GITLEAKS found secrets in repositories. |
| Dependencies and SBOM over time | [Grype](https://github.com/anchore/grype) + [Syft](https://github.com/anchore/syft), [OSV-Scanner](https://github.com/google/osv-scanner), [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | Many apps to follow over time; Trivy already covers a one-off scan. |
| Application code | [Semgrep](https://github.com/semgrep/semgrep), [Bearer](https://github.com/bearer/bearer) (finds personal data flows) | Code handles sensitive data; in CI, not on the server. |
| Web application from outside | [OWASP ZAP](https://github.com/zaproxy/zaproxy), [Nuclei](https://github.com/projectdiscovery/nuclei) | Only against sites you own or have written permission to test, ideally a staging copy. Never as part of an automatic round. |

## Why not merge them all into one program

- Each tool's value is its rule base, updated continuously. A merged copy goes stale in weeks.
- Their licences differ (Lynis GPL-3.0, Trivy Apache-2.0, Gitleaks MIT): calling them keeps each one under its own terms.
- Some are infrastructure (Wazuh, Vault), some are active attacks (ZAP, Nuclei): neither belongs in a read-only round that is safe to run on production at any time.
