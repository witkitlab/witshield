**One command to check common server risks, with a preview and your approval before supported repairs.**

![WitShield check and interactive repair demo](docs/demo/check.gif)

```bash
curl -fsSLO https://github.com/witkitlab/witshield/releases/download/v0.4.0/check.sh && less check.sh && sudo bash check.sh --version v0.4.0
curl -fsSL https://github.com/witkitlab/witshield/releases/download/v0.4.0/check.sh | sudo bash -s -- --version v0.4.0
```

**v0.4.0 is planned and has not been released.** These commands become usable when its release assets are published. The first downloads the script for review; the second executes the downloaded script directly. The script checks the binary's SHA-256 and the GitHub release workflow's Sigstore identity before running it. Review the script itself and trust its download source.

[中文说明](README.md) · [Website](https://witshield.witkitlab.com) · [Threat model](docs/threat-model.md) · [Contributing](CONTRIBUTING.md)

Linux `amd64` and `arm64`; Ubuntu/Debian is the primary target. No account, daemon, or management port is needed. You can scan without root, but unavailable checks are reported explicitly. The score covers completed checks only and is not a full security audit or proof that a host is uncompromised.

## What it checks

- SSH password authentication and direct root login.
- Additional UID 0 accounts.
- Access permissions on `/etc/shadow`.
- TCP services listening on non-loopback addresses.
- Host firewall status; review cloud security groups separately.
- Kernel hardening settings.
- Pending upgrades from APT's local package index.
- World-accessible Docker sockets.

The report explains the top three findings and lists the rest. It also tries to count SSH login failures over the last 24 hours, distinct source IPs, and the top three sources. Unavailable logs are reported as unavailable, never as zero failures.

The wrapper runs a temporary binary and removes it on exit. Run the downloaded script again to repeat a check or pass `--fix`; if you downloaded the standalone release binary, use:

```bash
witshield check
sudo witshield check --fix
witshield check --json
witshield version
```

Check exit codes: `0` for a score of at least 60, `1` below 60, `2` for usage or runtime errors. Inspect JSON `summary` for incomplete coverage. Scan again after repairs for a new score.

## Why allow repairs?

`--fix` needs root and supports Debian-family systems. Each repair runs prechecks, shows a preview, waits for approval, and verifies the result. It calls existing typed playbooks; AI text cannot execute commands.

| Supported repair | Scope and limits |
|---|---|
| Disable SSH password authentication | Requires a public key, validates SSH configuration, and reloads the service. Keep the original session open and confirm a second key-based login. Without confirmation, it attempts to restore the configuration after 180 seconds by default. |
| Repair `/etc/shadow` permissions | Only that file: `root:shadow 0640`, or `root:root 0600` if the shadow group is absent. |
| Upgrade installed packages | At most 64 explicit packages, no new or removed packages. A locked APT transaction guard rejects unauthorized dependency changes; versions are recorded and checked. |

Firewall, kernel, Docker, and root-login findings have manual guidance only. Recovery can fail, and package maintainer scripts, service restarts, and database migrations cannot be guaranteed reversible. Keep backups, take a snapshot before upgrades, and retain out-of-band access. See the [threat model](docs/threat-model.md).

## Use your own AI provider

AI is optional. This example contains a dummy key; set your real key privately without committing it or exposing it in shared terminal history:

```bash
export WITSHIELD_AI_BASE_URL=https://api.deepseek.com/v1
export WITSHIELD_AI_API_KEY=your-api-key
export WITSHIELD_AI_MODEL=deepseek-chat
export WITSHIELD_AI_PROTOCOL=openai_chat
witshield check --ai
```

The [Chinese README](README.md) also has Qwen and Doubao examples. These are configuration templates, not claims that every provider or model has been tested. Supported protocols are `openai_chat` (default), `openai_responses`, and `anthropic_messages`; see [provider configuration](docs/ai-providers.md).

`--ai` sends the score, completed and total check counts, finding severity and Chinese titles, and SSH failure and distinct-source counts to your configured provider. Unavailable SSH logs are identified as unknown. It does not send IP addresses, raw evidence, hostnames, logs, or file contents. Review your provider's retention policy. Model output is display-only and cannot trigger a repair. The example uses the standalone binary without passing API credentials to root.

## FAQ

**Can it lock me out?** Safeguards reduce risk but do not guarantee access. Verify key login yourself before changing SSH; a public-key file alone is not proof. Confirm a second connection while keeping the first open. Timeout, rejection, or Ctrl-C during confirmation attempts restoration. The confirmation window is 180 seconds by default, configurable to 30–600 seconds with `--ssh-confirm-seconds`. After `kill -9` or a host reboot, the CLI cannot rely on its stopped process to keep the timer running: the next root invocation of any `witshield` subcommand attempts recovery from `/var/lib/witshield-cli/ssh-rollbacks`. Retain a cloud console or other out-of-band access.

**Does it install a service or change settings?** A one-shot scan does neither. The wrapper downloads assets; a plain scan reads local data. `--ai` calls your provider, and package upgrades contact package repositories. `--fix` changes only approved items and keeps its state in `/var/lib/witshield-cli`. If the full Helper is active, it recommends using the console and asks for additional confirmation. Other Linux families may provide partial scan results, but repairs require a Debian-family system.

**Does data leave the host?** Plain scans have no telemetry or report upload. Only explicitly configured `--ai` sends the limited context described above. JSON stays local unless you choose to forward it.

**Does it replace a hosting panel or fail2ban?** It can complement panels such as 1Panel. A one-shot check does not continuously monitor or ban sources. See the full deployment for continuous observation and separately authorized experimental defense.

**Is there a mainland China mirror?** Gitee is planned. Repository setup, publishing credentials, and mainland download/signature tests are still pending. The [Chinese README](README.md) shows the future command; mirror assets must still pass SHA-256 and the GitHub workflow's Sigstore verification.

## Advanced: continuous protection for multiple servers

For the self-hosted Controller, Agents, Docker observer, notifications, schedules, and defense boundaries, see the [full deployment guide](docs/advanced.md), [architecture](docs/architecture.md), and [operations guide](docs/operations.md).

## Roadmap

MCP / Skill access for Claude Code and Codex is planned, within the existing authorization and typed-action boundaries. Panel integrations are also future work.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before contributing. Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
