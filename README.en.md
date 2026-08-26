# WitShield AI

**WitShield AI (妙盾)** is an open-source, agentic security guard for Linux servers. It continuously inspects a server, explains evidence-backed findings, proposes structured remediation, and acts only within explicit approval and policy boundaries.

Key properties:

- local-first single-server mode and a self-hosted, single-admin multi-device controller;
- scheduled security posture checks with auditable evidence;
- optional, user-supplied OpenAI- or Anthropic-compatible API URL, key, and model;
- approval, verification, rollback, and audit around remediation;
- narrowly scoped, reversible, time-limited automatic containment;
- signed Webhook and SMTP notifications configured and tested from Settings, with a durable per-channel retry outbox;
- no hack-back, no public SaaS dependency, and no bundled API key.

SSH automatic containment requires at least one non-loopback administrator IP/CIDR allowlist entry; the product does not guess NAT, bastion, or dynamic management sources. Docker observer reports every unavailable check and marks its score as incomplete rather than treating partial visibility as a full-host assessment.

The Controller is the sole authority for recurring schedules. An Agent runs one startup scan and then scans only on Controller commands; its interval setting is merely the initial schedule hint sent during first enrollment. SSH hardening remains `awaiting_confirmation` after the change while a durable local Helper timer protects access. It becomes successful only after the administrator verifies a second connection and confirms it; expiry triggers the safety restore without pretending that the Controller received a successful rollback receipt.

Emergency stop is device-scoped. It prevents new automatic decisions and atomically cancels policy actions that have not crossed the Agent's final authorization gate. It does not misreport an action already executing as cancelled, and active nftables bans still expire by their kernel TTL or can be rolled back explicitly.

Privileged action results are bound to the exact command and payload by the device's persistent Ed25519 identity. Possession of a bearer device credential alone is therefore insufficient to forge a successful remediation result. A per-device long-poll gate, Agent request limits, and bounded report/event retention keep one compromised device from exhausting the single-node Controller.

The base Docker observer mounts only `/etc/passwd` and the host IPv4 TCP table. Optional single-file overlays add SSH and IPv6 visibility only when those files exist; missing IPv6 data preserves visible IPv4 evidence while marking TCP coverage incomplete.

The project is in early development. Automatic action is off by default. See the [Chinese README](README.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [operations guide](docs/operations.md).

## Install on Ubuntu/Debian

Review the installer before running it:

```bash
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://github.com/witkitlab/witshield/releases/latest/download/install.sh
less install.sh
sudo bash install.sh --mode standalone
```

The installer downloads from an immutable GitHub Release, verifies the
release-workflow Sigstore identity, and bootstraps a checksum-pinned Cosign
verifier when the host does not already provide one. It records the installed
version and refuses implicit downgrades.

The controller listens on `127.0.0.1:8080` by default. Docker is supported only as a constrained read-only observer; native systemd installation is required for remediation.

Licensed under [Apache-2.0](LICENSE).
