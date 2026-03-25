# ManagedSSH

ManagedSSH is a terminal-first SSH connection manager built with Go, Cobra, and Bubble Tea. It helps you organize hosts, store encrypted credentials, and connect quickly from a guided TUI.

## Dashboard Preview

![ManagedSSH Dashboard](dashboard.jpg)

## Why ManagedSSH

- Keep SSH hosts, users, and auth settings in one place.
- Encrypt secrets at rest with a master key.
- Validate host connectivity and host keys before saving.
- Use a keyboard-driven dashboard for fast daily operations.

## Key Features

- Beautiful TUI workflow for setup, unlock, host management, and connection.
- Encrypted vault using Argon2 + AES-GCM for stored credentials.
- Host key verification with known_hosts integration and trust confirmation.
- Host profiles with:
	- Alias, hostname, port, group, tags
	- Multiple user accounts per host
	- Per-user password or SSH key authentication
- Support for SSH key path or inline encrypted key data.
- Passphrase-aware key handling, including save-on-success for key passphrases.
- Master key rotation that re-encrypts all stored secrets.
- Backup export with atomic writes.
- Backup import with master key verification, validation checks, and overwrite confirmation.
- Search and filtering in dashboard by alias, host, group, tags, and users.

## Requirements

- Go 1.26.1
- macOS, Linux, or another environment with terminal SSH access

## Quick Start

1. Build:

```bash
make build
```

2. Run:

```bash
make run
```
3. Install:
```bash
make install
```

4. First launch flow:
- Create a master key.
- Add a host and one or more users.
- Confirm host key trust if prompted.
- Connect from the dashboard.

## Dashboard Controls

- q: quit
- l: lock vault
- c: change master key
- /: focus search
- esc: clear search or cancel current context
- j / k or arrow keys: move selection
- a: add host
- e: edit selected host
- y: duplicate selected host
- d: delete selected host (with confirmation)
- h: run health check for all saved hosts (green/yellow/red indicators)
- enter: connect to selected host
- x: export backup
- i: import backup

## Security Model (Brief)

- Vault metadata is stored in ~/.config/managedssh/vault.json.
- Host data is stored in ~/.config/managedssh/hosts.json.
- Sensitive data is encrypted and handled as byte slices with explicit zeroing where possible.
- Host trust follows known_hosts behavior and requires explicit trust for unknown keys.

## Development

Common commands:

```bash
make build
make run
make test
make fmt
make tidy
make install
make clean
```

Install behavior:

- `make install` uses `go install .` when `GOBIN` or `GOPATH` is set.
- If both are missing, it installs to `~/.local/bin`.
- If `~/.local/bin` is not in your `PATH`, install prints:
	`~/.local/bin is not in path please add it to path.`

## Project Layout

- main.go: entry point
- cmd/: Cobra command wiring
- internal/tui/: Bubble Tea state machine and views
- internal/host/: host models and JSON persistence
- internal/sshclient/: SSH verify, trust, and session logic
- internal/vault/: master key setup, unlock, and encryption helpers

## License

GNU AGPL v3. See LICENSE.
