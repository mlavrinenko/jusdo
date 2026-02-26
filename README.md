# jusdo

**Run `just` recipes as root — without giving users full `sudo` access.**

You have a `Justfile` with recipes that need root privileges (deploying,
restarting services, rebuilding NixOS). Today you either give developers (or an
LLM agent) `sudo` — which means unrestricted root — or you hand-craft `sudoers`
rules for every command.

jusdo is a lightweight daemon that lets an admin pre-approve specific Justfiles
for a limited time. Developers then run recipes through jusdo, which executes
`just` as root on their behalf — scoped to the approved file, verified by hash,
and automatically expiring.

## How It Works

1. A **daemon** (`jusdo serve`) runs as root, listening on a Unix socket.
2. An **admin** reviews and approves a Justfile (`sudo jusdo allow ./Justfile`).
   The daemon records the file's SHA-256 hash and starts a countdown (default: 60 min).
3. A **developer** runs a recipe (`jusdo run ./Justfile -- build`) — no `sudo` needed.
   The daemon verifies the grant, re-checks the file hash, and executes `just` as root.
4. Grants expire automatically, or the admin can revoke them early.

## Usage

### Admin commands (require sudo)

```bash
# Start the daemon (or use the systemd service)
sudo jusdo serve

# Review and approve a Justfile for 60 minutes (default)
sudo jusdo allow ./Justfile

# Approve for 120 minutes, skip interactive confirmation
sudo jusdo allow ./Justfile -d 120 -y

# Extend an existing grant by another 120 minutes
sudo jusdo renew ./Justfile -d 120

# List active grants
sudo jusdo list

# Revoke a grant immediately
sudo jusdo revoke ./Justfile
```

### Developer commands (no sudo)

```bash
# Run a recipe from an approved Justfile
jusdo run ./Justfile -- build

# Pass arguments to just
jusdo run ./Justfile -- deploy --release
```

### Quick demo

```bash
# Approve and run — no sudo needed for the developer:
$ sudo jusdo allow demo.Justfile
$ jusdo run demo.Justfile whoami
root
```

## Installation

### NixOS (recommended)

Add jusdo as a flake input and enable the module:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    jusdo.url = "github:mlavrinenko/jusdo";
    jusdo.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, jusdo, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        jusdo.nixosModules.default
        {
          services.jusdo = {
            enable = true;
            package = jusdo.packages.x86_64-linux.default;
          };
        }
      ];
    };
  };
}
```

#### Module Options

| Option | Default | Description |
|---|---|---|
| `services.jusdo.enable` | `false` | Enable the jusdo daemon |
| `services.jusdo.package` | — | The jusdo package to use |
| `services.jusdo.socketDir` | `"/run/jusdo"` | Socket directory |
| `services.jusdo.defaultDurationMins` | `60` | Default grant duration |
| `services.jusdo.expiryWarnSecs` | `300` | Seconds before expiry to warn |
| `services.jusdo.auditLogPath` | `null` | Audit log path (null = disabled) |

### Build from source

Requires Rust 1.85+.

```bash
cargo install --path .
```

## Configuration

Optional config file at `/etc/jusdo/config.toml`:

```toml
socket_dir = "/run/jusdo"
default_duration_mins = 60
expiry_warn_secs = 300
# audit_log_path = "/var/log/jusdo/audit.jsonl"
```

All fields are optional; defaults apply when omitted.

## Security

**Socket permissions.** The daemon socket is world-accessible (`0666`) so
unprivileged users can send `Run` requests. Authorization is enforced
per-request via `SO_PEERCRED`: only root (uid 0) may call `allow`,
`revoke`, `renew`, or `list`. Any user may call `run`, but only for
their own grants.

**Environment isolation.** The child `just` process runs with a cleared
environment (`env_clear()`). Only `PATH`, `HOME`, and `LANG` are set to
minimal safe values.

**Hash verification.** Each grant records the SHA-256 hash of the
Justfile at approval time. Before execution, the daemon re-hashes the
file and rejects the request if it has changed.

**TOCTOU note.** There is an inherent time-of-check/time-of-use race
between the hash verification and the actual `just` invocation — an
attacker with write access could modify the file in the gap between
these two operations. Fully eliminating this would require `just` to
accept an already-open file descriptor or read from stdin, which it
currently does not support. For most use cases this window is
negligibly small, but be aware of it if your threat model includes
local attackers with write access to the Justfile.

**Forbidden arguments.** Users cannot pass `--justfile`, `-f`,
`--working-directory`, or `-d` to override the server-controlled paths.

## Known Limitations

- **Single-threaded accept loop.** The daemon processes one connection at
  a time. A slow or malicious client can block others for up to 30 seconds
  (the connection timeout). This is acceptable for typical workloads but
  not suited for high-concurrency scenarios.
- **In-memory grants.** Grants are not persisted — a daemon restart clears
  all active grants.

## Development

Prerequisites: [Nix](https://nixos.org/) with flakes enabled.

```bash
# Enter dev shell
direnv allow
# or: nix develop

# Run checks (clippy + tests + file size limits)
just check

# Build
just build

# Run tests
just test

# Code coverage
just cover

# Format
just fmt
```

## License

MIT
