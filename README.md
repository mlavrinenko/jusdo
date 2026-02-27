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

### Start the daemon

```bash
sudo jusdo serve
sudo jusdo serve --duration 120 --audit-log /var/log/jusdo.jsonl
```

### Admin commands (require sudo)

```bash
sudo jusdo allow ./Justfile            # approve for 60 min (default)
sudo jusdo allow ./Justfile -d 120 -y  # 120 min, skip confirmation
sudo jusdo renew ./Justfile -d 120     # extend by 120 min
sudo jusdo list                        # show active grants
sudo jusdo revoke ./Justfile           # revoke immediately
```

### Developer commands (no sudo)

```bash
jusdo run ./Justfile -- build
jusdo run ./Justfile -- deploy --release
```

### Quick demo

```bash
$ sudo jusdo allow demo.Justfile
$ jusdo run demo.Justfile whoami
root
```

## Installation

### Nix

Add jusdo as a flake input:

```nix
# flake.nix
{
  inputs.jusdo.url = "github:mlavrinenko/jusdo";

  outputs = { nixpkgs, jusdo, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [{
        environment.systemPackages = [
          jusdo.packages.x86_64-linux.default
        ];
      }];
    };
  };
}
```

Or install directly with the Nix package manager:

```bash
nix profile install github:mlavrinenko/jusdo
```

### Build from source

Requires Rust 1.85+.

```bash
cargo install --path .
```

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
nix develop
just check    # clippy + tests + file size limits
just build
just test
just cover
just fmt
```

## License

MIT
