# jusdo

Let your AI agent run privileged commands — without handing it `sudo`.
Using a [Justfile](https://github.com/casey/just).

## The Problem

You're configuring your PC with an AI agent. The conversation goes like this:

> **You:** Set up my firewall — block all incoming except SSH and HTTP.
>
> **Agent:** I'll configure iptables for you. Let me check the current rules first.
>
> ```
> $ iptables -L
> iptables: Permission denied (you must be root)
> ```
>
> **Agent:** I need root access to run this. Could you grant me `sudo`?

Now you have a choice: give an AI agent unrestricted root access, or
type every command yourself. Neither is great.

## The Solution

With jusdo, you stay in control. You write the commands in a Justfile,
review them, and approve for a limited time. The agent runs them
through jusdo — no `sudo`, no password, no unrestricted access.

> **You:** Set up my firewall — block all incoming except SSH and HTTP.
>
> **Agent:** I'll create a Justfile with the firewall rules. Please review
> and approve it with jusdo.
>
> ```just
> # firewall.just
> setup:
>     iptables -F
>     iptables -P INPUT DROP
>     iptables -A INPUT -i lo -j ACCEPT
>     iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
>     iptables -A INPUT -p tcp --dport 22 -j ACCEPT
>     iptables -A INPUT -p tcp --dport 80 -j ACCEPT
> ```
>
> **You:** Looks good.
> ```
> $ sudo jusdo allow firewall.just
> ```
>
> **Agent:** Running it now.
> ```
> $ jusdo run firewall.just -- setup
> ```
> Done. Your firewall is configured.

The grant expires automatically after 60 minutes. The agent can only
run recipes from the exact file you approved — if anyone changes it,
jusdo rejects the request.

## Quick Start

Start the daemon (once, as root):

```bash
sudo jusdo serve
```

The workflow is then three steps:

```bash
# 1. Agent writes a Justfile with the commands it needs
# 2. You review and approve it
sudo jusdo allow ./Justfile

# 3. Agent runs recipes — no sudo needed
jusdo run ./Justfile -- recipe-name
```

## Commands

### Admin (require sudo)

```bash
sudo jusdo allow ./Justfile            # approve for 60 min
sudo jusdo allow ./Justfile -d 120 -y  # 120 min, skip confirmation
sudo jusdo renew ./Justfile -d 120     # extend grant
sudo jusdo list                        # show active grants
sudo jusdo revoke ./Justfile           # revoke immediately
```

### Agent / developer (no sudo)

```bash
jusdo run ./Justfile -- build
jusdo run ./Justfile -- deploy --release
```

## Installation

### Nix

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

Or install directly:

```bash
nix profile install github:mlavrinenko/jusdo
```

### Build from source

Requires Rust 1.85+.

```bash
cargo install --path .
```

## Security

- **Scoped access.** Grants are tied to a specific Justfile, user, and
  time window. No blanket root.
- **Hash verification.** The daemon records the SHA-256 of the Justfile
  at approval time and re-checks before every execution. Modified files
  are rejected.
- **Environment isolation.** Child processes run with a cleared
  environment — only `PATH`, `HOME`, and `LANG` are set.
- **Socket auth.** `SO_PEERCRED` verifies the caller's UID on every
  request. Only root can grant/revoke. Any user can run approved recipes.
- **Auto-expiry.** Grants expire after the configured duration. No
  standing privileges.

## Development

Prerequisites: [Nix](https://nixos.org/) with flakes enabled.

```bash
nix develop
just check    # clippy + tests + file size limits
```

## License

MIT
