# jusdo

**Let your AI agent run privileged commands — without handing it `sudo`.**

## The Problem

You asked your AI agent to fix a networking issue. It needs to
check routes, tweak settings, verify — and repeat until it works.
Every step requires root.

> **You:** My VPN traffic isn't routing correctly. Fix it.
>
> **Agent:** Let me check your routing table.
> ```
> $ ip route show
> Permission denied
> ```
> I need root to diagnose this. Could you grant me `sudo`?

You have two bad options: give the agent unrestricted `sudo`, or
manually copy-paste every command it suggests. The first is reckless.
The second defeats the purpose of having an agent.

## How `jusdo` Solves This

The agent writes its commands into a `Justfile`. You review it and
approve with `jusdo`. The agent then runs recipes freely — iterating
as many times as needed — without `sudo` and without bothering you
for each step.

> **You:** My VPN traffic isn't routing correctly. Fix it.
>
> **Agent:** I'll need to inspect and modify your network config. Here's a
> Justfile with the commands I may need — please review and approve it.
>
> ```just
> # net-debug.just
> routes:
>     ip route show
>     ip rule list
> add-route interface gateway:
>     ip route add 10.0.0.0/8 via {{gateway}} dev {{interface}}
> dns:
>     resolvectl status
> restart-vpn:
>     systemctl restart openvpn-client@work
> ```
>
> **You:** *(reviews the commands)* Looks reasonable.
> ```
> $ sudo jusdo allow net-debug.just -d 30
> ```
>
> **Agent:** Thanks. Let me investigate.
> ```
> $ jusdo run net-debug.just -- routes
> default via 192.168.1.1 dev eth0
> 10.0.0.0/8 via 192.168.1.1 dev eth0    # <- wrong, should go via tun0
> ```
> Found it — the VPN route is going through your LAN gateway.
> ```
> $ jusdo run net-debug.just -- add-route tun0 10.8.0.1
> ```
> Let me verify.
> ```
> $ jusdo run net-debug.just -- routes
> 10.0.0.0/8 via 10.8.0.1 dev tun0       # fixed
> ```
> Route is correct now. Let me restart the VPN to make sure it holds.
> ```
> $ jusdo run net-debug.just -- restart-vpn
> $ jusdo run net-debug.just -- routes
> 10.0.0.0/8 via 10.8.0.1 dev tun0       # still good
> ```
> Done. Your VPN traffic is routing correctly now.

The agent ran 5 privileged commands across multiple iterations — you
only had to approve once. The grant expires in 30 minutes automatically.

## Quick Start

Start the daemon (once, as root):

```bash
sudo jusdo serve
```

Then the workflow is always:

```bash
# 1. Agent writes a Justfile with the commands it needs
# 2. You review and approve
sudo jusdo allow ./Justfile
# 3. Agent runs recipes as many times as needed — no sudo
jusdo run ./Justfile -- recipe-name
```

## Commands

```bash
# Admin (require sudo)
sudo jusdo allow ./Justfile            # approve for 60 min (default)
sudo jusdo allow ./Justfile -d 120 -y  # 120 min, skip confirmation
sudo jusdo renew ./Justfile -d 120     # extend grant
sudo jusdo list                        # show active grants
sudo jusdo revoke ./Justfile           # revoke immediately

# Agent / developer (no sudo needed)
jusdo run ./Justfile -- recipe-name
jusdo run ./Justfile -- recipe arg1 arg2
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

Or: `nix profile install github:mlavrinenko/jusdo`

### Build from source

```bash
cargo install --path .   # requires Rust 1.85+
```

## Agent Skill

```bash
npx skills add https://github.com/mlavrinenko/jusdo --skill jusdo
```

Once installed, the agent will use the `jusdo` workflow whenever it needs
root — no prompting required.

## Security

- **Scoped access.** Grants are tied to a specific Justfile, user, and
  time window. No blanket root.
- **Hash verification.** SHA-256 of the Justfile is recorded at approval
  and re-checked before every run. Modified files are rejected.
- **Environment isolation.** Child processes get a cleared environment.
  Only `PATH`, `HOME`, and `LANG` are set.
- **Socket auth.** `SO_PEERCRED` verifies caller UID. Only root can
  grant/revoke. Any user can run approved recipes.
- **Auto-expiry.** Grants expire after the configured duration.

## Development

Prerequisites: [Nix](https://nixos.org/) with flakes enabled.

```bash
nix develop
just check    # clippy + tests + file size limits
```

## License

MIT
