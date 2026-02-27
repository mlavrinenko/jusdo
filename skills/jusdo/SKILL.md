---
name: jusdo
description: >
  How to run privileged (root/sudo) commands safely using the jusdo tool.
  Use this skill whenever the agent needs elevated privileges — for example,
  when encountering "Permission denied" errors, when tasks involve systemctl,
  ip route, iptables, mount, chown, package managers (apt, dnf, pacman),
  editing files in /etc, or any operation that would normally require sudo.
  Also use it when the user explicitly mentions jusdo, Justfiles for
  privileged commands, or asks you to "fix something as root." Even if the
  user doesn't mention jusdo by name, use this skill whenever root access
  is needed — jusdo is the approved way to get it.
---

# jusdo — Run Privileged Commands Safely

You have access to `jusdo`, a tool that lets you run commands as root
without having (or needing) `sudo`. Instead of asking the user for their
sudo password or suggesting they run commands manually, use the jusdo
workflow described below.

## Why jusdo exists

Giving an AI agent unrestricted `sudo` is reckless. Asking the user to
copy-paste every privileged command defeats the purpose of having an
agent. jusdo solves this: you write a Justfile declaring what commands
you need, the user reviews and approves it once, and then you can run
those recipes freely — iterating as many times as needed.

## The workflow

### 1. Write a Justfile

When you realize you need root privileges, write a Justfile containing
recipes for the commands you'll need. Think ahead — include recipes for
diagnosis, action, and verification so you can iterate without going
back to the user.

```just
# Example: networking troubleshooting
routes:
    ip route show
    ip rule list

add-route interface gateway:
    ip route add 10.0.0.0/8 via {{gateway}} dev {{interface}}

dns:
    resolvectl status

restart-vpn:
    systemctl restart openvpn-client@work
```

**Guidelines for writing good Justfiles:**

- **Be specific.** Only include commands relevant to the task. Don't add
  a catch-all `shell` recipe or anything that gives arbitrary execution.
  The user is reviewing this for safety — make it easy to audit.
- **Use parameters** for values that vary (interfaces, paths, service
  names) rather than hardcoding them. This makes recipes reusable across
  iterations without modifying the file.
- **Group related commands** into logical recipes. A `diagnose` recipe
  that runs three read-only commands is easier to review than three
  separate one-liners.
- **Name recipes clearly.** `restart-nginx` is better than `fix-it`.
- **Include read-only recipes** (status checks, log viewing) alongside
  write recipes. You'll need them to verify your changes worked.
- **Don't modify the file after approval.** jusdo verifies the SHA-256
  hash on every run. If you edit the Justfile, all subsequent `jusdo run`
  calls will fail until the user re-approves it. Plan ahead.

Save the Justfile with a descriptive name related to the task, e.g.,
`net-debug.just`, `nginx-fix.just`, `disk-cleanup.just`. Place it in
the current working directory or a sensible project location.

### 2. Ask the user to approve

After writing the Justfile, tell the user what you wrote and why, then
ask them to approve it:

```
I need root access to diagnose your networking issue. I've written a
Justfile at ./net-debug.just with the commands I'll need — please
review it and approve when ready:

    sudo jusdo allow ./net-debug.just

This grants me access for 60 minutes (the default). You can adjust
the duration with -d, e.g., `sudo jusdo allow ./net-debug.just -d 30`
for 30 minutes.
```

Do NOT proceed until the user confirms they've approved the file.
Wait for their explicit go-ahead.

### 3. Run recipes with `jusdo run`

Once approved, execute recipes like this:

```bash
jusdo run ./net-debug.just -- routes
jusdo run ./net-debug.just -- add-route tun0 10.8.0.1
jusdo run ./net-debug.just -- restart-vpn
```

The syntax is always:
```
jusdo run <JUSTFILE> -- <recipe> [args...]
```

The `--` separator is required. Everything after it is passed to `just`.

You can run recipes as many times as you need — diagnose, fix, verify,
repeat. That's the whole point: one approval, unlimited iterations.

### 4. Handle errors

**"no active grant"** — The user hasn't approved the file yet, or the
grant was revoked. Ask them to run `sudo jusdo allow <file>`.

**"grant has expired"** — The time window ran out. Ask the user to
re-approve: `sudo jusdo allow <file>` (or `sudo jusdo renew <file>`
to extend an existing grant).

**"justfile has been modified"** — You (or something) changed the file
after it was approved. The hash no longer matches. If you need to change
the Justfile, tell the user what changed and ask them to re-approve.

**"Permission denied" on jusdo itself** — The jusdo daemon may not be
running. Suggest: `sudo jusdo serve` to start it.

**"`just` is not installed"** — jusdo needs `just` in PATH. Suggest
installing it: `cargo install just` or `nix profile install nixpkgs#just`.

## Important rules

- **Never suggest raw `sudo`** to the user for commands you could run
  through jusdo. The whole point is to avoid that.
- **Don't modify an approved Justfile.** If you need new commands, write
  a new file or tell the user you need to update the existing one and
  ask them to re-approve.
- **Plan your recipes upfront.** Think about what diagnostic commands,
  actions, and verification steps you'll need. It's much better to
  include a recipe you might not use than to have to ask for re-approval
  because you forgot one.
- **Be transparent.** When asking for approval, explain what each recipe
  does and why you need it. The user is trusting you with root access
  to specific commands — earn that trust.

## Quick reference

```bash
# User approves (requires sudo)
sudo jusdo allow ./file.just            # 60 min default
sudo jusdo allow ./file.just -d 120     # 2 hours
sudo jusdo allow ./file.just -d 30 -y   # 30 min, skip confirmation

# User manages grants
sudo jusdo renew ./file.just            # extend by 60 min
sudo jusdo renew ./file.just -d 120     # extend by 2 hours
sudo jusdo list                         # show active grants
sudo jusdo revoke ./file.just           # revoke immediately

# Agent runs recipes (no sudo needed)
jusdo run ./file.just -- recipe-name
jusdo run ./file.just -- recipe arg1 arg2
```
