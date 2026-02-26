# jusdo

## Agent Rules

- NixOS environment — prefix cargo/just commands with `nix develop --command`
- Use `just` recipes instead of raw cargo commands (see `Justfile`)
- Use `-q` for cargo commands — only show errors/warnings
- After any code changes, run `nix develop --command just check` and fix all warnings
- If clippy suggests `--fix`, use `nix develop --command cargo clippy --fix --workspace --all-targets`
