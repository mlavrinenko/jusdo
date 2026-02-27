use anyhow::Result;
use clap::Parser;

use jusdo::cli::{Cli, Cmd};
use jusdo::commands;
use jusdo::config::Config;

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Cmd::Serve {
            socket_dir,
            duration,
            expiry_warn,
            audit_log,
        } => {
            let config = Config::for_server(&socket_dir, duration, expiry_warn, audit_log);
            commands::serve::execute(&config)?;
        }
        Cmd::Allow {
            justfile,
            duration,
            yes,
        } => {
            let config = Config::for_client(&cli.socket);
            commands::allow::execute(&config, &justfile, duration, yes)?;
        }
        Cmd::Revoke { justfile } => {
            let config = Config::for_client(&cli.socket);
            commands::revoke::execute(&config, &justfile)?;
        }
        Cmd::Renew { justfile, duration } => {
            let config = Config::for_client(&cli.socket);
            commands::renew::execute(&config, &justfile, duration)?;
        }
        Cmd::List => {
            let config = Config::for_client(&cli.socket);
            commands::list::execute(&config)?;
        }
        Cmd::Run { justfile, args } => {
            let config = Config::for_client(&cli.socket);
            commands::run::execute(&config, &justfile, args)?;
        }
    }

    Ok(())
}
