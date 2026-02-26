use anyhow::Result;
use clap::Parser;

use jusdo::cli::{Cli, Cmd};
use jusdo::commands;
use jusdo::config::Config;

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let config = Config::load()?;

    match cli.command {
        Cmd::Serve => commands::serve::execute(&config)?,
        Cmd::Allow {
            justfile,
            duration,
            yes,
        } => commands::allow::execute(&config, &justfile, duration, yes)?,
        Cmd::Revoke { justfile } => commands::revoke::execute(&config, &justfile)?,
        Cmd::Renew { justfile, duration } => {
            commands::renew::execute(&config, &justfile, duration)?;
        }
        Cmd::List => commands::list::execute(&config)?,
        Cmd::Run { justfile, args } => commands::run::execute(&config, &justfile, args)?,
    }

    Ok(())
}
