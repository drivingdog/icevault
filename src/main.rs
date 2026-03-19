mod cli;
mod commands;
mod env_file;
mod error;
mod reference;
mod vault;

use std::path::PathBuf;

use clap::Parser;
use cli::{Cli, Commands};

fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".icevault").join("vault.ice")
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> error::Result<()> {
    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(default_vault_path);

    match cli.command {
        Commands::Init => commands::init::run(&vault_path),

        Commands::Add { path } => commands::add::run(&path, &vault_path),

        Commands::List { filter } => commands::list::run(filter.as_deref(), &vault_path),

        Commands::Delete { path } => commands::delete::run(&path, &vault_path),

        Commands::Migrate { env_file, prefix } => {
            commands::migrate::run(&env_file, &prefix, &vault_path)
        }

        Commands::Shred { file } => commands::shred::run(&file),

        Commands::Run { env_file, cmd } => commands::run::run(&env_file, &cmd, &vault_path),

        Commands::Export { env_file, confirm } => {
            commands::export::run(&env_file, confirm, &vault_path)
        }
    }
}
