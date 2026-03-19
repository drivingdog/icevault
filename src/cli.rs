use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "icevault",
    about = "Local secret manager — store encrypted secrets, inject at runtime",
    version
)]
pub struct Cli {
    /// Path to vault file (default: ~/.icevault/vault.ice)
    #[arg(long, global = true)]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new encrypted vault
    Init,

    /// Store a secret in the vault (prompts for value with hidden input)
    Add {
        /// Path in format Vault/Category/Key (e.g. Development/Database/connection_string)
        path: String,
    },

    /// List stored secret paths (values are never shown)
    List {
        /// Filter by vault name (e.g. Development)
        filter: Option<String>,
    },

    /// Delete a secret from the vault
    Delete {
        /// Path in format Vault/Category/Key
        path: String,
    },

    /// Inject secrets into a child process
    ///
    /// Example: icevault run --env-file=.env -- npm run dev
    Run {
        /// Path to .env file with iv:// references
        #[arg(long)]
        env_file: PathBuf,

        /// Command and arguments to run (everything after --)
        #[arg(last = true)]
        cmd: Vec<String>,
    },

    /// Migrate an existing .env file into the vault and generate a .env.ice with iv:// references
    ///
    /// Example: icevault migrate --env-file=.env.local --prefix=Ecommerce/Development
    Migrate {
        /// Path to the existing .env file with real values
        #[arg(long)]
        env_file: PathBuf,

        /// Vault/Category prefix for all migrated secrets (e.g. Ecommerce/Development)
        #[arg(long)]
        prefix: String,
    },

    /// Securely overwrite and delete a file containing secrets
    ///
    /// Example: icevault shred --file=.env.local
    Shred {
        /// File to securely delete
        #[arg(long)]
        file: PathBuf,
    },

    /// Print resolved env vars to stdout (debug only — prints secrets!)
    Export {
        /// Path to .env file with iv:// references
        #[arg(long)]
        env_file: PathBuf,

        /// Required to actually print secrets
        #[arg(long)]
        confirm: bool,
    },
}
