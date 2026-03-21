mod args;
mod commands;
mod error;
mod proxy;

use args::{Cli, Commands};
use clap::Parser;
use error::Result;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => commands::env::run_create(&cli.path),
        Some(Commands::Add(a)) => commands::env::run_add(a),
        Some(Commands::Remove(ref a)) => commands::env::run_remove(a),
        Some(Commands::List(ref a)) => commands::env::run_list(a),
        Some(Commands::Run(a)) => commands::env::run_run(a).await,
        Some(Commands::Trust(ref a)) => commands::env::run_trust(a),
        Some(Commands::Untrust(ref a)) => commands::env::run_untrust(a),
        Some(Commands::Daemon(a)) => commands::env::run_daemon_cmd(a).await,
        Some(Commands::Stop(ref a)) => commands::env::run_stop(a),
        Some(Commands::Port(a)) => commands::env::run_port(a).await,
    }
}
