mod args;
mod commands;
mod error;
mod proxy;

use args::{Cli, Commands, InitArgs, NameArgs};
use clap::Parser;
use error::Result;

fn main() {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to create tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = rt.block_on(run()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init(InitArgs { path, name }) => commands::env::run_create(&path, name.as_deref()),
        Commands::Add(a) => commands::env::run_add(a).await,
        Commands::Remove(ref a) => commands::env::run_remove(a),
        Commands::List(ref a) => commands::env::run_list(a),
        Commands::Run(a) => commands::env::run_run(a).await,
        Commands::Trust(ref a) => commands::env::run_trust(a),
        Commands::Untrust(ref a) => commands::env::run_untrust(a),
        Commands::Daemon(a) => commands::env::run_daemon_cmd(a).await,
        Commands::Stop(ref a) => commands::env::run_stop(a),
        Commands::Port(a) => commands::env::run_port(a).await,
        Commands::Name(NameArgs { ref project_dir }) => commands::env::run_name(project_dir),
        Commands::Activate(ref a) => commands::env::run_activate(a).await,
        Commands::Sync(ref a) => commands::env::run_sync(a),
        Commands::Allow(ref a) => commands::env::run_allow(a),
        Commands::Block(ref a) => commands::env::run_block(a),
    }
}
