use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "nv")]
#[command(about = "NV — a transparent browser for agents.")]
#[command(version)]
#[allow(unreachable_pub)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Initialise a net environment in the current directory
    Init(InitArgs),

    /// Add or update auth for a host (secret stored in OS keychain)
    Add(AddArgs),

    /// Remove a host rule
    Remove(RemoveArgs),

    /// List all configured hosts
    List(ListArgs),

    /// Run a command inside the net environment
    Run(RunArgs),

    /// Install the proxy CA into the system trust store
    Trust(TrustArgs),

    /// Remove the proxy CA from the system trust store
    Untrust(UntrustArgs),

    /// Start the proxy daemon (internal)
    #[command(name = "_daemon", hide = true)]
    Daemon(DaemonArgs),

    /// Stop the proxy daemon (internal)
    #[command(name = "_stop", hide = true)]
    Stop(StopArgs),

    /// Print the proxy port, starting the daemon if needed (internal)
    #[command(name = "_port", hide = true)]
    Port(PortArgs),

    /// Open browser auth window (internal)
    #[command(name = "_auth", hide = true)]
    Auth(AuthArgs),

    /// Open a browser window to establish a session
    Browse(BrowseArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct InitArgs {
    /// Project directory to initialise (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Display name shown in the shell prompt (default: directory name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Parser)]
pub(crate) struct AddArgs {
    /// Hostname to match (e.g. api.example.com)
    pub host: String,

    /// Bearer token auth (secret stored in OS keychain)
    #[arg(long, conflicts_with_all = ["header", "query", "oauth2"])]
    pub bearer: bool,

    /// Custom header auth — specify the header name
    #[arg(long, value_name = "NAME", conflicts_with_all = ["bearer", "query", "oauth2"])]
    pub header: Option<String>,

    /// Query parameter auth — specify the param name
    #[arg(long, value_name = "PARAM", conflicts_with_all = ["bearer", "header", "oauth2"])]
    pub query: Option<String>,

    /// OAuth2 client credentials auth
    #[arg(long, conflicts_with_all = ["bearer", "header", "query"], requires = "token_url")]
    pub oauth2: bool,

    /// OAuth2 token endpoint URL
    #[arg(long, value_name = "URL")]
    pub token_url: Option<String>,

    /// OAuth2 scopes (repeatable)
    #[arg(long, value_name = "SCOPE")]
    pub scopes: Vec<String>,

    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct RemoveArgs {
    /// Hostname to remove
    pub host: String,

    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct ListArgs {
    /// Project directory containing nv.toml (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct RunArgs {
    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,

    /// Command to run
    pub cmd: String,

    /// Arguments to pass to the command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

#[derive(Debug, Parser)]
pub(crate) struct TrustArgs {
    /// Project directory containing nv.toml (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct UntrustArgs {
    /// Project directory containing nv.toml (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct DaemonArgs {
    /// Absolute path to project directory
    pub project_dir: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct StopArgs {
    /// Absolute path to project directory
    pub project_dir: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct PortArgs {
    /// Absolute path to project directory
    pub project_dir: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct AuthArgs {
    /// URL to open in the browser
    pub url: String,

    /// Proxy port to route through
    pub proxy_port: u16,
}

#[derive(Debug, Parser)]
pub(crate) struct BrowseArgs {
    /// URL to open
    pub url: String,

    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
}
