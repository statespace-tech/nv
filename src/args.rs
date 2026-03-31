use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "nv")]
#[command(about = "nv — a transparent HTTPS proxy for agents.")]
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

    /// Add or update auth for a host (secret stored in .nv/secrets.enc)
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

    /// Manage the project encryption key
    Key(KeyArgs),

    /// Start a shell with the net environment active
    Activate(ActivateArgs),
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

    /// Bearer token auth
    #[arg(long, conflicts_with_all = ["header", "query", "oauth2", "device_flow"])]
    pub bearer: bool,

    /// Custom header auth — specify the header name
    #[arg(long, value_name = "NAME", conflicts_with_all = ["bearer", "query", "oauth2", "device_flow"])]
    pub header: Option<String>,

    /// Query parameter auth — specify the param name
    #[arg(long, value_name = "PARAM", conflicts_with_all = ["bearer", "header", "oauth2", "device_flow"])]
    pub query: Option<String>,

    /// OAuth2 client credentials auth
    #[arg(long, conflicts_with_all = ["bearer", "header", "query", "device_flow"], requires = "token_url")]
    pub oauth2: bool,

    /// OAuth2 / device flow token endpoint URL
    #[arg(long, value_name = "URL")]
    pub token_url: Option<String>,

    /// OAuth2 / device flow scopes (repeatable)
    #[arg(long, value_name = "SCOPE")]
    pub scopes: Vec<String>,

    /// OAuth2 device authorization flow — opens default browser to authorize
    #[arg(long, conflicts_with_all = ["bearer", "header", "query", "oauth2"])]
    pub device_flow: bool,

    /// Device code endpoint URL (inferred for known services, required otherwise)
    #[arg(long, value_name = "URL")]
    pub device_url: Option<String>,

    /// OAuth2 client ID (required for device flow with unknown services)
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,

    /// Collect the secret via a browser form instead of a terminal prompt
    #[arg(long)]
    pub browser: bool,

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
pub(crate) struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum KeyCommands {
    /// Print the base64-encoded project key (for CI or transferring to another machine)
    Export(KeyExportArgs),
    /// Import a base64-encoded project key onto this machine
    Import(KeyImportArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct ActivateArgs {
    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct KeyExportArgs {
    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct KeyImportArgs {
    /// Base64-encoded 32-byte key (output of `nv key export`)
    pub key: String,
    /// Project directory containing nv.toml (default: current directory)
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
}
