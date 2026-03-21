use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::args::{
    AddArgs, DaemonArgs, ListArgs, PortArgs, RemoveArgs, RunArgs, StopArgs, TrustArgs, UntrustArgs,
};
use crate::error::{Error, Result};
use crate::proxy::ca::generate_ca;
use crate::proxy::config::{
    AuthConfig, EnvConfig, HostConfig, default_config_template, global_ca_cert_path,
    global_ca_dir, pid_path, port_path, validate_env_dir,
};
use crate::proxy::server::run_daemon;

pub(crate) fn run_create(path: &Path) -> Result<()> {
    let env_dir = canonicalize_or_create(path)?;

    let config_path = crate::proxy::config::config_path(&env_dir);
    if config_path.exists() {
        println!(
            "Env already exists at '{}'. Use `nv add` to configure auth.",
            env_dir.display()
        );
        return Ok(());
    }

    std::fs::create_dir_all(&env_dir)?;

    // Ensure global CA exists; generate + trust it if this is the first env ever
    let ca_dir = global_ca_dir()
        .ok_or_else(|| Error::cli("Cannot determine system config directory"))?;

    if !ca_dir.join("ca.crt").exists() {
        std::fs::create_dir_all(&ca_dir)
            .map_err(|e| Error::cli(format!("Failed to create CA directory: {e}")))?;
        generate_ca(&ca_dir)?;
        trust_ca_global()?;
    }

    std::fs::write(&config_path, default_config_template())?;
    write_activate_script(&env_dir)?;

    println!("Creating net environment at: {}", path.display());
    println!("Activate with: source {}/bin/activate", path.display());

    Ok(())
}

fn write_activate_script(env_dir: &Path) -> Result<()> {
    let env_dir_abs = env_dir
        .canonicalize()
        .map_err(|e| Error::cli(format!("Cannot resolve env dir: {e}")))?;
    let env_dir_str = env_dir_abs.display();

    let script = format!(
        r#"#!/bin/sh
# nv — source this file to activate: source {env_dir_str}/bin/activate
_NV_DIR="{env_dir_str}"
_NV_PORT=$(nv _port "$_NV_DIR")
if [ $? -ne 0 ]; then
    echo "Failed to start nv proxy." >&2
    return 1
fi
export NV_ENV="$_NV_DIR"
export HTTP_PROXY="http://127.0.0.1:$_NV_PORT"
export HTTPS_PROXY="http://127.0.0.1:$_NV_PORT"
export NO_PROXY="localhost,127.0.0.1"
export _NV_OLD_PS1="$PS1"
_NV_NAME="$(basename "$_NV_DIR")"
export PS1="[$_NV_NAME] $PS1"
deactivate() {{
    nv _stop "$NV_ENV"
    export PS1="$_NV_OLD_PS1"
    unset HTTP_PROXY HTTPS_PROXY NV_ENV NO_PROXY _NV_OLD_PS1
    unset -f deactivate
    echo "nv deactivated."
}}
echo "nv [$_NV_NAME] active (port $_NV_PORT). Run 'deactivate' to stop."
"#
    );

    let bin_dir = env_dir.join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let activate_path = bin_dir.join("activate");
    std::fs::write(&activate_path, script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&activate_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&activate_path, perms)?;
    }

    Ok(())
}

pub(crate) fn run_add(args: AddArgs) -> Result<()> {
    let env_dir = resolve_env_dir(&args.path)?;
    validate_env_dir(&env_dir)?;

    let auth = if args.bearer || (!args.oauth2 && args.header.is_none() && args.query.is_none()) {
        let secret = prompt_secret("Bearer token")?;
        crate::proxy::keychain::store(&args.host, "token", &secret)?;
        AuthConfig::Bearer { token: None }
    } else if let Some(header_name) = args.header {
        let secret = prompt_secret(&format!("Value for header '{header_name}'"))?;
        crate::proxy::keychain::store(&args.host, "value", &secret)?;
        AuthConfig::Header { name: header_name, value: None }
    } else if let Some(param) = args.query {
        let secret = prompt_secret(&format!("Value for query param '{param}'"))?;
        crate::proxy::keychain::store(&args.host, "value", &secret)?;
        AuthConfig::Query { param, value: None }
    } else {
        let token_url = args.token_url.ok_or_else(|| Error::cli("--token-url is required for --oauth2"))?;
        let client_id = prompt_secret("OAuth2 client ID")?;
        let client_secret = prompt_secret("OAuth2 client secret")?;
        crate::proxy::keychain::store(&args.host, "client_id", &client_id)?;
        crate::proxy::keychain::store(&args.host, "client_secret", &client_secret)?;
        AuthConfig::OAuth2 {
            client_id: None,
            client_secret: None,
            token_url,
            scopes: args.scopes,
        }
    };

    let mut config = EnvConfig::load(&env_dir)?;
    config
        .hosts
        .entry(args.host.clone())
        .or_insert_with(HostConfig::default)
        .auth = Some(auth);
    config.save(&env_dir)?;

    println!("Auth configured for '{}' (secret stored in keychain).", args.host);
    Ok(())
}

fn prompt_secret(label: &str) -> Result<String> {
    inquire::Password::new(&format!("{label}:"))
        .without_confirmation()
        .prompt()
        .map_err(|e| Error::cli(format!("Input cancelled: {e}")))
}

pub(crate) fn run_remove(args: &RemoveArgs) -> Result<()> {
    let env_dir = resolve_env_dir(&args.path)?;
    validate_env_dir(&env_dir)?;

    let mut config = EnvConfig::load(&env_dir)?;
    if config.hosts.shift_remove(&args.host).is_some() {
        // Clean up any keychain entries for this host
        for field in &["token", "value", "client_id", "client_secret"] {
            crate::proxy::keychain::delete(&args.host, field);
        }
        config.save(&env_dir)?;
        println!("Removed '{}'.", args.host);
    } else {
        println!("No entry found for '{}'.", args.host);
    }
    Ok(())
}

pub(crate) fn run_list(args: &ListArgs) -> Result<()> {
    let env_dir = resolve_env_dir(&args.path)?;
    validate_env_dir(&env_dir)?;

    let config = EnvConfig::load(&env_dir)?;
    if config.hosts.is_empty() {
        println!("No hosts configured. Edit .nv/config.toml to add rules.");
    } else {
        println!("Configured hosts:");
        for (host, cfg) in &config.hosts {
            let auth_hint = if cfg.auth.is_some() { " [auth]" } else { "" };
            let redirect_hint = cfg
                .redirect
                .as_deref()
                .map(|r| format!(" -> {r}"))
                .unwrap_or_default();
            println!("  {host}{auth_hint}{redirect_hint}");
        }
    }
    Ok(())
}

pub(crate) async fn run_run(args: RunArgs) -> Result<()> {
    let env_dir = resolve_env_dir(&args.path)?;
    validate_env_dir(&env_dir)?;

    let port = ensure_daemon_running(&env_dir).await?;
    let proxy_url = format!("http://127.0.0.1:{port}");

    let status = std::process::Command::new(&args.cmd)
        .args(&args.args)
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("NV_ENV", env_dir.as_os_str())
        .status()
        .map_err(|e| Error::cli(format!("Failed to execute '{}': {e}", args.cmd)))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(Error::cli(format!(
            "Command '{}' exited with status {code}",
            args.cmd
        )));
    }

    Ok(())
}

pub(crate) fn run_trust(args: &TrustArgs) -> Result<()> {
    let env_dir = resolve_env_dir(&args.path)?;
    validate_env_dir(&env_dir)?;
    trust_ca_global()
}

/// Trust the global CA certificate in the system trust store.
fn trust_ca_global() -> Result<()> {
    let cert_path = global_ca_cert_path()
        .ok_or_else(|| Error::cli("Cannot determine global CA certificate path"))?;
    trust_ca_cert(&cert_path)
}

fn trust_ca_cert(cert_path: &Path) -> Result<()> {
    let cert_str = cert_path.to_string_lossy();

    eprintln!("Trusting proxy CA... (you may be prompted for your password)");

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("sudo")
            .args([
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                &cert_str,
            ])
            .status()
            .map_err(|e| Error::cli(format!("Failed to run security command: {e}")))?;

        if status.success() {
            eprintln!("CA trusted. Run `nv untrust` to remove it.");
        } else {
            return Err(Error::cli("Failed to install CA certificate."));
        }
    }

    #[cfg(all(target_os = "linux", not(target_os = "macos")))]
    {
        trust_linux(&cert_str)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("Automatic trust installation is not supported on this platform.");
        eprintln!("Install the CA manually: {cert_str}");
    }

    Ok(())
}

pub(crate) fn run_untrust(args: &UntrustArgs) -> Result<()> {
    let env_dir = resolve_env_dir(&args.path)?;
    validate_env_dir(&env_dir)?;
    let cert_path = global_ca_cert_path()
        .ok_or_else(|| Error::cli("Cannot determine global CA certificate path"))?;
    let cert_str = cert_path.to_string_lossy();

    eprintln!("Removing CA certificate from system trust store...");
    eprintln!("(You may be prompted for your password.)");
    eprintln!();

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("sudo")
            .args(["security", "remove-trusted-cert", "-d", &cert_str])
            .status()
            .map_err(|e| Error::cli(format!("Failed to run security command: {e}")))?;

        if status.success() {
            eprintln!("CA removed from system trust store.");
        } else {
            return Err(Error::cli("Failed to remove CA certificate."));
        }
    }

    #[cfg(all(target_os = "linux", not(target_os = "macos")))]
    {
        untrust_linux()?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("Automatic trust removal is not supported on this platform.");
        eprintln!("Remove the CA manually from your system trust store.");
    }

    Ok(())
}

pub(crate) async fn run_daemon_cmd(args: DaemonArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::sink)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();
    run_daemon(args.env_dir).await
}

pub(crate) fn run_stop(args: &StopArgs) -> Result<()> {
    let env_dir = &args.env_dir;

    let pid_file = pid_path(env_dir);
    if !pid_file.exists() {
        return Ok(());
    }

    let pid_str = std::fs::read_to_string(&pid_file)?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .map_err(|e| Error::cli(format!("Invalid PID in proxy.pid: {e}")))?;

    kill_process(pid)?;

    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(port_path(env_dir));

    Ok(())
}

pub(crate) async fn run_port(args: PortArgs) -> Result<()> {
    let port = ensure_daemon_running(&args.env_dir).await?;
    println!("{port}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn trust_linux(cert_str: &str) -> Result<()> {
    let (dest, update_cmd) =
        if std::path::Path::new("/usr/local/share/ca-certificates").exists() {
            (
                "/usr/local/share/ca-certificates/nv-proxy.crt",
                "update-ca-certificates",
            )
        } else {
            (
                "/etc/pki/ca-trust/source/anchors/nv-proxy.crt",
                "update-ca-trust",
            )
        };

    let cp_status = std::process::Command::new("sudo")
        .args(["cp", cert_str, dest])
        .status()
        .map_err(|e| Error::cli(format!("Failed to copy CA cert: {e}")))?;
    if !cp_status.success() {
        return Err(Error::cli("Failed to copy CA certificate."));
    }

    let update_status = std::process::Command::new("sudo")
        .arg(update_cmd)
        .status()
        .map_err(|e| Error::cli(format!("Failed to run {update_cmd}: {e}")))?;
    if !update_status.success() {
        return Err(Error::cli(format!("{update_cmd} failed.")));
    }

    eprintln!("CA trusted. Run `nv untrust` to remove it.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn untrust_linux() -> Result<()> {
    let (dest, update_cmd) =
        if std::path::Path::new("/usr/local/share/ca-certificates").exists() {
            (
                "/usr/local/share/ca-certificates/nv-proxy.crt",
                "update-ca-certificates",
            )
        } else {
            (
                "/etc/pki/ca-trust/source/anchors/nv-proxy.crt",
                "update-ca-trust",
            )
        };

    let rm_status = std::process::Command::new("sudo")
        .args(["rm", "-f", dest])
        .status()
        .map_err(|e| Error::cli(format!("Failed to remove CA cert: {e}")))?;
    if !rm_status.success() {
        return Err(Error::cli("Failed to remove CA certificate."));
    }

    let update_status = std::process::Command::new("sudo")
        .arg(update_cmd)
        .status()
        .map_err(|e| Error::cli(format!("Failed to run {update_cmd}: {e}")))?;
    if !update_status.success() {
        return Err(Error::cli(format!("{update_cmd} failed.")));
    }

    eprintln!("CA removed from system trust store.");
    Ok(())
}

// ── internal helpers ──────────────────────────────────────────────────────────

async fn ensure_daemon_running(env_dir: &Path) -> Result<u16> {
    if let Some(port) = read_running_daemon_port(env_dir) {
        return Ok(port);
    }

    spawn_daemon(env_dir)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(port) = read_running_daemon_port(env_dir) {
            return Ok(port);
        }
        if Instant::now() > deadline {
            return Err(Error::cli(
                "Timed out waiting for proxy daemon to start. \
                 Check that `nv` is in PATH.",
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn read_running_daemon_port(env_dir: &Path) -> Option<u16> {
    let pid_file = pid_path(env_dir);
    let port_file = port_path(env_dir);

    if !pid_file.exists() || !port_file.exists() {
        return None;
    }

    let pid_str = std::fs::read_to_string(&pid_file).ok()?;
    let pid: u32 = pid_str.trim().parse().ok()?;

    if !is_process_alive(pid) {
        let _ = std::fs::remove_file(&pid_file);
        let _ = std::fs::remove_file(&port_file);
        return None;
    }

    let port_str = std::fs::read_to_string(&port_file).ok()?;
    port_str.trim().parse().ok()
}

fn spawn_daemon(env_dir: &Path) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::cli(format!("Cannot determine executable path: {e}")))?;

    let env_dir_abs = env_dir
        .canonicalize()
        .map_err(|e| Error::cli(format!("Cannot resolve env dir: {e}")))?;

    let null_file = open_null()?;

    std::process::Command::new(exe)
        .args(["_daemon", &env_dir_abs.to_string_lossy()])
        .stdin(null_file.try_clone()?)
        .stdout(null_file.try_clone()?)
        .stderr(null_file)
        .spawn()
        .map_err(|e| Error::cli(format!("Failed to spawn proxy daemon: {e}")))?;

    Ok(())
}

fn resolve_env_dir(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        path.canonicalize()
            .map_err(|e| Error::cli(format!("Cannot resolve path '{}': {e}", path.display())))
    } else {
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| Error::cli(format!("Cannot get current directory: {e}")))?
                .join(path)
        };
        Ok(abs)
    }
}

fn canonicalize_or_create(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        path.canonicalize()
            .map_err(|e| Error::cli(format!("Cannot resolve path '{}': {e}", path.display())))
    } else {
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| Error::cli(format!("Cannot get current directory: {e}")))?
                .join(path)
        };
        Ok(abs)
    }
}

// ── platform-specific helpers ─────────────────────────────────────────────────

#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_process_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(unix)]
fn kill_process(pid: u32) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| Error::cli(format!("Failed to run kill: {e}")))?;
    let _ = status;
    Ok(())
}

#[cfg(not(unix))]
fn kill_process(pid: u32) -> Result<()> {
    std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| Error::cli(format!("Failed to run taskkill: {e}")))?;
    Ok(())
}

#[cfg(unix)]
fn open_null() -> Result<std::fs::File> {
    std::fs::File::open("/dev/null").map_err(Error::Io)
}

#[cfg(not(unix))]
fn open_null() -> Result<std::fs::File> {
    std::fs::File::open("NUL").map_err(Error::Io)
}
