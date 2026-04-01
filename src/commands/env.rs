use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::args::{
    ActivateArgs, AddArgs, AllowArgs, BlockArgs, DaemonArgs, ListArgs, PortArgs, RemoveArgs,
    RunArgs, StopArgs, SyncArgs, TrustArgs, UntrustArgs,
};
use crate::error::{Error, Result};
use crate::proxy::ca::generate_ca;
use crate::proxy::config::{
    AuthConfig, EnvConfig, HostConfig, default_config_template, global_ca_cert_path,
    global_ca_dir, pid_path, port_path, runtime_dir, secrets_path, validate_project_dir,
};
use crate::proxy::secrets::{
    SecretsStore, generate_key, generate_project_id, load_key, store_key,
};
use crate::proxy::server::run_daemon;

pub(crate) fn run_create(path: &Path, name: Option<&str>) -> Result<()> {
    let project_dir = canonicalize_or_create(path)?;

    let config_path = crate::proxy::config::config_path(&project_dir);
    if config_path.exists() {
        println!(
            "Env '{}' already exists. Use `nv add` to configure auth.",
            project_dir.display()
        );
        return Ok(());
    }

    // Ensure global CA exists; generate + trust if first env ever
    let ca_dir = global_ca_dir()
        .ok_or_else(|| Error::cli("Cannot determine system config directory"))?;
    if !ca_dir.join("ca.crt").exists() {
        std::fs::create_dir_all(&ca_dir)
            .map_err(|e| Error::cli(format!("Failed to create CA directory: {e}")))?;
        generate_ca(&ca_dir)?;
        trust_ca_global()?;
    }

    // Generate project ID and encryption key
    let project_id = generate_project_id();
    store_key(&project_id, &generate_key())?;

    // Write nv.toml with id (and optional name) prepended to the template
    let mut header = format!("id = \"{project_id}\"");
    if let Some(n) = name {
        header.push_str(&format!("\nname = \"{n}\""));
    }
    let template = format!("{header}\n\n{}", default_config_template());
    std::fs::write(&config_path, template)?;

    write_activate_script(&project_dir)?;

    let display_name = name.unwrap_or_else(|| {
        project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("nv")
    });
    println!(
        "Initialised net environment [{}] in: {}",
        display_name,
        project_dir.display()
    );
    println!("Activate with: source .nenv/bin/activate");

    Ok(())
}

fn write_activate_script(project_dir: &Path) -> Result<()> {
    let project_dir_abs = project_dir
        .canonicalize()
        .map_err(|e| Error::cli(format!("Cannot resolve project dir: {e}")))?;
    let project_dir_str = project_dir_abs.display();

    let script = format!(
        r#"#!/bin/sh
# nv — source this file to activate: source .nenv/bin/activate
_NV_DIR="{project_dir_str}"
_NV_PORT=$(nv _port "$_NV_DIR")
if [ $? -ne 0 ]; then
    echo "Failed to start nv proxy." >&2
    return 1
fi
# NV_KEY is consumed by the daemon; unset it so agent processes cannot read it
unset NV_KEY
# Read the env name from nv.toml at activation time (name field, else directory basename)
_NV_NAME=$(nv _name "$_NV_DIR")
export NV_ENV="$_NV_DIR"
export HTTP_PROXY="http://127.0.0.1:$_NV_PORT"
export HTTPS_PROXY="http://127.0.0.1:$_NV_PORT"
export NO_PROXY="localhost,127.0.0.1"
export _NV_OLD_PS1="$PS1"
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

    let bin_dir = runtime_dir(project_dir).join("bin");
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

pub(crate) async fn run_add(args: AddArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    if args.device_flow {
        return run_device_flow(args, &project_dir).await;
    }

    let (auth, secret_fields) = collect_auth_config(&args).await?;

    write_secrets(&args.host, &secret_fields, &project_dir)?;

    let mut config = EnvConfig::load(&project_dir)?;
    config
        .hosts
        .entry(args.host.clone())
        .or_insert_with(HostConfig::default)
        .auth = Some(auth);
    // nv add implicitly allows the host
    let allowed = config.proxy.allow_only.get_or_insert_with(Vec::new);
    if !allowed.contains(&args.host) {
        allowed.push(args.host.clone());
    }
    config.save(&project_dir)?;

    println!(
        "Auth configured for '{}' (secret stored in .nenv/secrets.enc).",
        args.host
    );
    Ok(())
}

/// Prompt for secrets and build the auth config + list of (field, secret) pairs.
async fn collect_auth_config(args: &AddArgs) -> Result<(AuthConfig, Vec<(String, String)>)> {
    if args.bearer || (!args.oauth2 && args.header.is_none() && args.query.is_none()) {
        let secret = collect_secret(&args.host, args.browser, "Bearer token").await?;
        Ok((
            AuthConfig::Bearer { token: None },
            vec![("token".to_owned(), secret)],
        ))
    } else if let Some(ref header_name) = args.header {
        let secret = collect_secret(
            &args.host,
            args.browser,
            &format!("Value for header '{header_name}'"),
        )
        .await?;
        Ok((
            AuthConfig::Header {
                name: header_name.clone(),
                value: None,
            },
            vec![("value".to_owned(), secret)],
        ))
    } else if let Some(ref param) = args.query {
        let secret = collect_secret(
            &args.host,
            args.browser,
            &format!("Value for query param '{param}'"),
        )
        .await?;
        Ok((
            AuthConfig::Query {
                param: param.clone(),
                value: None,
            },
            vec![("value".to_owned(), secret)],
        ))
    } else {
        // oauth2
        let token_url = args
            .token_url
            .clone()
            .ok_or_else(|| Error::cli("--token-url is required for --oauth2"))?;
        let client_id =
            collect_secret(&args.host, args.browser, "OAuth2 client ID").await?;
        let client_secret =
            collect_secret(&args.host, args.browser, "OAuth2 client secret").await?;
        Ok((
            AuthConfig::OAuth2 {
                client_id: None,
                client_secret: None,
                token_url,
                scopes: args.scopes.clone(),
            },
            vec![
                ("client_id".to_owned(), client_id),
                ("client_secret".to_owned(), client_secret),
            ],
        ))
    }
}

async fn collect_secret(host: &str, use_browser: bool, label: &str) -> Result<String> {
    if use_browser {
        crate::proxy::browser::collect_via_browser(host, label).await
    } else {
        prompt_secret(label)
    }
}

/// Load the secrets store for `project_dir`, apply `fields`, and save.
fn write_secrets(
    host: &str,
    fields: &[(String, String)],
    project_dir: &Path,
) -> Result<()> {
    let (key, sp) = load_project_key(project_dir)?;
    std::fs::create_dir_all(
        sp.parent()
            .ok_or_else(|| Error::cli("Invalid secrets path"))?,
    )?;
    let mut store = SecretsStore::load(&sp, &key)?;
    for (field, value) in fields {
        store.set(host, field, value.clone());
    }
    store.save(&sp, &key)
}

/// Load the project key from config + key store.
fn load_project_key(project_dir: &Path) -> Result<([u8; 32], PathBuf)> {
    let config = EnvConfig::load(project_dir)?;
    let project_id = config
        .id
        .as_deref()
        .ok_or_else(|| Error::cli("nv.toml is missing 'id'. Run `nv init` to reinitialise."))?
        .to_owned();
    let key = load_key(&project_id)?;
    let sp = secrets_path(project_dir);
    Ok((key, sp))
}

async fn run_device_flow(args: AddArgs, project_dir: &std::path::Path) -> Result<()> {
    let host = &args.host;

    let mut config = EnvConfig::load(project_dir)?;
    let project_id = config
        .id
        .clone()
        .ok_or_else(|| Error::cli("nv.toml is missing 'id'. Run `nv init` to reinitialise."))?;

    let (device_url, token_url) = resolve_device_flow_endpoints(
        host,
        args.device_url.as_deref(),
        args.token_url.as_deref(),
    )?;

    let client_id = args
        .client_id
        .or_else(|| builtin_client_id(host))
        .ok_or_else(|| {
            Error::cli(format!(
                "--client-id is required for device flow with unknown service '{host}'"
            ))
        })?;

    let scope_str = args.scopes.join(" ");

    let http = reqwest::Client::new();
    let mut params = vec![("client_id", client_id.as_str())];
    if !scope_str.is_empty() {
        params.push(("scope", scope_str.as_str()));
    }

    #[derive(serde::Deserialize)]
    struct DeviceCodeResponse {
        device_code: String,
        user_code: String,
        verification_uri: String,
        #[serde(default = "default_interval")]
        interval: u64,
        expires_in: Option<u64>,
    }
    fn default_interval() -> u64 {
        5
    }

    let resp = http
        .post(&device_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| Error::cli(format!("Device code request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::cli(format!(
            "Device code endpoint returned {}",
            resp.status()
        )));
    }

    let device: DeviceCodeResponse = resp
        .json()
        .await
        .map_err(|e| Error::cli(format!("Failed to parse device code response: {e}")))?;

    println!();
    println!("  Open this URL in your browser:");
    println!("  {}", device.verification_uri);
    println!();
    println!("  Enter code:  {}", device.user_code);
    println!();

    let _ = open::that(&device.verification_uri);

    let expires_secs = device.expires_in.unwrap_or(900);
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(expires_secs);
    let interval = std::time::Duration::from_secs(device.interval);

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        error: Option<String>,
    }

    println!("Waiting for authorization\u{2026}");

    loop {
        tokio::time::sleep(interval).await;

        if std::time::Instant::now() > deadline {
            return Err(Error::cli("Device flow authorization timed out"));
        }

        let poll_resp = http
            .post(&token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id.as_str()),
                ("device_code", device.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .map_err(|e| Error::cli(format!("Token poll failed: {e}")))?;

        let tok: TokenResponse = poll_resp
            .json()
            .await
            .map_err(|e| Error::cli(format!("Failed to parse token response: {e}")))?;

        match tok.error.as_deref() {
            Some("authorization_pending") | Some("slow_down") => continue,
            Some("expired_token") => {
                return Err(Error::cli("Device flow expired — run nv add again"))
            }
            Some("access_denied") => return Err(Error::cli("Authorization denied by user")),
            Some(other) => return Err(Error::cli(format!("Device flow error: {other}"))),
            None => {}
        }

        if let Some(token) = tok.access_token {
            // Store token in encrypted secrets
            let key = load_key(&project_id)?;
            let sp = secrets_path(project_dir);
            std::fs::create_dir_all(
                sp.parent()
                    .ok_or_else(|| Error::cli("Invalid secrets path"))?,
            )?;
            let mut store = SecretsStore::load(&sp, &key)?;
            store.set(host, "token", token);
            store.save(&sp, &key)?;

            // Update nv.toml
            config
                .hosts
                .entry(host.clone())
                .or_insert_with(HostConfig::default)
                .auth = Some(AuthConfig::Bearer { token: None });
            config.save(project_dir)?;

            println!("Authorized \u{2713}  {host} requests will use Bearer token.");
            return Ok(());
        }
    }
}

fn resolve_device_flow_endpoints(
    host: &str,
    device_url: Option<&str>,
    token_url: Option<&str>,
) -> Result<(String, String)> {
    let known: Option<(&str, &str)> = match host {
        "github.com" | "api.github.com" => Some((
            "https://github.com/login/device/code",
            "https://github.com/login/oauth/access_token",
        )),
        "gitlab.com" => Some((
            "https://gitlab.com/oauth/authorize_device",
            "https://gitlab.com/oauth/token",
        )),
        _ => None,
    };

    let (d, t) = if let Some((d, t)) = known {
        (
            device_url.unwrap_or(d).to_string(),
            token_url.unwrap_or(t).to_string(),
        )
    } else {
        let d = device_url
            .ok_or_else(|| Error::cli("--device-url is required for unknown service"))?;
        let t = token_url
            .ok_or_else(|| Error::cli("--token-url is required for unknown service"))?;
        (d.to_string(), t.to_string())
    };

    Ok((d, t))
}

fn builtin_client_id(_host: &str) -> Option<String> {
    None
}

fn prompt_secret(label: &str) -> Result<String> {
    inquire::Password::new(&format!("{label}:"))
        .without_confirmation()
        .prompt()
        .map_err(|e| Error::cli(format!("Input cancelled: {e}")))
}

pub(crate) fn run_remove(args: &RemoveArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let mut config = EnvConfig::load(&project_dir)?;
    if config.hosts.shift_remove(&args.host).is_some() {
        // Remove from encrypted secrets store (best-effort)
        if let Ok((key, sp)) = load_project_key(&project_dir) {
            if let Ok(mut store) = SecretsStore::load(&sp, &key) {
                store.remove_host(&args.host);
                let _ = store.save(&sp, &key);
            }
        }
        // Clean up allow_only and block lists
        if let Some(ref mut allowed) = config.proxy.allow_only {
            allowed.retain(|h| h != &args.host);
        }
        if let Some(ref mut blocked) = config.proxy.block {
            blocked.retain(|h| h != &args.host);
        }
        config.save(&project_dir)?;
        println!("Removed '{}'.", args.host);
    } else {
        println!("No entry found for '{}'.", args.host);
    }
    Ok(())
}

pub(crate) fn run_list(args: &ListArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let config = EnvConfig::load(&project_dir)?;
    if config.hosts.is_empty() {
        println!("No hosts configured. Edit nv.toml to add rules.");
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
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let port = ensure_daemon_running(&project_dir).await?;
    let proxy_url = format!("http://127.0.0.1:{port}");

    let status = std::process::Command::new(&args.cmd)
        .args(&args.args)
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("NV_ENV", project_dir.as_os_str())
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
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;
    trust_ca_global()
}

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
        let status = std::process::Command::new("security")
            .args([
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
            eprintln!("Failed to install CA certificate.");
            eprintln!("Try running: sudo nv trust");
            return Err(Error::cli(
                "Failed to install CA certificate. Try: sudo nv trust",
            ));
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
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;
    let cert_path = global_ca_cert_path()
        .ok_or_else(|| Error::cli("Cannot determine global CA certificate path"))?;
    let cert_str = cert_path.to_string_lossy();

    eprintln!("Removing CA certificate from system trust store...");
    eprintln!("(You may be prompted for your password.)");
    eprintln!();

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("security")
            .args(["remove-trusted-cert", "-d", &cert_str])
            .status()
            .map_err(|e| Error::cli(format!("Failed to run security command: {e}")))?;

        if status.success() {
            eprintln!("CA removed from system trust store.");
        } else {
            eprintln!("Failed to remove CA certificate.");
            eprintln!("Try running: sudo nv untrust");
            return Err(Error::cli(
                "Failed to remove CA certificate. Try: sudo nv untrust",
            ));
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
    run_daemon(args.project_dir).await
}

pub(crate) fn run_stop(args: &StopArgs) -> Result<()> {
    let project_dir = &args.project_dir;

    let pid_file = pid_path(project_dir);
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
    let _ = std::fs::remove_file(port_path(project_dir));

    Ok(())
}

pub(crate) async fn run_port(args: PortArgs) -> Result<()> {
    let port = ensure_daemon_running(&args.project_dir).await?;
    println!("{port}");
    Ok(())
}

// ── Name ─────────────────────────────────────────────────────────────────────

/// Resolve the display name for a project directory: `name` from nv.toml, else
/// the directory basename. Used by the activate script at activation time.
pub(crate) fn run_name(project_dir: &Path) -> Result<()> {
    let name = resolve_env_name(project_dir);
    println!("{name}");
    Ok(())
}

fn resolve_env_name(project_dir: &Path) -> String {
    EnvConfig::load(project_dir)
        .ok()
        .and_then(|c| c.name)
        .or_else(|| {
            project_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "nv".to_string())
}

// ── Allow / Block ─────────────────────────────────────────────────────────────

pub(crate) fn run_allow(args: &AllowArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let mut config = EnvConfig::load(&project_dir)?;
    let allowed = config.proxy.allow_only.get_or_insert_with(Vec::new);
    if allowed.contains(&args.host) {
        println!("'{}' is already allowed.", args.host);
        return Ok(());
    }
    allowed.push(args.host.clone());
    config.save(&project_dir)?;
    println!("Allowed '{}' (pass-through, no auth injection).", args.host);
    Ok(())
}

pub(crate) fn run_block(args: &BlockArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let mut config = EnvConfig::load(&project_dir)?;
    let blocked = config.proxy.block.get_or_insert_with(Vec::new);
    if blocked.contains(&args.host) {
        println!("'{}' is already blocked.", args.host);
        return Ok(());
    }
    blocked.push(args.host.clone());
    config.save(&project_dir)?;
    println!("Blocked '{}'.", args.host);
    Ok(())
}

// ── Activate ──────────────────────────────────────────────────────────────────

pub(crate) async fn run_activate(args: &ActivateArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let port = ensure_daemon_running(&project_dir).await?;
    let proxy_url = format!("http://127.0.0.1:{port}");
    let env_name = resolve_env_name(&project_dir);
    let project_dir_str = project_dir.display();

    // Print to stderr so it isn't captured by eval
    eprintln!("nv [{env_name}] active (port {port}). Run 'deactivate' to stop.");

    // Print shell commands to stdout for: eval "$(nv activate)"
    println!("export HTTP_PROXY='{proxy_url}';");
    println!("export HTTPS_PROXY='{proxy_url}';");
    println!("export NO_PROXY='localhost,127.0.0.1';");
    println!("export NV_ENV='{project_dir_str}';");
    println!("unset NV_KEY;");
    println!("export _NV_OLD_PS1=\"$PS1\";");
    println!("export PS1='[{env_name}] '$PS1;");
    println!(
        "deactivate() {{ nv _stop \"$NV_ENV\"; \
        export PS1=\"$_NV_OLD_PS1\"; \
        unset HTTP_PROXY HTTPS_PROXY NV_ENV NO_PROXY _NV_OLD_PS1; \
        unset -f deactivate; \
        echo 'nv deactivated.'; }}"
    );

    Ok(())
}

// ── Sync ──────────────────────────────────────────────────────────────────────

pub(crate) fn run_sync(args: &SyncArgs) -> Result<()> {
    let project_dir = resolve_project_dir(&args.path)?;
    validate_project_dir(&project_dir)?;

    let config = EnvConfig::load(&project_dir)?;
    let (key, sp) = load_project_key(&project_dir)?;
    std::fs::create_dir_all(
        sp.parent().ok_or_else(|| Error::cli("Invalid secrets path"))?,
    )?;
    let mut store = SecretsStore::load(&sp, &key)?;

    // Collect (host, field, prompt_label) for every secret missing from both
    // nv.toml (as an explicit/env-var value) and .nenv/secrets.enc.
    let mut missing: Vec<(String, String, String)> = Vec::new();

    for (host, host_cfg) in &config.hosts {
        let Some(ref auth) = host_cfg.auth else {
            continue;
        };
        match auth {
            AuthConfig::Bearer { token } => {
                if token.is_none() && store.get(host, "token").is_none() {
                    missing.push((host.clone(), "token".into(), format!("{host} (bearer token)")));
                }
            }
            AuthConfig::Header { name, value } => {
                if value.is_none() && store.get(host, "value").is_none() {
                    missing.push((host.clone(), "value".into(), format!("{host} ({name} header)")));
                }
            }
            AuthConfig::Query { param, value } => {
                if value.is_none() && store.get(host, "value").is_none() {
                    missing.push((host.clone(), "value".into(), format!("{host} ({param} query param)")));
                }
            }
            AuthConfig::OAuth2 { client_id, client_secret, .. } => {
                if client_id.is_none() && store.get(host, "client_id").is_none() {
                    missing.push((host.clone(), "client_id".into(), format!("{host} (oauth2 client ID)")));
                }
                if client_secret.is_none() && store.get(host, "client_secret").is_none() {
                    missing.push((host.clone(), "client_secret".into(), format!("{host} (oauth2 client secret)")));
                }
            }
        }
    }

    if missing.is_empty() {
        println!("All secrets up to date.");
        return Ok(());
    }

    for (host, field, label) in missing {
        let secret = prompt_secret(&label)?;
        store.set(&host, &field, secret);
    }
    store.save(&sp, &key)?;
    println!("Secrets saved.");
    Ok(())
}

// ── CA helpers ────────────────────────────────────────────────────────────────

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

// ── Daemon helpers ────────────────────────────────────────────────────────────

async fn ensure_daemon_running(project_dir: &Path) -> Result<u16> {
    if let Some(port) = read_running_daemon_port(project_dir) {
        return Ok(port);
    }

    spawn_daemon(project_dir)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(port) = read_running_daemon_port(project_dir) {
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

fn read_running_daemon_port(project_dir: &Path) -> Option<u16> {
    let pid_file = pid_path(project_dir);
    let port_file = port_path(project_dir);

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

fn spawn_daemon(project_dir: &Path) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::cli(format!("Cannot determine executable path: {e}")))?;

    let project_dir_abs = project_dir
        .canonicalize()
        .map_err(|e| Error::cli(format!("Cannot resolve project dir: {e}")))?;

    let null_file = open_null()?;

    std::process::Command::new(exe)
        .args(["_daemon", &project_dir_abs.to_string_lossy()])
        .stdin(null_file.try_clone()?)
        .stdout(null_file.try_clone()?)
        .stderr(null_file)
        .spawn()
        .map_err(|e| Error::cli(format!("Failed to spawn proxy daemon: {e}")))?;

    Ok(())
}

fn resolve_project_dir(path: &Path) -> Result<PathBuf> {
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

// ── Platform helpers ──────────────────────────────────────────────────────────

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
