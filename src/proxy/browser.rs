//! Browser-through-proxy authentication.
//!
//! When an upstream responds with 401, 403, or a redirect to a login page,
//! the proxy daemon spawns `nv _auth <url> <port>` which opens a wry webview
//! pointed at the auth URL with the proxy set to the daemon's port.  The user
//! logs in normally; the proxy captures the resulting cookies via MITM and
//! injects them into all subsequent agent requests automatically.

use std::sync::Arc;

use reqwest_cookie_store::CookieStoreMutex;
use tao::{
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use tracing::{info, warn};
use wry::{ProxyConfig, ProxyEndpoint, WebViewBuilder};

use crate::error::Error;

// ── Login-wall detection ──────────────────────────────────────────────────────

/// Path prefixes that reliably indicate a login wall redirect.
const LOGIN_PATHS: &[&str] = &[
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/oauth",
    "/sso",
    "/saml",
    "/session/new",
    "/users/sign_in",   // GitHub, GitLab
    "/accounts/login",  // Google
    "/account/login",
    "/user/login",
    "/oidc/",
];

/// Hostnames (or suffixes) that are identity providers.
const IDP_HOSTS: &[&str] = &[
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "login.github.com",
    "appleid.apple.com",
    "okta.com",
    "auth0.com",
    "onelogin.com",
    "ping.com",
    "pingidentity.com",
    "idp.",
    "sso.",
];

/// Returns `true` if a redirect to `url` looks like a login wall.
pub(crate) fn is_login_redirect(url: &reqwest::Url) -> bool {
    let path = url.path().to_lowercase();
    let host = url.host_str().unwrap_or("").to_lowercase();

    LOGIN_PATHS.iter().any(|p| path.starts_with(p))
        || IDP_HOSTS.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")) || host.starts_with(d))
}

// ── Cookie inspection ─────────────────────────────────────────────────────────

/// Returns `true` if the cookie store contains at least one cookie for `host`.
pub(crate) fn has_cookies_for_host(host: &str, store: &Arc<CookieStoreMutex>) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("https://{host}/")) else {
        return false;
    };
    use reqwest::cookie::CookieStore as _;
    store.cookies(&url).is_some()
}

// ── Auth URL helpers ──────────────────────────────────────────────────────────

/// Returns the URL to open for browser authentication.
///
/// If a redirect URL is provided (from a login-wall redirect), that is used
/// directly.  Otherwise, strips one subdomain level from `host` so that
/// `api.github.com` opens `https://github.com`.
pub(crate) fn auth_url(host: &str, redirect_url: Option<&str>) -> String {
    if let Some(url) = redirect_url {
        return url.to_string();
    }
    let base = if host.chars().filter(|&c| c == '.').count() >= 2 {
        host.splitn(2, '.').nth(1).unwrap_or(host)
    } else {
        host
    };
    format!("https://{base}")
}

// ── Daemon-side: spawn the auth window ───────────────────────────────────────

/// Spawns `nv _auth <url> <proxy_port>` as a child process.
///
/// Returns the child handle so the caller can kill it when auth completes.
///
/// # Errors
///
/// Returns an error if the current executable path cannot be determined or if
/// spawning fails.
pub(crate) fn open_with_proxy(
    url: &str,
    proxy_port: u16,
) -> crate::error::Result<std::process::Child> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::cli(format!("Cannot determine executable path: {e}")))?;

    info!("Opening auth window for {url} via proxy port {proxy_port}");

    std::process::Command::new(exe)
        .args(["_auth", url, &proxy_port.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| Error::cli(format!("Failed to spawn auth window: {e}")))
}

// ── Auth window process ───────────────────────────────────────────────────────

/// Opens a wry browser window for interactive authentication.
///
/// Called as `nv _auth <url> <proxy_port>`.  Runs the event loop and never
/// returns normally — exits via `std::process::exit`.
pub(crate) fn run_auth_window(url: &str, proxy_port: u16) -> ! {
    match try_run_auth_window(url, proxy_port) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn try_run_auth_window(
    url: &str,
    proxy_port: u16,
) -> crate::error::Result<std::convert::Infallible> {
    eprintln!("nv: opening browser for authentication — log in, then close this window.");

    let event_loop = EventLoop::new();

    let window = WindowBuilder::new()
        .with_title("Sign in — nv")
        .with_inner_size(tao::dpi::LogicalSize::new(960.0_f64, 720.0_f64))
        .build(&event_loop)
        .map_err(|e| Error::cli(format!("Failed to create window: {e}")))?;

    let proxy_config = ProxyConfig::Http(ProxyEndpoint {
        host: "127.0.0.1".to_string(),
        port: proxy_port.to_string(),
    });

    let _webview = WebViewBuilder::new(&window)
        .with_url(url)
        .map_err(|e| Error::cli(format!("Invalid auth URL: {e}")))?
        .with_proxy_config(proxy_config)
        .build()
        .map_err(|e| Error::cli(format!("Failed to create webview: {e}")))?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let tao::event::Event::WindowEvent {
            event: tao::event::WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    })
}

// ── Cookie jar serialization ──────────────────────────────────────────────────

/// Serialize the cookie store to a JSON string for keychain storage.
#[allow(deprecated)]
pub(crate) fn serialize_cookies(store: &CookieStoreMutex) -> Option<String> {
    let guard = store.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = Vec::new();
    guard.save_json(&mut buf).ok()?;
    String::from_utf8(buf).ok()
}

/// Restore a cookie store in-place from a JSON string.
#[allow(deprecated)]
pub(crate) fn restore_cookies(json: &str, store: &CookieStoreMutex) {
    if let Ok(loaded) = reqwest_cookie_store::CookieStore::load_json(json.as_bytes()) {
        let mut guard = store.lock().unwrap_or_else(|e| e.into_inner());
        *guard = loaded;
        info!("Session cookies restored from keychain");
    } else {
        warn!("Failed to restore session cookies from keychain");
    }
}
