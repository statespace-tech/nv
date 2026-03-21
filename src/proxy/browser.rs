//! Browser-through-proxy authentication.
//!
//! When an upstream responds with 401 and no auth is configured, the proxy
//! daemon spawns `nv _auth <url> <port>` which opens a wry webview pointed at
//! the auth URL with `--proxy-server` set to the daemon's port.  The user logs
//! in normally; the proxy captures the resulting cookies via MITM and injects
//! them into all subsequent agent requests automatically.

use std::path::Path;
use std::sync::Arc;

use reqwest_cookie_store::CookieStoreMutex;
use tao::{
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use tracing::{info, warn};
use wry::WebViewBuilder;

use crate::error::Error;

/// Returns the base URL to open for browser authentication for the given host.
///
/// Strips one subdomain level so `api.github.com` → `https://github.com`.
pub(crate) fn auth_url_for_host(host: &str) -> String {
    let base = if host.chars().filter(|&c| c == '.').count() >= 2 {
        host.splitn(2, '.').nth(1).unwrap_or(host)
    } else {
        host
    };
    format!("https://{base}")
}

/// Returns `true` if the cookie store contains at least one cookie for `host`.
pub(crate) fn has_cookies_for_host(host: &str, store: &Arc<CookieStoreMutex>) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("https://{host}/")) else {
        return false;
    };
    use reqwest::cookie::CookieStore as _;
    store.cookies(&url).is_some()
}

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
    _runtime_dir: &Path,
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

/// Opens a wry browser window for interactive authentication.
///
/// Called as `nv _auth <url> <proxy_port>`.  Configures the webview to route
/// all traffic through `http://127.0.0.1:<proxy_port>` so the daemon can
/// capture cookies via MITM.  Runs the event loop and never returns.
pub(crate) fn run_auth_window(url: &str, proxy_port: u16) -> ! {
    match try_run_auth_window(url, proxy_port) {
        Ok(never) => never,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn try_run_auth_window(url: &str, proxy_port: u16) -> crate::error::Result<!> {
    let event_loop = EventLoop::new();

    let window = WindowBuilder::new()
        .with_title("Sign in — nv")
        .with_inner_size(tao::dpi::LogicalSize::new(960.0_f64, 720.0_f64))
        .build(&event_loop)
        .map_err(|e| Error::cli(format!("Failed to create window: {e}")))?;

    let proxy_config = wry::webview::ProxyConfig::Http(wry::webview::ProxyEndpoint {
        host: "127.0.0.1".to_string(),
        port: proxy_port.to_string(),
    });

    let _webview = WebViewBuilder::new(&window)
        .with_url(url)
        .map_err(|e| Error::cli(format!("Invalid auth URL: {e}")))?
        .with_proxy_config(proxy_config)
        .build()
        .map_err(|e| Error::cli(format!("Failed to create webview: {e}")))?;

    warn!(
        "nv auth window open — log in and the window will close automatically. \
         Close it manually to cancel."
    );

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
