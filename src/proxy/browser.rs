//! Browser-based authentication helpers.
//!
//! Two modes:
//! - `open_login_window`: wry MITM webview for `nv add --login`
//! - `collect_via_browser`: local HTTP form for `nv add --browser`

use std::sync::Arc;
use tokio::sync::Notify;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest_cookie_store::CookieStoreMutex;
use tao::{
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use tracing::{info, warn};
use wry::{ProxyConfig, ProxyEndpoint, WebViewBuilder};

use crate::error::{Error, Result};

// ── Login window (wry MITM) ───────────────────────────────────────────────────

/// Spawns `nv _login <url> <proxy_port>` as a detached child process.
pub(crate) fn open_login_window(
    url: &str,
    proxy_port: u16,
) -> Result<std::process::Child> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::cli(format!("Cannot determine executable path: {e}")))?;
    info!("Opening login window for {url} via proxy port {proxy_port}");
    std::process::Command::new(exe)
        .args(["_login", url, &proxy_port.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| Error::cli(format!("Failed to spawn login window: {e}")))
}

/// Runs the wry login window. Called as `nv _login <url> <proxy_port>`.
/// Never returns normally — calls `std::process::exit`.
pub(crate) fn run_login_window(url: &str, proxy_port: u16) -> ! {
    match try_run_login_window(url, proxy_port) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn try_run_login_window(
    url: &str,
    proxy_port: u16,
) -> Result<std::convert::Infallible> {
    eprintln!("nv: opening login window — sign in, then close this window.");

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
        .map_err(|e| Error::cli(format!("Invalid URL: {e}")))?
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

// ── Cookie helpers ────────────────────────────────────────────────────────────

#[allow(dead_code)]
/// Returns `true` if the cookie store has at least one cookie for `host`.
pub(crate) fn has_cookies_for_host(host: &str, store: &Arc<CookieStoreMutex>) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("https://{host}/")) else {
        return false;
    };
    use reqwest::cookie::CookieStore as _;
    store.cookies(&url).is_some()
}

/// Serialize the cookie store to JSON for keychain storage.
#[allow(deprecated)]
pub(crate) fn serialize_cookies(store: &CookieStoreMutex) -> Option<String> {
    let guard = store.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = Vec::new();
    guard.save_json(&mut buf).ok()?;
    String::from_utf8(buf).ok()
}

/// Restore a cookie store in-place from JSON.
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

// ── Browser form (--browser flag) ────────────────────────────────────────────

/// Collect a secret value via a browser form.
pub(crate) async fn collect_via_browser(host: &str, label: &str) -> Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::cli(format!("Failed to bind local server: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::cli(format!("Failed to get local address: {e}")))?
        .port();

    let html = Arc::new(form_html(host, label));
    let result: Arc<tokio::sync::Mutex<Option<String>>> = Arc::new(tokio::sync::Mutex::new(None));
    let notify = Arc::new(Notify::new());

    open::that(format!("http://127.0.0.1:{port}"))
        .map_err(|e| Error::cli(format!("Failed to open browser: {e}")))?;

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| Error::cli(format!("Accept error: {e}")))?;

        let html_clone = Arc::clone(&html);
        let result_clone = Arc::clone(&result);
        let notify_clone = Arc::clone(&notify);

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let html = Arc::clone(&html_clone);
                        let result = Arc::clone(&result_clone);
                        let notify = Arc::clone(&notify_clone);
                        async move { handle_form(req, html, result, notify).await }
                    }),
                )
                .await;
        });

        if result.lock().await.is_some() {
            break;
        }

        notify.notified().await;
        if result.lock().await.is_some() {
            break;
        }
    }

    let value = result
        .lock()
        .await
        .take()
        .ok_or_else(|| Error::cli("Browser form closed without submitting"))?;

    Ok(value)
}

async fn handle_form(
    req: Request<hyper::body::Incoming>,
    html: Arc<String>,
    result: Arc<tokio::sync::Mutex<Option<String>>>,
    notify: Arc<Notify>,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match req.method() {
        &Method::GET => {
            let resp = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html.as_bytes().to_vec())))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
            Ok(resp)
        }
        &Method::POST => {
            let body = req
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body);
            let value = extract_form_value(&body_str, "value").unwrap_or_default();
            *result.lock().await = Some(value);
            notify.notify_one();
            let resp = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(success_html())))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
            Ok(resp)
        }
        _ => {
            let resp = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
            Ok(resp)
        }
    }
}

fn extract_form_value(body: &str, key: &str) -> Option<String> {
    for pair in body.split('&') {
        let mut parts = pair.splitn(2, '=');
        let k = parts.next()?;
        let v = parts.next().unwrap_or("");
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let with_spaces = s.replace('+', " ");
    let mut out = String::with_capacity(with_spaces.len());
    let mut chars = with_spaces.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            if let Ok(b) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                out.push(b as char);
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn form_html(host: &str, label: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>nv — {host}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; background: #f5f5f5; }}
    .card {{ background: white; padding: 2rem; border-radius: 8px;
             box-shadow: 0 2px 8px rgba(0,0,0,.1); width: 360px; }}
    h2 {{ margin: 0 0 0.25rem; font-size: 1.1rem; }}
    p  {{ margin: 0 0 1.25rem; color: #666; font-size: .875rem; }}
    input {{ width: 100%; box-sizing: border-box; padding: .625rem .75rem;
             border: 1px solid #d0d0d0; border-radius: 6px;
             font-size: .9375rem; margin-bottom: 1rem; }}
    button {{ width: 100%; padding: .625rem; background: #0070f3;
              color: white; border: none; border-radius: 6px;
              font-size: .9375rem; cursor: pointer; }}
    button:hover {{ background: #0060df; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>{host}</h2>
    <p>{label}</p>
    <form method="POST" action="/">
      <input type="password" name="value" placeholder="Paste here…" autofocus required>
      <button type="submit">Save</button>
    </form>
  </div>
</body>
</html>"#
    )
}

fn success_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>nv — saved</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; background: #f5f5f5; }
    .card { background: white; padding: 2rem; border-radius: 8px;
             box-shadow: 0 2px 8px rgba(0,0,0,.1); width: 360px; text-align: center; }
    h2 { color: #0070f3; }
    p  { color: #666; font-size: .875rem; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Saved ✓</h2>
    <p>You can close this tab.</p>
  </div>
</body>
</html>"#
}
