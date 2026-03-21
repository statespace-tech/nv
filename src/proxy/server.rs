use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use notify::{EventKind, RecursiveMode, Watcher};
use reqwest_cookie_store::CookieStoreMutex;
use rustls::ServerConfig;
use std::collections::HashSet;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::proxy::ca::{CertificateAuthority, generate_host_cert};
use crate::proxy::config::{
    AuthConfig, EnvConfig, config_path, pid_path, port_path, runtime_dir, sessions_path,
};

/// Hop-by-hop headers that must not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HOP_BY_HOP.contains(&lower.as_str())
}

async fn fetch_oauth_token(
    client_id: &str,
    client_secret: &str,
    token_url: &str,
    scopes: &[String],
    client: &reqwest::Client,
) -> Result<(String, std::time::Duration)> {
    let scope_str = scopes.join(" ");
    let mut params = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if !scope_str.is_empty() {
        params.push(("scope", scope_str.as_str()));
    }

    let resp = client
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| Error::cli(format!("OAuth2 token request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::cli(format!(
            "OAuth2 token endpoint returned {}",
            resp.status()
        )));
    }

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
        expires_in: Option<u64>,
    }

    let body: TokenResponse = resp
        .json()
        .await
        .map_err(|e| Error::cli(format!("Failed to parse OAuth2 response: {e}")))?;

    let ttl = std::time::Duration::from_secs(body.expires_in.unwrap_or(3600));
    Ok((body.access_token, ttl))
}

async fn get_cached_oauth_token(
    cache_key: &str,
    client_id: &str,
    client_secret: &str,
    token_url: &str,
    scopes: &[String],
    client: &reqwest::Client,
    cache: &tokio::sync::Mutex<std::collections::HashMap<String, OAuthToken>>,
    force_refresh: bool,
) -> Result<String> {
    if !force_refresh {
        let guard = cache.lock().await;
        if let Some(tok) = guard.get(cache_key) {
            if tok.expires_at
                > std::time::Instant::now() + std::time::Duration::from_secs(60)
            {
                return Ok(tok.access_token.clone());
            }
        }
    }

    let (access_token, ttl) =
        fetch_oauth_token(client_id, client_secret, token_url, scopes, client).await?;

    let mut guard = cache.lock().await;
    guard.insert(
        cache_key.to_string(),
        OAuthToken {
            access_token: access_token.clone(),
            expires_at: std::time::Instant::now() + ttl,
        },
    );
    Ok(access_token)
}

/// Cached OAuth2 token entry.
#[derive(Debug)]
struct OAuthToken {
    access_token: String,
    expires_at: std::time::Instant,
}

/// Shared state passed to every connection handler.
#[allow(missing_debug_implementations)]
struct ProxyState {
    config: Arc<RwLock<EnvConfig>>,
    ca: CertificateAuthority,
    client: reqwest::Client,
    oauth_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, OAuthToken>>>,
    /// Inspectable cookie jar — shared with the reqwest client via cookie_provider.
    cookie_store: Arc<CookieStoreMutex>,
    /// The port this daemon is listening on (passed to browser auth windows).
    port: u16,
    /// Project directory (used for sessions file and keychain key).
    project_dir: std::path::PathBuf,
    /// Hosts for which a browser auth window is currently open.
    browser_auth_in_progress: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

/// Run the proxy daemon. This function does not return until the process exits.
pub(crate) async fn run_daemon(project_dir: std::path::PathBuf) -> Result<()> {
    // Ensure runtime dir exists (.nv/)
    let rt_dir = runtime_dir(&project_dir);
    std::fs::create_dir_all(&rt_dir)?;

    // Load config and CA
    let mut initial_config = EnvConfig::load(&project_dir)?;
    initial_config.resolve_secrets();
    let config = Arc::new(RwLock::new(initial_config));
    let ca = crate::proxy::ca::ensure_global_ca()?;

    // Inspectable cookie jar — restore from keychain if available
    let cookie_store = Arc::new(CookieStoreMutex::default());
    let keychain_key = project_dir.to_string_lossy().into_owned();
    if let Some(json) = crate::proxy::keychain::get("sessions", &keychain_key) {
        crate::proxy::browser::restore_cookies(&json, &cookie_store);
    }

    // Build reqwest client with:
    //  - custom redirect policy that stops at login-wall redirects
    //  - shared inspectable cookie jar
    let cookie_store_for_client = Arc::clone(&cookie_store);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .cookie_provider(cookie_store_for_client)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if crate::proxy::browser::is_login_redirect(attempt.url()) {
                attempt.stop()
            } else if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| Error::cli(format!("Failed to build HTTP client: {e}")))?;

    // Bind on an OS-assigned port first so we know the port before building state.
    let std_listener = StdTcpListener::bind("127.0.0.1:0")?;
    let port = std_listener
        .local_addr()
        .map_err(|e| Error::cli(format!("Failed to get local address: {e}")))?
        .port();
    std_listener
        .set_nonblocking(true)
        .map_err(|e| Error::cli(format!("Failed to set non-blocking: {e}")))?;
    let listener = TcpListener::from_std(std_listener)?;

    let state = Arc::new(ProxyState {
        config: Arc::clone(&config),
        ca,
        client,
        oauth_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cookie_store,
        port,
        project_dir: project_dir.clone(),
        browser_auth_in_progress: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
    });

    // Watch nv.toml for changes and reload automatically
    let nv_toml = config_path(&project_dir);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                let _ = tx.blocking_send(());
            }
        }
    })
    .map_err(|e| Error::cli(format!("Failed to create file watcher: {e}")))?;

    watcher
        .watch(&nv_toml, RecursiveMode::NonRecursive)
        .map_err(|e| Error::cli(format!("Failed to watch nv.toml: {e}")))?;

    let config_for_watcher = Arc::clone(&config);
    let project_dir_for_watcher = project_dir.clone();
    tokio::spawn(async move {
        let _watcher = watcher;
        while rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            while rx.try_recv().is_ok() {}
            match EnvConfig::load(&project_dir_for_watcher) {
                Ok(mut new_config) => {
                    new_config.resolve_secrets();
                    *config_for_watcher.write().await = new_config;
                    info!("config reloaded");
                }
                Err(e) => warn!("Failed to reload config: {e}"),
            }
        }
    });

    // Write PID and port files into .nv/
    let pid = std::process::id();
    std::fs::write(pid_path(&project_dir), pid.to_string())?;
    std::fs::write(port_path(&project_dir), port.to_string())?;

    tracing::info!("Proxy daemon listening on 127.0.0.1:{port} (PID {pid})");

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("Accepted connection from {peer}");
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state_clone).await {
                warn!("Connection error from {peer}: {e}");
            }
        });
    }
}

/// Poll the cookie store until cookies arrive for `host` or the timeout elapses.
async fn wait_for_browser_auth(
    host: &str,
    cookie_store: &Arc<CookieStoreMutex>,
    timeout_secs: u64,
) -> bool {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if crate::proxy::browser::has_cookies_for_host(host, cookie_store) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

/// Persist the cookie jar to the OS keychain and update the agent-readable
/// sessions file in `.nv/sessions`.
fn persist_session(host: &str, state: &ProxyState) {
    // Save cookie jar to keychain
    let keychain_key = state.project_dir.to_string_lossy().into_owned();
    if let Some(json) = crate::proxy::browser::serialize_cookies(&state.cookie_store) {
        if let Err(e) = crate::proxy::keychain::store("sessions", &keychain_key, &json) {
            warn!("Failed to persist session cookies to keychain: {e}");
        }
    }

    // Update .nv/sessions — agent-readable list of authenticated hosts
    let sessions_file = sessions_path(&state.project_dir);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Read existing sessions, add/update this host
    let mut sessions: serde_json::Map<String, serde_json::Value> =
        std::fs::read_to_string(&sessions_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

    sessions.insert(
        host.to_string(),
        serde_json::json!({ "authenticated_at": timestamp }),
    );

    if let Ok(json) = serde_json::to_string_pretty(&serde_json::Value::Object(sessions)) {
        if let Err(e) = std::fs::write(&sessions_file, json) {
            warn!("Failed to write sessions file: {e}");
        }
    }

    info!("Session persisted for {host}");
}

/// Classify whether a response requires browser authentication.
enum AuthNeeded {
    /// No auth required.
    No,
    /// 401/403 — open the host's root login page.
    ApiAuth,
    /// Redirect to a login wall — open that URL directly.
    LoginRedirect(String),
}

fn classify_response(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    base_url: &reqwest::Url,
) -> AuthNeeded {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return AuthNeeded::ApiAuth;
    }

    if status.is_redirection() {
        if let Some(location) = headers.get(reqwest::header::LOCATION) {
            if let Ok(loc_str) = location.to_str() {
                let resolved = reqwest::Url::parse(loc_str)
                    .or_else(|_| base_url.join(loc_str));
                if let Ok(loc_url) = resolved {
                    if crate::proxy::browser::is_login_redirect(&loc_url) {
                        return AuthNeeded::LoginRedirect(loc_url.to_string());
                    }
                }
            }
        }
    }

    AuthNeeded::No
}

async fn handle_connection(
    stream: TcpStream,
    state: Arc<ProxyState>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let state_clone = Arc::clone(&state);

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let state = Arc::clone(&state_clone);
                async move { handle_request(req, state).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| Error::cli(format!("HTTP connection error: {e}")))?;

    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    if req.method() == Method::CONNECT {
        Ok(handle_connect(req, state))
    } else {
        Ok(handle_http(req, state).await)
    }
}

/// Handle a plain HTTP proxy request (non-CONNECT).
async fn handle_http(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let uri = req.uri().clone();

    let Some(host) = extract_host_from_request(&req, &uri) else {
        return error_response(StatusCode::BAD_REQUEST, "Missing host");
    };
    let path = uri.path().to_string();

    let (auth, extra_headers, body_inject, allowed, timeout) = {
        let cfg = state.config.read().await;
        let host_cfg = cfg.find_host_config(&host, &path);
        let auth = host_cfg.and_then(|c| c.auth.clone());
        let extra_headers = host_cfg.map(|c| c.headers.clone()).unwrap_or_default();
        let body_inject = host_cfg.map(|c| c.body.clone()).unwrap_or_default();
        let allowed = cfg.is_host_allowed(&host);
        let timeout = host_cfg.and_then(|c| c.timeout_secs).or(cfg.proxy.timeout_secs);
        (auth, extra_headers, body_inject, allowed, timeout)
    };

    if !allowed {
        return error_response(
            StatusCode::FORBIDDEN,
            &format!("Host '{host}' is not in the allow list"),
        );
    }

    let base_url = match uri.to_string().parse::<reqwest::Url>() {
        Ok(u) => u,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("Invalid URL: {e}")),
    };

    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("Invalid method: {e}"))
        }
    };

    let incoming_headers: Vec<(String, Vec<u8>)> = req
        .headers()
        .iter()
        .filter(|(n, _)| !is_hop_by_hop(n.as_str()) && *n != hyper::header::HOST)
        .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_owned()))
        .collect();

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Failed to read request body: {e}"),
            )
        }
    };
    let body_bytes = inject_into_body(body_bytes, &body_inject);

    let mut force_token_refresh = false;
    let mut browser_auth_attempted = false;
    loop {
        let mut target_url = base_url.clone();

        if let Some(AuthConfig::Query { ref param, value: Some(ref value) }) = auth {
            target_url.query_pairs_mut().append_pair(param, value);
        }

        let mut builder = state.client.request(method.clone(), target_url);

        for (name, value) in &incoming_headers {
            builder = builder.header(name.as_str(), value.as_slice());
        }
        for (name, value) in &extra_headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }

        builder = inject_auth(builder, &auth, &host, &state, force_token_refresh).await;
        if let Err(e) = check_auth_config(&auth, &host) {
            return e;
        }

        if let Some(secs) = timeout {
            builder = builder.timeout(std::time::Duration::from_secs(secs));
        }
        builder = builder.body(body_bytes.clone());

        let upstream = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_GATEWAY, &format!("Upstream error: {e}"))
            }
        };

        // OAuth2: evict cached token and retry once on 401
        if upstream.status() == reqwest::StatusCode::UNAUTHORIZED
            && matches!(auth, Some(AuthConfig::OAuth2 { .. }))
            && !force_token_refresh
        {
            state.oauth_cache.lock().await.remove(&host);
            force_token_refresh = true;
            continue;
        }

        // Browser auth: 401, 403, or redirect to login wall
        if auth.is_none() && !browser_auth_attempted {
            let needs_auth =
                classify_response(upstream.status(), upstream.headers(), &base_url);
            if let Some(response) =
                try_browser_auth(&host, needs_auth, &state, &mut browser_auth_attempted).await
            {
                if response {
                    continue;
                }
            }
        }

        let response_status = upstream.status();
        let response_headers = upstream.headers().clone();
        let response_body = match upstream.bytes().await {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read upstream body: {e}");
                Bytes::new()
            }
        };

        return build_response_from_parts(response_status, &response_headers, response_body);
    }
}

/// Attempt browser auth if needed. Returns `Some(true)` to retry the request,
/// `Some(false)` to continue without retry, `None` if no auth was needed.
async fn try_browser_auth(
    host: &str,
    needs_auth: AuthNeeded,
    state: &ProxyState,
    browser_auth_attempted: &mut bool,
) -> Option<bool> {
    let open_url = match needs_auth {
        AuthNeeded::No => return None,
        AuthNeeded::ApiAuth => crate::proxy::browser::auth_url(host, None),
        AuthNeeded::LoginRedirect(ref url) => url.clone(),
    };

    let mut in_progress = state.browser_auth_in_progress.lock().await;
    if !in_progress.contains(host) {
        in_progress.insert(host.to_string());
        drop(in_progress);

        match crate::proxy::browser::open_with_proxy(&open_url, state.port) {
            Ok(mut child) => {
                info!("Browser auth required for {host} — opening {open_url}");
                eprintln!("nv: authentication required for {host} — browser window opened.");
                let got_cookies =
                    wait_for_browser_auth(host, &state.cookie_store, 300).await;
                let _ = child.kill();
                if got_cookies {
                    info!("Browser auth complete for {host}");
                    eprintln!("nv: authenticated ✓ {host}");
                    persist_session(host, state);
                    *browser_auth_attempted = true;
                    state.browser_auth_in_progress.lock().await.remove(host);
                    return Some(true);
                }
                warn!("Browser auth timed out or cancelled for {host}");
                eprintln!("nv: authentication cancelled or timed out for {host}");
            }
            Err(e) => warn!("Failed to open browser auth window: {e}"),
        }

        state.browser_auth_in_progress.lock().await.remove(host);
    } else {
        drop(in_progress);
        // Another concurrent request already opened the window; wait for it
        let _got = wait_for_browser_auth(host, &state.cookie_store, 300).await;
    }

    *browser_auth_attempted = true;
    Some(false)
}

/// Handle a CONNECT tunnel request (HTTPS MITM).
fn handle_connect(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let host_and_port = req
        .uri()
        .authority()
        .map(ToString::to_string)
        .unwrap_or_default();
    let hostname = host_and_port
        .split(':')
        .next()
        .unwrap_or(&host_and_port)
        .to_string();

    let response = match Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build CONNECT response: {e}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                error!("Upgrade failed for {hostname}: {e}");
                return;
            }
        };
        if let Err(e) = mitm_tls(upgraded, hostname, state).await {
            debug!("MITM error: {e}");
        }
    });

    response
}

async fn mitm_tls(
    upgraded: hyper::upgrade::Upgraded,
    hostname: String,
    state: Arc<ProxyState>,
) -> Result<()> {
    let (host_cert, host_key) = generate_host_cert(&hostname, &state.ca)?;

    let cert_der = host_cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(host_key.serialize_der()),
    );

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| Error::cli(format!("Failed to build TLS server config: {e}")))?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let io = TokioIo::new(upgraded);
    let tls_stream = acceptor
        .accept(io)
        .await
        .map_err(|e| Error::cli(format!("TLS handshake failed for {hostname}: {e}")))?;

    let tls_io = TokioIo::new(tls_stream);
    let state_clone = Arc::clone(&state);
    let hostname_clone = hostname.clone();

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            tls_io,
            hyper::service::service_fn(move |req| {
                let state = Arc::clone(&state_clone);
                let host = hostname_clone.clone();
                async move { handle_inner_https(req, state, host).await }
            }),
        )
        .await
        .map_err(|e| Error::cli(format!("Inner HTTPS connection error: {e}")))?;

    Ok(())
}

async fn handle_inner_https(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    hostname: String,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    let path = req.uri().path().to_string();

    let (auth, extra_headers, body_inject, allowed, timeout) = {
        let cfg = state.config.read().await;
        let host_cfg = cfg.find_host_config(&hostname, &path);
        let auth = host_cfg.and_then(|c| c.auth.clone());
        let extra_headers = host_cfg.map(|c| c.headers.clone()).unwrap_or_default();
        let body_inject = host_cfg.map(|c| c.body.clone()).unwrap_or_default();
        let allowed = cfg.is_host_allowed(&hostname);
        let timeout = host_cfg.and_then(|c| c.timeout_secs).or(cfg.proxy.timeout_secs);
        (auth, extra_headers, body_inject, allowed, timeout)
    };

    if !allowed {
        return Ok(error_response(
            StatusCode::FORBIDDEN,
            &format!("Host '{hostname}' is not in the allow list"),
        ));
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str)
        .to_owned();
    let base_url_str = format!("https://{hostname}{path_and_query}");
    let base_url = match base_url_str.parse::<reqwest::Url>() {
        Ok(u) => u,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid URL: {e}"),
            ))
        }
    };

    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid method: {e}"),
            ))
        }
    };

    let incoming_headers: Vec<(String, Vec<u8>)> = req
        .headers()
        .iter()
        .filter(|(n, _)| !is_hop_by_hop(n.as_str()) && *n != hyper::header::HOST)
        .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_owned()))
        .collect();

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Failed to read request body: {e}"),
            ))
        }
    };
    let body_bytes = inject_into_body(body_bytes, &body_inject);

    let mut force_token_refresh = false;
    let mut browser_auth_attempted = false;
    loop {
        let mut url = base_url.clone();

        if let Some(AuthConfig::Query { ref param, value: Some(ref value) }) = auth {
            url.query_pairs_mut().append_pair(param, value);
        }

        let mut builder = state.client.request(method.clone(), url);

        for (name, value) in &incoming_headers {
            builder = builder.header(name.as_str(), value.as_slice());
        }
        for (name, value) in &extra_headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }

        builder = inject_auth(builder, &auth, &hostname, &state, force_token_refresh).await;
        if let Err(e) = check_auth_config(&auth, &hostname) {
            return Ok(e);
        }

        if let Some(secs) = timeout {
            builder = builder.timeout(std::time::Duration::from_secs(secs));
        }
        builder = builder.body(body_bytes.clone());

        let upstream = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("Upstream error: {e}"),
                ))
            }
        };

        // OAuth2: evict cached token and retry once on 401
        if upstream.status() == reqwest::StatusCode::UNAUTHORIZED
            && matches!(auth, Some(AuthConfig::OAuth2 { .. }))
            && !force_token_refresh
        {
            state.oauth_cache.lock().await.remove(&hostname);
            force_token_refresh = true;
            continue;
        }

        // Browser auth: 401, 403, or redirect to login wall
        if auth.is_none() && !browser_auth_attempted {
            let needs_auth =
                classify_response(upstream.status(), upstream.headers(), &base_url);
            if let Some(response) =
                try_browser_auth(&hostname, needs_auth, &state, &mut browser_auth_attempted)
                    .await
            {
                if response {
                    continue;
                }
            }
        }

        let response_status = upstream.status();
        let response_headers = upstream.headers().clone();
        let response_body = match upstream.bytes().await {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read upstream body: {e}");
                Bytes::new()
            }
        };

        return Ok(build_response_from_parts(
            response_status,
            &response_headers,
            response_body,
        ));
    }
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

/// Inject authentication headers/params into the request builder.
/// Returns the (possibly modified) builder.
async fn inject_auth(
    mut builder: reqwest::RequestBuilder,
    auth: &Option<AuthConfig>,
    host: &str,
    state: &ProxyState,
    force_token_refresh: bool,
) -> reqwest::RequestBuilder {
    match auth {
        Some(AuthConfig::Bearer { token: Some(token) }) => {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        Some(AuthConfig::Header { name, value: Some(value) }) => {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        Some(AuthConfig::OAuth2 {
            client_id: Some(cid),
            client_secret: Some(cs),
            token_url,
            scopes,
        }) => {
            if let Ok(token) = get_cached_oauth_token(
                host,
                cid,
                cs,
                token_url,
                scopes,
                &state.client,
                &state.oauth_cache,
                force_token_refresh,
            )
            .await
            {
                builder = builder.header("Authorization", format!("Bearer {token}"));
            }
        }
        _ => {}
    }
    builder
}

/// Check auth config for missing secrets. Returns `Err(response)` if the
/// request should be aborted.
fn check_auth_config(
    auth: &Option<AuthConfig>,
    host: &str,
) -> std::result::Result<(), Response<BoxBody<Bytes, hyper::Error>>> {
    match auth {
        Some(AuthConfig::Bearer { token: None }) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            &format!("No secret for '{host}' — run `nv add`"),
        )),
        Some(AuthConfig::Header { value: None, .. }) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            &format!("No secret for '{host}' — run `nv add`"),
        )),
        Some(AuthConfig::OAuth2 { client_id: None, .. })
        | Some(AuthConfig::OAuth2 { client_secret: None, .. }) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            &format!("No OAuth2 credentials for '{host}' — run `nv add`"),
        )),
        _ => Ok(()),
    }
}

// ── Body injection ────────────────────────────────────────────────────────────

fn inject_into_body(
    body_bytes: Bytes,
    inject: &IndexMap<String, IndexMap<String, String>>,
) -> Bytes {
    if inject.is_empty() || body_bytes.is_empty() {
        return body_bytes;
    }
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) else {
        return body_bytes;
    };
    let Some(obj) = json.as_object_mut() else {
        return body_bytes;
    };
    for (field, values) in inject {
        let entry = obj
            .entry(field)
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(field_obj) = entry.as_object_mut() {
            for (k, v) in values {
                field_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        }
    }
    serde_json::to_vec(&json)
        .map(Bytes::from)
        .unwrap_or(body_bytes)
}

// ── Response helpers ──────────────────────────────────────────────────────────

fn build_response_from_parts(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body_bytes: Bytes,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let status_code =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status_code);
    for (name, value) in headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    match builder.body(Full::new(body_bytes).map_err(|e| match e {}).boxed()) {
        Ok(r) => r,
        Err(_) => Response::new(empty_body()),
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

fn error_response(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Bytes::from(msg.to_string());
    match Response::builder()
        .status(status)
        .body(Full::new(body).map_err(|e| match e {}).boxed())
    {
        Ok(r) => r,
        Err(_) => Response::new(empty_body()),
    }
}

fn extract_host_from_request(req: &Request<Incoming>, uri: &Uri) -> Option<String> {
    if let Some(host) = uri.host() {
        return Some(host.to_string());
    }
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
