use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Authentication configuration for a host.
///
/// Secret fields are `Option<String>`:
/// - `Some(value)` — literal value or `$VAR` reference (expanded at load time)
/// - `None` — resolved from the OS keychain at proxy startup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum AuthConfig {
    Bearer {
        #[serde(default)]
        token: Option<String>,
    },
    Header {
        name: String,
        #[serde(default)]
        value: Option<String>,
    },
    Query {
        param: String,
        #[serde(default)]
        value: Option<String>,
    },
    #[serde(rename = "oauth2")]
    OAuth2 {
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
        token_url: String,
        #[serde(default)]
        scopes: Vec<String>,
    },
}

/// Top-level `nv.toml` structure.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct EnvConfig {
    /// Display name shown in the shell prompt (e.g. `[myproject]`).
    /// Defaults to the project directory's basename.
    pub name: Option<String>,

    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Per-host rules. Keys are exact hostnames, glob patterns (`*`, `**`),
    /// or `host/path` patterns (e.g. `api.openai.com/v1/*`).
    /// Evaluated in order: host+path exact, host+path glob, host exact, host glob.
    #[serde(default)]
    pub hosts: IndexMap<String, HostConfig>,
}

/// Proxy-wide settings.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ProxyConfig {
    pub timeout_secs: Option<u64>,
    pub allow_only: Option<Vec<String>>,
}

/// Per-host rule.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct HostConfig {
    pub auth: Option<AuthConfig>,

    #[serde(default)]
    pub headers: IndexMap<String, String>,

    /// JSON body fields to inject. Each key is a top-level JSON field;
    /// its value is a map of key/value pairs merged into that field.
    #[serde(default)]
    pub body: IndexMap<String, IndexMap<String, String>>,

    pub redirect: Option<String>,
    pub timeout_secs: Option<u64>,
}

fn expand_env_vars(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                i += 2;
                let start = i;
                while i < chars.len() && chars[i] != '}' {
                    i += 1;
                }
                let var: String = chars[start..i].iter().collect();
                if i < chars.len() {
                    i += 1;
                }
                result.push_str(
                    &std::env::var(&var).unwrap_or_else(|_| format!("${{{var}}}")),
                );
            } else if chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_' {
                i += 1;
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_')
                {
                    i += 1;
                }
                let var: String = chars[start..i].iter().collect();
                result.push_str(
                    &std::env::var(&var).unwrap_or_else(|_| format!("${var}")),
                );
            } else {
                result.push(chars[i]);
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

impl EnvConfig {
    /// Parse and load the config, expanding `$VAR` references.
    /// Does NOT resolve keychain secrets — call `resolve_secrets` separately for the proxy.
    pub(crate) fn load(env_dir: &Path) -> Result<Self> {
        let path = config_path(env_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)?;
        let mut config: Self = toml::from_str(&text)
            .map_err(|e| Error::cli(format!("Failed to parse config.toml: {e}")))?;
        config.expand_env();
        Ok(config)
    }

    pub(crate) fn save(&self, env_dir: &Path) -> Result<()> {
        let path = config_path(env_dir);
        let text = toml::to_string_pretty(self)
            .map_err(|e| Error::cli(format!("Failed to serialize config: {e}")))?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Fill in any `None` secret fields from the OS keychain.
    /// Called by the proxy daemon after `load`; not called when editing config.
    pub(crate) fn resolve_secrets(&mut self) {
        use crate::proxy::keychain;
        for (host, host_cfg) in &mut self.hosts {
            match &mut host_cfg.auth {
                Some(AuthConfig::Bearer { token }) => {
                    if token.is_none() {
                        *token = keychain::get(host, "token");
                    }
                }
                Some(AuthConfig::Header { value, .. }) => {
                    if value.is_none() {
                        *value = keychain::get(host, "value");
                    }
                }
                Some(AuthConfig::Query { value, .. }) => {
                    if value.is_none() {
                        *value = keychain::get(host, "value");
                    }
                }
                Some(AuthConfig::OAuth2 { client_id, client_secret, .. }) => {
                    if client_id.is_none() {
                        *client_id = keychain::get(host, "client_id");
                    }
                    if client_secret.is_none() {
                        *client_secret = keychain::get(host, "client_secret");
                    }
                }
                None => {}
            }
        }
    }

    fn expand_env(&mut self) {
        for host_cfg in self.hosts.values_mut() {
            match &mut host_cfg.auth {
                Some(AuthConfig::Bearer { token }) => {
                    if let Some(t) = token { *t = expand_env_vars(t); }
                }
                Some(AuthConfig::Header { value, .. }) => {
                    if let Some(v) = value { *v = expand_env_vars(v); }
                }
                Some(AuthConfig::Query { value, .. }) => {
                    if let Some(v) = value { *v = expand_env_vars(v); }
                }
                Some(AuthConfig::OAuth2 { client_id, client_secret, token_url, .. }) => {
                    if let Some(id) = client_id { *id = expand_env_vars(id); }
                    if let Some(sec) = client_secret { *sec = expand_env_vars(sec); }
                    *token_url = expand_env_vars(token_url);
                }
                None => {}
            }
            for value in host_cfg.headers.values_mut() {
                *value = expand_env_vars(value);
            }
            for field_values in host_cfg.body.values_mut() {
                for value in field_values.values_mut() {
                    *value = expand_env_vars(value);
                }
            }
        }
    }

    /// Returns `true` if `host` is allowed by the `allow_only` list (or if no list is set).
    pub(crate) fn is_host_allowed(&self, host: &str) -> bool {
        let Some(ref allowed) = self.proxy.allow_only else {
            return true;
        };
        let bare = strip_port(host);
        allowed.iter().any(|pattern| pattern.as_str() == bare || host_glob_matches(pattern, bare))
    }

    /// Find the first `HostConfig` that matches `host` and `path`.
    pub(crate) fn find_host_config(&self, host: &str, path: &str) -> Option<&HostConfig> {
        let bare = strip_port(host);

        let exact_with_path = format!("{bare}{path}");
        if let Some(cfg) = self.hosts.get(&exact_with_path) {
            return Some(cfg);
        }

        for (key, cfg) in &self.hosts {
            if !key.contains('/') { continue; }
            if pattern_matches_host_path(key, bare, path) {
                return Some(cfg);
            }
        }

        if let Some(cfg) = self.hosts.get(bare) {
            return Some(cfg);
        }

        for (key, cfg) in &self.hosts {
            if key.contains('/') { continue; }
            if host_glob_matches(key, bare) {
                return Some(cfg);
            }
        }

        None
    }
}

fn host_glob_matches(pattern: &str, host: &str) -> bool {
    if !pattern.contains('*') {
        return false;
    }
    glob_to_regex(pattern)
        .map(|re| re.is_match(host))
        .unwrap_or(false)
}

fn glob_to_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    let mut out = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            out.push_str(".*");
            i += 2;
        } else if chars[i] == '*' {
            out.push_str("[^.]*");
            i += 1;
        } else {
            let c = chars[i];
            if r"\.+^${}()|[]".contains(c) {
                out.push('\\');
            }
            out.push(c);
            i += 1;
        }
    }
    out.push('$');
    Regex::new(&out)
}

fn path_glob_to_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    let mut out = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            out.push_str(".*");
            i += 2;
        } else if chars[i] == '*' {
            out.push_str("[^/]*");
            i += 1;
        } else {
            let c = chars[i];
            if r"\.+^${}()|[]".contains(c) {
                out.push('\\');
            }
            out.push(c);
            i += 1;
        }
    }
    out.push('$');
    Regex::new(&out)
}

fn path_glob_matches(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    path_glob_to_regex(pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn pattern_matches_host_path(key: &str, host: &str, path: &str) -> bool {
    let Some((host_pattern, path_pattern)) = key.split_once('/') else {
        return false;
    };
    let full_path_pattern = format!("/{path_pattern}");
    let host_ok = host_pattern == host || host_glob_matches(host_pattern, host);
    let path_ok = path_glob_matches(&full_path_pattern, path);
    host_ok && path_ok
}

fn strip_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

/// Path to the project-level config file (committed).
pub(crate) fn config_path(project_dir: &Path) -> PathBuf {
    project_dir.join("nv.toml")
}

/// Path to the runtime directory (gitignored, holds pid/port/activate).
pub(crate) fn runtime_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".nv")
}

pub(crate) fn ca_cert_path(env_dir: &Path) -> PathBuf {
    env_dir.join("ca.crt")
}

pub(crate) fn ca_key_path(env_dir: &Path) -> PathBuf {
    env_dir.join("ca.key")
}

pub(crate) fn pid_path(project_dir: &Path) -> PathBuf {
    runtime_dir(project_dir).join("proxy.pid")
}

pub(crate) fn port_path(project_dir: &Path) -> PathBuf {
    runtime_dir(project_dir).join("proxy.port")
}

pub(crate) fn validate_project_dir(project_dir: &Path) -> Result<()> {
    if !config_path(project_dir).exists() {
        return Err(Error::cli(format!(
            "No nv.toml found in '{}'. Run `nv` first.",
            project_dir.display()
        )));
    }
    Ok(())
}

/// Returns the directory where the global proxy CA is stored.
pub(crate) fn global_ca_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nv/proxy-ca"))
}

/// Returns the path to the global proxy CA certificate.
pub(crate) fn global_ca_cert_path() -> Option<PathBuf> {
    global_ca_dir().map(|d| d.join("ca.crt"))
}

/// Default config template written on env creation.
pub(crate) fn default_config_template() -> &'static str {
    r#"# nv.toml — net environment configuration
#
# Host patterns:
#   exact host:       "api.example.com"
#   glob host:        "*.example.com"      (* = single label, ** = any labels)
#   exact host+path:  "api.example.com/v1/chat/completions"
#   glob host+path:   "api.example.com/v1/*"  (* = single segment, ** = any segments)
#
# Match order: host+path (most specific) before host-only; exact before glob; file order wins ties.
#
# Secret fields can be omitted to use the OS keychain (set via `nv add`),
# or set explicitly using $VAR / ${VAR} environment variable expansion.

[proxy]
# timeout_secs = 30
# allow_only = ["api.openai.com", "api.anthropic.com"]

# ── Bearer token ──────────────────────────────────────────────────────────────
# Keychain:  nv add api.openai.com --bearer
# Env var:   token = "$OPENAI_API_KEY"
# [hosts."api.openai.com".auth]
# type = "bearer"

# ── Custom header auth (e.g. Anthropic) ───────────────────────────────────────
# Keychain:  nv add api.anthropic.com --header x-api-key
# Env var:   value = "$ANTHROPIC_API_KEY"
# [hosts."api.anthropic.com".auth]
# type = "header"
# name = "x-api-key"

# ── Extra headers ─────────────────────────────────────────────────────────────
# [hosts."api.anthropic.com".headers]
# anthropic-version = "2023-06-01"

# ── Query-parameter auth ──────────────────────────────────────────────────────
# Keychain:  nv add api.example.com --query api_key
# Env var:   value = "$EXAMPLE_API_KEY"
# [hosts."api.example.com".auth]
# type = "query"
# param = "api_key"

# ── OAuth2 client credentials ─────────────────────────────────────────────────
# Keychain:  nv add api.internal.com --oauth2 --token-url https://auth.internal.com/token
# Env vars:  client_id = "$CLIENT_ID" / client_secret = "$CLIENT_SECRET"
# [hosts."api.internal.com".auth]
# type = "oauth2"
# token_url = "https://auth.internal.com/token"
# scopes = ["read"]

# ── JSON body injection ───────────────────────────────────────────────────────
# [hosts."api.myapp.com".body.env]
# OPENAI_API_KEY = "$OPENAI_API_KEY"
# DB_URL = "$DB_URL"

# ── Redirect to local dev server ──────────────────────────────────────────────
# [hosts."api.staging.com"]
# redirect = "localhost:8080"
"#
}
