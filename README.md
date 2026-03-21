# nv

**A transparent browser for agents.**

nv is a per-project HTTPS proxy that sits between an AI agent and the internet. It injects credentials, manages session cookies, follows redirects, and handles authentication — so agents can make authenticated HTTP requests without ever seeing a secret or implementing auth logic themselves.

When an agent needs to access a service that requires a login, nv opens a browser window for the user to authenticate. The session is captured transparently and reused for all subsequent requests. The agent never needs to know it happened.

---

## How it works

1. You activate a net environment in your project directory — this starts a background proxy daemon and exports `HTTP_PROXY`/`HTTPS_PROXY` so all agent HTTP traffic routes through it.
2. nv intercepts every request. For hosts with configured auth, it injects credentials before forwarding. For hosts with no config that return 401, it opens a browser window for interactive login and captures the session via MITM.
3. The agent retries the original request with the session in place. From the agent's perspective, it just worked.

nv acts as a MITM proxy for HTTPS using a per-installation CA certificate. Run `nv trust` once to install it into the system trust store.

---

## Setup

```sh
# Install (from source)
cargo install --path .

# First time: install the proxy CA into your system trust store
nv trust
```

---

## Quickstart

```sh
# Initialise a net environment in the current project
nv init

# Add credentials for an API
nv add api.openai.com --bearer       # prompts for token, stores in OS keychain

# Activate the environment in your shell
source .nv/bin/activate

# Run an agent or any CLI tool — its HTTP traffic now flows through nv
nv run python agent.py
# or just run anything after activating:
python agent.py

# Deactivate when done
deactivate
```

---

## Commands

### `nv init [path] [--name NAME]`

Initialise a net environment in a project directory. Creates `nv.toml` (the committed config) and `.nv/bin/activate` (the shell activation script). Generates a global CA certificate on first run.

```sh
nv init                    # current directory
nv init ~/projects/myapp   # specific directory
nv init --name "myapp"     # custom name shown in shell prompt
```

### `nv add <host> <auth-type> [options]`

Configure auth for a host. Secrets are stored in the OS keychain and never written to `nv.toml`.

```sh
nv add api.openai.com --bearer                        # Bearer token
nv add api.anthropic.com --header x-api-key           # Custom header
nv add api.example.com --query api_key                # Query parameter
nv add auth.example.com --oauth2 \
  --token-url https://auth.example.com/token \
  --scopes read write                                 # OAuth2 client credentials
```

Auth can also be set via environment variables in `nv.toml` using `$VAR` or `${VAR}` syntax — useful for CI.

### `nv remove <host>`

Remove a host's auth config from `nv.toml` and delete its keychain entries.

```sh
nv remove api.openai.com
```

### `nv list`

List all configured hosts and their auth types.

```sh
nv list
```

### `nv run <command> [args...]`

Run a command inside the net environment without activating in the shell. The proxy is started automatically if not already running.

```sh
nv run curl https://api.openai.com/v1/models
nv run python agent.py --task "summarise this repo"
nv run -- node index.js --verbose
```

### `nv trust`

Install the proxy CA certificate into the system trust store. Required once per machine so browsers and tools accept nv's MITM certificates for HTTPS.

```sh
nv trust    # may prompt for your password
```

### `nv untrust`

Remove the proxy CA from the system trust store.

```sh
nv untrust
```

---

## Shell activation

Sourcing `.nv/bin/activate` starts the daemon, exports proxy environment variables, and updates your shell prompt:

```sh
source .nv/bin/activate
# [myapp] $  ← prompt shows the active environment

deactivate   # stops the daemon and restores the environment
```

Exported variables:
- `HTTP_PROXY` / `HTTPS_PROXY` — point to the local daemon; picked up automatically by curl, Python requests, Node fetch, and most HTTP clients
- `NO_PROXY=localhost,127.0.0.1` — local traffic bypasses the proxy
- `NV_ENV` — absolute path to the project directory

---

## Authentication

nv handles four kinds of configured auth and one automatic kind:

| Type | How it works |
|---|---|
| **Bearer** | Injects `Authorization: Bearer <token>` on every request to the host |
| **Header** | Injects a custom header (e.g. `x-api-key`) |
| **Query** | Appends a parameter to the request URL |
| **OAuth2** | Fetches a client-credentials token, caches it, refreshes 60s before expiry; retries automatically on 401 |
| **Browser** | On 401 with no configured auth, opens a browser window for interactive login; captures session cookies via MITM |

For the browser flow, nv opens a webview (WebKit on macOS, WebView2 on Windows, WebKitGTK on Linux) pointed at the site's login page with the proxy set. The user logs in normally. nv captures the resulting session cookies and uses them for all future requests to that host — no config required.

---

## nv.toml reference

`nv.toml` lives at the project root and is meant to be committed. Secrets are never stored here — they live in the OS keychain or environment variables.

```toml
# Optional display name for the shell prompt
name = "myapp"

[proxy]
timeout_secs = 30
# Restrict which hosts the proxy will forward to (optional)
allow_only = ["api.openai.com", "api.anthropic.com"]

# Bearer token (secret from keychain or $VAR)
[hosts."api.openai.com".auth]
type = "bearer"
# token = "$OPENAI_API_KEY"   ← or use: nv add api.openai.com --bearer

# Custom header auth
[hosts."api.anthropic.com".auth]
type = "header"
name = "x-api-key"

# Extra headers (added to every request for the host)
[hosts."api.anthropic.com".headers]
anthropic-version = "2023-06-01"

# OAuth2 client credentials
[hosts."api.internal.com".auth]
type = "oauth2"
token_url = "https://auth.internal.com/token"
scopes = ["read", "write"]
# client_id / client_secret from keychain or $CLIENT_ID / $CLIENT_SECRET

# Query parameter auth
[hosts."api.example.com".auth]
type = "query"
param = "api_key"

# Inject values into the top-level fields of a JSON request body
[hosts."api.myapp.com".body.env]
OPENAI_API_KEY = "$OPENAI_API_KEY"

# Redirect a host to a local dev server
[hosts."api.staging.com"]
redirect = "localhost:8080"
```

### Host patterns

Keys in `[hosts]` can be:
- Exact hostname: `"api.example.com"`
- Glob: `"*.example.com"` (`*` matches a single label, `**` matches any labels)
- Host + path: `"api.example.com/v1/chat/completions"`
- Host + path glob: `"api.example.com/v1/*"`

Match order: host+path (most specific) before host-only; exact before glob; file order breaks ties.

---

## Project layout

```
your-project/
├── nv.toml          # committed — host rules, proxy settings, no secrets
└── .nv/             # gitignored — runtime state
    ├── proxy.pid
    ├── proxy.port
    └── bin/
        └── activate
```

The global CA lives at `~/.config/nv/proxy-ca/` and is shared across all projects.

---

## For agents

If you are an agent running inside an nv environment (`NV_ENV` is set), the following applies:

- All outbound HTTP and HTTPS requests are transparently proxied — no special configuration needed if your HTTP client respects `HTTP_PROXY`/`HTTPS_PROXY`.
- Credentials are injected automatically. Do not attempt to manage API keys or session tokens yourself.
- If a request returns 401 and no auth is configured, a browser window will appear for the user to authenticate. Your request will be retried automatically once auth completes. You do not need to retry it yourself.
- Cookies and session state persist for the lifetime of the daemon (one per project activation). You can rely on session continuity across requests.
- `NO_PROXY=localhost,127.0.0.1` — requests to local services bypass the proxy.
