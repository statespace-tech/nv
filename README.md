# nv

### A transparent HTTPS proxy for AI agents.

nv sits between an agent and the internet, injecting credentials automatically so agents can make authenticated API requests without ever seeing a secret.

- **Zero agent changes** — any HTTP client that respects `HTTP_PROXY`/`HTTPS_PROXY` works out of the box
- **Per-project secrets** — credentials are encrypted per-project; two projects using the same API can have different keys
- **Secrets never on disk in plaintext** — AES-256-GCM encrypted at rest, decrypted into daemon memory only
- **Agent-proof** — the encryption key lives outside the project directory; agents cannot access it
- **CI-ready** — export the project key once; inject as `NV_KEY` in any CI provider

---

## Installation

```console
$ cargo install --path .
```

Then install the proxy CA certificate once per machine:

```console
$ nv trust
```

---

## Quickstart

```console
$ nv init
Initialised net environment [myproject] in: /path/to/myproject

$ nv add api.openai.com --bearer
Bearer token: ••••••••

$ nv activate
nv [myproject] active (port 51234). Type 'exit' to deactivate.

$ python agent.py   # credentials injected automatically
```

---

## How it works

```
agent → HTTP_PROXY → nv daemon → inject credentials → upstream API
```

nv performs MITM proxying for HTTPS using a locally-trusted CA. Secrets are stored encrypted in `.nv/secrets.enc`, decrypted by the daemon at startup using a per-project key stored outside the project directory.

```
~/.config/nv/keys/<project-id>   ← AES-256 key  (never in project dir)
        ↓ decrypts
.nv/secrets.enc                  ← encrypted secrets  (gitignored)
        ↓ daemon loads into
memory only                      ← secrets never written to disk in plaintext
```

---

## Activating an environment

**Option 1 — subshell** (no shell setup required):

```console
$ nv activate
nv [myproject] active. Type 'exit' to deactivate.
```

**Option 2 — current shell** (sets env vars in place):

```console
$ source .nv/bin/activate
[myproject] $

[myproject] $ deactivate
```

---

## Commands

### `nv init [path] [--name <name>]`

Create a net environment. Generates a project ID, creates an encryption key at `~/.config/nv/keys/<id>`, and writes `nv.toml`.

```console
$ nv init
$ nv init ~/projects/myapp
$ nv init --name myapp
```

### `nv add <host> <auth-type>`

Configure authentication for a host. Prompts for the secret, encrypts it, and writes it to `.nv/secrets.enc`. The auth type is recorded in `nv.toml`; the secret value never is.

```console
$ nv add api.openai.com --bearer
$ nv add api.anthropic.com --header x-api-key
$ nv add api.example.com --query api_key
$ nv add auth.example.com --oauth2 --token-url https://auth.example.com/token
$ nv add github.com --device-flow --client-id <id>
```

Add `--browser` to collect the secret via a local browser form instead of a terminal prompt.

### `nv activate [--path <dir>]`

Start a new shell with the proxy environment active. `exit` to leave.

### `nv run <command>`

Run a single command inside the environment without activating a shell.

```console
$ nv run python agent.py
$ nv run curl https://api.openai.com/v1/models
```

### `nv list`

Show configured hosts and auth types.

### `nv remove <host>`

Remove a host's auth config and erase its secrets from `.nv/secrets.enc`.

### `nv key export`

Print the base64-encoded project key. Use this to move the key to another machine or inject it into CI.

```console
$ nv key export
abc123...

$ NV_KEY=$(nv key export)
$ export NV_KEY
$ nv activate   # daemon reads NV_KEY; activate script unsets it before agent starts
```

### `nv key import <key>`

Import a base64-encoded key onto this machine.

```console
$ nv key import abc123...
```

### `nv trust` / `nv untrust`

Install or remove the proxy CA from the system trust store.

---

## CI usage

```yaml
- name: Run agent
  env:
    NV_KEY: ${{ secrets.NV_PROJECT_KEY }}
  run: |
    source .nv/bin/activate
    python agent.py
```

`NV_KEY` is read by the daemon at startup and unset by the activate script before your command runs. The agent process never has access to it.

To get the key for CI, run `nv key export` once on your dev machine and store the output as a masked secret.

---

## nv.toml

`nv.toml` is committed to your repository. It contains auth types and host rules — never secrets.

```toml
id = "a3f9c2d1-..."   # stable project ID, do not edit

[proxy]
# timeout_secs = 30
# allow_only = ["api.openai.com", "api.anthropic.com"]

[hosts."api.openai.com".auth]
type = "bearer"
# token = "$OPENAI_API_KEY"   ← env var fallback; or use: nv add api.openai.com --bearer

[hosts."api.anthropic.com".auth]
type = "header"
name = "x-api-key"

[hosts."api.anthropic.com".headers]
anthropic-version = "2023-06-01"

[hosts."auth.example.com".auth]
type = "oauth2"
token_url = "https://auth.example.com/token"
scopes = ["read", "write"]
```

### Host patterns

| Pattern | Matches |
|---|---|
| `"api.example.com"` | exact hostname |
| `"*.example.com"` | single label wildcard |
| `"**.example.com"` | any subdomain depth |
| `"api.example.com/v1/*"` | host + path glob |

---

## Project layout

```
your-project/
├── nv.toml          # committed — project ID, host rules, no secrets
└── .nv/             # gitignored — runtime state + encrypted secrets
    ├── secrets.enc
    ├── proxy.pid
    ├── proxy.port
    └── bin/activate

~/.config/nv/
├── proxy-ca/        # global CA (shared across projects)
└── keys/
    └── <project-id> # 32-byte AES key, mode 0600
```
