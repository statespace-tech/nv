# nv

### A transparent HTTPS proxy for AI agents.

nv sits between an agent and the internet, injecting credentials automatically so agents can make authenticated API requests without ever seeing a secret.

- **Zero agent changes** — any HTTP client that respects `HTTP_PROXY`/`HTTPS_PROXY` works out of the box
- **Per-project secrets** — credentials are encrypted per-project; two projects using the same API can have different keys
- **Secrets never on disk in plaintext** — AES-256-GCM encrypted at rest, decrypted into daemon memory only
- **Agent-proof** — the encryption key lives outside the project directory; agents cannot access it
- **CI-ready** — inject the project key as `NV_KEY` in any CI provider

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
Initialised net environment [.nv] in: /path/to/myproject

$ source .nv/bin/activate
nv [.nv] active (port 51234). Run 'deactivate' to stop.

[.nv] $ nv add api.example.com --bearer
Bearer token: ••••••••
Auth configured for 'api.example.com' (secret stored in .nv/secrets.enc).

[.nv] $ claude "Make some API requests"
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

## Commands

### `nv init [path] [--name <name>]`

Create a net environment. Generates a project ID, creates an encryption key at `~/.config/nv/keys/<id>`, and writes `nv.toml`.

```console
$ nv init
$ nv init ~/projects/myapp
$ nv init --name myapp
```

### `nv add <host> <auth-type>`

Configure authentication for a host. Prompts for the secret, encrypts it into `.nv/secrets.enc`, and records the auth type in `nv.toml`. The secret value is never written to `nv.toml`.

Host can be an exact hostname or a glob pattern:

```console
$ nv add api.openai.com --bearer
$ nv add api.anthropic.com --header x-api-key
$ nv add api.example.com --query api_key
$ nv add auth.example.com --oauth2 --token-url https://auth.example.com/token
$ nv add github.com --device-flow --client-id <id>
$ nv add "*.example.com" --bearer
```

Add `--browser` to collect the secret via a local browser form instead of a terminal prompt.

### `nv sync`

Populate missing secrets interactively. Reads `nv.toml`, finds every host with auth configured but no secret in `.nv/secrets.enc`, and prompts for each one. Run this after cloning a repo that already has an `nv.toml`.

```console
$ nv sync
api.openai.com (bearer token): ••••••••
api.anthropic.com (x-api-key header): ••••••••
Secrets saved.
```

If everything is already populated:

```console
$ nv sync
All secrets up to date.
```

### `source .nv/bin/activate`

Activate the environment in the current shell. Sets `HTTP_PROXY`/`HTTPS_PROXY` to point at the nv daemon and updates the prompt. Run `deactivate` to stop.

```console
$ source .nv/bin/activate
nv [.nv] active (port 51234). Run 'deactivate' to stop.

[.nv] $ deactivate
nv deactivated.
```

### `nv activate`

Same as `source .nv/bin/activate` but spawns a subshell instead of modifying the current shell. `exit` to leave.

```console
$ nv activate
nv [.nv] active (port 51234). Type 'exit' to deactivate.
```

### `nv run <command>`

Run a single command inside the environment without activating a shell.

```console
$ nv run python agent.py
$ nv run curl https://api.openai.com/v1/models
```

### `nv list`

Show all configured hosts and their auth types.

### `nv remove <host>`

Remove a host's auth config from `nv.toml` and erase its secret from `.nv/secrets.enc`.

### `nv trust` / `nv untrust`

Install or remove the proxy CA from the system trust store. Required once per machine.

---

## CI usage

Commit `nv.toml` and `.nv/secrets.enc` to your repository. Export the project key once and store it as a masked CI secret:

```console
$ cat ~/.config/nv/keys/<project-id> | base64
abc123...
```

Then in CI:

```yaml
- name: Run agent
  env:
    NV_KEY: ${{ secrets.NV_PROJECT_KEY }}
  run: |
    source .nv/bin/activate
    python agent.py
```

`NV_KEY` is read by the daemon at startup and unset by the activate script before your command runs. The agent process never has access to it.

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
