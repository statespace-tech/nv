# nv

[![License](https://img.shields.io/badge/license-MIT-007ec6?style=flat-square)](https://github.com/statespace-tech/nv/blob/main/LICENSE)

`nv` is a transparent HTTPS proxy for AI that sits between your agents and the internet. It injects credentials automatically so agents can make authenticated API requests without ever seeing a secret.

---

## Installation

Install nv:

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

$ nv activate
nv [myproject] active (port 51234). Run 'deactivate' to stop.

$ nv add api.example.com --bearer
Bearer token: ••••••••
Auth configured for 'api.example.com' (secret stored in .nenv/secrets.enc).

$ claude "Make some API requests"
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

Configure authentication for a host. Prompts for the secret, encrypts it into `.nenv/secrets.enc`, and records the auth type in `nv.toml`. The secret value is never written to `nv.toml`.

Host can be an exact hostname or a glob pattern:

```console
$ nv add api.stripe.com --bearer
$ nv add api.notion.com --header authorization
$ nv add maps.googleapis.com --query key
$ nv add api.sendgrid.com --bearer
$ nv add auth.example.com --oauth2 --token-url https://auth.example.com/token
$ nv add github.com --device-flow --client-id <id>
$ nv add "*.googleapis.com" --query key
$ nv add "*.azure.com" --bearer
```

> Tip: Add `--browser` to collect the secret via a local browser form instead of a terminal prompt.

### `nv sync`

Populate missing secrets interactively. Reads `nv.toml`, finds every host with auth configured but no secret in `.nenv/secrets.enc`, and prompts for each one. Run this after cloning a repo that already has an `nv.toml`.

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

### `nv activate`

Activate the environment in the current shell. Starts the proxy daemon, sets `HTTP_PROXY`/`HTTPS_PROXY`, and defines `deactivate` to undo everything.

```console
$ nv activate
nv [myproject] active (port 51234). Run 'deactivate' to stop.

[myproject] $ deactivate
nv deactivated.
```

> `source .nenv/bin/activate` is equivalent.

### `nv run <command>`

Run a single command inside the environment without activating a shell.

```console
$ nv run python agent.py
$ nv run curl https://api.openai.com/v1/models
```

### `nv list`

Show all configured hosts and their auth types.

### `nv allow <host>`

Allow a host to pass through the proxy without auth injection. Useful for hosts the agent needs to reach but that don't require credentials. Accepts globs.

```console
$ nv allow cdn.example.com
$ nv allow "*.cloudflare.com"
```

### `nv block <host>`

Block a host from passing through the proxy. Use `"*"` to block all traffic by default, then selectively allow or add hosts.

```console
$ nv block "*.analytics.com"
$ nv block "*"                    # block everything by default
$ nv add api.stripe.com --bearer  # implicitly allowed, wins over block *
$ nv allow cdn.example.com        # pass-through, also wins over block *
```

Explicit allows (`nv add`, `nv allow`) always take precedence over blocks, including `"*"`.

### `nv remove <host>`

Remove a host's auth config from `nv.toml` and erase its secret from `.nenv/secrets.enc`.

### `nv trust` / `nv untrust`

Install or remove the proxy CA from the system trust store. Required once per machine.

---

## CI usage

Commit `nv.toml` and `.nenv/secrets.enc` to your repository. Export the project key once and store it as a masked CI secret:

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
    source .nenv/bin/activate
    python agent.py
```

`NV_KEY` is read by the daemon at startup and unset by the activate script before your command runs. The agent process never has access to it.

---

## nv.toml

`nv.toml` can be committed to your repository. It contains auth types and host rules but **never** secrets.

```toml
id = "a3f9c2d1-..."

[proxy]
block = ["*"]
allow_only = ["api.stripe.com", "cdn.example.com"]

[hosts."api.stripe.com".auth]
type = "bearer"

[hosts."api.notion.com".auth]
type = "header"
name = "authorization"

[hosts."api.notion.com".headers]
Notion-Version = "2022-06-28"

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

## Community

- **Discord** — [Join our community server](https://discord.gg/statespace) for real-time help and discussions
- **X** — Follow us [@statespace_tech](https://x.com/statespace_tech) for updates and news
- **Issues** — Report bugs or request features on [GitHub Issues](https://github.com/statespace-tech/nv/issues)

## License

This project is licensed under the terms of the MIT license.
