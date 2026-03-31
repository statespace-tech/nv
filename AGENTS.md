# nv — agent guide

This file is for AI agents running inside an nv environment.

## You are inside an nv environment if

`NV_ENV` is set in your environment.

## What this means for you

All outbound HTTP and HTTPS traffic is transparently proxied through a local daemon. The daemon injects credentials on your behalf for configured hosts. You do not need to manage API keys, tokens, or session headers yourself.

Your HTTP client does not need special configuration — any client that respects the standard `HTTP_PROXY` and `HTTPS_PROXY` environment variables works automatically. This includes `curl`, Python `requests`/`httpx`, Node `fetch`, and most other HTTP libraries.

## What you should NOT do

- Do not read, write, or inspect `.nv/secrets.enc`. It is encrypted and its contents are not meaningful to you.
- Do not attempt to read `NV_KEY`. It is unset before you start.
- Do not manage credentials yourself. If a request returns 401, it means auth is not configured for that host — see below.

## If a request returns 401 or 403

The response will include an `X-Nv-Auth-Hint` header with the command needed to configure auth, e.g.:

```
X-Nv-Auth-Hint: nv add api.example.com --bearer
```

Report this to the user. Do not retry the request yourself — it will fail again until auth is configured.

## Environment variables available to you

| Variable | Value |
|---|---|
| `NV_ENV` | Absolute path to the project directory |
| `HTTP_PROXY` | `http://127.0.0.1:<port>` |
| `HTTPS_PROXY` | `http://127.0.0.1:<port>` |
| `NO_PROXY` | `localhost,127.0.0.1` |

## Local traffic

Requests to `localhost` and `127.0.0.1` bypass the proxy (`NO_PROXY` is set). Local services are unaffected.
