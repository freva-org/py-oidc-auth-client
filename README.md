<p align="center">
  <img src="https://raw.githubusercontent.com/freva-org/py-oidc-auth-client/main/docs/source/_static/logo.png" alt="py-oidc-auth-client logo" width="560">
</p>
<p align="center">
<em>Typed client library for the authentication routes exposed by py-oidc-auth.</em>
</p>

[![License](https://img.shields.io/badge/License-BSD-purple.svg)](LICENSE)
[![codecov](https://codecov.io/gh/freva-org/py-oidc-auth-client/graph/badge.svg?token=9JP9UWixaf)](https://codecov.io/gh/freva-org/py-oidc-auth-client)
[![docs](https://readthedocs.org/projects/py-oidc-auth-client/badge/?version=latest)](https://py-oidc-auth-client.readthedocs.io/en/latest/?badge=latest)
[![PyPI](https://img.shields.io/pypi/v/py-oidc-auth-client)](https://pypi.org/project/py-oidc-auth-client/)
[![Python Versions](https://img.shields.io/pypi/pyversions/py-oidc-auth-client)](https://pypi.org/project/py-oidc-auth-client)

py-oidc-auth-client is the counterpart of the server-side library **py-oidc-auth**.

While **py-oidc-auth** helps you add OpenID Connect login, token, and device endpoints to web frameworks,
**py-oidc-auth-client** consumes those routes and gives you ready-to-use bearer tokens for calling protected APIs.

## Features

* One high level helper: `authenticate()`
* `TokenStore` as a first-class, host-aware token persistence layer
* Device flow for headless sessions
* Authorization code flow for interactive logins
* Token exchange (RFC 8693) with `exchange()`, also across trusting servers
* Token caching and refresh token support
* Fully typed public API

## Install

```console
python -m pip install py-oidc-auth-client
```

Import name is `py_oidc_auth_client`:

```python
from py_oidc_auth_client import authenticate
```

## Relationship to py-oidc-auth

A typical **py-oidc-auth** server exposes endpoints similar to:

* `GET  /auth/v2/login`
* `GET  /auth/v2/callback`
* `POST /auth/v2/token`
* `POST /auth/v2/device`
* `GET  /auth/v2/logout`
* `GET  /auth/v2/userinfo`

This client calls the relevant routes (token and device, and possibly login/callback) and returns a `Token`
object that contains a ready-made `Authorization` header.

## Quick start

```python
from py_oidc_auth_client import authenticate

token = authenticate(host="https://auth.example.org")

# Use with any HTTP client
headers = token["headers"]
print(headers["Authorization"])
```

### Use with httpx

```python
import httpx
from py_oidc_auth_client import authenticate

token = authenticate(host="https://auth.example.org")

with httpx.Client() as client:
    r = client.get("https://service.example.org/protected", headers=token["headers"])
    r.raise_for_status()
    print(r.json())
```

## TokenStore

`TokenStore` is the storage layer that keeps authentication state available between runs.
It is one of the main building blocks of the library, alongside `authenticate()`,
`CodeFlow`, and `DeviceFlow`.

`TokenStore` separates tokens by host internally. That means a single token database file
is usually enough for one application, even if it talks to multiple auth servers.
Use separate store files when you want isolation between applications or environments,
not simply because the host changes.

Use it when you want to:

* choose a predictable token location
* separate tokens per application or environment
* support refresh-token based reuse in batch, remote, or repeated runs
* reuse one host-aware token store across multiple auth servers

```python
from py_oidc_auth_client import TokenStore, authenticate

store = TokenStore(path="~/.cache/py-oidc-auth-client/my-app.json")

token = authenticate(
    host="https://auth.example.org",
    store=store,
)
```

## Choosing the right entry point

Use these building blocks as a rule of thumb:

* start with `authenticate()`
* add an explicit `TokenStore` when token persistence matters; one store usually covers multiple hosts
* use `CodeFlow` directly for browser-based interactive login control
* use `DeviceFlow` directly for headless or remote sessions

For many applications, the best default is `authenticate()` together with an explicit
`TokenStore`, typically one store per application or environment.

## Interactive and non-interactive environments

The client tries to select a suitable strategy:

1. Use a valid cached access token.
2. Refresh using the refresh token.
3. If interactive authentication is possible, fall back to an interactive login.
4. If running in a non-interactive session without a usable token, raise an error telling you how to provide a token file.

For headless sessions, the device flow is the recommended approach. In those environments,
`TokenStore` is especially important because it lets later runs reuse persisted auth state.

## Advanced usage

If you need more control than `authenticate()`, use the flow helpers from `py_oidc_auth_client.auth`.

### Device flow

```python
import asyncio
from py_oidc_auth_client import Config, DeviceFlow

async def main() -> None:
    cfg = Config(host="https://auth.example.org")
    flow = DeviceFlow(config=cfg, token=None, timeout=600)

    device = await flow.get_device_code()
    print("Open:", device.uri)
    print("Code:", device.user_code)

    token = await flow.poll(device["device_code"], int(device["interval"]))
    print(token["headers"])

asyncio.run(main())
```

### Authorization code flow

```python
import asyncio
from py_oidc_auth_client import Config, CodeFlow

async def main() -> None:
    cfg = Config(host="https://auth.example.org")
    flow = CodeFlow(config=cfg, token=None, timeout=120)
    token = await flow.authenticate()
    print(token["headers"])

asyncio.run(main())
```

### Token exchange

`exchange()` turns a token into another one: for another audience, with fewer
scopes, or for a peer server that trusts this one. The exchanged token is cached
and exchanged again from a fresh subject token when it expires.

```python
from py_oidc_auth_client import DeviceFlow, exchange

# Your login on the server, exchanged for a token for another service
token = exchange("https://auth.example.org", audience="s3-gateway")

# A login on one server, used at a peer server
login = DeviceFlow("https://auth.example.org")
peer_token = exchange("https://peer.example.org", subject=login)
```

The same from the command line, where `--flow auto|device|code|exchange` picks the
flow and any exchange option selects the exchange:

```console
oidc-auth https://auth.example.org --audience s3-gateway --json
oidc-auth https://peer.example.org --subject-host https://auth.example.org
```

## Stable public API

The main public building blocks are:

* `authenticate`
* `authenticate_async`
* `exchange`
* `exchange_async`
* `TokenStore`
* `CodeFlow`
* `DeviceFlow`
* `ExchangeFlow`
* `Config`
* `Token`
* `AuthError`

## Docs hub

The documentation is organised around a few task-oriented entry points:

* Overview
* Quickstart
* TokenStore
* Choosing an authentication strategy
* Non-interactive environments
* Configuration
* Recipes
* Stable public API

## Contributing

Contributions are welcome. Please open an issue to discuss larger changes before submitting a pull request.

### Development

Development runs in containers, driven by [just](https://just.systems). You need
`just`, `git` and docker (or podman with `COMPOSE=podman-compose`); no local Python
environment is involved.

```console
just test                 # the tests with coverage, on Python 3.13
just test -k exchange     # or any pytest arguments
PY=3.11 just test         # another Python version
just test-all             # every supported version
just lint                 # import order, style, spelling, docstrings, security
just types                # mypy
just docs                 # the docs, into docs/build/html
just pkg                  # packaging metadata and wheel
just check                # all of the above, as CI runs them
```

The first run builds a dev image per Python version with the dependencies installed.
The checkout is mounted into it, so edits apply without a rebuild, and a change to
`pyproject.toml` gets a fresh image. `just setup` does that up front, clones
py-oidc-auth (see below) and turns on the git hooks.

#### Git hooks

`just setup` and `just dev` turn on the hooks in `.githooks`:

* **pre-commit** runs `lint` and `types` (a few seconds), only for commits that touch
  `src/`, `tests/` or `pyproject.toml`. It checks the working tree, unstaged edits
  included. If it fails on formatting, `just fmt` fixes it.
* **pre-push** runs what CI runs: `lint`, `types`, `docs`, `pkg` and the tests on
  `$PY` (under a minute). `PREPUSH_ALL=1 git push` tests every Python version.

Both need docker or podman running. Skip them once with `--no-verify`, for a whole
shell with `SKIP_HOOKS=1`, or turn them off with `just hooks-off`.

To work on client and server together, `just dev` clones
[py-oidc-auth](https://github.com/freva-org/py-oidc-auth) into `dev-env/py-oidc-auth`
(untracked, not a submodule) and runs its own `just dev`: Keycloak on
`http://localhost:8080` and a py-oidc-auth server on `http://localhost:7777`, with its
auth routes under `/api/test`. Point the client at it from another terminal and log in
as `$USER` / `secret`:

```console
just dev                                   # terminal 1: Keycloak and the server
just cli http://localhost:7777/api/test    # terminal 2: log in with the client
just server test -k exchange               # any py-oidc-auth recipe, in its checkout
just update-server                         # git pull origin main in the checkout
just down                                  # stop the server stack
```

`just update-server` only fast-forwards the checkout while it is on `main`; on another
branch it leaves it alone, so you can work on a server branch there. Nothing is pushed
from these recipes.

Releases are tagged with `just release`.
