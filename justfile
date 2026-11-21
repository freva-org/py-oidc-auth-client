# py-oidc-auth-client development.
#
#   just setup                the dev image, the py-oidc-auth checkout, git hooks
#   just test [pytest args]   the tests, in a container on Python $PY
#   just check                lint, types, docs, packaging and tests
#   just dev [framework]      Keycloak and a py-oidc-auth dev server on :7777
#   just cli http://localhost:7777/api/test
#                             the client CLI against that server
#
# Everything but `release` runs in containers, one image per Python version
# with the dependencies installed into the image's own Python (no virtualenv).
# The checkout is mounted, so edits apply without a rebuild; a change to
# pyproject.toml gets a fresh image on the next run.
#
#   PY=3.11 just test                 another Python version
#   COMPOSE=podman-compose just test  podman instead of docker
#
# To check client and server together, `just dev` clones py-oidc-auth into
# dev-env/py-oidc-auth (untracked, no submodule) and runs that checkout's own
# `just dev`: Keycloak on :8080 and the server on :7777. `just update-server`
# fast-forwards it to origin/main. Nothing is ever pushed from here.
#
# The git hooks in .githooks run the same checks: lint and types before a
# commit that touches code, what CI runs before a push. `just setup` and
# `just dev` turn them on, `just hooks-off` turns them off, and
# `--no-verify` or SKIP_HOOKS=1 skips them.
#
# The recipes that run inside the container live in dev-env/container.just;
# the ones here drive compose from outside.

set shell := ["bash", "-euo", "pipefail", "-c"]
# Pass recipe arguments on as "$@", so quoting survives: just test -k "a and b"
set positional-arguments

compose := env("COMPOSE", "docker compose")
export PY := env("PY", "3.13")
export DEPS_HASH := `sha256sum pyproject.toml | cut -c1-12`
versions := "3.10 3.11 3.12 3.13 3.14"
dc := compose + " -f dev-env/docker-compose.yaml"
engine := if compose =~ "podman" { "podman" } else { "docker" }

# The py-oidc-auth checkout for `just dev` and `just server`.
server := "dev-env/py-oidc-auth"
server_repo := env("OIDC_AUTH_REPO", "https://github.com/freva-org/py-oidc-auth.git")
server_just := just_executable() + " --justfile " + server + "/justfile --working-directory " + server

# Files the container writes into the checkout (coverage, reports, docs)
# should belong to you. Rootless podman maps container root to you anyway;
# docker needs to be told. DEV_AS_USER=0 turns it off (rootless docker).
as_user := env("DEV_AS_USER", if compose =~ "podman" { "0" } else { "1" })
run := dc + " run --rm" + if as_user == "1" { " --user " + `id -u` + ":" + `id -g` } else { "" }

[private]
default:
    @just --justfile {{ justfile() }} --list
    @echo
    @echo "  python      {{ PY }}  (PY=3.11 just ...)"
    @echo "  server      http://localhost:7777  (just dev, from {{ server }})"
    @echo "  keycloak    http://localhost:8080  (admin: keycloak / secret, you: ${USER:-$(id -un)} / secret)"

# --- setup ------------------------------------------------------------------

# Get going: clone py-oidc-auth, build the dev image, turn on the git hooks
[group('setup')]
setup: fetch build hooks

# Turn on the git hooks: lint and types before commits, CI before pushes
[group('setup')]
hooks:
    @git config core.hooksPath .githooks

# Turn the git hooks off again
[group('setup')]
hooks-off:
    git config --unset core.hooksPath || true

# Run container recipes for a git hook, in one container start
[private]
_hook name *recipes:
    #!/usr/bin/env bash
    set -euo pipefail
    name=$1; shift
    if ! {{ engine }} info >/dev/null 2>&1; then
      echo "$name hook: {{ engine }} is not running. Start it, or skip the hook with --no-verify." >&2
      exit 1
    fi
    echo "$name hook: just $* (skip with --no-verify)" >&2
    {{ run }} -T dev just "$@"

# --- py-oidc-auth -----------------------------------------------------------

# Clone py-oidc-auth into dev-env/py-oidc-auth, if it is not there yet
[group('setup')]
fetch:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d {{ server }}/.git ]; then
      git clone {{ server_repo }} {{ server }}
    fi

# Fast-forward the py-oidc-auth checkout, but only while it is on main
[group('server')]
update-server: fetch
    #!/usr/bin/env bash
    set -euo pipefail
    branch=$(git -C {{ server }} branch --show-current)
    if [ "$branch" = "main" ]; then
      git -C {{ server }} pull --ff-only origin main
    else
      echo "leaving {{ server }} alone: it is on '$branch', not main"
    fi

# Keycloak plus the py-oidc-auth dev server on :7777: just dev litestar
[group('server')]
dev *args: hooks _server
    @{{ server_just }} dev "$@"

# Run any recipe of the py-oidc-auth checkout: just server test -k exchange
[group('server')]
server *args: _server
    @{{ server_just }} "$@"

# Stop the py-oidc-auth stack
[group('server')]
down:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f {{ server }}/justfile ]; then
      {{ server_just }} down
    fi

[private]
_server: fetch
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -f {{ server }}/justfile ]; then
      echo "{{ server }} has no justfile: run 'just update-server'" >&2
      exit 1
    fi

# --- the client -------------------------------------------------------------

# Run the client CLI in the dev image: just cli http://localhost:7777/api/test
[group('client')]
cli *args:
    {{ run }} dev just cli "$@"

# Open a shell in the dev image
[group('client')]
shell:
    {{ run }} dev bash

# --- quality ----------------------------------------------------------------

# Run the tests on $PY: all with coverage, or `pytest ARGS`: just test -k pkce
[group('quality')]
test *args:
    {{ run }} dev just test "$@"

# Run the tests on every supported Python version, then list what failed
[group('quality')]
test-all *args:
    #!/usr/bin/env bash
    set -uo pipefail
    failed=()
    for v in {{ versions }}; do
      echo "=== Python $v"
      PY=$v {{ just_executable() }} --justfile {{ justfile() }} test "$@" || failed+=("$v")
    done
    if [ ${#failed[@]} -gt 0 ]; then
      echo "failed on Python: ${failed[*]}" >&2
      exit 1
    fi
    echo "passed on Python: {{ versions }}"

# Check import order, style, spelling, docstrings and security
[group('quality')]
lint:
    {{ run }} dev just lint

# Format the code with black and isort
[group('quality')]
fmt:
    {{ run }} dev just fmt

# Static type checking
[group('quality')]
types:
    {{ run }} dev just types

# Build the docs into docs/build/html, warnings are errors
[group('quality')]
docs:
    {{ run }} dev just docs

# Check that the documentation links still resolve
[group('quality')]
linkcheck:
    {{ run }} dev just linkcheck

# Validate the packaging metadata and build the wheel
[group('quality')]
pkg:
    {{ run }} dev just pkg

# Lint, types, docs, packaging and tests, as CI runs them
[group('quality')]
check: lint types docs pkg test

# --- images -----------------------------------------------------------------

# Build the dev image for $PY (happens on first use anyway)
[group('images')]
build:
    {{ dc }} build dev

# Rebuild the dev image for $PY from scratch, pulling the base image
[group('images')]
rebuild:
    {{ dc }} build --pull --no-cache dev

# Remove all dev images of the client, for every Python version
[group('images')]
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    images=$({{ engine }} images --format '{{{{.Repository}}:{{{{.Tag}}' | grep '^localhost/py-oidc-auth-client-dev:' || true)
    [ -z "$images" ] || {{ engine }} rmi $images
    echo "dev images removed; 'just test' builds them again."

# --- release ----------------------------------------------------------------

# Tag a release (runs on the host, needs python3 and git)
[group('release')]
release:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -m pip install git-python requests packaging tomli
    curl -H 'Cache-Control: no-cache' -Ls -o bump.py \
      https://raw.githubusercontent.com/freva-org/freva-admin/main/release.py
    trap 'rm -f bump.py' EXIT
    python3 bump.py tag py_oidc_auth_client
