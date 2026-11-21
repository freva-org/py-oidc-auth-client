# Recipes that run INSIDE the dev container.
#
# The dev image sets JUST_JUSTFILE to this file and JUST_WORKING_DIRECTORY
# to the mounted checkout, so plain `just <recipe>` works in it. CI runs the
# same recipes straight on the runner, after `pip install -e .[dev]`:
#
#   just -f dev-env/container.just -d . test
#
# The host-side counterpart is the justfile in the repository root.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

[private]
default:
    @just --justfile {{ justfile() }} --list

# --- the client -------------------------------------------------------------

# Run the client CLI: just cli http://localhost:7777/api/test --list
[group('client')]
cli *args:
    python -m py_oidc_auth_client "$@"

# --- quality ----------------------------------------------------------------

# Run the tests: all of them with coverage, or `pytest ARGS` if given
[group('quality')]
test *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ $# -gt 0 ]; then
      exec python -m pytest "$@"
    fi
    python -m pytest -vv --cov=py_oidc_auth_client --cov-report=html:coverage_report \
      --cov-report xml --junitxml report.xml tests/
    python -m coverage report --fail-under=100 --precision=2 --show-missing

# Check import order, style, spelling, docstrings and security
[group('quality')]
lint:
    python -m isort --check --diff -t py312 --profile black src
    python -m flake8 src tests --count --statistics --show-source
    codespell --quiet-level=2 src/ tests/
    python -m pydocstyle src/py_oidc_auth_client
    bandit -r src/py_oidc_auth_client --severity-level medium --confidence-level high

# Format the code with black and isort
[group('quality')]
fmt:
    python -m black --line-length 79 src tests
    python -m isort src tests

# Static type checking
[group('quality')]
types:
    python -m mypy --install-types --non-interactive

# Build the docs into docs/build/html, warnings are errors
[group('quality')]
docs:
    codespell --quiet-level=2 docs/source
    rm -rf docs/build
    python -m sphinx -M html docs/source docs/build -W --keep-going

# Check that the documentation links still resolve
[group('quality')]
linkcheck:
    python -m sphinx -M linkcheck docs/source docs/build

# Validate the packaging metadata and build the wheel (dist/ is removed after)
[group('quality')]
pkg:
    #!/usr/bin/env bash
    set -euo pipefail
    # A misspelled key under [project] is silently ignored by the build
    # backend: that is how the classifiers went missing from 2603.0.1.
    python -m validate_pyproject pyproject.toml
    trap 'rm -rf dist' EXIT
    python -m flit build --no-use-vcs
    python -m twine check dist/*
    python - <<'EOF'
    import glob, zipfile
    wheel = zipfile.ZipFile(glob.glob("dist/*.whl")[0])
    names = wheel.namelist()
    meta = wheel.read(next(n for n in names if n.endswith("METADATA"))).decode()
    assert "Classifier: Programming Language :: Python :: 3." in meta, (
        "no Python version classifiers in wheel metadata"
    )
    assert any(n.endswith("py.typed") for n in names), "py.typed missing from wheel"
    print("wheel metadata ok")
    EOF
