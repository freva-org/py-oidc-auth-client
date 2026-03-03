"""
CLI entry point for py_oidc_auth_client.

Usage::

    python -m py_oidc_auth_client https://myapp.example.com
    python -m py_oidc_auth_client https://myapp.example.com --timeout 120
    python -m py_oidc_auth_client https://myapp.example.com --force
    python -m py_oidc_auth_client --list
    python -m py_oidc_auth_client --clear
    python -m py_oidc_auth_client --remove https://myapp.example.com
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

try:
    from rich_argparse import (
        ArgumentDefaultsRichHelpFormatter as ArgumentFormatter,
    )
except ImportError:
    from argparse import ArgumentDefaultsHelpFormatter as ArgumentFormatter

from . import TokenStore, authenticate
from .exceptions import AuthError


def _build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Authenticate to an OIDC protected server.",
        formatter_class=ArgumentFormatter,
    )

    # Positional: host (optional so that --list/--clear work without it)
    parser.add_argument(
        "host",
        nargs="?",
        default=None,
        help="Base URL of the server (e.g. https://myapp.example.com).",
    )
    parser.add_argument(
        "-l",
        "--login-route",
        help="Server path for the authorization code login endpoint.",
        default="/auth/v2/login",
    )
    parser.add_argument(
        "-t",
        "--token-route",
        help="Server path for the token exchange endpoint.",
        default="/auth/v2/token",
    )
    parser.add_argument(
        "-d",
        "--device-route",
        help="Server path for the device authorization endpoint.",
        default="/auth/v2/device",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="Ports to try for the local callback server (code flow only).",
        default=[53100, 53101, 53102, 53103, 53104, 53105],
        nargs="+",
    )
    # Auth options
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force a fresh login even if a cached token exists.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to wait for the user to approve (default: 30).",
    )
    parser.add_argument(
        "--app-name",
        default="py-oidc-auth",
        help=(
            "Application name for the cache directory " "(default: py-oidc-auth)."
        ),
    )

    # Store management
    store_group = parser.add_argument_group("token store management")
    store_group.add_argument(
        "--list",
        action="store_true",
        dest="list_hosts",
        help="List all hosts with cached tokens, then exit.",
    )
    store_group.add_argument(
        "--clear",
        action="store_true",
        help="Remove all cached tokens, then exit.",
    )
    store_group.add_argument(
        "--remove",
        metavar="HOST",
        help="Remove the cached token for HOST, then exit.",
    )

    # Output options
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Print the full token as JSON instead of a summary.",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None, prog: str = "oidc-auth") -> int:
    """Run the CLI.

    Parameters
    ----------
    argv : list of str or None
        Command line arguments.  Uses ``sys.argv[1:]`` when ``None``.
    prog: str
        Name of the cli

    Returns
    -------
    int
        Exit code (0 on success, 1 on error).
    """
    parser = _build_parser(prog)
    args = parser.parse_args(argv)

    store = TokenStore(app_name=args.app_name)

    # -- Store management commands (no host required) -------------------

    if args.list_hosts:
        hosts = store.hosts()
        if not hosts:
            print("No cached tokens.")
        else:
            for host in sorted(hosts):
                token = store.get(host)
                status = "valid" if token else "expired"
                print(f"  {host}  ({status})")
        return 0

    if args.clear:
        store.clear()
        print("All cached tokens removed.")
        return 0

    if args.remove:
        if store.remove(args.remove):
            print(f"Removed token for {args.remove}")
        else:
            print(f"No cached token for {args.remove}")
        return 0

    # -- Authentication (host required) ---------------------------------

    if not args.host:
        parser.error("host is required for authentication")

    try:
        token = authenticate(
            args.host,
            store=store,
            app_name=args.app_name,
            force=args.force,
            timeout=args.timeout,
        )
    except AuthError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
        return 1

    if args.output_json:
        print(json.dumps(dict(token), indent=2))
    else:
        access = token.get("access_token", "")
        preview = f"{access[:20]}..." if len(access) > 20 else access
        print(f"Authenticated to {args.host}")
        print(f"  access_token: {preview}")
        print(f"  scope:        {token.get('scope', '')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main(prog="python -m py_oidc_auth_client")
    )  # pragma: no cover
