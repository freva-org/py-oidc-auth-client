"""
CLI entry point for py_oidc_auth_client.

Usage::

    python -m py_oidc_auth_client https://myapp.example.com
    python -m py_oidc_auth_client https://myapp.example.com --timeout 120
    python -m py_oidc_auth_client https://myapp.example.com --force
    python -m py_oidc_auth_client --list
    python -m py_oidc_auth_client --list --verbose
    python -m py_oidc_auth_client --clear
    python -m py_oidc_auth_client --remove https://myapp.example.com
    python -m py_oidc_auth_client --remove a3f1c9d2e8b40571
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from rich_argparse import (
        ArgumentDefaultsRichHelpFormatter as ArgumentFormatter,
    )
except ImportError:
    from argparse import ArgumentDefaultsHelpFormatter as ArgumentFormatter

from . import TokenStore, authenticate
from .exceptions import AuthError
from .token_store import StoreEntry
from .utils import DEFAULT_APP_NAME


def _humanise(seconds: float) -> str:
    """Render a duration compactly for a listing column."""
    seconds = int(max(seconds, 0))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d"


def _status(entry: StoreEntry, now: float) -> str:
    """Describe what is still usable about an entry."""
    if entry.access_valid(now):
        return f"expires in {_humanise(entry.token.get('expires', 0) - now)}"
    if entry.refresh_valid(now):
        left = entry.token.get("refresh_expires", 0) - now
        return f"refresh only, {_humanise(left)} left"
    return "expired"


def _describe(entry: StoreEntry, now: float) -> List[str]:
    """Build the columns for one entry in the listing."""
    identity = entry.identity
    grant = identity.grant.display if identity.grant else "unknown grant"
    details = []
    if identity.client_id:
        details.append(f"client={identity.client_id}")
    if identity.scopes:
        details.append("scopes=" + ",".join(identity.scopes))
    if identity.audience:
        details.append(f"audience={identity.audience}")
    if identity.grant is None:
        details.append("migrated")
    return [grant, " ".join(details), _status(entry, now), entry.digest[:8]]


def _resolve_target(store: TokenStore, target: str) -> Optional[str]:
    """Resolve a ``--remove`` argument that looks like a digest prefix.

    ``--list`` shows digests truncated, so the value a user copies from
    it is a prefix rather than a whole digest.  Returns the full digest
    on a unique match, ``target`` unchanged when it is not digest like
    (a host URL), and ``None`` when the prefix is ambiguous.
    """
    if (
        "/" in target
        or not target
        or not all(char in "0123456789abcdef" for char in target)
    ):
        return target
    matches = [e.digest for e in store.entries() if e.digest.startswith(target)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(
            f"Ambiguous digest {target!r}, matches: {', '.join(sorted(matches))}",
            file=sys.stderr,
        )
        return None
    return target


def _print_listing(store: TokenStore, verbose: bool = False) -> None:
    """Print cached tokens grouped by host.

    Exchanged tokens are indented under the entry whose token was used
    as the exchange subject, which is also the entry that would take
    them with it if it were removed.
    """
    entries = store.entries()
    if not entries:
        print("No cached tokens.")
        return

    now = time.time()
    by_parent: Dict[Optional[str], List[StoreEntry]] = {}
    for entry in entries:
        by_parent.setdefault(entry.parent, []).append(entry)
    known = {entry.digest for entry in entries}

    rows: List[Tuple[StoreEntry, List[str]]] = []

    def walk(entry: StoreEntry, depth: int) -> None:
        columns = _describe(entry, now)
        if verbose:
            columns[3] = entry.digest
        indent = "  " + ("  " * depth) + ("\u2514\u2500 " if depth else "")
        # Fold the tree indent into the first column so that everything
        # to the right of it still lines up.
        columns[0] = indent + columns[0]
        rows.append((entry, columns))
        for child in sorted(
            by_parent.get(entry.digest, []), key=lambda e: e.identity.label
        ):
            walk(child, depth + 1)

    # Roots are entries with no parent, plus orphans whose parent has
    # already been evicted.
    roots = [e for e in entries if e.parent is None or e.parent not in known]
    for entry in sorted(roots, key=lambda e: (e.identity.host, e.identity.label)):
        walk(entry, 0)

    widths = [max(len(columns[i]) for _, columns in rows) for i in range(3)]
    current_host = None
    for entry, columns in rows:
        if entry.identity.host != current_host:
            print(entry.identity.host)
            current_host = entry.identity.host
        print(
            f"{columns[0]:<{widths[0]}}  {columns[1]:<{widths[1]}}  "
            f"{columns[2]:<{widths[2]}}  {columns[3]}".rstrip()
        )
        if verbose and entry.identity.issuer:
            print(f"{' ' * (widths[0] + 2)}issuer={entry.identity.issuer}")


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
        type=int,
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
        default=DEFAULT_APP_NAME,
        help="Application name for the cache directory.",
    )

    # Store management
    store_group = parser.add_argument_group("token store management")
    store_group.add_argument(
        "--list",
        action="store_true",
        dest="list_hosts",
        help="List cached tokens grouped by host, then exit.",
    )
    store_group.add_argument(
        "--clear",
        action="store_true",
        help="Remove all cached tokens, then exit.",
    )
    store_group.add_argument(
        "--remove",
        metavar="HOST_OR_DIGEST",
        help=(
            "Remove cached tokens, then exit.  A host removes every token "
            "for that server; a digest removes one entry.  Tokens derived "
            "by exchange are removed along with their subject."
        ),
    )
    store_group.add_argument(
        "--verbose",
        action="store_true",
        help="Show full digests and issuers in --list output.",
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
        _print_listing(store, verbose=args.verbose)
        return 0

    if args.clear:
        store.clear()
        print("All cached tokens removed.")
        return 0

    if args.remove:
        target = _resolve_target(store, args.remove)
        if target is None:
            return 1
        removed = store.remove(target)
        if removed:
            plural = "" if removed == 1 else "s"
            print(f"Removed {removed} token{plural} for {args.remove}")
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
            login_route=args.login_route,
            token_route=args.token_route,
            device_route=args.device_route,
            redirect_ports=args.ports,
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
    raise SystemExit(main(prog="python -m py_oidc_auth_client"))  # pragma: no cover
