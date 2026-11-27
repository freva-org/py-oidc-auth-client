"""
CLI entry point for py_oidc_auth_client.

Usage::

    python -m py_oidc_auth_client https://myapp.example.com
    python -m py_oidc_auth_client https://myapp.example.com --timeout 120
    python -m py_oidc_auth_client https://myapp.example.com --scope openid email
    python -m py_oidc_auth_client https://myapp.example.com --force
    python -m py_oidc_auth_client https://myapp.example.com --flow code
    python -m py_oidc_auth_client https://myapp.example.com --audience other-app
    python -m py_oidc_auth_client https://peer.example.org \
        --subject-host https://myapp.example.com
    echo "$TOKEN" | python -m py_oidc_auth_client https://myapp.example.com \
        --flow exchange --subject-token -
    python -m py_oidc_auth_client --discovery-url \
        https://kc.example.org/realms/freva --client-id freva-cli
    OIDC_CLIENT_SECRET=... python -m py_oidc_auth_client --discovery-url \
        https://kc.example.org/realms/freva --client-id job \
        --flow client-credentials
    python -m py_oidc_auth_client --list
    python -m py_oidc_auth_client --list --verbose
    python -m py_oidc_auth_client --clear
    python -m py_oidc_auth_client --remove https://myapp.example.com
    python -m py_oidc_auth_client --remove a3f1c9d2e8b40571
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple, Union

try:
    from rich_argparse import (
        ArgumentDefaultsRichHelpFormatter as ArgumentFormatter,
    )
except ImportError:
    from argparse import ArgumentDefaultsHelpFormatter as ArgumentFormatter

from . import TokenStore, authenticate, exchange
from .exceptions import AuthError
from .flows import (
    BaseFlow,
    ClientCredentialsFlow,
    CodeFlow,
    DeviceFlow,
    LoginFlow,
)
from .schema import Token
from .token_store import StoreEntry
from .types import TOKEN_TYPES
from .utils import DEFAULT_APP_NAME, Config

FLOWS = ("auto", "device", "code", "exchange", "client-credentials")
#: Environment variable the client secret is read from.
SECRET_ENV = "OIDC_CLIENT_SECRET"
#: Options that only make sense for a plain OpenID Connect provider.
OIDC_OPTIONS = (
    "client_id",
    "client_secret",
    "client_secret_file",
    "server_key",
    "key_id",
)
#: Options that only make sense for a token exchange.
EXCHANGE_OPTIONS = (
    "audience",
    "resource",
    "requested_token_type",
    "subject_host",
    "subject_token",
)


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
    if "/" in target or not target or not all(
        char in "0123456789abcdef" for char in target
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
        "-f",
        "--flow",
        choices=FLOWS,
        default="auto",
        help=(
            "How to get the token.  auto: an exchange if an exchange option "
            "is given, otherwise a login with the device flow, or the code "
            "flow where the server has no device flow.  client-credentials: "
            "a token for the client itself (--discovery-url only)."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Log in, or exchange, again even if a cached token exists.",
    )
    parser.add_argument(
        "-s",
        "--scope",
        dest="scopes",
        nargs="+",
        default=None,
        metavar="SCOPE",
        help="Scopes to request instead of the server's default ones.",
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

    # Plain OpenID Connect provider
    oidc_group = parser.add_argument_group(
        "plain OpenID Connect provider (Keycloak, ...)",
        "Log in at the provider directly instead of through a py-oidc-auth "
        "server.  The client secret is read from --client-secret-file or $"
        + SECRET_ENV
        + ".",
    )
    oidc_group.add_argument(
        "--discovery-url",
        metavar="URL",
        help=(
            "The provider's discovery document, or its issuer "
            "(https://kc.example.org/realms/freva).  Replaces HOST."
        ),
    )
    oidc_group.add_argument(
        "--client-id",
        help="Client registered at the provider (default: --app-name).",
    )
    oidc_group.add_argument(
        "--client-secret-file",
        metavar="PATH",
        help="File holding the client secret of a confidential client.",
    )
    oidc_group.add_argument(
        "--client-secret",
        help=argparse.SUPPRESS,
    )
    oidc_group.add_argument(
        "--server-key",
        metavar="PATH",
        help="PEM private key for private_key_jwt client authentication.",
    )
    oidc_group.add_argument(
        "--key-id",
        help="kid header of the private_key_jwt assertions.",
    )

    # Token exchange
    exchange_group = parser.add_argument_group(
        "token exchange (RFC 8693)",
        "Any of these selects --flow exchange.  --scope sets the scopes of "
        "the exchanged token.",
    )
    exchange_group.add_argument(
        "--audience",
        help="Service the exchanged token is for.",
    )
    exchange_group.add_argument(
        "--resource",
        help="URI of the service the exchanged token is for.",
    )
    exchange_group.add_argument(
        "--requested-token-type",
        metavar="TYPE",
        help=(
            "Type of the token wanted: " + ", ".join(TOKEN_TYPES) + " or a "
            "token type URN.  Left to the server when not given."
        ),
    )
    subject = exchange_group.add_mutually_exclusive_group()
    subject.add_argument(
        "--subject-host",
        metavar="URL",
        help=(
            "Exchange your login on this server instead of the one on "
            "HOST (logging in there first if needed), e.g. for a peer "
            "server that trusts it."
        ),
    )
    subject.add_argument(
        "--subject-token",
        metavar="TOKEN",
        help="Exchange this token; - reads it from stdin.",
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

    config = _oidc_config(parser, args)
    if config is None and not args.host:
        parser.error("host is required for authentication")
    if config is not None and args.host:
        parser.error("give either HOST or --discovery-url, not both")
    target = args.host or (config.host if config else "")

    flow = _choose_flow(parser, args)
    if flow == "client-credentials" and config is None:
        parser.error("--flow client-credentials needs --discovery-url")
    try:
        token = _run_flow(flow, args, store, config)
    except AuthError as exc:
        verb = "Token exchange" if flow == "exchange" else "Authentication"
        print(f"{verb} failed: {exc}", file=sys.stderr)
        return 1

    if args.output_json:
        print(json.dumps(dict(token), indent=2))
    else:
        access = token.get("access_token", "")
        preview = f"{access[:20]}..." if len(access) > 20 else access
        if flow == "exchange":
            print(f"Exchanged a token at {target}")
            print(f"  issued_token_type: {token.get('issued_token_type', '')}")
        else:
            print(f"Authenticated to {target}")
        print(f"  access_token: {preview}")
        print(f"  scope:        {token.get('scope', '')}")

    return 0


def _choose_flow(parser: argparse.ArgumentParser, args: argparse.Namespace) -> str:
    """Resolve ``--flow auto`` and reject options that do not fit the flow."""
    given = [
        "--" + name.replace("_", "-")
        for name in EXCHANGE_OPTIONS
        if getattr(args, name) is not None
    ]
    if args.flow == "auto":
        return "exchange" if given else "auto"
    if given and args.flow != "exchange":
        parser.error(f"{', '.join(given)} only work with --flow exchange")
    return str(args.flow)


def _client_secret(args: argparse.Namespace) -> Optional[str]:
    """Read the client secret: file, then flag (warned about), then env."""
    if args.client_secret_file:
        with open(os.path.expanduser(args.client_secret_file), encoding="utf-8") as f:
            return f.read().strip() or None
    if args.client_secret:
        print(
            "Warning: --client-secret is visible to other users (ps, shell "
            f"history); use --client-secret-file or ${SECRET_ENV}.",
            file=sys.stderr,
        )
        return str(args.client_secret)
    return os.environ.get(SECRET_ENV) or None


def _oidc_config(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> Optional[Config]:
    """Build the config for a plain OpenID Connect provider, if asked for."""
    if not args.discovery_url:
        given = [
            "--" + name.replace("_", "-")
            for name in OIDC_OPTIONS
            if getattr(args, name) is not None
        ]
        if given:
            parser.error(f"{', '.join(given)} only work with --discovery-url")
        return None
    return Config.from_discovery(
        args.discovery_url,
        client_id=args.client_id,
        client_secret=_client_secret(args),
        server_key=args.server_key,
        key_id=args.key_id,
        redirect_ports=args.ports,
        app_name=args.app_name,
    )


def _run_flow(
    flow: str,
    args: argparse.Namespace,
    store: TokenStore,
    config: Optional[Config] = None,
) -> Token:
    """Get the token the chosen way."""
    routes = {
        "login_route": args.login_route,
        "token_route": args.token_route,
        "device_route": args.device_route,
        "redirect_ports": args.ports,
    }
    if flow == "auto":
        return authenticate(
            args.host or "",
            config=config,
            store=store,
            app_name=args.app_name,
            force=args.force,
            timeout=args.timeout,
            scopes=args.scopes,
            **routes,
        )
    if flow in ("device", "code", "client-credentials"):
        classes = {
            "device": DeviceFlow,
            "code": CodeFlow,
            "client-credentials": ClientCredentialsFlow,
        }
        login: BaseFlow = classes[flow](
            args.host or "",
            config=config,
            store=store,
            timeout=args.timeout,
            scopes=args.scopes,
            **routes,
        )
        return asyncio.run(login.authenticate(force=args.force))
    subject: Optional[Union[LoginFlow, str]] = None
    if args.subject_token is not None:
        subject = args.subject_token
        if subject == "-":
            subject = sys.stdin.read().strip()
        if not subject:
            raise AuthError("No subject token given.", status_code=400)
    elif args.subject_host is not None:
        subject = LoginFlow(
            args.subject_host, store=store, timeout=args.timeout, **routes
        )
    return exchange(
        args.host or "",
        config=config,
        subject=subject,
        audience=args.audience,
        scopes=args.scopes,
        resource=args.resource,
        requested_token_type=args.requested_token_type,
        token_route=args.token_route,
        store=store,
        force=args.force,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(
        main(prog="python -m py_oidc_auth_client")
    )  # pragma: no cover
