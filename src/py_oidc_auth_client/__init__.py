"""
py_oidc_auth_client
===================

A lightweight OIDC/OAuth 2.0 client library for authenticating against
servers that use ``py-oidc-auth`` (or any standard OIDC provider).

The main entry point is the :func:`authenticate` function which handles
token caching, refresh, and interactive login automatically.

Quick start
~~~~~~~~~~~

.. code-block:: python

    from py_oidc_auth_client import authenticate

    # Interactive login (opens browser, returns token)
    token = authenticate(host="https://myapp.example.com")
    print(token["access_token"][:20], "...")

    # Use the token with any HTTP client
    import httpx
    resp = httpx.get(
        "https://myapp.example.com/api/data",
        headers=token["headers"],
    )

Non interactive / batch mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    # On your workstation: login once and save the token
    token = authenticate(host="https://myapp.example.com")

    # On the cluster or in CI: reuses cached token automatically
    token = authenticate(host="https://myapp.example.com")

Multiple servers and multiple identities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tokens are cached per :class:`~identity.AuthIdentity`, which covers the
host together with everything else that made the token unique: the
grant that produced it, the client it was issued to, the scopes granted
and the audience it was minted for.  Authenticating to a different
server, or as a different principal on the same server, never
overwrites an existing token.

.. code-block:: python

    token_a = authenticate(host="https://server-a.example.com")
    token_b = authenticate(host="https://server-b.example.com")

You do not build identities yourself.  Each flow derives its own from
the parameters you pass it, and exposes it read only as
``flow.identity``.  Identities come back out of the store when you
inspect the cache.

For finer control over individual flows, see :class:`~flows.DeviceFlow`
and :class:`~flows.CodeFlow`.

CLI usage
~~~~~~~~~

.. code-block:: bash

    python -m py_oidc_auth_client https://myapp.example.com
    python -m py_oidc_auth_client https://myapp.example.com --timeout 120
    python -m py_oidc_auth_client --list
    python -m py_oidc_auth_client --list --verbose
    python -m py_oidc_auth_client --clear
    python -m py_oidc_auth_client --remove https://myapp.example.com
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from .exceptions import AuthError
from .flows import BaseFlow, CodeFlow, DeviceFlow
from .identity import AuthIdentity, Grant
from .schema import DeviceCode, Token
from .token_store import StoreEntry, TokenStore
from .utils import Config

__version__ = "2609.0.0"


def authenticate(
    host: str,
    *,
    login_route: str = "/auth/v2/login",
    token_route: str = "/auth/v2/token",
    device_route: str = "/auth/v2/device",
    redirect_ports: Optional[List[int]] = None,
    store: Optional[TokenStore] = None,
    app_name: str = "py-oidc-auth",
    force: bool = False,
    timeout: Optional[int] = 30,
) -> Token:
    """Authenticate to an OIDC protected server and return a token.

    This is the primary entry point for the library.  It handles the
    full authentication lifecycle:

    1. Check the token store for a cached token for this identity.
    2. If the access token is still valid, return it immediately.
    3. If only the refresh token is valid, perform a token refresh.
    4. Otherwise, start an interactive login.  The device flow is
       attempted first; if the server does not support it, the
       authorization code flow (local browser) is used as a fallback.

    Tokens are cached per :class:`~identity.AuthIdentity`, one file per
    entry, so authenticating to multiple servers or as multiple
    principals does not overwrite previous tokens.

    Parameters
    ----------
    host : str
        Base URL of the application server
        (e.g. ``"https://myapp.example.com"``).
    login_route : str
        Server side route for the authorization code login endpoint.
    token_route : str
        Server side route for the token exchange endpoint.
    device_route : str
        Server side route for the device authorization endpoint.
    redirect_ports : list of int, optional
        Ports to try when starting a local HTTP server for the
        authorization code callback.  The first available port is used.
        Defaults to ``[53100, 53101, 53102, 53103, 53104, 53105]``.
    store : TokenStore or None
        Custom :class:`TokenStore` for token persistence.  When
        ``None`` a default store is created in the platform cache
        directory (e.g. ``~/.cache/<app_name>/tokens/``).
    app_name : str
        Application name for the cache directory.  Only used when
        *store* is ``None``.  Defaults to ``"py-oidc-auth"``.
    force : bool
        When ``True``, skip the cache and force a fresh interactive
        login even if a valid token exists.
    timeout : int or None
        Maximum seconds to wait for the user to complete the browser
        login.  ``None`` waits indefinitely.

    Returns
    -------
    Token
        A token dictionary with keys ``access_token``,
        ``refresh_token``, ``expires``, ``refresh_expires``,
        ``scope``, ``token_type``, and ``headers``.

        The ``headers`` value is a ready to use dict:
        ``{"Authorization": "Bearer eyJ..."}``.

    Raises
    ------
    AuthError
        If authentication fails (timeout, user denial, server error,
        or no interactive session available in a batch environment).

    Examples
    --------
    Basic interactive login:

    .. code-block:: python

        from py_oidc_auth_client import authenticate

        token = authenticate(host="https://myapp.example.com")
        print(token["access_token"][:20])

    Authenticate to multiple servers:

    .. code-block:: python

        token_a = authenticate(host="https://server-a.example.com")
        token_b = authenticate(host="https://server-b.example.com")
        # Both tokens are cached independently

    Force re authentication:

    .. code-block:: python

        token = authenticate(
            host="https://myapp.example.com",
            force=True,
            timeout=120,
        )

    Custom app name (changes cache directory):

    .. code-block:: python

        token = authenticate(
            host="https://myapp.example.com",
            app_name="my-project",
        )
        # Tokens stored in ~/.cache/my-project/tokens/

    Custom token store:

    .. code-block:: python

        from py_oidc_auth_client import TokenStore, authenticate

        store = TokenStore("~/.config/myapp/tokens")
        token = authenticate(
            host="https://myapp.example.com",
            store=store,
        )
    """
    return asyncio.run(
        authenticate_async(
            host,
            store=store,
            login_route=login_route,
            device_route=device_route,
            token_route=token_route,
            redirect_ports=redirect_ports,
            app_name=app_name,
            force=force,
            timeout=timeout,
        )
    )


async def authenticate_async(
    host: str,
    *,
    login_route: str = "/auth/v2/login",
    token_route: str = "/auth/v2/token",
    device_route: str = "/auth/v2/device",
    redirect_ports: Optional[List[int]] = None,
    store: Optional[TokenStore] = None,
    app_name: str = "py-oidc-auth",
    force: bool = False,
    timeout: Optional[int] = 30,
) -> Token:
    """Async version of :func:`authenticate`.

    Identical behaviour but can be awaited from an existing
    event loop (e.g. inside a Jupyter notebook or an async
    application).

    Parameters
    ----------
    host : str
        Base URL of the application server.
    login_route : str
        Server side route for the authorization code login endpoint.
    token_route : str
        Server side route for the token exchange endpoint.
    device_route : str
        Server side route for the device authorization endpoint.
    redirect_ports : list of int, optional
        Ports to try when starting a local HTTP server for the
        authorization code callback.  The first available port is used.
        Defaults to ``[53100, 53101, 53102, 53103, 53104, 53105]``.
    store : TokenStore or None
        Custom token store.  Shared default when ``None``.
    app_name : str
        Application name for the cache directory.
    force : bool
        Skip the cache and force a fresh login.
    timeout : int or None
        Maximum seconds to wait for user approval.

    Returns
    -------
    Token
        The authentication token.

    Raises
    ------
    AuthError
        If authentication fails.

    Examples
    --------
    .. code-block:: python

        from py_oidc_auth_client import authenticate_async

        token = await authenticate_async(
            host="https://myapp.example.com",
            timeout=120,
        )

    See Also
    --------
    authenticate : Synchronous wrapper for non async code.
    """
    effective_store = store or TokenStore(app_name=app_name)
    # Try device flow first (works headless and interactively)
    device = DeviceFlow(
        host,
        redirect_ports=redirect_ports,
        login_route=login_route,
        device_route=device_route,
        token_route=token_route,
        store=effective_store,
        timeout=timeout,
    )
    try:
        return await device.authenticate(force=force)
    except AuthError as device_error:
        if device_error.status_code == 503:
            # Server does not support device flow, fall back to code flow
            code = CodeFlow(
                host,
                redirect_ports=redirect_ports,
                login_route=login_route,
                device_route=device_route,
                token_route=token_route,
                store=effective_store,
                timeout=timeout,
            )
            return await code.authenticate(force=force)
        raise


__all__ = [
    "AuthError",
    "AuthIdentity",
    "BaseFlow",
    "CodeFlow",
    "Config",
    "DeviceCode",
    "DeviceFlow",
    "Grant",
    "StoreEntry",
    "Token",
    "TokenStore",
    "authenticate",
    "authenticate_async",
    "__version__",
]
