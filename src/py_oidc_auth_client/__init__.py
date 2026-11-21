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

Usually you do not build identities yourself.  Each flow derives its
own from the parameters you pass it, and exposes it read only as
``flow.identity``.  Pass ``scopes`` to request fewer scopes than the
server's default; the token is cached separately from the default
login.  To store a token under a key of your choosing, pass an
explicit ``identity``:

.. code-block:: python

    from py_oidc_auth_client import AuthIdentity, Grant, authenticate

    token = authenticate(host="https://myapp.example.com", scopes="openid email")

    ident = AuthIdentity(
        host="https://myapp.example.com",
        backend="py-oidc-auth",
        grant=Grant.DEVICE_CODE,
        scopes=("openid", "email"),
    )
    token = authenticate(host="https://myapp.example.com", identity=ident)

For finer control over individual flows, see :class:`~flows.DeviceFlow`
and :class:`~flows.CodeFlow`.

Token exchange
~~~~~~~~~~~~~~

:func:`exchange` turns a token into another one (RFC 8693): one for
another audience or with fewer scopes, or one of a trusting peer
server.  By default the subject is your login on the same server:

.. code-block:: python

    from py_oidc_auth_client import exchange

    token = exchange(host="https://myapp.example.com", audience="s3-gateway")

The subject can also be a flow, a cached identity or a token string, and
the exchanging server another one than the subject's:

.. code-block:: python

    from py_oidc_auth_client import exchange
    from py_oidc_auth_client.flows import DeviceFlow

    login = DeviceFlow("https://freva.dkrz.de")
    token = exchange(host="https://freva.example.org", subject=login)

CLI usage
~~~~~~~~~

.. code-block:: bash

    python -m py_oidc_auth_client https://myapp.example.com
    python -m py_oidc_auth_client https://myapp.example.com --timeout 120
    python -m py_oidc_auth_client https://myapp.example.com --scope openid email
    python -m py_oidc_auth_client --list
    python -m py_oidc_auth_client --list --verbose
    python -m py_oidc_auth_client --clear
    python -m py_oidc_auth_client --remove https://myapp.example.com
"""

from __future__ import annotations

import asyncio
from typing import Iterable, List, Optional, Union

from .exceptions import AuthError
from .flows import BaseFlow, CodeFlow, DeviceFlow, ExchangeFlow, Subject
from .identity import AuthIdentity, Grant
from .schema import DeviceCode, Token
from .token_store import StoreEntry, TokenStore
from .types import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_ID,
    TOKEN_TYPE_JWT,
    TOKEN_TYPE_REFRESH,
)
from .utils import Config

__version__ = "2611.0.0"


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
    scopes: Optional[Union[str, Iterable[str]]] = None,
    identity: Optional[AuthIdentity] = None,
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
    scopes : str or iterable of str or None
        Scopes to request instead of the server's default ones.  A
        token with fewer scopes is cached separately, so it never
        stands in for a default login.
    identity : AuthIdentity or None
        Store the token under exactly this identity, and only reuse a
        token cached under it.  Its host must be *host*, its grant an
        interactive one (device code or authorization code; either
        flow may produce the token), and its scopes are requested from
        the server.  Mutually exclusive with *scopes*.

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

    Request only some scopes:

    .. code-block:: python

        token = authenticate(
            host="https://myapp.example.com",
            scopes=["openid", "email"],
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
            scopes=scopes,
            identity=identity,
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
    scopes: Optional[Union[str, Iterable[str]]] = None,
    identity: Optional[AuthIdentity] = None,
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
    scopes : str or iterable of str or None
        Scopes to request instead of the server's default ones.
    identity : AuthIdentity or None
        Exact cache key for the token.  See :func:`authenticate`.

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
        scopes=scopes,
        identity=identity,
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
                scopes=scopes,
                identity=identity,
            )
            return await code.authenticate(force=force)
        raise


def exchange(
    host: str,
    *,
    subject: Optional[Subject] = None,
    audience: Optional[str] = None,
    scopes: Optional[Union[str, Iterable[str]]] = None,
    resource: Optional[str] = None,
    requested_token_type: Optional[str] = None,
    subject_token_type: str = TOKEN_TYPE_ACCESS,
    token_route: str = "/auth/v2/token",
    store: Optional[TokenStore] = None,
    app_name: str = "py-oidc-auth",
    force: bool = False,
    timeout: Optional[int] = 30,
) -> Token:
    """Exchange a token for another one (RFC 8693) and return it.

    The exchanged token is cached.  While it is valid it is returned
    as is; once it expires a fresh subject token is obtained and
    exchanged again, since exchanged tokens usually have no refresh
    token.

    Parameters
    ----------
    host : str
        Base URL of the server that performs the exchange.
    subject : DeviceFlow or CodeFlow or ExchangeFlow or AuthIdentity or str
        Where the subject token comes from: a flow, which is asked for
        a valid token first (and may log in); the identity of a cached
        token; or a token string.  ``None`` uses a device flow login on
        *host*.
    audience : str or None
        Service the new token is for.
    scopes : str or iterable of str or None
        Scopes wanted for the new token.
    resource : str or None
        URI of the service the new token is for.
    requested_token_type : str or None
        RFC 8693 type of the token wanted, e.g.
        :data:`TOKEN_TYPE_ACCESS`.  ``None`` leaves it to the server.
    subject_token_type : str
        RFC 8693 type of the subject token.
    token_route : str
        Server side route of the token endpoint.
    store : TokenStore or None
        Token store for the exchanged token and the subject's token.
    app_name : str
        Application name for the cache directory.  Only used when
        *store* is ``None``.
    force : bool
        Exchange again even if a valid exchanged token is cached.
    timeout : int or None
        HTTP timeout in seconds.

    Returns
    -------
    Token
        The exchanged token.  ``issued_token_type`` says what it is.

    Raises
    ------
    AuthError
        If no subject token can be obtained or the server refuses the
        exchange (``error`` is e.g. ``invalid_target``).

    Examples
    --------
    .. code-block:: python

        from py_oidc_auth_client import exchange

        token = exchange("https://myapp.example.com", audience="s3-gateway")
    """
    return asyncio.run(
        exchange_async(
            host,
            subject=subject,
            audience=audience,
            scopes=scopes,
            resource=resource,
            requested_token_type=requested_token_type,
            subject_token_type=subject_token_type,
            token_route=token_route,
            store=store,
            app_name=app_name,
            force=force,
            timeout=timeout,
        )
    )


async def exchange_async(
    host: str,
    *,
    subject: Optional[Subject] = None,
    audience: Optional[str] = None,
    scopes: Optional[Union[str, Iterable[str]]] = None,
    resource: Optional[str] = None,
    requested_token_type: Optional[str] = None,
    subject_token_type: str = TOKEN_TYPE_ACCESS,
    token_route: str = "/auth/v2/token",
    store: Optional[TokenStore] = None,
    app_name: str = "py-oidc-auth",
    force: bool = False,
    timeout: Optional[int] = 30,
) -> Token:
    """Async version of :func:`exchange`.

    Parameters
    ----------
    host : str
        Base URL of the server that performs the exchange.
    subject : DeviceFlow or CodeFlow or ExchangeFlow or AuthIdentity or str
        Where the subject token comes from.  See :func:`exchange`.
    audience : str or None
        Service the new token is for.
    scopes : str or iterable of str or None
        Scopes wanted for the new token.
    resource : str or None
        URI of the service the new token is for.
    requested_token_type : str or None
        RFC 8693 type of the token wanted.
    subject_token_type : str
        RFC 8693 type of the subject token.
    token_route : str
        Server side route of the token endpoint.
    store : TokenStore or None
        Token store.  See :func:`exchange`.
    app_name : str
        Application name for the cache directory.
    force : bool
        Exchange again even if a valid exchanged token is cached.
    timeout : int or None
        HTTP timeout in seconds.

    Returns
    -------
    Token
        The exchanged token.

    Raises
    ------
    AuthError
        If no subject token can be obtained or the exchange fails.
    """
    flow = ExchangeFlow(
        host,
        subject=subject,
        audience=audience,
        scopes=scopes,
        resource=resource,
        requested_token_type=requested_token_type,
        subject_token_type=subject_token_type,
        token_route=token_route,
        store=store or TokenStore(app_name=app_name),
        timeout=timeout,
    )
    return await flow.authenticate(force=force)


__all__ = [
    "AuthError",
    "AuthIdentity",
    "BaseFlow",
    "CodeFlow",
    "Config",
    "DeviceCode",
    "DeviceFlow",
    "ExchangeFlow",
    "Grant",
    "StoreEntry",
    "Subject",
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_ID",
    "TOKEN_TYPE_JWT",
    "TOKEN_TYPE_REFRESH",
    "Token",
    "TokenStore",
    "authenticate",
    "authenticate_async",
    "exchange",
    "exchange_async",
    "__version__",
]
