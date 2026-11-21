"""
Authentication Flows
====================

OIDC/OAuth 2.0 client side authentication flows.

The module provides three classes arranged in an inheritance hierarchy:

.. code-block:: text

    BaseFlow          (token lifecycle, persistence, refresh)
      |
      +-- DeviceFlow  (OAuth 2.0 Device Authorization Grant)
      +-- CodeFlow    (OAuth 2.0 Authorization Code Grant with PKCE)

All flow classes share a process wide token store via :class:`BaseFlow`
so that repeated calls reuse existing tokens when possible.

Quick start
~~~~~~~~~~~

Most users should use the top level :func:`~py_oidc_auth_client.authenticate`
function which picks the right flow automatically.  The classes in this
module are useful when you need explicit control over the flow.

.. code-block:: python

    from py_oidc_auth_client.flows import DeviceFlow

    flow = DeviceFlow("https://myapp.example.com")
    code = await flow.get_device_code()
    print(f"Open {code['uri']} and enter: {code['user_code']}")
    token = await flow.poll(code["device_code"], code["interval"])
"""

import datetime
import logging
import random
import socket
import time
import urllib.parse
import warnings
import webbrowser
from asyncio import sleep as asleep
from getpass import getuser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
from typing import Any, ClassVar, Iterable, List, Optional, Union

from .backends import PyOIDCAuth
from .exceptions import AuthError
from .identity import (
    INTERACTIVE_GRANTS,
    AuthIdentity,
    Grant,
    normalise_host,
    normalise_scopes,
)
from .schema import DeviceCode, Token
from .token_store import StoreEntry, TokenStore
from .types import TokenResponse
from .utils import (
    Config,
    choose_token_strategy,
    clock,
    pprint,
)

logger = logging.getLogger(__name__)

REDIRECT_URI = "http://localhost:{port}/callback"

_INTERACTIVE_DEVICE_MESSAGE = """Will attempt to open the auth url in your browser.

If this doesn't work, try opening the following url:

{b}{uri}{b_end}

You might have to enter this code manually: {b}{user_code}{b_end}
"""

_NON_INTERACTIVE_DEVICE_MESSAGE = """
Visit the following url to authorise your session:

{b}{uri}{b_end}

You might have to enter this code manually: {b}{user_code}{b_end}
"""


# -----------------------------------------------------------------------
# Local callback server for the authorization code flow
# -----------------------------------------------------------------------


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the ``code`` query parameter."""

    def log_message(self, format: str, *args: object) -> None:
        logger.debug(format, *args)

    def do_GET(self) -> None:  # noqa: N802
        """Handle the OAuth authorization callback."""
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)

        setattr(
            self.server,
            "auth_state",
            params.get("state", [None])[0],
        )

        if "code" in params:
            setattr(
                self.server,
                "auth_code",
                params["code"][0],
            )

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful! You can close this tab.")
            return

        if "error" in params:
            setattr(
                self.server,
                "auth_error",
                params["error"][0],
            )
            setattr(
                self.server,
                "auth_error_description",
                params.get(
                    "error_description",
                    [None],
                )[0],
            )

        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Authorization failed.")


# -----------------------------------------------------------------------
# BaseFlow
# -----------------------------------------------------------------------


class BaseFlow:
    """Shared token lifecycle, caching, and persistence.

    This class is not meant to be instantiated directly.  Use
    :class:`DeviceFlow` or :class:`CodeFlow` instead, or the
    convenience function :func:`~py_oidc_auth_client.authenticate`.

    Tokens are persisted in a :class:`~token_store.TokenStore`, keyed by
    the flow's :attr:`identity`.  Expired entries are evicted
    automatically on every read.

    Without an explicit *identity*, a cached token from either
    interactive grant is reused: a device flow login serves a later
    code flow and the other way round, as long as the scopes fit.  A new
    login is stored under :attr:`identity`.

    Parameters
    ----------
    host : str
        Base URL of the application server.
    config : Config or None
        Full configuration object.  When provided, *host* and all
        keyword arguments are ignored.
    store : TokenStore or None
        Custom token store instance.  A shared default store is used
        when ``None``.
    login_route : str
        Server path for the authorization code login endpoint.
    token_route : str
        Server path for the token exchange endpoint.
    device_route : str
        Server path for the device authorization endpoint.
    redirect_ports : list of int or None
        Ports to try for the local callback server (code flow only).
    timeout : int or None
        HTTP and polling timeout in seconds.
    scopes : str or iterable of str or None
        Scopes to request instead of the server's default ones, as a
        space separated string or a list.  They take part in the cache
        key, so a narrowly scoped token never stands in for a default
        login.
    identity : AuthIdentity or None
        Exact cache key for the token, instead of the one the flow
        derives.  Its host must be the flow's host and its grant an
        interactive one; its scopes are the scopes requested.  Only
        this entry is read and written.  Mutually exclusive with
        *scopes*.

    Raises
    ------
    TypeError
        If both *scopes* and *identity* are given.
    ValueError
        If *identity* belongs to another host or a non interactive
        grant.

    Examples
    --------
    Shared token store across flows:

    .. code-block:: python

        device = DeviceFlow("https://myapp.example.com")
        code   = CodeFlow("https://myapp.example.com")

        token = await device.authenticate()
        assert code.token is not None  # same store, same host

    A narrowly scoped login, cached separately from the default one:

    .. code-block:: python

        flow = CodeFlow("https://myapp.example.com", scopes="openid email")
        token = await flow.authenticate()
        print(flow.identity.label)
    """

    _default_store: ClassVar[Optional[TokenStore]] = None
    #: Grant of the tokens this flow mints.
    grant: ClassVar[Grant] = Grant.DEVICE_CODE

    def __init__(
        self,
        host: str = "",
        config: Optional[Config] = None,
        *,
        store: Optional[TokenStore] = None,
        login_route: str = "/auth/v2/login",
        token_route: str = "/auth/v2/token",
        device_route: str = "/auth/v2/device",
        redirect_ports: Optional[List[int]] = None,
        timeout: Optional[int] = None,
        scopes: Optional[Union[str, Iterable[str]]] = None,
        identity: Optional[AuthIdentity] = None,
    ) -> None:
        config = config or Config(
            host=host,
            login_route=login_route,
            token_route=token_route,
            device_route=device_route,
            redirect_ports=redirect_ports or [53100, 53101, 53102, 53103, 53104, 53105],
        )
        self.provider = PyOIDCAuth(config, timeout=timeout)
        self.store = store or self._get_default_store()
        self._explicit_identity = identity is not None
        self._identity = self._resolve_identity(config.host, scopes, identity)

    @classmethod
    def _get_default_store(cls) -> TokenStore:
        """Return (or create) the shared default :class:`TokenStore`."""
        if cls._default_store is None:
            cls._default_store = TokenStore()
        return cls._default_store

    # -- Identity -------------------------------------------------------

    def _resolve_identity(
        self,
        host: str,
        scopes: Optional[Union[str, Iterable[str]]],
        identity: Optional[AuthIdentity],
    ) -> AuthIdentity:
        """Check a given identity, or derive the flow's own one."""
        if identity is None:
            return AuthIdentity(
                host=host,
                backend="py-oidc-auth",
                grant=self.grant,
                scopes=normalise_scopes(scopes),
            )
        if scopes is not None:
            raise TypeError("Pass either scopes or identity, not both.")
        if identity.host != normalise_host(host):
            raise ValueError(
                f"The identity is for {identity.host}, not for "
                f"{normalise_host(host)}."
            )
        if identity.grant is not None and identity.grant not in INTERACTIVE_GRANTS:
            raise ValueError(
                f"A {type(self).__name__} cannot mint tokens for the "
                f"{identity.grant.display} grant."
            )
        return identity

    @property
    def identity(self) -> AuthIdentity:
        """The cache key new tokens of this flow are stored under.

        Derived from the host, the flow's grant and the requested
        scopes, unless an explicit identity was passed.
        """
        return self._identity

    # -- Token cache ----------------------------------------------------

    def _cached_entry(self) -> Optional[StoreEntry]:
        """Find the best cached entry this flow may use.

        With an explicit identity only that entry counts.  Otherwise
        any interactive entry for the host qualifies whose scopes cover
        the requested ones.  Without requested scopes only default
        logins qualify, plus entries migrated from the old host keyed
        store, which never carried requested scopes.
        """
        if self._explicit_identity:
            return self.store.get_entry(self._identity)
        wanted = self._identity.scopes
        for entry in self.store.find(
            host=self._identity.host,
            backend="py-oidc-auth",
            grants=INTERACTIVE_GRANTS,
            scopes=wanted or None,
        ):
            ident = entry.identity
            if ident.client_id or ident.audience or ident.exchange:
                continue
            if not wanted and ident.scopes and ident.grant is not None:
                continue
            return entry
        return None

    def _refresh_target(self, entry: StoreEntry) -> AuthIdentity:
        """Where a token refreshed from *entry* is stored.

        Under the entry's own identity, so a refresh never duplicates a
        cached login, except for entries migrated from the old host
        keyed store: those move to the flow's identity.
        """
        if entry.identity.grant is None:
            return self._identity
        return entry.identity

    @property
    def token(self) -> Optional[Token]:
        """The cached token this flow would use, or ``None``.

        Reads from the :class:`~token_store.TokenStore`.  Expired
        entries are pruned automatically.

        Returns
        -------
        Token or None
            The cached token, or ``None`` if no valid entry exists.
        """
        entry = self._cached_entry()
        return entry.token if entry else None

    async def _from_cache(self, force: bool = False) -> Optional[Token]:
        """Return a cached token, refreshing it when needed.

        Returns ``None`` when an interactive login is needed: with
        *force*, without a usable entry, or when the refresh fails.
        """
        if force:
            return None
        entry = self._cached_entry()
        if entry is None:
            return None
        strategy = choose_token_strategy(entry.token)
        if strategy == "use_token":
            return entry.token
        if strategy == "refresh_token":
            try:
                raw = await self.provider.refresh_token(
                    entry.token.get("refresh_token", "")
                )
                return self._build_token(raw, self._refresh_target(entry))
            except AuthError:
                logger.info("Refresh failed, falling back to an interactive login")
        return None

    # -- Token persistence ----------------------------------------------

    def _save_token(
        self, token: Token, identity: Optional[AuthIdentity] = None
    ) -> Token:
        """Store the token under *identity*, by default :attr:`identity`.

        Parameters
        ----------
        token : Token
            The token payload to store.
        identity : AuthIdentity or None
            Cache key, :attr:`identity` when ``None``.

        Returns
        -------
        Token
            The same token, for chaining convenience.
        """
        self.store.put(identity or self._identity, token)
        return token

    @property
    def _scope_param(self) -> Optional[str]:
        """The requested scopes as sent to the server, or ``None``."""
        return " ".join(self._identity.scopes) or None

    def _check_granted_scopes(self, token: Token) -> None:
        """Log when the server granted fewer scopes than requested."""
        granted = set(token.get("scope", "").split())
        missing = set(self._identity.scopes) - granted
        if granted and missing:
            logger.warning(
                "The server did not grant the requested scope(s): %s",
                " ".join(sorted(missing)),
            )

    def _build_token(
        self,
        response: TokenResponse,
        identity: Optional[AuthIdentity] = None,
    ) -> Token:
        """Normalise a raw token response into a :class:`Token`.

        Handles the various expiry field names that different OIDC
        providers use (``expires``, ``expires_in``, ``exp``, etc.).
        A response without a refresh token (token exchange, or a
        provider that does not hand one out) gets an empty
        ``refresh_token`` and ``refresh_expires`` of ``0``, so the
        token is never mistaken for a refreshable one.

        Parameters
        ----------
        response : dict
            Raw JSON payload from the token endpoint.
        identity : AuthIdentity or None
            Cache key, :attr:`identity` when ``None``.

        Returns
        -------
        Token
            Normalised token with ``headers`` pre built.
        """
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        access_token = response["access_token"]
        token_type = response.get("token_type", "Bearer")
        expires = int(
            response.get("expires")
            or response.get("exp")
            or response.get("expires_at")
            or now + response.get("expires_in", 180)
        )
        refresh_token = response.get("refresh_token") or ""
        refresh_expires = 0
        if refresh_token:
            refresh_expires = int(
                response.get("refresh_expires")
                or response.get("refresh_exp")
                or response.get("refresh_expires_at")
                or now + response.get("refresh_expires_in", 180)
            )
        token = Token(
            access_token=access_token,
            token_type=token_type,
            expires=expires,
            refresh_token=refresh_token,
            refresh_expires=refresh_expires,
            scope=response.get("scope", ""),
            headers={"Authorization": f"{token_type} {access_token}"},
        )
        return self._save_token(token, identity)

    # -- Token refresh --------------------------------------------------

    async def refresh(self, refresh_token: str) -> Token:
        """Obtain a new access token using a refresh token.

        Parameters
        ----------
        refresh_token : str
            The refresh token from a previous authentication.

        Returns
        -------
        Token
            A fresh token with updated expiry times.

        Raises
        ------
        AuthError
            If the refresh request fails (e.g. token revoked).

        Examples
        --------
        .. code-block:: python

            flow = DeviceFlow("https://myapp.example.com")
            new_token = await flow.refresh(old_token["refresh_token"])
        """
        target = self._identity
        entry = self._cached_entry()
        if entry and entry.token.get("refresh_token") == refresh_token:
            target = self._refresh_target(entry)
        raw = await self.provider.refresh_token(refresh_token)
        return self._build_token(raw, target)

    # -- Legacy ---------------------------------------------------------
    @classmethod
    def reset_instances(cls) -> None:
        """Clear all cached singleton instances.

        .. deprecated:: 2609.0.0
            Flows are no longer cached per host, so there is nothing
            to reset.  This method is a no-op kept for backwards
            compatibility and will be removed in a future release.
            Drop the call; construct a new flow instead.

        Examples
        --------
        .. code-block:: python

            DeviceFlow.reset_instances()  # no-op, remove the call
        """
        warnings.warn(
            "BaseFlow.reset_instances() is a no-op since 2609.0.0: flow "
            "instances are no longer cached per host. It will be removed "
            "in a future release.",
            DeprecationWarning,
            stacklevel=2,
        )  # pragma: no cover


# -----------------------------------------------------------------------
# DeviceFlow
# -----------------------------------------------------------------------


class DeviceFlow(BaseFlow):
    """OAuth 2.0 Device Authorization Grant (RFC 8628).

    Best suited for CLI tools, headless servers, CI jobs, and
    environments where opening a local browser is not possible.  The
    user visits a URL on any device, enters a short code, and the
    client polls until approval.

    Parameters
    ----------
    host : str
        Base URL of the application server.
    config : Config or None
        Full configuration object.  Overrides *host* and keyword
        arguments.
    store : TokenStore or None
        Custom token store.  Shared default when ``None``.
    timeout : int or None
        Maximum seconds to wait for user approval during polling.
    interactive : bool or None
        Whether to show a spinner and attempt to open the browser.
        ``None`` auto detects based on the terminal environment.

    Examples
    --------
    Fully automatic login (opens browser, polls, returns token):

    .. code-block:: python

        from py_oidc_auth_client.flows import DeviceFlow

        flow = DeviceFlow("https://myapp.example.com", timeout=120)
        token = await flow.authenticate()
        print(token["access_token"][:20], "...")

    Step by step control:

    .. code-block:: python

        flow = DeviceFlow("https://myapp.example.com")

        # Step 1: get device code
        code = await flow.get_device_code()
        print(f"Open {code['uri']}")
        print(f"Enter code: {code['user_code']}")

        # Step 2: poll until user approves
        token = await flow.poll(
            device_code=code["device_code"],
            interval=code["interval"],
        )

    Reusing a cached token:

    .. code-block:: python

        flow = DeviceFlow("https://myapp.example.com")
        if flow.token:
            print("Already authenticated!")
        else:
            token = await flow.authenticate()

    See Also
    --------
    CodeFlow : Browser based authorization code flow.
    authenticate : Top level convenience function.
    """

    def __init__(
        self,
        host: str = "",
        config: Optional[Config] = None,
        *,
        store: Optional[TokenStore] = None,
        timeout: Optional[int] = 30,
        interactive: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(host, config, store=store, timeout=timeout, **kwargs)
        self.interactive = interactive

    async def authenticate(
        self,
        *,
        force: bool = False,
        auto_open: bool = True,
    ) -> Token:
        """Run the full device flow and return a token.

        Checks cached tokens first.  When *force* is ``False`` and a
        valid access token exists, it is returned immediately.  When
        only the refresh token is still valid, a refresh is attempted
        before falling back to a full device flow.

        Parameters
        ----------
        force : bool
            Skip the cache and force a new interactive login.
        auto_open : bool
            Attempt to open the verification URL in the default
            browser.

        Returns
        -------
        Token
            The authentication token.

        Raises
        ------
        AuthError
            If the flow fails, times out, or the user denies access.

        Examples
        --------
        .. code-block:: python

            flow = DeviceFlow("https://myapp.example.com")
            token = await flow.authenticate()
        """
        cached = await self._from_cache(force)
        if cached is not None:
            return cached
        return await self._run_device_flow(auto_open=auto_open)

    async def get_device_code(self) -> DeviceCode:
        """Request a new device code from the authorization server.

        Returns
        -------
        DeviceCode
            Contains ``uri``, ``user_code``, ``device_code``, and
            ``interval``.  Display ``uri`` and ``user_code`` to the
            user, then call :meth:`poll` with ``device_code`` and
            ``interval``.

        Raises
        ------
        AuthError
            If the device authorization endpoint is unavailable or
            returns an invalid response.

        Examples
        --------
        .. code-block:: python

            flow = DeviceFlow("https://myapp.example.com")
            code = await flow.get_device_code()
            print(f"Go to: {code['uri']}")
            print(f"Code:  {code['user_code']}")
        """
        init = await self.provider.device_authorization(scope=self._scope_param)
        uri = init.get("verification_uri_complete") or init["verification_uri"]
        return DeviceCode(
            uri=uri,
            user_code=init["user_code"],
            device_code=init["device_code"],
            interval=int(init.get("interval", 5)),
        )

    async def poll(
        self,
        device_code: str,
        interval: int = 5,
    ) -> Token:
        """Poll the token endpoint until the user approves or denies.

        Parameters
        ----------
        device_code : str
            The ``device_code`` obtained from :meth:`get_device_code`.
        interval : int
            Minimum seconds between poll requests.  Use the value
            from :meth:`get_device_code` to respect the provider's
            rate limit.

        Returns
        -------
        Token
            The authentication token after user approval.

        Raises
        ------
        AuthError
            On timeout, denial (``access_denied``), or token expiry.

        Examples
        --------
        .. code-block:: python

            code = await flow.get_device_code()
            # ... show code to user ...
            token = await flow.poll(
                code["device_code"],
                code["interval"],
            )
        """
        response = await self._poll_for_token(
            device_code=device_code,
            base_interval=interval,
        )
        token = self._build_token(response)
        self._check_granted_scopes(token)
        return token

    # -- Internals ------------------------------------------------------

    async def _run_device_flow(
        self,
        *,
        auto_open: bool = True,
    ) -> Token:
        """Run the complete device flow with user prompts."""
        init = await self.provider.device_authorization(scope=self._scope_param)
        uri = init.get("verification_uri_complete") or init["verification_uri"]
        user_code = init["user_code"]

        if auto_open and init.get("verification_uri_complete"):
            try:
                pprint(
                    _INTERACTIVE_DEVICE_MESSAGE,
                    user_code=user_code,
                    uri=uri,
                )
                webbrowser.open(init["verification_uri_complete"])
            except Exception as error:
                logger.warning("Could not auto open browser: %s", error)
        else:
            pprint(
                _NON_INTERACTIVE_DEVICE_MESSAGE,
                user_code=user_code,
                uri=uri,
            )

        raw = await self._poll_for_token(
            device_code=init["device_code"],
            base_interval=int(init.get("interval", 5)),
        )
        token = self._build_token(raw)
        self._check_granted_scopes(token)
        return token

    async def _poll_for_token(
        self,
        device_code: str,
        base_interval: int = 5,
    ) -> TokenResponse:
        """Poll a device token."""
        start = time.monotonic()
        interval = max(1, base_interval)
        with clock(self.provider.timeout, self.interactive):
            while True:
                sleep = interval + random.uniform(-0.2, 0.4)
                if (
                    self.provider.timeout is not None
                    and time.monotonic() - start > self.provider.timeout
                ):
                    raise AuthError(
                        "Login did not complete within the allotted "
                        "time; approve the request in your browser "
                        "and try again."
                    )
                try:
                    return await self.provider.get_device_token(device_code)
                except AuthError as error:
                    err = error.error
                    if err == "authorization_pending":
                        await asleep(sleep)
                    elif err == "slow_down":
                        interval += 5
                        await asleep(sleep)
                    elif err in {"expired_token", "access_denied"}:
                        raise AuthError(
                            f"Device flow failed: {err}",
                            detail=error.detail,
                            status_code=error.status_code,
                        )
                    elif err is None and error.status_code >= 500:
                        # Server or provider briefly unavailable: keep
                        # polling until the timeout.
                        logger.debug("Transient error while polling: %s", error)
                        await asleep(sleep)
                    else:
                        raise


# -----------------------------------------------------------------------
# CodeFlow
# -----------------------------------------------------------------------


class CodeFlow(BaseFlow):
    """OAuth 2.0 Authorization Code Grant with PKCE.

    Opens the provider's login page in a local browser, starts a
    temporary HTTP server to capture the callback, and exchanges
    the authorization code for tokens.  The PKCE verifier is made and
    kept by the client, and a callback whose ``state`` does not match
    the login is refused.

    Best suited for desktop and local development environments where
    a browser is available on the same machine.

    Parameters
    ----------
    host : str
        Base URL of the application server.
    config : Config or None
        Full configuration object.  Overrides *host* and keyword
        arguments.
    store : TokenStore or None
        Custom token store.  Shared default when ``None``.
    timeout : int or None
        Maximum seconds to wait for the user to complete the browser
        login.

    Examples
    --------
    .. code-block:: python

        from py_oidc_auth_client.flows import CodeFlow

        flow = CodeFlow("https://myapp.example.com", timeout=120)
        token = await flow.authenticate()
        print(token["access_token"][:20], "...")

    See Also
    --------
    DeviceFlow : Headless/CLI device authorization flow.
    authenticate : Top level convenience function.
    """

    grant: ClassVar[Grant] = Grant.AUTHORIZATION_CODE

    async def authenticate(
        self,
        *,
        force: bool = False,
    ) -> Token:
        """Run the authorization code flow and return a token.

        Checks cached tokens first.  Falls back to a browser based
        login when no valid tokens are available.

        Parameters
        ----------
        force : bool
            Skip the cache and force a new interactive login.

        Returns
        -------
        Token
            The authentication token.

        Raises
        ------
        AuthError
            If the login times out or the code exchange fails.

        Examples
        --------
        .. code-block:: python

            flow = CodeFlow("https://myapp.example.com")
            token = await flow.authenticate()
        """
        cached = await self._from_cache(force)
        if cached is not None:
            return cached
        return await self._run_code_flow()

    # -- Internals ------------------------------------------------------

    @staticmethod
    def _start_local_server(port: int, event: Event) -> HTTPServer:
        """Start a local HTTP server to capture the callback.

        The worker thread is attached to the returned server as
        ``worker_thread``.  Callers must set *event* and join it before
        calling ``server_close()``: closing the socket while the thread
        is blocked in ``handle_request()`` raises ``ValueError: Invalid
        file descriptor: -1`` in the thread, which surfaces as a
        traceback on the user's terminal whenever a login is aborted.
        """
        server = HTTPServer(("localhost", port), _OAuthCallbackHandler)
        # Poll rather than block forever, so the loop below can notice
        # that *event* was set and exit on its own.
        server.timeout = 0.5

        def handle() -> None:
            logger.info("Waiting for browser callback on port %s ...", port)
            while not event.is_set():
                server.handle_request()
                if getattr(server, "auth_code", None) or getattr(
                    server, "auth_error", None
                ):
                    event.set()

        thread = Thread(target=handle, daemon=True)
        server.worker_thread = thread  # type: ignore[attr-defined]
        thread.start()
        return server

    def _find_free_port(self) -> int:
        """Find a free port from the configured redirect ports."""
        for port in self.provider.config.redirect_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("localhost", port))
                    return port
                except (OSError, PermissionError):
                    pass
        raise OSError("No free ports available for login flow")

    @staticmethod
    async def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
        """Wait until a TCP port starts accepting connections."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                try:
                    if sock.connect_ex((host, port)) == 0:
                        return
                except OSError:
                    pass
            await asleep(0.05)
        raise TimeoutError(f"Port {port} on {host} did not open within {timeout}s.")

    async def _run_code_flow(self) -> Token:
        """Run the full browser based code flow."""
        port = self._find_free_port()
        redirect_uri = REDIRECT_URI.format(port=port)
        login_url = await self.provider.get_authorization_url(
            redirect_uri=redirect_uri,
            scope=self._scope_param,
        )
        pprint("Opening browser for login: {b}{url}{b_end}\n", url=login_url)
        pprint(
            "If you are on a remote host, forward port {b}{port:d}{b_end}:\n"
            "    {b}ssh -L {port:d}:localhost:{port:d} {user}@{host}{b_end}",
            port=port,
            user=getuser(),
            host=socket.gethostname(),
        )

        event = Event()
        server = self._start_local_server(port, event)
        code: Optional[str] = None
        state: Optional[str] = None
        reason = "Login failed."
        try:
            await self._wait_for_port("localhost", port)
            webbrowser.open(login_url)
            success = event.wait(timeout=self.provider.timeout or None)
            if not success:
                raise TimeoutError(
                    f"Login did not complete within {self.provider.timeout}s. "
                    "Possibly headless environment."
                )
            auth_error = getattr(server, "auth_error", None)
            if auth_error:
                description = getattr(
                    server,
                    "auth_error_description",
                    None,
                )
                reason = str(description)
            else:
                code = getattr(server, "auth_code", None)
                state = getattr(server, "auth_state", None)
        except Exception as error:
            logger.warning(
                "Could not open browser automatically. %s "
                "Please open the URL manually.",
                error,
            )
            reason = str(error)
        finally:
            # Stop the worker before the socket goes away, or it wakes up
            # inside handle_request() on a closed file descriptor.
            event.set()
            worker = getattr(server, "worker_thread", None)
            if worker is not None:
                worker.join(timeout=2.0)
            if hasattr(server, "server_close"):
                try:
                    server.server_close()
                except Exception as error:
                    logger.debug("Failed to close server cleanly: %s", error)

        if not code:
            raise AuthError(reason)
        raw = await self.provider.exchange_authorization_code(
            redirect_uri=redirect_uri, code=code, state=state
        )
        token = self._build_token(raw)
        self._check_granted_scopes(token)
        return token
