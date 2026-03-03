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

All flow classes share a process wide token cache via :class:`BaseFlow`
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
import webbrowser
from asyncio import sleep as asleep
from getpass import getuser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
from typing import Any, ClassVar, Dict, List, Optional, cast

import httpx
import rich.console

from .exceptions import AuthError
from .schema import DeviceCode, Token
from .token_store import TokenStore
from .utils import (
    Config,
    _clock,
    build_url,
    choose_token_strategy,
    is_interactive_shell,
)

logger = logging.getLogger(__name__)

REDIRECT_URI = "http://localhost:{port}/callback"

_BROWSER_MESSAGE = """Will attempt to open the auth url in your browser.

If this doesn't work, try opening the following url:

{b}{uri}{b_end}

You might have to enter this code manually: {b}{user_code}{b_end}
"""

_NON_INTERACTIVE_MESSAGE = """
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
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        if "code" in params:
            setattr(self.server, "auth_code", params["code"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful! You can close this tab.")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Authorization code not found.")


# -----------------------------------------------------------------------
# BaseFlow
# -----------------------------------------------------------------------


class BaseFlow:
    """Shared token lifecycle, caching, and persistence.

    This class is not meant to be instantiated directly.  Use
    :class:`DeviceFlow` or :class:`CodeFlow` instead, or the
    convenience function :func:`~py_oidc_auth_client.authenticate`.

    Instances are singletons **per host**: calling
    ``DeviceFlow("https://a.example.com")`` twice returns the same
    object, but ``DeviceFlow("https://b.example.com")`` creates a
    separate instance.

    Tokens are persisted in a per host JSON store
    (:class:`~token_store.TokenStore`).  Expired entries are evicted
    automatically on every read.

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

    Notes
    -----
    The per host singleton pattern ensures that only one instance per
    concrete subclass **and** host exists.  Token state is shared
    between ``DeviceFlow`` and ``CodeFlow`` for the same host via
    the :class:`~token_store.TokenStore`.

    Examples
    --------
    Per host singletons:

    .. code-block:: python

        a = DeviceFlow("https://host-a.example.com")
        b = DeviceFlow("https://host-a.example.com")
        c = DeviceFlow("https://host-b.example.com")

        assert a is b       # same host -> same instance
        assert a is not c   # different host -> different instance

    Shared token cache across flows:

    .. code-block:: python

        device = DeviceFlow("https://myapp.example.com")
        code   = CodeFlow("https://myapp.example.com")

        token = await device.authenticate()
        assert code.token is not None  # same store, same host
    """

    _instances: ClassVar[Dict[str, "BaseFlow"]] = {}
    _default_store: ClassVar[Optional[TokenStore]] = None

    def __new__(
        cls, host: str = "", config: Optional[Config] = None, **kwargs: Any
    ) -> "BaseFlow":
        from .token_store import _normalise_host

        effective_host = (config.host if config else host) or ""
        key = f"{cls.__name__}::{_normalise_host(effective_host)}"
        if key not in cls._instances:
            instance = super().__new__(cls)
            cls._instances[key] = instance
        return cls._instances[key]

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
        timeout: Optional[int] = 30,
    ) -> None:
        if getattr(self, "_initialized", False):
            return
        self.config = config or Config(
            host=host,
            login_route=login_route,
            token_route=token_route,
            device_route=device_route,
            redirect_ports=redirect_ports
            or [53100, 53101, 53102, 53103, 53104, 53105],
        )
        self.timeout = timeout
        self.store = store or self._get_default_store()
        self._session: Optional[httpx.AsyncClient] = None
        self._initialized = True

    @classmethod
    def _get_default_store(cls) -> TokenStore:
        """Return (or create) the shared default :class:`TokenStore`."""
        if cls._default_store is None:
            cls._default_store = TokenStore()
        return cls._default_store

    @classmethod
    def reset_instances(cls) -> None:
        """Clear all cached singleton instances.

        Primarily useful in tests to ensure a clean state.

        Examples
        --------
        .. code-block:: python

            DeviceFlow.reset_instances()
        """
        cls._instances.clear()

    @property
    def session(self) -> httpx.AsyncClient:
        """Lazy ``httpx.AsyncClient`` shared across all requests."""
        if self._session is None or self._session.is_closed:
            self._session = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout or 600),
                verify=True,
                follow_redirects=True,
            )
        return self._session

    # -- Token cache (per host, via store) ------------------------------

    @property
    def token(self) -> Optional[Token]:
        """The cached token for this host, or ``None``.

        Reads from the :class:`~token_store.TokenStore`.  Expired
        entries are pruned automatically.

        Returns
        -------
        Token or None
            The cached token, or ``None`` if no valid entry exists.
        """
        return self.store.get(self.config.host)

    # -- Token persistence ----------------------------------------------

    def _save_token(self, token: Token) -> Token:
        """Store the token in the per host cache.

        Parameters
        ----------
        token : Token
            The token payload to store.

        Returns
        -------
        Token
            The same token, for chaining convenience.
        """
        self.store.put(self.config.host, token)
        return token

    def _build_token(
        self,
        response: Dict[str, Any],
    ) -> Token:
        """Normalise a raw token response into a :class:`Token`.

        Handles the various expiry field names that different OIDC
        providers use (``expires``, ``expires_in``, ``exp``, etc.).

        Parameters
        ----------
        response : dict
            Raw JSON payload from the token endpoint.

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
            refresh_token=response.get("refresh_token", ""),
            refresh_expires=refresh_expires,
            scope=response.get("scope", ""),
            headers={"Authorization": f"{token_type} {access_token}"},
        )
        return self._save_token(token)

    # -- Shared HTTP helper ---------------------------------------------

    async def _post_form(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """POST form encoded data and return the JSON response.

        Parameters
        ----------
        url : str
            Absolute URL to POST to.
        data : dict or None
            Form fields.

        Returns
        -------
        dict
            Parsed JSON response body.

        Raises
        ------
        AuthError
            On HTTP >= 400 or unparsable response bodies.
        """
        resp = await self.session.post(
            url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "close",
            },
            timeout=30,
        )
        if resp.status_code >= 400:
            try:
                payload = resp.json()
            except Exception:
                payload = {
                    "error": "http_error",
                    "error_description": resp.text[:300],
                }
            raise AuthError(
                f"{url} -> {resp.status_code}",
                detail=payload,
                status_code=resp.status_code,
            )
        try:
            return cast(Dict[str, Any], resp.json())
        except Exception as error:
            raise AuthError(f"Invalid JSON from {url}: {error}")

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
        url = build_url(self.config.host, self.config.token_route)
        response = await self._post_form(
            url, data={"refresh-token": refresh_token}
        )
        return self._build_token(response)

    # -- Strategy -------------------------------------------------------

    def _get_strategy(self, force: bool = False) -> str:
        """Choose the authentication strategy.

        Parameters
        ----------
        force : bool
            When ``True``, always trigger a fresh interactive login.

        Returns
        -------
        str
            One of ``"use_token"``, ``"refresh_token"``,
            ``"interactive_auth"``, or ``"fail"``.
        """
        if force:
            return "interactive_auth"
        return choose_token_strategy(self.token)


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
        timeout: Optional[int] = 600,
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
        strategy = self._get_strategy(force=force)
        if strategy == "use_token" and self.token:
            return self.token
        if strategy == "refresh_token" and self.token:
            try:
                return await self.refresh(self.token["refresh_token"])
            except AuthError:
                logger.info("Refresh failed, falling back to device flow")

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
        init = await self._authorize()
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
        return self._build_token(response)

    # -- Internals ------------------------------------------------------

    async def _authorize(self) -> Dict[str, Any]:
        """Start device authorization; return the raw init payload."""
        url = build_url(self.config.host, self.config.device_route)
        payload = await self._post_form(url)
        for k in (
            "device_code",
            "user_code",
            "verification_uri",
            "expires_in",
        ):
            if k not in payload:
                raise AuthError(
                    f"Device authorization missing '{k}'",
                    status_code=502,
                )
        return payload

    async def _poll_for_token(
        self,
        *,
        device_code: str,
        base_interval: int,
    ) -> Dict[str, Any]:
        """Poll until approved, denied, or expired."""
        url = build_url(self.config.host, self.config.token_route)
        start = time.monotonic()
        interval = max(1, base_interval)
        with _clock(self.timeout, self.interactive):
            while True:
                sleep = interval + random.uniform(-0.2, 0.4)
                if (
                    self.timeout is not None
                    and time.monotonic() - start > self.timeout
                ):
                    raise AuthError(
                        "Login did not complete within the allotted "
                        "time; approve the request in your browser "
                        "and try again."
                    )
                data = {"device-code": device_code}
                try:
                    return await self._post_form(url, data)
                except AuthError as error:
                    err = (
                        error.detail.get("error")
                        if isinstance(error.detail, dict)
                        else None
                    )
                    if err is None or "authorization_pending" in err:
                        await asleep(sleep)
                    elif "slow_down" in err:
                        interval += 5
                        await asleep(sleep)
                    elif "expired_token" in err or "access_denied" in err:
                        raise AuthError(f"Device flow failed: {err}")
                    else:
                        raise  # pragma: no cover

    async def _run_device_flow(
        self,
        *,
        auto_open: bool = True,
    ) -> Token:
        """Run the complete device flow with user prompts."""
        init = await self._authorize()
        uri = init.get("verification_uri_complete") or init["verification_uri"]
        user_code = init["user_code"]

        console = rich.console.Console(
            force_terminal=is_interactive_shell(), stderr=True
        )
        pprint = console.print if console.is_terminal else print
        b, b_end = ("[b]", "[/b]") if console.is_terminal else ("", "")

        if auto_open and init.get("verification_uri_complete"):
            try:
                pprint(
                    _BROWSER_MESSAGE.format(
                        user_code=user_code,
                        uri=uri,
                        b=b,
                        b_end=b_end,
                    )
                )
                webbrowser.open(init["verification_uri_complete"])
            except Exception as error:
                logger.warning("Could not auto open browser: %s", error)
        else:
            pprint(
                _NON_INTERACTIVE_MESSAGE.format(
                    user_code=user_code,
                    uri=uri,
                    b=b,
                    b_end=b_end,
                )
            )

        raw = await self._poll_for_token(
            device_code=init["device_code"],
            base_interval=int(init.get("interval", 5)),
        )
        return self._build_token(raw)


# -----------------------------------------------------------------------
# CodeFlow
# -----------------------------------------------------------------------


class CodeFlow(BaseFlow):
    """OAuth 2.0 Authorization Code Grant with PKCE.

    Opens the provider's login page in a local browser, starts a
    temporary HTTP server to capture the callback, and exchanges
    the authorization code for tokens.

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
        strategy = self._get_strategy(force=force)
        if strategy == "use_token" and self.token:
            return self.token
        if strategy == "refresh_token" and self.token:
            try:
                return await self.refresh(self.token["refresh_token"])
            except AuthError:
                logger.info("Refresh failed, falling back to code flow")

        return await self._run_code_flow()

    # -- Internals ------------------------------------------------------

    @staticmethod
    def _start_local_server(port: int, event: Event) -> HTTPServer:
        """Start a local HTTP server to capture the callback."""
        server = HTTPServer(("localhost", port), _OAuthCallbackHandler)

        def handle() -> None:
            logger.info("Waiting for browser callback on port %s ...", port)
            while not event.is_set():
                server.handle_request()
                if getattr(server, "auth_code", None):
                    event.set()

        thread = Thread(target=handle, daemon=True)
        thread.start()
        return server

    def _find_free_port(self) -> int:
        """Find a free port from the configured redirect ports."""
        for port in self.config.redirect_ports:
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
        raise TimeoutError(
            f"Port {port} on {host} did not open within {timeout}s."
        )

    async def _run_code_flow(self) -> Token:
        """Run the full browser based code flow."""
        login_url_base = build_url(self.config.host, self.config.login_route)
        token_url = build_url(self.config.host, self.config.token_route)
        port = self._find_free_port()
        redirect_uri = REDIRECT_URI.format(port=port)
        params = {
            "redirect_uri": redirect_uri,
            "offline_access": "true",
            "prompt": "consent",
        }
        login_url = f"{login_url_base}?{urllib.parse.urlencode(params)}"

        logger.info("Opening browser for login:\n%s", login_url)
        logger.info(
            "If you are on a remote host, forward port %d:\n"
            "    ssh -L %d:localhost:%d %s@%s",
            port,
            port,
            port,
            getuser(),
            socket.gethostname(),
        )

        event = Event()
        server = self._start_local_server(port, event)
        code: Optional[str] = None
        reason = "Login failed."
        try:
            await self._wait_for_port("localhost", port)
            webbrowser.open(login_url)
            success = event.wait(timeout=self.timeout or None)
            if not success:
                raise TimeoutError(
                    f"Login did not complete within {self.timeout}s. "
                    "Possibly headless environment."
                )
            code = getattr(server, "auth_code", None)
        except Exception as error:
            logger.warning(
                "Could not open browser automatically. %s "
                "Please open the URL manually.",
                error,
            )
            reason = str(error)
        finally:
            if hasattr(server, "server_close"):
                try:
                    server.server_close()
                except Exception as error:
                    logger.debug("Failed to close server cleanly: %s", error)

        if not code:
            raise AuthError(reason)

        data = {
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        raw = await self._post_form(token_url, data)
        return self._build_token(raw)
