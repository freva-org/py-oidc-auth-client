"""
Supported auth backends
=======================

A backend encapsulates provider specific OIDC behaviour (endpoint
discovery, request shapes, parameter names) behind the
:class:`ProviderBackend` interface, so that the flows in
:mod:`py_oidc_auth_client.flows` stay provider agnostic.

Currently implemented:

    - PyOIDCAuth: authentication against ``py-oidc-auth`` services.

Support for generic OpenID Connect providers is added on top of the
same interface.
"""

import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping, Optional, TypeVar, cast

import httpx

from .exceptions import AuthError
from .types import DeviceAuthorizationResponse, JSONResponse, TokenResponse
from .utils import Config, build_url

OIDCResponseType = TypeVar(
    "OIDCResponseType",
    TokenResponse,
    DeviceAuthorizationResponse,
)


@dataclass
class ProviderBackend(ABC):
    """Interface for provider specific OIDC behaviour.

    A backend owns everything that differs between identity providers:
    which endpoints exist, how they are located, which parameter names
    they expect, and how their responses are shaped.  The flows in
    :mod:`py_oidc_auth_client.flows` drive the user interaction and the
    token lifecycle and stay provider agnostic by talking only to this
    interface.

    All methods return the provider's raw JSON payload, decoded but
    otherwise untouched.  Normalisation into a :class:`~schema.Token`
    is the flow's job, so a backend never has to know how tokens are
    cached or when they expire.

    Every method is asynchronous, including the ones that perform no
    I/O for py-oidc-auth servers: a generic OIDC backend has to resolve
    its endpoints from a discovery document first, and the interface
    has to accommodate that.

    Parameters
    ----------
    config : Config
        Connection details for the provider.
    session : httpx.AsyncClient or None
        Client reused across requests.  Created on first use when
        ``None`` or when the current one is closed.
    timeout : int or None
        HTTP timeout in seconds.  ``None`` disables the timeout.

    Notes
    -----
    Implementations should raise :class:`~exceptions.AuthError` for
    every provider side failure, with ``detail`` set to the parsed
    error body where one is available.  The flows branch on
    ``detail["error"]`` to distinguish the OAuth error codes defined in
    RFC 8628 (``authorization_pending``, ``slow_down``,
    ``access_denied``, ``expired_token``) from genuine failures, so a
    backend that swallows those codes will break device polling.
    """

    config: Config
    session: Optional[httpx.AsyncClient] = None
    timeout: Optional[int] = None

    @abstractmethod
    async def device_authorization(self) -> DeviceAuthorizationResponse:
        """Start a device authorization request (RFC 8628).

        Returns
        -------
        dict
            The raw initiation payload.  Implementations must
            guarantee ``device_code``, ``user_code``,
            ``verification_uri`` and ``expires_in``, and should pass
            through ``verification_uri_complete`` and ``interval``
            when the provider sends them.  The flow opens the complete
            URI when present and falls back to ``verification_uri``
            plus a manually entered ``user_code`` otherwise; a missing
            ``interval`` defaults to five seconds.

        Raises
        ------
        AuthError
            If the request fails or the payload lacks a required key.
        """

    @abstractmethod
    async def get_authorization_url(self, *, redirect_uri: str) -> str:
        """Build the URL that starts the authorization code flow.

        Parameters
        ----------
        redirect_uri : str
            Local callback URI the provider redirects back to.  The
            flow picks the port at runtime, so this cannot be derived
            from *config*.

        Returns
        -------
        str
            Absolute URL to open in the user's browser.

        Notes
        -----
        Whatever per attempt state the backend needs in order to
        complete :meth:`exchange_authorization_code` — a PKCE code
        verifier, a nonce, a CSRF token — has to survive the round trip
        through the browser, either inside the ``state`` parameter or
        on the backend instance.  The flow itself keeps no state
        between the two calls beyond what the callback hands back.
        """

    @abstractmethod
    async def get_device_token(self, device_code: str) -> TokenResponse:
        """Attempt to redeem a device code for tokens.

        Called repeatedly by the polling loop, so this must stay a
        single request without retries or sleeps of its own.

        Parameters
        ----------
        device_code : str
            The ``device_code`` from :meth:`device_authorization`.

        Returns
        -------
        dict
            Raw token response once the user has approved the request.

        Raises
        ------
        AuthError
            While approval is still pending, and on denial or expiry.
            The distinction is carried in ``detail["error"]``; see the
            class notes.
        """

    @abstractmethod
    async def exchange_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens.

        Parameters
        ----------
        code : str
            Authorization code captured on the callback.
        redirect_uri : str
            The same URI passed to :meth:`get_authorization_url`.
            Providers reject the exchange when the two differ.
        state : str or None
            Opaque state returned on the callback, or ``None`` when
            the provider sent none.

        Returns
        -------
        dict
            Raw token response.

        Raises
        ------
        AuthError
            If the code is invalid, already used, or expired, or if
            the returned state fails the backend's own validation.
        """

    @abstractmethod
    async def refresh_token(self, token: str) -> TokenResponse:
        """Obtain a new bearer token from a refresh token.

        Parameters
        ----------
        token : str
            The refresh token from a previous authentication.

        Returns
        -------
        dict
            Raw token response.  Providers that rotate refresh tokens
            return a new ``refresh_token`` here, which the flow
            persists in place of the old one.

        Raises
        ------
        AuthError
            If the refresh token is expired, revoked or unknown.  The
            flows treat this as recoverable and fall back to a full
            interactive login.
        """

    async def post_form(
        self,
        url: str,
        data: Optional[Mapping[str, Optional[str]]] = None,
    ) -> JSONResponse:
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
        if self.session is None or self.session.is_closed:
            self.session = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout or None),
                verify=True,
                follow_redirects=True,
            )
        data = data or {}
        resp = await self.session.post(
            url,
            data={k: v for (k, v) in data.items() if v},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "close",
            },
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
            return cast(JSONResponse, resp.json())
        except Exception as error:
            raise AuthError(f"Invalid JSON from {url}: {error}")


class PyOIDCAuth(ProviderBackend):
    """Apply authentication flows tailored around py-oidc-auth servers.

    Authentication against these services doesn't need specification of
    ``client_id``, ``scopes``, ``client_secrets`` or other authentication
    methods as those are set by the server.

    Parameters
    -----------
    config: py_oidc_auth.utils.Config
        The oidc config holding information on who to connect to the
        ``py-oidc-auth`` service.
    """

    async def device_authorization(self) -> DeviceAuthorizationResponse:
        """Start device authorization; return the raw init payload."""
        payload = await self.post_form(self._device_authorization_endpoint)
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
        return cast(DeviceAuthorizationResponse, payload)

    async def exchange_authorization_code(
        self,
        *,
        redirect_uri: str,
        code: str,
        state: Optional[str] = None,
    ) -> TokenResponse:
        """Definitions of supported authentication backends.

        A backend encapsulates provider specific OIDC behaviour (endpoint
        discovery, request shapes, parameter names) behind the
        :class:`ProviderBackend` interface, so that the flows in
        :mod:`py_oidc_auth_client.flows` stay provider agnostic.

        Currently implemented:

            - PyOIDCAuth: authentication against ``py-oidc-auth`` services.

        Support for generic OpenID Connect providers is added on top of the
        same interface.
        """
        code_verifier: Optional[str] = None
        if state:
            code_verifier = state.rpartition("|")[-1]
        data = {
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        return cast(TokenResponse, await self.post_form(self._token_endpoint, data))

    async def get_authorization_url(self, *, redirect_uri: str) -> str:
        """Build the URL used to start authorization code flow."""
        login_url_base = build_url(self.config.host, self.config.login_route)
        params = {
            "redirect_uri": redirect_uri,
            "offline_access": "true",
            "prompt": "consent",
        }
        return f"{login_url_base}?{urllib.parse.urlencode(params)}"

    async def get_device_token(self, device_code: str) -> TokenResponse:
        """Query a device token."""
        return cast(
            TokenResponse,
            await self.post_form(
                self._token_endpoint, data={"device-code": device_code}
            ),
        )

    async def refresh_token(self, token: str) -> TokenResponse:
        """Refresh a bearer token with help of a refresh token."""
        return cast(
            TokenResponse,
            await self.post_form(
                self._token_endpoint,
                data={"refresh-token": token},
            ),
        )

    # -- Internals -------------------------------------------------------------

    @property
    def _device_authorization_endpoint(self) -> str:
        """Define the device authorization endpoint."""
        return build_url(self.config.host, self.config.device_route)

    @property
    def _token_endpoint(self) -> str:
        """Get the token endpoint of the IDP."""
        return build_url(self.config.host, self.config.token_route)
