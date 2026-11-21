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

import logging
import secrets
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, TypeVar, cast

import httpx

from .exceptions import AuthError
from .types import DeviceAuthorizationResponse, JSONResponse, TokenResponse
from .utils import Config, build_url, pkce_pair

logger = logging.getLogger(__name__)

GRANT_TYPE_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"

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
    async def device_authorization(
        self, *, scope: Optional[str] = None
    ) -> DeviceAuthorizationResponse:
        """Start a device authorization request (RFC 8628).

        Parameters
        ----------
        scope : str or None
            Space separated scopes to request instead of the default
            ones.  ``None`` requests the default scopes.

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
    async def get_authorization_url(
        self, *, redirect_uri: str, scope: Optional[str] = None
    ) -> str:
        """Build the URL that starts the authorization code flow.

        Parameters
        ----------
        redirect_uri : str
            Local callback URI the provider redirects back to.  The
            flow picks the port at runtime, so this cannot be derived
            from *config*.
        scope : str or None
            Space separated scopes to request instead of the default
            ones.  ``None`` requests the default scopes.

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


@dataclass
class PyOIDCAuth(ProviderBackend):
    """Apply authentication flows tailored around py-oidc-auth servers.

    Authentication against these services doesn't need specification of
    ``client_id``, ``scopes``, ``client_secrets`` or other authentication
    methods as those are set by the server.

    Both interactive flows use PKCE (RFC 7636) with a verifier that never
    leaves the client: the S256 challenge goes to ``/login`` or
    ``/device``, the verifier to the token endpoint.  Servers that
    predate client side PKCE ignore the challenge; for the code flow the
    verifier those servers put into ``state`` is used instead.

    Parameters
    -----------
    config: py_oidc_auth.utils.Config
        The oidc config holding information on who to connect to the
        ``py-oidc-auth`` service.
    """

    #: PKCE verifiers of pending code flow logins, keyed by ``state``.
    _login_verifiers: Dict[str, str] = field(
        default_factory=dict, init=False, repr=False
    )
    #: PKCE verifiers of pending device logins, keyed by device code.
    _device_verifiers: Dict[str, str] = field(
        default_factory=dict, init=False, repr=False
    )

    async def device_authorization(
        self, *, scope: Optional[str] = None
    ) -> DeviceAuthorizationResponse:
        """Start device authorization; return the raw init payload.

        *scope* is sent as ``scope``.  py-oidc-auth servers that do not
        accept a scope for device logins ignore it and grant their
        default scopes.
        """
        verifier, challenge = pkce_pair()
        payload = await self.post_form(
            self._device_authorization_endpoint,
            {
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": scope,
            },
        )
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
        self._device_verifiers[str(payload["device_code"])] = verifier
        return cast(DeviceAuthorizationResponse, payload)

    async def exchange_authorization_code(
        self,
        *,
        redirect_uri: str,
        code: str,
        state: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens.

        The verifier is the one made for *state* by
        :meth:`get_authorization_url`.  A server that ignored the
        client's challenge returns its own ``state`` in the legacy form
        ``<random>|<redirect_uri>|<verifier>``; the verifier is then
        taken from there.

        Raises
        ------
        AuthError
            If a login was started here but *state* matches none of
            them: the callback did not come from that login.
        """
        code_verifier: Optional[str] = None
        if state and state in self._login_verifiers:
            code_verifier = self._login_verifiers.pop(state)
        elif state and "|" in state:
            logger.debug("Server ignored the PKCE challenge, using its verifier")
            code_verifier = state.rpartition("|")[-1]
        elif self._login_verifiers:
            raise AuthError(
                "The login callback does not belong to this login "
                "(state mismatch); please try again.",
                detail={"error": "invalid_request"},
                status_code=400,
            )
        data = {
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        return cast(TokenResponse, await self.post_form(self._token_endpoint, data))

    async def get_authorization_url(
        self, *, redirect_uri: str, scope: Optional[str] = None
    ) -> str:
        """Build the URL used to start authorization code flow."""
        login_url_base = build_url(self.config.host, self.config.login_route)
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        self._login_verifiers[state] = verifier
        params = {
            "redirect_uri": redirect_uri,
            "offline_access": "true",
            "prompt": "consent",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        if scope:
            params["scope"] = scope
        return f"{login_url_base}?{urllib.parse.urlencode(params)}"

    async def get_device_token(self, device_code: str) -> TokenResponse:
        """Query a device token.

        Sends the standard ``device_code`` field and the older
        ``device-code`` name, which older py-oidc-auth servers expect.
        """
        data = {
            "grant_type": GRANT_TYPE_DEVICE_CODE,
            "device_code": device_code,
            "device-code": device_code,
            "code_verifier": self._device_verifiers.get(device_code),
        }
        token = await self.post_form(self._token_endpoint, data)
        self._device_verifiers.pop(device_code, None)
        return cast(TokenResponse, token)

    async def refresh_token(self, token: str) -> TokenResponse:
        """Refresh a bearer token with help of a refresh token.

        Sends the standard ``refresh_token`` field and the older
        ``refresh-token`` name, which older py-oidc-auth servers expect.
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": token,
            "refresh-token": token,
        }
        return cast(TokenResponse, await self.post_form(self._token_endpoint, data))

    # -- Internals -------------------------------------------------------------

    @property
    def _device_authorization_endpoint(self) -> str:
        """Define the device authorization endpoint."""
        return build_url(self.config.host, self.config.device_route)

    @property
    def _token_endpoint(self) -> str:
        """Get the token endpoint of the IDP."""
        return build_url(self.config.host, self.config.token_route)
