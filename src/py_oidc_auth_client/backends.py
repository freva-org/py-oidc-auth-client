"""
Supported auth backends
=======================

A backend encapsulates provider specific OIDC behaviour (endpoint
discovery, request shapes, parameter names) behind the
:class:`ProviderBackend` interface, so that the flows in
:mod:`py_oidc_auth_client.flows` stay provider agnostic.

Currently implemented:

    - PyOIDCAuth: authentication against ``py-oidc-auth`` services.
    - OIDCBackend: any OpenID Connect provider (Keycloak, ...), with the
      endpoints taken from its discovery document.

:func:`make_backend` picks one from ``Config.backend``.
"""

import base64
import logging
import secrets
import time
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, TypeVar, cast

import httpx

from .exceptions import AuthError
from .types import (
    TOKEN_TYPE_ACCESS,
    DeviceAuthorizationResponse,
    JSONResponse,
    OIDCDiscoveryDocument,
    TokenResponse,
)
from .utils import Config, build_url, pkce_pair

logger = logging.getLogger(__name__)

GRANT_TYPE_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


def _unreachable(url: str, error: Exception) -> AuthError:
    """Turn a connection failure into an :class:`AuthError` (502)."""
    return AuthError(f"Cannot reach {url}: {error}", status_code=502)


def _check_device_payload(payload: JSONResponse) -> None:
    """Make sure a device authorization answer has what the flow needs."""
    for k in ("device_code", "user_code", "verification_uri", "expires_in"):
        if k not in payload:
            raise AuthError(f"Device authorization missing '{k}'", status_code=502)


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

    @abstractmethod
    async def exchange_token(
        self,
        *,
        subject_token: str,
        subject_token_type: str = TOKEN_TYPE_ACCESS,
        requested_token_type: Optional[str] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange a token for another one (RFC 8693).

        Parameters
        ----------
        subject_token : str
            The token to exchange, usually an access token.
        subject_token_type : str
            RFC 8693 type of *subject_token*.
        requested_token_type : str or None
            RFC 8693 type of the token wanted.  ``None`` leaves it to
            the server, which normally issues an access token.
        audience : str or None
            Logical name of the service the new token is for.
        scope : str or None
            Space separated scopes wanted for the new token.
        resource : str or None
            URI of the service the new token is for.

        Returns
        -------
        dict
            Raw token response, usually with ``issued_token_type`` and
            without a refresh token.

        Raises
        ------
        AuthError
            If the server refuses the exchange, e.g. ``invalid_target``
            for an audience the subject token may not be exchanged for.
        """

    async def client_credentials(
        self, *, scope: Optional[str] = None
    ) -> TokenResponse:
        """Get a token for the client itself (client credentials grant).

        Only providers that know the client's credentials offer this.

        Parameters
        ----------
        scope : str or None
            Space separated scopes wanted.

        Returns
        -------
        dict
            Raw token response.

        Raises
        ------
        AuthError
            Always for backends without client credentials, with status
            501.
        """
        raise AuthError(
            f"{type(self).__name__} does not support the client credentials "
            "grant; use an OpenID Connect provider directly.",
            detail={"error": "unsupported_grant_type"},
            status_code=501,
        )

    def _client(self) -> httpx.AsyncClient:
        """Return the HTTP client, creating it when needed."""
        if self.session is None or self.session.is_closed:
            self.session = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout or None),
                verify=True,
                follow_redirects=True,
            )
        return self.session

    async def post_form(
        self,
        url: str,
        data: Optional[Mapping[str, Optional[str]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> JSONResponse:
        """POST form encoded data and return the JSON response.

        Parameters
        ----------
        url : str
            Absolute URL to POST to.
        data : dict or None
            Form fields.  Empty values are left out.
        headers : dict or None
            Extra headers, e.g. ``Authorization``.

        Returns
        -------
        dict
            Parsed JSON response body.

        Raises
        ------
        AuthError
            On HTTP >= 400 or unparsable response bodies.
        """
        data = data or {}
        try:
            resp = await self._client().post(
                url,
                data={k: v for (k, v) in data.items() if v},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    **(headers or {}),
                },
            )
        except httpx.TransportError as error:
            raise _unreachable(url, error) from error
        return self._json(url, resp)

    async def get_json(self, url: str) -> JSONResponse:
        """GET *url* and return the JSON response.

        Raises
        ------
        AuthError
            On HTTP >= 400 or unparsable response bodies.
        """
        try:
            resp = await self._client().get(url)
        except httpx.TransportError as error:
            raise _unreachable(url, error) from error
        return self._json(url, resp)

    @staticmethod
    def _json(url: str, resp: httpx.Response) -> JSONResponse:
        """Decode a response, raising :class:`AuthError` for errors."""
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
        _check_device_payload(payload)
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

    async def exchange_token(
        self,
        *,
        subject_token: str,
        subject_token_type: str = TOKEN_TYPE_ACCESS,
        requested_token_type: Optional[str] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange a token at the server's token endpoint (RFC 8693).

        Depending on its configuration the server passes the exchange on
        to its identity provider, or answers with a broker token of its
        own.  The latter also accepts broker tokens of trusted peer
        servers as *subject_token*.
        """
        data = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "requested_token_type": requested_token_type,
            "audience": audience,
            "scope": scope,
            "resource": resource,
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


@dataclass
class OIDCBackend(ProviderBackend):
    """Talk to an OpenID Connect provider (Keycloak, ...) directly.

    The endpoints come from the provider's discovery document, fetched on
    first use from :attr:`Config.discovery_document_url`.  The client is
    ``Config.client_id`` (``app_name`` by default) and authenticates

    * not at all, as a public client: PKCE alone protects the logins;
    * with ``Config.client_secret``, by ``client_secret_basic`` or, if the
      provider only lists that, ``client_secret_post``;
    * with ``Config.server_key``, by ``private_key_jwt`` (RFC 7523): a
      short lived assertion signed with the key (``keys`` extra).

    Both interactive flows use PKCE and the code flow checks ``state``.
    Scopes default to ``Config.scopes``, or ``openid``.

    Parameters
    ----------
    config : Config
        A config with ``backend="oidc"``, e.g. from
        :meth:`Config.from_discovery`.
    """

    #: PKCE verifiers of pending code flow logins, keyed by ``state``.
    _login_verifiers: Dict[str, str] = field(
        default_factory=dict, init=False, repr=False
    )
    #: PKCE verifiers of pending device logins, keyed by device code.
    _device_verifiers: Dict[str, str] = field(
        default_factory=dict, init=False, repr=False
    )
    _discovery: Optional[OIDCDiscoveryDocument] = field(
        default=None, init=False, repr=False
    )

    # -- Discovery -------------------------------------------------------------

    async def discovery(self) -> OIDCDiscoveryDocument:
        """Return the provider's discovery document, fetched once.

        Raises
        ------
        AuthError
            If it cannot be fetched or lacks ``issuer`` or
            ``token_endpoint``.
        """
        if self._discovery is None:
            url = self.config.discovery_document_url
            document = await self.get_json(url)
            for key in ("issuer", "token_endpoint"):
                if not isinstance(document, dict) or not document.get(key):
                    raise AuthError(
                        f"{url} is no OpenID Connect discovery document "
                        f"(no '{key}')",
                        status_code=502,
                    )
            self._discovery = cast(OIDCDiscoveryDocument, document)
        return self._discovery

    async def _endpoint(self, name: str, flow: str) -> str:
        """Look up an endpoint in the discovery document, or raise a 501."""
        document = cast(Dict[str, Any], await self.discovery())
        url = document.get(name)
        if not url:
            raise AuthError(
                f"{document['issuer']} offers no {flow} (no {name} in its "
                "discovery document)",
                detail={"error": "unsupported_grant_type"},
                status_code=501,
            )
        return str(url)

    # -- Client authentication -------------------------------------------------

    def _scope(self, scope: Optional[str]) -> str:
        return scope or " ".join(self.config.scopes) or "openid"

    async def _authenticated(
        self, data: Dict[str, Optional[str]]
    ) -> "tuple[Dict[str, Optional[str]], Dict[str, str]]":
        """Add the client and its credentials to a request."""
        client_id = self.config.effective_client_id
        data = {**data, "client_id": client_id}
        headers: Dict[str, str] = {}
        if self.config.server_key:
            document = await self.discovery()
            data["client_assertion_type"] = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            data["client_assertion"] = self._client_assertion(
                document["token_endpoint"]
            )
        elif self.config.client_secret:
            document = await self.discovery()
            methods = document.get("token_endpoint_auth_methods_supported") or []
            if methods and "client_secret_basic" not in methods:
                data["client_secret"] = self.config.client_secret
            else:
                quote = urllib.parse.quote
                pair = f"{quote(client_id, safe='')}:"
                pair += quote(self.config.client_secret, safe="")
                basic = base64.b64encode(pair.encode()).decode()
                headers["Authorization"] = f"Basic {basic}"
        return data, headers

    def _client_assertion(self, audience: str) -> str:
        """Sign a ``private_key_jwt`` client assertion (RFC 7523)."""
        try:
            import jwt
            from cryptography.hazmat.primitives.asymmetric import (
                ec,
                ed25519,
                rsa,
            )
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
        except ImportError as error:  # pragma: no cover - depends on extras
            raise AuthError(
                "private_key_jwt needs the keys extra: "
                "pip install 'py-oidc-auth-client[keys]'",
                status_code=500,
            ) from error
        path = Path(str(self.config.server_key)).expanduser()
        try:
            key = load_pem_private_key(path.read_bytes(), password=None)
        except (OSError, ValueError, TypeError) as error:
            raise AuthError(
                f"Cannot read the private key {path}: {error}", status_code=500
            ) from error
        now = int(time.time())
        client_id = self.config.effective_client_id
        claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 60,
        }
        headers = {"kid": self.config.key_id} if self.config.key_id else None
        if isinstance(key, rsa.RSAPrivateKey):
            return str(jwt.encode(claims, key, algorithm="RS256", headers=headers))
        if isinstance(key, ec.EllipticCurvePrivateKey):
            bits = {256: "ES256", 384: "ES384", 521: "ES512"}
            algorithm = bits.get(key.curve.key_size, "ES256")
            return str(jwt.encode(claims, key, algorithm=algorithm, headers=headers))
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return str(jwt.encode(claims, key, algorithm="EdDSA", headers=headers))
        raise AuthError(
            f"{path}: use an RSA, EC or Ed25519 key for private_key_jwt.",
            status_code=500,
        )

    async def _token(self, data: Dict[str, Optional[str]]) -> TokenResponse:
        """POST an authenticated request to the token endpoint."""
        document = await self.discovery()
        data, headers = await self._authenticated(data)
        return cast(
            TokenResponse,
            await self.post_form(document["token_endpoint"], data, headers),
        )

    # -- Flows -----------------------------------------------------------------

    async def device_authorization(
        self, *, scope: Optional[str] = None
    ) -> DeviceAuthorizationResponse:
        """Start a device login at the provider's device endpoint.

        Raises
        ------
        AuthError
            With status 501 if the provider has no device endpoint.
        """
        url = await self._endpoint("device_authorization_endpoint", "device flow")
        verifier, challenge = pkce_pair()
        data, headers = await self._authenticated(
            {
                "scope": self._scope(scope),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        payload = await self.post_form(url, data, headers)
        _check_device_payload(payload)
        self._device_verifiers[str(payload["device_code"])] = verifier
        return cast(DeviceAuthorizationResponse, payload)

    async def get_device_token(self, device_code: str) -> TokenResponse:
        """Poll the token endpoint for a device login."""
        token = await self._token(
            {
                "grant_type": GRANT_TYPE_DEVICE_CODE,
                "device_code": device_code,
                "code_verifier": self._device_verifiers.get(device_code),
            }
        )
        self._device_verifiers.pop(device_code, None)
        return token

    async def get_authorization_url(
        self, *, redirect_uri: str, scope: Optional[str] = None
    ) -> str:
        """Build the provider's authorization URL for a code flow login."""
        url = await self._endpoint("authorization_endpoint", "code flow")
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        self._login_verifiers[state] = verifier
        params = {
            "response_type": "code",
            "client_id": self.config.effective_client_id,
            "redirect_uri": redirect_uri,
            "scope": self._scope(scope),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{urllib.parse.urlencode(params)}"

    async def exchange_authorization_code(
        self,
        *,
        redirect_uri: str,
        code: str,
        state: Optional[str] = None,
    ) -> TokenResponse:
        """Redeem an authorization code with its PKCE verifier.

        Raises
        ------
        AuthError
            If *state* belongs to no login started here.
        """
        if not state or state not in self._login_verifiers:
            raise AuthError(
                "The login callback does not belong to this login "
                "(state mismatch); please try again.",
                detail={"error": "invalid_request"},
                status_code=400,
            )
        return await self._token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": self._login_verifiers.pop(state),
            }
        )

    async def refresh_token(self, token: str) -> TokenResponse:
        """Refresh a token at the provider's token endpoint."""
        return await self._token({"grant_type": "refresh_token", "refresh_token": token})

    async def exchange_token(
        self,
        *,
        subject_token: str,
        subject_token_type: str = TOKEN_TYPE_ACCESS,
        requested_token_type: Optional[str] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange a token at the provider (RFC 8693).

        Keycloak (standard token exchange, 26.2+) needs a confidential
        client that is in the subject token's audience.
        """
        return await self._token(
            {
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "subject_token": subject_token,
                "subject_token_type": subject_token_type,
                "requested_token_type": requested_token_type,
                "audience": audience,
                "scope": scope,
                "resource": resource,
            }
        )

    async def client_credentials(
        self, *, scope: Optional[str] = None
    ) -> TokenResponse:
        """Get a token for the client itself, e.g. a service account.

        Needs a confidential client (a secret or a key).
        """
        if not (self.config.client_secret or self.config.server_key):
            raise AuthError(
                "The client credentials grant needs a client secret or a key.",
                detail={"error": "invalid_client"},
                status_code=400,
            )
        return await self._token({"grant_type": "client_credentials", "scope": scope})


def make_backend(config: Config, timeout: Optional[int] = None) -> ProviderBackend:
    """Create the backend ``config.backend`` names.

    Parameters
    ----------
    config : Config
        Connection details; ``backend`` is ``py-oidc-auth`` or ``oidc``.
    timeout : int or None
        HTTP timeout in seconds.

    Returns
    -------
    ProviderBackend
        A :class:`PyOIDCAuth` or an :class:`OIDCBackend`.
    """
    if config.backend == "oidc":
        return OIDCBackend(config, timeout=timeout)
    return PyOIDCAuth(config, timeout=timeout)
