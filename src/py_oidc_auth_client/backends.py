"""Definitions of supported authentication backends.

Currently supported definitions are:

    - OIDCAuth: For authentication flows using generic OpenID Connect Servers.
    - PyOIDCAuth: For authentication against ``py-oidc-auth`` services.

"""

import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, cast

import httpx

from .exceptions import AuthError
from .utils import Config, build_url


@dataclass
class ProviderBackend(ABC):
    """Base class providing an interface for making OIDC connections."""

    config: Config
    session: Optional[httpx.AsyncClient] = None
    timeout: Optional[int] = None

    @abstractmethod
    async def device_authorization(self) -> Dict[str, Any]:
        """Start device authorization; return the raw init payload."""

    @abstractmethod
    async def get_authorization_url(self, *, redirect_uri: str) -> str:
        """Build the URL used to start authorization code flow."""

    @abstractmethod
    async def get_device_token(self, device_code: str) -> Dict[str, Any]:
        """Query a device token."""

    @abstractmethod
    async def exchange_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange an authorization code for tokens."""

    @abstractmethod
    async def refresh_token(self, token: str) -> Dict[str, Any]:
        """Refresh a brearer token with help of a refresh token."""

    async def post_form(
        self,
        url: str,
        data: Optional[Mapping[str, Optional[str]]] = None,
    ) -> Dict[str, Any]:
        """POST form encoded data and return the JSON response.

        Parameters
        ----------
        url : str
            Absolute URL to POST to.
        session: Optional[httpx.AsyncClient]
            httpx Async Client
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
            return cast(Dict[str, Any], resp.json())
        except Exception as error:
            raise AuthError(f"Invalid JSON from {url}: {error}")


class PyOIDCAuth(ProviderBackend):
    """Apply authentication flows tailore around py-oidc-auth servers.

    Authentication against these services doesn't need specification of
    ``client_id``, ``scopes``, ``client_secrets`` or other authentication
    methods as those are set by the server.

    Parameters
    -----------
    config: py_oidc_auth.utils.Config
        The oidc config holding information on who to connect to the
        ``py-oidc-auth`` service.
    """

    async def device_authorization(self) -> Dict[str, Any]:
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
        return payload

    async def exchange_authorization_code(
        self,
        *,
        redirect_uri: str,
        code: str,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build the URL used to start authorization code flow."""
        code_verifier: Optional[str] = None
        if state:
            code_verifier = state.rpartition("|")[-1]
        data = {
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        return await self.post_form(self._token_endpoint, data)

    async def get_authorization_url(self, *, redirect_uri: str) -> str:
        """Build the URL used to start authorization code flow."""
        login_url_base = build_url(self.config.host, self.config.login_route)
        params = {
            "redirect_uri": redirect_uri,
            "offline_access": "true",
            "prompt": "consent",
        }
        return f"{login_url_base}?{urllib.parse.urlencode(params)}"

    async def get_device_token(self, device_code: str) -> Dict[str, Any]:
        """Query a device token."""
        return await self.post_form(
            self._token_endpoint, data={"device-code": device_code}
        )

    async def refresh_token(self, token: str) -> Dict[str, Any]:
        """Refresh a brearer token with help of a refresh token."""
        return await self.post_form(
            self._token_endpoint,
            data={"refresh-token": token},
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
