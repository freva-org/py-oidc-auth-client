"""A small fake OpenID Connect provider (Keycloak-like) for the tests.

Mounted on the test server under ``/idp/realms/test``.  The test server
runs in a thread of the test process, so tests reach :data:`IDP` directly
to configure the provider and inspect what it was sent.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

PREFIX = "/idp/realms/test"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


@dataclass
class Client:
    """A registered client: public, with a secret, or with a public key."""

    secret: Optional[str] = None
    public_key: Optional[Any] = None

    @property
    def confidential(self) -> bool:
        return bool(self.secret or self.public_key)


@dataclass
class FakeIdP:
    """State of the fake provider."""

    secret: str = ""
    clients: Dict[str, Client] = field(default_factory=dict)
    auth_methods: Optional[List[str]] = None
    device_enabled: bool = True
    codes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    devices: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    refresh_tokens: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    requests: List[Dict[str, Any]] = field(default_factory=list)
    discovery_hits: int = 0

    def reset(self) -> None:
        """Back to the default clients and settings."""
        self.clients = {
            "public-cli": Client(),
            "conf": Client(secret="s3:cr/et x"),
        }
        self.auth_methods = None
        self.device_enabled = True
        self.codes.clear()
        self.devices.clear()
        self.refresh_tokens.clear()
        self.requests.clear()
        self.discovery_hits = 0


IDP = FakeIdP()
IDP.reset()


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _error(code: str, status: int = 400, description: str = "") -> JSONResponse:
    body = {"error": code}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status)


def _issuer(request: Request) -> str:
    url = str(request.url)
    return url[: url.index(PREFIX) + len(PREFIX)]


def _tokens(client_id: str, sub: str, scope: str, refresh: bool = True) -> dict:
    now = int(time.time())
    access = jwt.encode(
        {"sub": sub, "azp": client_id, "scope": scope, "iat": now, "exp": now + 300,
         "jti": uuid.uuid4().hex},
        IDP.secret,
    )
    body: Dict[str, Any] = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": scope,
    }
    if refresh:
        token = secrets.token_urlsafe(16)
        IDP.refresh_tokens[token] = {"client_id": client_id, "sub": sub, "scope": scope}
        body["refresh_token"] = token
        body["refresh_expires_in"] = 1800
    return body


def _authenticate_client(request: Request, form: Dict[str, str]) -> Optional[str]:
    """Return the authenticated client id, or None."""
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        decoded = base64.b64decode(header[6:]).decode()
        raw_id, _, raw_secret = decoded.partition(":")
        client_id = urllib.parse.unquote(raw_id)
        client = IDP.clients.get(client_id)
        if client and client.secret == urllib.parse.unquote(raw_secret):
            return client_id
        return None
    client_id = form.get("client_id", "")
    client = IDP.clients.get(client_id)
    if client is None:
        return None
    if "client_secret" in form:
        return client_id if client.secret == form["client_secret"] else None
    if "client_assertion" in form:
        if client.public_key is None:
            return None
        try:
            claims = jwt.decode(
                form["client_assertion"],
                client.public_key,
                algorithms=["RS256", "ES256", "ES384", "ES512", "EdDSA"],
                audience=f"{_issuer(request)}/protocol/openid-connect/token",
            )
        except jwt.PyJWTError:
            return None
        if claims.get("iss") == claims.get("sub") == client_id:
            return client_id
        return None
    return None if client.confidential else client_id


def build_router() -> APIRouter:
    """The provider's routes."""
    router = APIRouter()

    @router.get("/.well-known/openid-configuration")
    async def discovery(request: Request) -> JSONResponse:
        IDP.discovery_hits += 1
        issuer = _issuer(request)
        document: Dict[str, Any] = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{issuer}/protocol/openid-connect/token",
            "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
        }
        if IDP.device_enabled:
            document["device_authorization_endpoint"] = (
                f"{issuer}/protocol/openid-connect/auth/device"
            )
        if IDP.auth_methods is not None:
            document["token_endpoint_auth_methods_supported"] = IDP.auth_methods
        return JSONResponse(document)

    @router.get("/protocol/openid-connect/auth")
    async def authorize(request: Request) -> Any:
        params = request.query_params
        if params.get("client_id") not in IDP.clients:
            return _error("invalid_client")
        if params.get("response_type") != "code":
            return _error("unsupported_response_type")
        if params.get("code_challenge_method") != "S256":
            return _error("invalid_request", description="PKCE required")
        code = secrets.token_urlsafe(12)
        IDP.codes[code] = {
            "client_id": params["client_id"],
            "challenge": params["code_challenge"],
            "redirect_uri": params["redirect_uri"],
            "scope": params.get("scope", ""),
        }
        query = urllib.parse.urlencode({"code": code, "state": params.get("state", "")})
        return RedirectResponse(f"{params['redirect_uri']}?{query}", status_code=302)

    @router.post("/protocol/openid-connect/auth/device")
    async def device(request: Request) -> JSONResponse:
        form = dict(await request.form())
        client_id = _authenticate_client(request, form)
        if client_id is None:
            return _error("invalid_client", 401)
        device_code = secrets.token_urlsafe(12)
        IDP.devices[device_code] = {
            "client_id": client_id,
            "challenge": form.get("code_challenge"),
            "scope": form.get("scope", ""),
            "pending": 1,
        }
        issuer = _issuer(request)
        return JSONResponse(
            {
                "device_code": device_code,
                "user_code": "ABCD-EFGH",
                "verification_uri": f"{issuer}/device",
                "verification_uri_complete": f"{issuer}/device?user_code=ABCD-EFGH",
                "expires_in": 600,
                "interval": 0,
            }
        )

    @router.post("/protocol/openid-connect/token")
    async def token(request: Request) -> JSONResponse:
        form = dict(await request.form())
        IDP.requests.append(
            {"form": form, "authorization": request.headers.get("authorization")}
        )
        client_id = _authenticate_client(request, form)
        if client_id is None:
            return _error("invalid_client", 401)
        grant = form.get("grant_type")
        if grant == "authorization_code":
            entry = IDP.codes.pop(form.get("code", ""), None)
            if (
                entry is None
                or entry["client_id"] != client_id
                or entry["redirect_uri"] != form.get("redirect_uri")
                or _s256(form.get("code_verifier", "")) != entry["challenge"]
            ):
                return _error("invalid_grant")
            return JSONResponse(_tokens(client_id, "alice", entry["scope"]))
        if grant == DEVICE_CODE:
            entry = IDP.devices.get(form.get("device_code", ""))
            if entry is None or entry["client_id"] != client_id:
                return _error("invalid_grant")
            if _s256(form.get("code_verifier", "")) != entry["challenge"]:
                return _error("invalid_grant", description="PKCE")
            if entry["pending"] > 0:
                entry["pending"] -= 1
                return _error("authorization_pending")
            IDP.devices.pop(form["device_code"])
            return JSONResponse(_tokens(client_id, "alice", entry["scope"]))
        if grant == "refresh_token":
            entry = IDP.refresh_tokens.pop(form.get("refresh_token", ""), None)
            if entry is None or entry["client_id"] != client_id:
                return _error("invalid_grant")
            return JSONResponse(_tokens(client_id, entry["sub"], entry["scope"]))
        if grant == "client_credentials":
            if not IDP.clients[client_id].confidential:
                return _error("unauthorized_client")
            scope = form.get("scope", "")
            return JSONResponse(
                _tokens(client_id, f"service-account-{client_id}", scope, refresh=False)
            )
        if grant == TOKEN_EXCHANGE:
            if not IDP.clients[client_id].confidential:
                return _error("unauthorized_client")
            try:
                claims = jwt.decode(
                    form.get("subject_token", ""), IDP.secret, algorithms=["HS256"]
                )
            except jwt.PyJWTError:
                return _error("invalid_token")
            body = _tokens(client_id, claims["sub"], form.get("scope", ""), refresh=False)
            body["issued_token_type"] = (
                "urn:ietf:params:oauth:token-type:access_token"
            )
            return JSONResponse(body)
        return _error("unsupported_grant_type")

    return router
