"""Shared fixtures for py_oidc_auth_client tests.

The centrepiece is a real FastAPI server that simulates the three OIDC
endpoints the client talks to (``/auth/v2/device``, ``/auth/v2/token``,
``/auth/v2/login``).  It runs in a background thread via uvicorn and
is reachable on ``http://127.0.0.1:<free_port>``.  Tests make real HTTP
requests against it — no httpx mocking required for the happy paths.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx
import jwt
import pytest
import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from py_oidc_auth_client.flows import BaseFlow
from py_oidc_auth_client.identity import AuthIdentity, Grant
from py_oidc_auth_client.schema import Token
from py_oidc_auth_client.token_store import TokenStore

from . import fake_idp

# ---------------------------------------------------------------------------
# Token factories
# ---------------------------------------------------------------------------

JWT_SECRET = secrets.token_urlsafe()


def make_raw_token_response(
    *,
    sub: str = "testuser",
    expires_in: int = 300,
    refresh_expires_in: int = 3600,
    scope: str = "openid profile email",
) -> Dict[str, Any]:
    """Build a raw token response as an OIDC provider would return."""
    now = int(time.time())
    access_token = jwt.encode(
        {"sub": sub, "iat": now, "exp": now + expires_in}, JWT_SECRET
    )
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires": now + expires_in,
        "refresh_token": f"rt_{uuid.uuid4().hex[:12]}",
        "refresh_expires": now + refresh_expires_in,
        "scope": scope,
    }


def make_token(
    *,
    expires_in: int = 300,
    refresh_expires_in: int = 3600,
    subject: str = "testuser",
) -> Token:
    """Build a normalised Token as the client library stores it.

    *subject* varies the encoded JWT so that two tokens minted in the
    same second are distinguishable, which matters for tests asserting
    that separate identities do not share a cache entry.
    """
    now = int(time.time())
    access_token = jwt.encode(
        {"sub": subject, "iat": now, "exp": now + expires_in}, JWT_SECRET
    )
    return Token(
        access_token=access_token,
        token_type="Bearer",
        expires=now + expires_in,
        refresh_token=f"rt_{uuid.uuid4().hex[:12]}",
        refresh_expires=now + refresh_expires_in,
        scope="openid profile email",
        headers={"Authorization": f"Bearer {access_token}"},
    )


def make_expired_token() -> Token:
    return make_token(expires_in=-7200, refresh_expires_in=-3600)


def make_refresh_only_token() -> Token:
    return make_token(expires_in=-300, refresh_expires_in=3600)


def make_access_only_token(
    *, expires_in: int = 300, subject: str = "testuser"
) -> Token:
    """A token with no refresh token, as client credentials and token
    exchange usually return."""
    token = make_token(expires_in=expires_in, subject=subject)
    token.pop("refresh_token", None)
    token.pop("refresh_expires", None)
    return token


def make_identity(
    *,
    host: str = "https://myapp.example.com",
    backend: str = "oidc",
    grant: Optional[Grant] = Grant.DEVICE_CODE,
    **kwargs: Any,
) -> AuthIdentity:
    """Build an AuthIdentity with defaults suited to the tests."""
    return AuthIdentity(host=host, backend=backend, grant=grant, **kwargs)


# ---------------------------------------------------------------------------
# httpx mock transport (for edge cases that need non-standard responses)
# ---------------------------------------------------------------------------


class MockTransport(httpx.AsyncBaseTransport):
    """Programmable httpx transport for testing.

    Each request pops the next (status, body) off the queue.
    When the queue has one item left it is recycled.
    body can be a dict (JSON) or bytes/str (raw).
    """

    def __init__(self) -> None:
        self.responses: List = []
        self.requests: List[httpx.Request] = []

    def add(self, status: int, body: Any) -> "MockTransport":
        self.responses.append((status, body))
        return self

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if len(self.responses) > 1:
            status, body = self.responses.pop(0)
        elif self.responses:
            status, body = self.responses[0]
        else:
            status, body = 500, {"error": "no responses configured"}

        if isinstance(body, dict):
            content = json.dumps(body).encode()
            ct = "application/json"
        elif isinstance(body, bytes):
            content = body
            ct = "text/plain"
        else:
            content = str(body).encode()
            ct = "text/plain"

        return httpx.Response(
            status_code=status,
            content=content,
            headers={"content-type": ct},
            request=request,
        )


# ---------------------------------------------------------------------------
# Fake OIDC server
# ---------------------------------------------------------------------------


def s256(verifier: str) -> str:
    """The PKCE S256 challenge of *verifier*."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _verifier_ok(challenge: Optional[str], verifier: Optional[str]) -> bool:
    """Check a verifier like the IdP would: only when a challenge was set."""
    if challenge is None:
        return True
    return verifier is not None and s256(verifier) == challenge


def create_test_app() -> FastAPI:
    """Create a FastAPI app that simulates OIDC provider endpoints.

    Controllable via POST to ``/_test/configure``.
    """

    @asynccontextmanager
    async def _init_state(app: FastAPI) -> None:
        app.state.device_codes: Dict[str, Dict[str, Any]] = {}
        app.state.valid_refresh_tokens: set = {"test_refresh_token"}
        app.state.valid_auth_codes: set = set()
        # code -> PKCE challenge it was issued for (None: no PKCE)
        app.state.code_challenges: Dict[str, Optional[str]] = {}
        # Behave like a server without client side PKCE support
        app.state.legacy_pkce: bool = False
        app.state.fail_device_start: bool = False
        app.state.pending_polls: int = 1
        # Forms of all token exchange requests, for assertions
        app.state.exchanges: List[Dict[str, Any]] = []
        yield

    app = FastAPI(lifespan=_init_state)
    # -- POST /auth/v2/device -------------------------------------------

    @app.post("/auth/v2/device")
    async def device_start(request: Request) -> JSONResponse:
        if app.state.fail_device_start:
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=503,
            )
        form = await request.form()
        device_code = f"DEV-{uuid.uuid4().hex[:8]}"
        user_code = f"{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
        challenge = None if app.state.legacy_pkce else form.get("code_challenge")
        app.state.device_codes[device_code] = {
            "user_code": user_code,
            "polls_remaining": app.state.pending_polls,
            "challenge": challenge,
        }
        base = str(request.base_url).rstrip("/")
        return JSONResponse(
            {
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": f"{base}/verify",
                "verification_uri_complete": (f"{base}/verify?user_code={user_code}"),
                "expires_in": 600,
                "interval": 0,
            }
        )

    # -- POST /auth/v2/token --------------------------------------------

    @app.post("/auth/v2/token")
    async def token_exchange(request: Request) -> JSONResponse:
        form = await request.form()
        device_code = form.get("device_code") or form.get("device-code")
        refresh_token = form.get("refresh_token") or form.get("refresh-token")
        grant_type = form.get("grant_type")
        code = form.get("code")
        verifier = form.get("code_verifier")

        if device_code:
            entry = app.state.device_codes.get(device_code)
            if entry is None:
                return JSONResponse(
                    {"error": "invalid_grant"},
                    status_code=400,
                )
            if not _verifier_ok(entry["challenge"], verifier):
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "PKCE"},
                    status_code=400,
                )
            if entry["polls_remaining"] > 0:
                entry["polls_remaining"] -= 1
                return JSONResponse(
                    {"error": "authorization_pending"},
                    status_code=400,
                )
            del app.state.device_codes[device_code]
            resp = make_raw_token_response()
            app.state.valid_refresh_tokens.add(resp["refresh_token"])
            return JSONResponse(resp)

        if refresh_token:
            if refresh_token not in app.state.valid_refresh_tokens:
                return JSONResponse(
                    {"error": "invalid_grant"},
                    status_code=401,
                )
            resp = make_raw_token_response()
            app.state.valid_refresh_tokens.discard(refresh_token)
            app.state.valid_refresh_tokens.add(resp["refresh_token"])
            return JSONResponse(resp)

        if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
            app.state.exchanges.append(dict(form))
            try:
                claims = jwt.decode(
                    form.get("subject_token", ""),
                    JWT_SECRET,
                    algorithms=["HS256"],
                    options={"verify_aud": False},
                )
            except jwt.PyJWTError:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "bad subject"},
                    status_code=400,
                )
            audience = form.get("audience")
            if audience == "forbidden":
                return JSONResponse(
                    {"error": "invalid_target", "error_description": "no way"},
                    status_code=400,
                )
            now = int(time.time())
            expires = min(int(claims["exp"]), now + 300)
            access_token = jwt.encode(
                {
                    "sub": claims["sub"],
                    "aud": audience or "exchanged",
                    "iat": now,
                    "exp": expires,
                    "n": len(app.state.exchanges),
                },
                JWT_SECRET,
            )
            return JSONResponse(
                {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": expires - now,
                    "scope": form.get("scope") or "openid",
                    "issued_token_type": form.get("requested_token_type")
                    or "urn:ietf:params:oauth:token-type:access_token",
                }
            )

        if grant_type == "authorization_code" and code:
            if code not in app.state.valid_auth_codes:
                return JSONResponse(
                    {"error": "invalid_grant"},
                    status_code=400,
                )
            if not _verifier_ok(app.state.code_challenges.get(code), verifier):
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "PKCE"},
                    status_code=400,
                )
            app.state.valid_auth_codes.discard(code)
            resp = make_raw_token_response()
            app.state.valid_refresh_tokens.add(resp["refresh_token"])
            return JSONResponse(resp)

        return JSONResponse(
            {"error": "invalid_request"},
            status_code=400,
        )

    # -- GET /auth/v2/login (simulates IdP redirect) --------------------

    @app.get("/auth/v2/login")
    async def login_redirect(
        redirect_uri: str = Query(...),
        offline_access: str = Query("false"),
        prompt: str = Query("consent"),
        code_challenge: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
    ) -> RedirectResponse:
        code = f"CODE-{uuid.uuid4().hex[:8]}"
        app.state.valid_auth_codes.add(code)
        if app.state.legacy_pkce:
            # Old servers ignore the client's challenge and state, and
            # carry their own verifier in state.
            verifier = secrets.token_urlsafe(32)
            code_challenge = s256(verifier)
            state = f"{uuid.uuid4().hex}|{redirect_uri}|{verifier}"
        app.state.code_challenges[code] = code_challenge
        query = {"code": code}
        if state:
            query["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            f"{redirect_uri}{sep}{urlencode(query)}",
            status_code=302,
        )

    # -- Edge-case endpoints for testing --------------------------------

    @app.post("/_test/non_json_error")
    async def non_json_error() -> PlainTextResponse:
        return PlainTextResponse("Internal Server Error", status_code=500)

    @app.post("/_test/non_json_ok")
    async def non_json_ok() -> PlainTextResponse:
        return PlainTextResponse("not json", status_code=200)

    # -- Control endpoint -----------------------------------------------

    @app.post("/_test/configure")
    async def configure(request: Request) -> JSONResponse:
        body = await request.json()
        if "fail_device_start" in body:
            app.state.fail_device_start = body["fail_device_start"]
        if body.get("reset_exchanges"):
            app.state.exchanges.clear()
        if "legacy_pkce" in body:
            app.state.legacy_pkce = body["legacy_pkce"]
        if "pending_polls" in body:
            app.state.pending_polls = body["pending_polls"]
        if "add_refresh_token" in body:
            app.state.valid_refresh_tokens.add(body["add_refresh_token"])
        if "add_auth_code" in body:
            app.state.valid_auth_codes.add(body["add_auth_code"])
        return JSONResponse({"ok": True})

    @app.get("/_test/exchanges")
    async def exchanges() -> JSONResponse:
        return JSONResponse(app.state.exchanges)

    # A plain OpenID Connect provider next to the py-oidc-auth routes
    fake_idp.IDP.secret = JWT_SECRET
    app.include_router(fake_idp.build_router(), prefix=fake_idp.PREFIX)

    return app


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Server on {host}:{port} not ready within {timeout}s")


@pytest.fixture(scope="session")
def test_server() -> str:
    """Start a fake OIDC server and return its base URL."""
    port = _find_free_port()
    app = create_test_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_for_server("127.0.0.1", port)
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Store fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_store(tmp_path: Path) -> TokenStore:
    """A TokenStore backed by a temp directory."""
    return TokenStore(path=tmp_path / "tokens")


@pytest.fixture(autouse=True)
def _reset_default_store():
    """Reset the shared default token store between tests."""
    BaseFlow._default_store = None
    yield
    BaseFlow._default_store = None


@pytest.fixture()
def configure_server(test_server: str):
    """Return a callable that POSTs to /_test/configure."""
    import requests as req

    def _configure(**kwargs: Any) -> None:
        resp = req.post(f"{test_server}/_test/configure", json=kwargs)
        resp.raise_for_status()

    return _configure


@pytest.fixture()
def legacy_pkce_server(test_server: str, configure_server):
    """The test server acting like a server without client side PKCE."""
    configure_server(legacy_pkce=True)
    yield test_server
    configure_server(legacy_pkce=False)


@pytest.fixture()
def exchanges(test_server: str, configure_server):
    """Return a callable listing the exchange requests the server saw."""
    import requests as req

    configure_server(reset_exchanges=True)

    def _exchanges() -> List[Dict[str, Any]]:
        resp = req.get(f"{test_server}/_test/exchanges")
        resp.raise_for_status()
        return resp.json()

    return _exchanges


@pytest.fixture()
def idp(test_server: str):
    """The fake OpenID Connect provider: its state, reset for each test."""
    fake_idp.IDP.reset()
    yield fake_idp.IDP
    fake_idp.IDP.reset()


@pytest.fixture()
def issuer(test_server: str, idp) -> str:
    """Issuer URL of the fake OpenID Connect provider."""
    return f"{test_server}{fake_idp.PREFIX}"
