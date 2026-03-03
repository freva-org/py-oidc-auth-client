"""Shared fixtures for py_oidc_auth_client tests.

The centrepiece is a real FastAPI server that simulates the three OIDC
endpoints the client talks to (``/auth/v2/device``, ``/auth/v2/token``,
``/auth/v2/login``).  It runs in a background thread via uvicorn and
is reachable on ``http://127.0.0.1:<free_port>``.  Tests make real HTTP
requests against it — no httpx mocking required for the happy paths.
"""

import json
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx
import jwt
import pytest
import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from py_oidc_auth_client.flows import BaseFlow, CodeFlow, DeviceFlow
from py_oidc_auth_client.schema import Token
from py_oidc_auth_client.token_store import TokenStore


# ---------------------------------------------------------------------------
# Token factories
# ---------------------------------------------------------------------------

JWT_SECRET = "test-secret-key"


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
) -> Token:
    """Build a normalised Token as the client library stores it."""
    now = int(time.time())
    access_token = jwt.encode(
        {"sub": "testuser", "iat": now, "exp": now + expires_in}, JWT_SECRET
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


def create_test_app() -> FastAPI:
    """Create a FastAPI app that simulates OIDC provider endpoints.

    Controllable via POST to ``/_test/configure``.
    """
    app = FastAPI()

    @app.on_event("startup")
    def _init_state() -> None:
        app.state.device_codes: Dict[str, Dict[str, Any]] = {}
        app.state.valid_refresh_tokens: set = {"test_refresh_token"}
        app.state.valid_auth_codes: set = set()
        app.state.fail_device_start: bool = False
        app.state.pending_polls: int = 1

    # -- POST /auth/v2/device -------------------------------------------

    @app.post("/auth/v2/device")
    async def device_start(request: Request) -> JSONResponse:
        if app.state.fail_device_start:
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=503,
            )
        device_code = f"DEV-{uuid.uuid4().hex[:8]}"
        user_code = (
            f"{uuid.uuid4().hex[:4].upper()}-"
            f"{uuid.uuid4().hex[:4].upper()}"
        )
        app.state.device_codes[device_code] = {
            "user_code": user_code,
            "polls_remaining": app.state.pending_polls,
        }
        base = str(request.base_url).rstrip("/")
        return JSONResponse({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": f"{base}/verify",
            "verification_uri_complete": (
                f"{base}/verify?user_code={user_code}"
            ),
            "expires_in": 600,
            "interval": 0,
        })

    # -- POST /auth/v2/token --------------------------------------------

    @app.post("/auth/v2/token")
    async def token_exchange(request: Request) -> JSONResponse:
        form = await request.form()
        device_code = form.get("device-code")
        refresh_token = form.get("refresh-token")
        grant_type = form.get("grant_type")
        code = form.get("code")

        if device_code:
            entry = app.state.device_codes.get(device_code)
            if entry is None:
                return JSONResponse(
                    {"error": "invalid_grant"},
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

        if grant_type == "authorization_code" and code:
            if code not in app.state.valid_auth_codes:
                return JSONResponse(
                    {"error": "invalid_grant"},
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
    ) -> RedirectResponse:
        code = f"CODE-{uuid.uuid4().hex[:8]}"
        app.state.valid_auth_codes.add(code)
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            f"{redirect_uri}{sep}{urlencode({'code': code})}",
            status_code=302,
        )

    # -- Edge-case endpoints for testing --------------------------------

    @app.post("/_test/non_json_error")
    async def non_json_error() -> PlainTextResponse:
        return PlainTextResponse(
            "Internal Server Error", status_code=500
        )

    @app.post("/_test/non_json_ok")
    async def non_json_ok() -> PlainTextResponse:
        return PlainTextResponse("not json", status_code=200)

    # -- Control endpoint -----------------------------------------------

    @app.post("/_test/configure")
    async def configure(request: Request) -> JSONResponse:
        body = await request.json()
        if "fail_device_start" in body:
            app.state.fail_device_start = body["fail_device_start"]
        if "pending_polls" in body:
            app.state.pending_polls = body["pending_polls"]
        if "add_refresh_token" in body:
            app.state.valid_refresh_tokens.add(body["add_refresh_token"])
        if "add_auth_code" in body:
            app.state.valid_auth_codes.add(body["add_auth_code"])
        return JSONResponse({"ok": True})

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
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_for_server("127.0.0.1", port)
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Store / singleton fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_store(tmp_path: Path) -> TokenStore:
    """A TokenStore backed by a temp file."""
    return TokenStore(path=tmp_path / "tokens.json")


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset flow singletons between tests."""
    BaseFlow._instances.clear()
    BaseFlow._default_store = None
    yield
    BaseFlow._instances.clear()
    BaseFlow._default_store = None


@pytest.fixture()
def configure_server(test_server: str):
    """Return a callable that POSTs to /_test/configure."""
    import requests as req

    def _configure(**kwargs: Any) -> None:
        resp = req.post(f"{test_server}/_test/configure", json=kwargs)
        resp.raise_for_status()

    return _configure
