"""Tests for py_oidc_auth_client.flows."""

import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import httpx
import jwt
import pytest
import requests

from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.flows import BaseFlow, CodeFlow, DeviceFlow
from py_oidc_auth_client.token_store import TokenStore
from py_oidc_auth_client.utils import build_url

from .conftest import (
    MockTransport,
    make_expired_token,
    make_raw_token_response,
    make_refresh_only_token,
    make_token,
)


# ======================================================================
# BaseFlow: singleton, token cache, session, shared helpers
# ======================================================================


class TestBaseFlowSingleton:
    """Per host singleton behaviour."""

    def test_same_host_same_instance(self, tmp_store: TokenStore):
        a = DeviceFlow("https://a.example.com", store=tmp_store)
        b = DeviceFlow("https://a.example.com", store=tmp_store)
        assert a is b

    def test_different_host_different_instance(self, tmp_store: TokenStore):
        a = DeviceFlow("https://a.example.com", store=tmp_store)
        b = DeviceFlow("https://b.example.com", store=tmp_store)
        assert a is not b

    def test_different_subclass_different_instance(self, tmp_store: TokenStore):
        d = DeviceFlow("https://a.example.com", store=tmp_store)
        c = CodeFlow("https://a.example.com", store=tmp_store)
        assert d is not c

    def test_reset_instances(self, tmp_store: TokenStore):
        a = DeviceFlow("https://a.example.com", store=tmp_store)
        BaseFlow.reset_instances()
        b = DeviceFlow("https://a.example.com", store=tmp_store)
        assert a is not b

    def test_host_normalised_for_singleton(self, tmp_store: TokenStore):
        a = DeviceFlow("https://Example.COM:443/", store=tmp_store)
        b = DeviceFlow("https://example.com", store=tmp_store)
        assert a is b

    def test_default_store_created_when_none_passed(self):
        """Covers _get_default_store branch."""
        flow = DeviceFlow("https://default-store.example.com")
        assert flow.store is not None
        assert isinstance(flow.store, TokenStore)


class TestBaseFlowSession:
    """Lazy httpx.AsyncClient creation."""

    def test_session_property_creates_client(self, tmp_store: TokenStore):
        """Covers the session property lazy init branch."""
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = None  # ensure not pre-set
        session = flow.session
        assert isinstance(session, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_session_recreated_when_closed(self, tmp_store: TokenStore):
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient()
        await flow._session.aclose()
        new_session = flow.session
        assert isinstance(new_session, httpx.AsyncClient)
        assert not new_session.is_closed


class TestBaseFlowTokenCache:
    """Token property reads through the store."""

    def test_no_token_initially(self, tmp_store: TokenStore):
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        assert flow.token is None

    def test_token_after_put(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put("https://a.example.com", token)
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        assert flow.token is not None
        assert flow.token["access_token"] == token["access_token"]

    def test_shared_store_between_flows(self, tmp_store: TokenStore):
        device = DeviceFlow("https://shared.example.com", store=tmp_store)
        code = CodeFlow("https://shared.example.com", store=tmp_store)
        tmp_store.put("https://shared.example.com", make_token())
        assert device.token is not None
        assert code.token is not None
        assert device.token["access_token"] == code.token["access_token"]


class TestBaseFlowBuildToken:
    """Token normalisation from raw provider responses."""

    def test_builds_token_with_headers(self, tmp_store: TokenStore):
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        raw = make_raw_token_response()
        token = flow._build_token(raw)
        assert "Authorization" in token["headers"]
        assert token["headers"]["Authorization"].startswith("Bearer ")

    def test_saves_to_store(self, tmp_store: TokenStore):
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        raw = make_raw_token_response()
        flow._build_token(raw)
        assert tmp_store.get("https://a.example.com") is not None

    def test_handles_expires_in_field(self, tmp_store: TokenStore):
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        now = int(time.time())
        raw = {
            "access_token": jwt.encode({"sub": "u"}, "s"),
            "expires_in": 600,
            "refresh_expires_in": 7200,
            "refresh_token": "rt",
        }
        token = flow._build_token(raw)
        assert token["expires"] >= now + 599
        assert token["refresh_expires"] >= now + 7199


class TestBaseFlowPostForm:
    """HTTP POST helper — success, error, and edge cases."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_store: TokenStore):
        transport = MockTransport().add(200, {"result": "ok"})
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient(transport=transport)
        result = await flow._post_form("https://a.example.com/token")
        assert result == {"result": "ok"}

    @pytest.mark.asyncio
    async def test_http_error_with_json_body(self, tmp_store: TokenStore):
        transport = MockTransport().add(401, {"error": "invalid_client"})
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError) as exc_info:
            await flow._post_form("https://a.example.com/token")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["error"] == "invalid_client"

    @pytest.mark.asyncio
    async def test_http_error_with_non_json_body(self, tmp_store: TokenStore):
        """Covers the except branch in _post_form for unparseable error bodies."""
        transport = MockTransport().add(500, b"Internal Server Error")
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError) as exc_info:
            await flow._post_form("https://a.example.com/token")
        assert exc_info.value.status_code == 500
        assert "http_error" in exc_info.value.detail["error"]

    @pytest.mark.asyncio
    async def test_success_with_non_json_body(self, tmp_store: TokenStore):
        """Covers the except branch for non-JSON 2xx responses."""
        transport = MockTransport().add(200, b"not json at all")
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError, match="Invalid JSON"):
            await flow._post_form("https://a.example.com/token")

    @pytest.mark.asyncio
    async def test_sends_form_encoded(self, tmp_store: TokenStore):
        transport = MockTransport().add(200, {"ok": True})
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient(transport=transport)
        await flow._post_form(
            "https://a.example.com/token", data={"grant_type": "device_code"}
        )
        req = transport.requests[0]
        assert b"grant_type=device_code" in req.content

    @pytest.mark.asyncio
    async def test_against_test_server_non_json_error(self, test_server: str, tmp_store: TokenStore):
        """Real HTTP to the test server's non-JSON error endpoint."""
        flow = DeviceFlow(test_server, store=tmp_store)
        with pytest.raises(AuthError) as exc_info:
            await flow._post_form(f"{test_server}/_test/non_json_error")
        assert exc_info.value.status_code == 500
        assert "http_error" in exc_info.value.detail["error"]

    @pytest.mark.asyncio
    async def test_against_test_server_non_json_ok(self, test_server: str, tmp_store: TokenStore):
        """Real HTTP to the test server's non-JSON success endpoint."""
        flow = DeviceFlow(test_server, store=tmp_store)
        with pytest.raises(AuthError, match="Invalid JSON"):
            await flow._post_form(f"{test_server}/_test/non_json_ok")


# ======================================================================
# DeviceFlow
# ======================================================================


class TestDeviceFlowGetDeviceCode:
    """get_device_code against the real test server."""

    @pytest.mark.asyncio
    async def test_success(self, test_server: str, tmp_store: TokenStore):
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5, interactive=False)
        code = await flow.get_device_code()
        assert code["device_code"].startswith("DEV-")
        assert len(code["user_code"]) > 0
        assert "uri" in code
        assert code["interval"] >= 0

    @pytest.mark.asyncio
    async def test_server_503_raises(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(fail_device_start=True)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5, interactive=False)
        try:
            with pytest.raises(AuthError) as exc_info:
                await flow.get_device_code()
            assert exc_info.value.status_code == 503
        finally:
            configure_server(fail_device_start=False)

    @pytest.mark.asyncio
    async def test_missing_required_field_raises(self, tmp_store: TokenStore):
        transport = MockTransport().add(
            200, {"verification_uri": "https://a.com", "expires_in": 60}
        )
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError, match="device_code"):
            await flow.get_device_code()


class TestDeviceFlowPoll:
    """Polling loop against the real test server."""

    @pytest.mark.asyncio
    async def test_pending_then_success(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(pending_polls=2)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=10, interactive=False)
        code = await flow.get_device_code()
        token = await flow.poll(code["device_code"], interval=0)
        assert "access_token" in token
        assert "headers" in token

    @pytest.mark.asyncio
    async def test_access_denied_raises(self, tmp_store: TokenStore):
        transport = MockTransport().add(
            400, {"error": "access_denied"}
        )
        flow = DeviceFlow("https://a.example.com", store=tmp_store, timeout=5)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError, match="access_denied"):
            await flow.poll("DEV-123", interval=0)

    @pytest.mark.asyncio
    async def test_expired_token_raises(self, tmp_store: TokenStore):
        transport = MockTransport().add(
            400, {"error": "expired_token"}
        )
        flow = DeviceFlow("https://a.example.com", store=tmp_store, timeout=5)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError, match="expired_token"):
            await flow.poll("DEV-123", interval=0)

    @pytest.mark.asyncio
    async def test_timeout_raises(self, tmp_store: TokenStore):
        transport = MockTransport().add(
            400, {"error": "authorization_pending"}
        )
        flow = DeviceFlow("https://a.example.com", store=tmp_store, timeout=0)
        flow._session = httpx.AsyncClient(transport=transport)
        with pytest.raises(AuthError, match="allotted time"):
            await flow.poll("DEV-123", interval=0)

    @pytest.mark.asyncio
    async def test_slow_down_handled(self, tmp_store: TokenStore):
        transport = MockTransport()
        transport.add(400, {"error": "slow_down"})
        transport.add(200, make_raw_token_response())
        flow = DeviceFlow("https://a.example.com", store=tmp_store, timeout=30)
        flow._session = httpx.AsyncClient(transport=transport)
        token = await flow.poll("DEV-123", interval=0)
        assert "access_token" in token


class TestDeviceFlowAuthenticate:
    """Full authenticate lifecycle."""

    @pytest.mark.asyncio
    async def test_returns_cached_token(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put("https://a.example.com", token)
        flow = DeviceFlow("https://a.example.com", store=tmp_store)
        result = await flow.authenticate()
        assert result["access_token"] == token["access_token"]

    @pytest.mark.asyncio
    async def test_refresh_against_test_server(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        """Expired access token + valid refresh -> server issues new token."""
        old_token = make_refresh_only_token()
        configure_server(add_refresh_token=old_token["refresh_token"])
        tmp_store.put(test_server, old_token)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5, interactive=False)
        result = await flow.authenticate()
        assert result["access_token"] != old_token["access_token"]
        decoded = jwt.decode(
            result["access_token"], options={"verify_signature": False}
        )
        assert decoded["sub"] == "testuser"

    @pytest.mark.asyncio
    async def test_refresh_failure_falls_back_to_device_flow(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        """Refresh fails (bad token) -> falls through to full device flow."""
        old_token = make_refresh_only_token()
        old_token["refresh_token"] = "invalid_rt_that_server_rejects"
        tmp_store.put(test_server, old_token)
        configure_server(pending_polls=0)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5, interactive=False)
        with patch("webbrowser.open"):
            result = await flow.authenticate(auto_open=False)
        assert "access_token" in result

    @pytest.mark.asyncio
    async def test_full_device_flow_against_test_server(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(pending_polls=1)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=10, interactive=False)
        with (
            patch(
                "py_oidc_auth_client.utils.is_interactive_auth_possible",
                return_value=True,
            ),
            patch("webbrowser.open"),
        ):
            result = await flow.authenticate(auto_open=False)
        assert "access_token" in result
        # Token should be persisted
        assert tmp_store.get(test_server) is not None

    @pytest.mark.asyncio
    async def test_force_bypasses_cache(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        tmp_store.put(test_server, make_token())
        configure_server(pending_polls=0)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5, interactive=False)
        with patch("webbrowser.open"):
            result = await flow.authenticate(force=True, auto_open=False)
        assert "access_token" in result


class TestDeviceFlowRunDeviceFlow:
    """_run_device_flow internals: browser open failure."""

    @pytest.mark.asyncio
    async def test_browser_open_failure_still_polls(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        """Covers the except branch when webbrowser.open raises."""
        configure_server(pending_polls=0)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=10, interactive=False)
        with patch("webbrowser.open", side_effect=RuntimeError("no display")):
            result = await flow._run_device_flow(auto_open=True)
        assert "access_token" in result

    @pytest.mark.asyncio
    async def test_non_interactive_prints_url(
        self, test_server: str, tmp_store: TokenStore, configure_server, capsys
    ):
        """When auto_open=False, the non-interactive message is printed."""
        configure_server(pending_polls=0)
        flow = DeviceFlow(test_server, store=tmp_store, timeout=10, interactive=False)
        result = await flow._run_device_flow(auto_open=False)
        assert "access_token" in result


class TestDeviceFlowRefresh:
    """Token refresh against the real test server."""

    @pytest.mark.asyncio
    async def test_refresh_success(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(add_refresh_token="rt_for_refresh_test")
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5)
        token = await flow.refresh("rt_for_refresh_test")
        assert "access_token" in token

    @pytest.mark.asyncio
    async def test_refresh_failure(
        self, test_server: str, tmp_store: TokenStore
    ):
        flow = DeviceFlow(test_server, store=tmp_store, timeout=5)
        with pytest.raises(AuthError):
            await flow.refresh("totally_invalid_refresh_token")


# ======================================================================
# CodeFlow
# ======================================================================


class TestCodeFlowAuthenticate:
    """Code flow with cached/refreshed tokens."""

    @pytest.mark.asyncio
    async def test_returns_cached_token(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put("https://a.example.com", token)
        flow = CodeFlow("https://a.example.com", store=tmp_store)
        result = await flow.authenticate()
        assert result["access_token"] == token["access_token"]

    @pytest.mark.asyncio
    async def test_refresh_against_test_server(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        old_token = make_refresh_only_token()
        configure_server(add_refresh_token=old_token["refresh_token"])
        tmp_store.put(test_server, old_token)
        flow = CodeFlow(test_server, store=tmp_store, timeout=5)
        result = await flow.authenticate()
        assert result["access_token"] != old_token["access_token"]

    @pytest.mark.asyncio
    async def test_refresh_failure_falls_back_to_code_flow(
        self, test_server: str, tmp_store: TokenStore
    ):
        """Covers the except AuthError branch in CodeFlow.authenticate."""
        old_token = make_refresh_only_token()
        old_token["refresh_token"] = "bad_rt_that_fails"
        tmp_store.put(test_server, old_token)
        flow = CodeFlow(test_server, store=tmp_store, timeout=5)
        # _run_code_flow will be called; mock it to avoid browser
        with patch.object(flow, "_run_code_flow", return_value=make_token()) as mock_run:
            result = await flow.authenticate()
        mock_run.assert_called_once()
        assert "access_token" in result


class TestCodeFlowWaitForPort:
    """_wait_for_port with real sockets."""

    @pytest.mark.asyncio
    async def test_success(self):
        """Start a server, then wait for its port."""
        import http.server

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        try:
            await CodeFlow._wait_for_port("127.0.0.1", port, timeout=2.0)
        finally:
            s.close()

    @pytest.mark.asyncio
    async def test_timeout_raises(self):
        """No server listening -> TimeoutError."""
        # Find a port that's definitely not listening
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # close it so nothing is listening
        with pytest.raises(TimeoutError, match="did not open"):
            await CodeFlow._wait_for_port("127.0.0.1", port, timeout=0.3)


class TestCodeFlowFindFreePort:
    """Port selection from config list."""

    def test_finds_a_free_port(self, tmp_store: TokenStore):
        flow = CodeFlow("https://a.example.com", store=tmp_store)
        port = flow._find_free_port()
        assert port in flow.config.redirect_ports

    def test_all_busy_raises(self, tmp_store: TokenStore):
        flow = CodeFlow("https://a.example.com", store=tmp_store)
        sockets = []
        try:
            for p in flow.config.redirect_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("localhost", p))
                except OSError:
                    continue
                sockets.append(s)
            with pytest.raises(OSError, match="No free ports"):
                flow._find_free_port()
        finally:
            for s in sockets:
                s.close()


class TestCodeFlowCallbackServer:
    """Local HTTP callback server for capturing auth codes."""

    def test_callback_captures_code(self, tmp_store: TokenStore):
        flow = CodeFlow("https://a.example.com", store=tmp_store)
        port = flow._find_free_port()
        event = threading.Event()
        server = CodeFlow._start_local_server(port, event)
        try:
            resp = requests.get(
                f"http://localhost:{port}/callback?code=TEST-CODE-123",
                timeout=3,
            )
            assert resp.status_code == 200
            event.wait(timeout=2)
            assert getattr(server, "auth_code", None) == "TEST-CODE-123"
        finally:
            server.server_close()

    def test_callback_without_code_returns_400(self, tmp_store: TokenStore):
        flow = CodeFlow("https://a.example.com", store=tmp_store)
        port = flow._find_free_port()
        event = threading.Event()
        server = CodeFlow._start_local_server(port, event)
        try:
            resp = requests.get(
                f"http://localhost:{port}/callback?foo=bar",
                timeout=3,
            )
            assert resp.status_code == 400
            assert not event.is_set()
        finally:
            server.server_close()


class TestCodeFlowRunCodeFlow:
    """Full _run_code_flow integration against the real test server.

    The trick: mock webbrowser.open to make a real HTTP GET that
    follows the test server's redirect to the local callback server.
    """

    @pytest.mark.asyncio
    async def test_full_code_flow_against_test_server(
        self, test_server: str, tmp_store: TokenStore
    ):
        """End-to-end: local server -> redirect -> code exchange -> token."""
        flow = CodeFlow(test_server, store=tmp_store, timeout=10)

        def fake_browser_open(url: str) -> None:
            """Instead of opening a browser, follow the redirect with requests."""
            # This hits the test server's /auth/v2/login which 302-redirects
            # to http://localhost:{port}/callback?code=CODE-xxx
            # requests follows the redirect, hitting the local callback server.
            requests.get(url, timeout=5)

        with patch("webbrowser.open", side_effect=fake_browser_open):
            token = await flow._run_code_flow()

        assert "access_token" in token
        assert "headers" in token
        decoded = jwt.decode(
            token["access_token"], options={"verify_signature": False}
        )
        assert decoded["sub"] == "testuser"
        # Token should be persisted in the store
        assert tmp_store.get(test_server) is not None

    @pytest.mark.asyncio
    async def test_code_flow_timeout(
        self, test_server: str, tmp_store: TokenStore
    ):
        """Browser never delivers the callback -> AuthError."""
        flow = CodeFlow(test_server, store=tmp_store, timeout=1)
        # webbrowser.open does nothing, so the event never gets set
        with patch("webbrowser.open"):
            with pytest.raises(AuthError, match="did not complete"):
                await flow._run_code_flow()

    @pytest.mark.asyncio
    async def test_code_flow_wait_for_port_failure(
        self, test_server: str, tmp_store: TokenStore
    ):
        """_wait_for_port times out -> caught as exception -> AuthError."""
        flow = CodeFlow(test_server, store=tmp_store, timeout=5)
        with (
            patch.object(
                CodeFlow,
                "_wait_for_port",
                side_effect=TimeoutError("port never opened"),
            ),
            patch("webbrowser.open"),
        ):
            with pytest.raises(AuthError, match="port never opened"):
                await flow._run_code_flow()

    @pytest.mark.asyncio
    async def test_code_flow_no_free_port(
        self, test_server: str, tmp_store: TokenStore
    ):
        """All configured ports busy -> OSError propagates."""
        flow = CodeFlow(test_server, store=tmp_store, timeout=5)
        with patch.object(
            flow, "_find_free_port", side_effect=OSError("No free ports available")
        ):
            with pytest.raises(OSError, match="No free ports"):
                await flow._run_code_flow()
