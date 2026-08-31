"""Tests for provider-specific authentication backends."""

from __future__ import annotations

import urllib.parse

import httpx
import pytest

from py_oidc_auth_client.backends import ProviderBackend, PyOIDCAuth
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.utils import Config

from .conftest import MockTransport, make_raw_token_response


def _backend(
    host: str = "https://a.example.com",
    *,
    transport: MockTransport | None = None,
    timeout: int | None = 30,
) -> PyOIDCAuth:
    session = httpx.AsyncClient(transport=transport) if transport is not None else None
    return PyOIDCAuth(Config(host=host), session=session, timeout=timeout)


def _form(request: httpx.Request) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(request.content.decode())


class TestProviderBackend:
    """Shared HTTP helper and abstract-base behaviour."""

    def test_base_class_is_abstract(self):
        with pytest.raises(TypeError):
            ProviderBackend(Config(host="https://a.example.com"))

    @pytest.mark.asyncio
    async def test_post_form_success(self):
        transport = MockTransport().add(200, {"result": "ok"})
        backend = _backend(transport=transport)
        result = await backend.post_form(
            "https://a.example.com/token",
            {"grant_type": "device_code", "empty": None},
        )
        assert result == {"result": "ok"}
        assert _form(transport.requests[0]) == {"grant_type": ["device_code"]}
        assert (
            transport.requests[0]
            .headers["content-type"]
            .startswith("application/x-www-form-urlencoded")
        )

    @pytest.mark.asyncio
    async def test_post_form_json_error(self):
        transport = MockTransport().add(401, {"error": "invalid_client"})
        backend = _backend(transport=transport)
        with pytest.raises(AuthError) as exc_info:
            await backend.post_form("https://a.example.com/token")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == {"error": "invalid_client"}

    @pytest.mark.asyncio
    async def test_post_form_non_json_error(self):
        transport = MockTransport().add(500, b"Internal Server Error")
        backend = _backend(transport=transport)
        with pytest.raises(AuthError) as exc_info:
            await backend.post_form("https://a.example.com/token")
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail["error"] == "http_error"
        assert "Internal Server Error" in exc_info.value.detail["error_description"]

    @pytest.mark.asyncio
    async def test_post_form_invalid_success_json(self):
        transport = MockTransport().add(200, b"not-json")
        backend = _backend(transport=transport)
        with pytest.raises(AuthError, match="Invalid JSON"):
            await backend.post_form("https://a.example.com/token")

    @pytest.mark.asyncio
    async def test_post_form_creates_session(self, test_server: str):
        backend = _backend(host=test_server, timeout=None)
        assert backend.session is None
        result = await backend.post_form(f"{test_server}/auth/v2/device")
        assert "device_code" in result
        assert isinstance(backend.session, httpx.AsyncClient)
        await backend.session.aclose()

    @pytest.mark.asyncio
    async def test_post_form_recreates_closed_session(self, test_server: str):
        backend = _backend(host=test_server)
        old_session = httpx.AsyncClient()
        await old_session.aclose()
        backend.session = old_session
        result = await backend.post_form(f"{test_server}/auth/v2/device")
        assert "device_code" in result
        assert backend.session is not old_session
        assert backend.session is not None
        await backend.session.aclose()


class TestPyOIDCAuth:
    """py-oidc-auth-specific endpoint and payload conventions."""

    @pytest.mark.asyncio
    async def test_device_authorization(self):
        transport = MockTransport().add(
            200,
            {
                "device_code": "DEV-1",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://a.example.com/verify",
                "expires_in": 600,
            },
        )
        backend = _backend(transport=transport)
        result = await backend.device_authorization()
        assert result["device_code"] == "DEV-1"
        assert str(transport.requests[0].url) == "https://a.example.com/auth/v2/device"

    @pytest.mark.asyncio
    async def test_device_authorization_missing_required_field(self):
        transport = MockTransport().add(
            200,
            {
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://a.example.com/verify",
                "expires_in": 600,
            },
        )
        backend = _backend(transport=transport)
        with pytest.raises(AuthError, match="device_code") as exc_info:
            await backend.device_authorization()
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_get_authorization_url(self):
        backend = _backend()
        url = await backend.get_authorization_url(
            redirect_uri="http://localhost:53100/callback"
        )
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        assert parsed.path == "/auth/v2/login"
        assert query == {
            "redirect_uri": ["http://localhost:53100/callback"],
            "offline_access": ["true"],
            "prompt": ["consent"],
        }

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_extracts_verifier_from_state(self):
        transport = MockTransport().add(200, make_raw_token_response())
        backend = _backend(transport=transport)
        result = await backend.exchange_authorization_code(
            code="CODE-1",
            redirect_uri="http://localhost:53100/callback",
            state="opaque|VERIFIER-1",
        )
        assert "access_token" in result
        assert _form(transport.requests[0]) == {
            "code": ["CODE-1"],
            "redirect_uri": ["http://localhost:53100/callback"],
            "grant_type": ["authorization_code"],
            "code_verifier": ["VERIFIER-1"],
        }

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_without_state_omits_verifier(self):
        transport = MockTransport().add(200, make_raw_token_response())
        backend = _backend(transport=transport)
        await backend.exchange_authorization_code(
            code="CODE-1",
            redirect_uri="http://localhost:53100/callback",
        )
        form = _form(transport.requests[0])
        assert "code_verifier" not in form

    @pytest.mark.asyncio
    async def test_get_device_token(self):
        transport = MockTransport().add(200, make_raw_token_response())
        backend = _backend(transport=transport)
        result = await backend.get_device_token("DEV-1")
        assert "access_token" in result
        assert _form(transport.requests[0]) == {"device-code": ["DEV-1"]}

    @pytest.mark.asyncio
    async def test_refresh_token(self):
        transport = MockTransport().add(200, make_raw_token_response())
        backend = _backend(transport=transport)
        result = await backend.refresh_token("REFRESH-1")
        assert "access_token" in result
        assert _form(transport.requests[0]) == {"refresh-token": ["REFRESH-1"]}

    def test_custom_routes_are_used(self):
        config = Config(
            host="https://a.example.com/root",
            device_route="/custom/device",
            token_route="/custom/token",
        )
        backend = PyOIDCAuth(config)
        assert backend._device_authorization_endpoint == (
            "https://a.example.com/root/custom/device"
        )
        assert backend._token_endpoint == "https://a.example.com/root/custom/token"
