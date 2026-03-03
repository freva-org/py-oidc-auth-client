"""Tests for the top level authenticate() and authenticate_async()."""

from pathlib import Path
from unittest.mock import patch

import httpx
import jwt
import pytest
import requests

from py_oidc_auth_client import authenticate, authenticate_async
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.flows import DeviceFlow
from py_oidc_auth_client.token_store import TokenStore

from .conftest import make_raw_token_response, make_token


class TestAuthenticateCached:
    """authenticate() returns cached tokens without hitting the network."""

    def test_returns_valid_cached_token(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put("https://a.example.com", token)
        result = authenticate("https://a.example.com", store=tmp_store)
        assert result["access_token"] == token["access_token"]

    def test_different_hosts_independent(self, tmp_store: TokenStore):
        token_a = make_token(expires_in=100)
        token_b = make_token(expires_in=200)
        tmp_store.put("https://a.example.com", token_a)
        tmp_store.put("https://b.example.com", token_b)
        result_a = authenticate("https://a.example.com", store=tmp_store)
        result_b = authenticate("https://b.example.com", store=tmp_store)
        assert result_a["expires"] == token_a["expires"]
        assert result_b["expires"] == token_b["expires"]


class TestAuthenticateDeviceFlow:
    """authenticate() runs device flow against the real test server."""

    def test_full_device_flow(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(pending_polls=0)
        with (
            patch(
                "py_oidc_auth_client.utils.is_interactive_auth_possible",
                return_value=True,
            ),
            patch("webbrowser.open"),
        ):
            result = authenticate(
                test_server, store=tmp_store, force=True
            )
        assert "access_token" in result
        decoded = jwt.decode(
            result["access_token"], options={"verify_signature": False}
        )
        assert decoded["sub"] == "testuser"
        # Persisted in store
        assert tmp_store.get(test_server) is not None


class TestAuthenticateFallback:
    """authenticate() falls back from device flow to code flow on 503."""

    @pytest.mark.asyncio
    async def test_device_503_falls_back_to_code_flow(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        """Device endpoint returns 503 -> code flow is tried."""
        configure_server(fail_device_start=True)
        try:
            def fake_browser_open(url: str) -> None:
                requests.get(url, timeout=5)

            with patch("webbrowser.open", side_effect=fake_browser_open):
                result = await authenticate_async(
                    test_server, store=tmp_store, force=True, timeout=10
                )
            assert "access_token" in result
        finally:
            configure_server(fail_device_start=False)

    @pytest.mark.asyncio
    async def test_device_non_503_raises(self, tmp_store: TokenStore):
        """Non 503 errors from device flow should propagate."""

        async def device_auth_fails(**kwargs):
            raise AuthError("timeout", status_code=408)

        with patch.object(
            DeviceFlow, "authenticate", side_effect=device_auth_fails
        ):
            with pytest.raises(AuthError, match="timeout"):
                await authenticate_async(
                    "https://a.example.com", store=tmp_store
                )


class TestAuthenticateForce:
    """Force flag bypasses cache."""

    def test_force_ignores_cached_token(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        old_token = make_token()
        tmp_store.put(test_server, old_token)
        configure_server(pending_polls=0)
        with (
            patch(
                "py_oidc_auth_client.utils.is_interactive_auth_possible",
                return_value=True,
            ),
            patch("webbrowser.open"),
        ):
            result = authenticate(
                test_server, store=tmp_store, force=True
            )
        # Server generates a random refresh_token each time, so it
        # will differ from the pre-seeded one, proving the cache was bypassed.
        assert result["refresh_token"] != old_token["refresh_token"]


class TestAuthenticateAppName:
    """app_name controls the cache directory."""

    def test_custom_app_name(self, tmp_path: Path):
        token = make_token()
        store = TokenStore(path=tmp_path / "custom-tokens.json")
        store.put("https://a.example.com", token)
        result = authenticate(
            "https://a.example.com",
            store=store,
            app_name="my-custom-app",
        )
        assert result["access_token"] == token["access_token"]
