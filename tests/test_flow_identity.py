"""Tests for the identities flows derive and use as cache keys (#35)."""

from __future__ import annotations

import logging
import urllib.parse
import warnings
from unittest.mock import AsyncMock, patch

import pytest
import requests

from py_oidc_auth_client import authenticate, authenticate_async
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.flows import CodeFlow, DeviceFlow
from py_oidc_auth_client.identity import AuthIdentity, Grant
from py_oidc_auth_client.token_store import TokenStore

from .conftest import (
    make_identity,
    make_raw_token_response,
    make_refresh_only_token,
    make_token,
)
from .test_flows import _free_port

HOST = "https://a.example.com"


def _py_identity(**kwargs) -> AuthIdentity:
    kwargs.setdefault("host", HOST)
    kwargs.setdefault("backend", "py-oidc-auth")
    return make_identity(**kwargs)


class TestFlowIdentity:
    """What flow.identity is, and which identities a flow accepts."""

    def test_device_flow_identity(self, tmp_store: TokenStore):
        flow = DeviceFlow(HOST, store=tmp_store)
        assert flow.identity == AuthIdentity(HOST, "py-oidc-auth", Grant.DEVICE_CODE)

    def test_code_flow_identity(self, tmp_store: TokenStore):
        flow = CodeFlow(HOST, store=tmp_store)
        assert flow.identity.grant is Grant.AUTHORIZATION_CODE

    def test_scopes_are_part_of_identity(self, tmp_store: TokenStore):
        flow = DeviceFlow(HOST, store=tmp_store, scopes="openid email openid")
        assert flow.identity.scopes == ("email", "openid")
        other = DeviceFlow(HOST, store=tmp_store, scopes=["email", "openid"])
        assert flow.identity == other.identity
        assert flow.identity != DeviceFlow(HOST, store=tmp_store).identity

    def test_explicit_identity_is_used(self, tmp_store: TokenStore):
        ident = _py_identity(grant=Grant.AUTHORIZATION_CODE, scopes=("openid",))
        assert DeviceFlow(HOST, store=tmp_store, identity=ident).identity is ident

    def test_scopes_and_identity_are_exclusive(self, tmp_store: TokenStore):
        with pytest.raises(TypeError, match="either scopes or identity"):
            DeviceFlow(HOST, store=tmp_store, scopes="openid", identity=_py_identity())

    def test_identity_for_other_host_is_refused(self, tmp_store: TokenStore):
        ident = _py_identity(host="https://b.example.com")
        with pytest.raises(ValueError, match="b.example.com"):
            DeviceFlow(HOST, store=tmp_store, identity=ident)

    def test_non_interactive_identity_is_refused(self, tmp_store: TokenStore):
        ident = _py_identity(grant=Grant.CLIENT_CREDENTIALS)
        with pytest.raises(ValueError, match="client_credentials"):
            CodeFlow(HOST, store=tmp_store, identity=ident)

    def test_legacy_sentinel_identity_is_accepted(self, tmp_store: TokenStore):
        ident = _py_identity(grant=None)
        assert DeviceFlow(HOST, store=tmp_store, identity=ident).identity is ident


class TestCacheLookup:
    """Which cached entries a flow reuses."""

    def test_no_deprecation_warning(self, tmp_store: TokenStore):
        flow = DeviceFlow(HOST, store=tmp_store)
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            assert flow.token is None
            flow._build_token(make_raw_token_response())
            assert flow.token is not None

    def test_token_saved_under_flow_identity(self, tmp_store: TokenStore):
        flow = CodeFlow(HOST, store=tmp_store)
        token = flow._build_token(make_raw_token_response())
        assert tmp_store.get(flow.identity) == token

    def test_sibling_grant_is_reused(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put(DeviceFlow(HOST, store=tmp_store).identity, token)
        assert CodeFlow(HOST, store=tmp_store).token == token

    def test_scoped_token_does_not_serve_default_login(self, tmp_store: TokenStore):
        scoped = DeviceFlow(HOST, store=tmp_store, scopes="openid")
        tmp_store.put(scoped.identity, make_token())
        assert DeviceFlow(HOST, store=tmp_store).token is None

    def test_default_token_does_not_serve_scoped_login(self, tmp_store: TokenStore):
        tmp_store.put(DeviceFlow(HOST, store=tmp_store).identity, make_token())
        assert DeviceFlow(HOST, store=tmp_store, scopes="openid").token is None

    def test_wider_scoped_token_serves_narrower_request(self, tmp_store: TokenStore):
        wide = DeviceFlow(HOST, store=tmp_store, scopes="openid email profile")
        token = make_token()
        tmp_store.put(wide.identity, token)
        assert CodeFlow(HOST, store=tmp_store, scopes="email").token == token

    def test_migrated_entry_serves_default_login(self, tmp_store: TokenStore):
        """Old host keyed entries carry the granted scopes but no grant."""
        legacy = _py_identity(grant=None, scopes=("openid", "profile"))
        token = make_token()
        tmp_store.put(legacy, token)
        assert DeviceFlow(HOST, store=tmp_store).token == token

    @pytest.mark.parametrize(
        "kwargs",
        [{"client_id": "other-client"}, {"audience": "s3"}, {"exchange": "abc"}],
    )
    def test_foreign_entries_are_ignored(self, tmp_store: TokenStore, kwargs):
        tmp_store.put(_py_identity(**kwargs), make_token())
        assert DeviceFlow(HOST, store=tmp_store).token is None

    def test_explicit_identity_reads_only_its_entry(self, tmp_store: TokenStore):
        tmp_store.put(DeviceFlow(HOST, store=tmp_store).identity, make_token())
        ident = _py_identity(scopes=("openid",))
        flow = DeviceFlow(HOST, store=tmp_store, identity=ident)
        assert flow.token is None
        token = make_token()
        tmp_store.put(ident, token)
        assert flow.token == token


class TestFromCache:
    """When the cache is not enough."""

    @pytest.mark.asyncio
    async def test_almost_expired_token_without_refresh(self, tmp_store: TokenStore):
        """Live for the store, too close to expiry to hand out."""
        flow = DeviceFlow(HOST, store=tmp_store)
        token = make_token(expires_in=45)
        token["refresh_token"] = ""
        token["refresh_expires"] = 0
        tmp_store.put(flow.identity, token)
        assert flow.token == token
        assert await flow._from_cache() is None


class TestRefreshTarget:
    """A refreshed token replaces the entry it came from."""

    @pytest.mark.asyncio
    async def test_refresh_keeps_sibling_key(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        device_identity = DeviceFlow(test_server, store=tmp_store).identity
        old = make_refresh_only_token()
        configure_server(add_refresh_token=old["refresh_token"])
        tmp_store.put(device_identity, old)
        flow = CodeFlow(test_server, store=tmp_store)
        token = await flow.authenticate()
        assert tmp_store.get(device_identity) == token
        assert tmp_store.get(flow.identity) is None

    @pytest.mark.asyncio
    async def test_refresh_moves_migrated_entry(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        legacy = AuthIdentity(test_server, "py-oidc-auth", None)
        old = make_refresh_only_token()
        configure_server(add_refresh_token=old["refresh_token"])
        tmp_store.put(legacy, old)
        flow = DeviceFlow(test_server, store=tmp_store)
        token = await flow.authenticate()
        assert tmp_store.get(flow.identity) == token

    @pytest.mark.asyncio
    async def test_public_refresh_keeps_sibling_key(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        code_identity = CodeFlow(test_server, store=tmp_store).identity
        old = make_refresh_only_token()
        configure_server(add_refresh_token=old["refresh_token"])
        tmp_store.put(code_identity, old)
        flow = DeviceFlow(test_server, store=tmp_store)
        token = await flow.refresh(old["refresh_token"])
        assert tmp_store.get(code_identity) == token
        assert tmp_store.get(flow.identity) is None

    @pytest.mark.asyncio
    async def test_public_refresh_of_unknown_token(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(add_refresh_token="rt-outside")
        flow = DeviceFlow(test_server, store=tmp_store)
        token = await flow.refresh("rt-outside")
        assert tmp_store.get(flow.identity) == token


class TestScopesRequested:
    """Requested scopes reach the server."""

    @pytest.mark.asyncio
    async def test_code_flow_sends_scope(self, tmp_store: TokenStore):
        flow = CodeFlow(HOST, store=tmp_store, scopes="email openid")
        url = await flow.provider.get_authorization_url(
            redirect_uri="http://localhost:1/callback", scope=flow._scope_param
        )
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        assert query["scope"] == ["email openid"]

    @pytest.mark.asyncio
    async def test_default_code_flow_sends_no_scope(self, tmp_store: TokenStore):
        flow = CodeFlow(HOST, store=tmp_store)
        assert flow._scope_param is None
        url = await flow.provider.get_authorization_url(
            redirect_uri="http://localhost:1/callback", scope=flow._scope_param
        )
        assert "scope=" not in url

    @pytest.mark.asyncio
    async def test_full_code_flow_with_scopes(
        self, test_server: str, tmp_store: TokenStore
    ):
        flow = CodeFlow(
            test_server,
            store=tmp_store,
            timeout=10,
            redirect_ports=[_free_port()],
            scopes="openid email",
        )
        seen = []

        def browse(url: str) -> None:
            seen.append(url)
            requests.get(url, timeout=5)

        with patch("webbrowser.open", side_effect=browse):
            token = await flow.authenticate()
        assert "scope=email+openid" in seen[0]
        assert tmp_store.get(flow.identity) == token

    @pytest.mark.asyncio
    async def test_device_flow_sends_scope(self, tmp_store: TokenStore):
        flow = DeviceFlow(HOST, store=tmp_store, scopes="openid")
        flow.provider.device_authorization = AsyncMock(
            return_value={
                "device_code": "D",
                "user_code": "U",
                "verification_uri": "https://v",
                "expires_in": 60,
            }
        )
        await flow.get_device_code()
        flow.provider.device_authorization.assert_awaited_once_with(scope="openid")

    @pytest.mark.asyncio
    async def test_missing_granted_scope_is_logged(
        self, test_server: str, tmp_store: TokenStore, configure_server, caplog
    ):
        """The test server grants 'openid profile email' whatever is asked."""
        configure_server(pending_polls=0)
        flow = DeviceFlow(
            test_server,
            store=tmp_store,
            timeout=10,
            interactive=False,
            scopes="openid admin",
        )
        code = await flow.get_device_code()
        with caplog.at_level(logging.WARNING, logger="py_oidc_auth_client.flows"):
            token = await flow.poll(code["device_code"], interval=0)
        assert "admin" in caplog.text
        assert tmp_store.get(flow.identity) == token


class TestAuthenticateIdentity:
    """authenticate() passes scopes and identity on to the flows."""

    def test_cached_token_under_explicit_identity(self, tmp_store: TokenStore):
        ident = _py_identity(scopes=("openid",))
        token = make_token()
        tmp_store.put(ident, token)
        assert authenticate(HOST, store=tmp_store, identity=ident) == token

    def test_scoped_cached_token(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put(DeviceFlow(HOST, store=tmp_store, scopes="openid").identity, token)
        assert authenticate(HOST, store=tmp_store, scopes=["openid"]) == token

    @pytest.mark.asyncio
    async def test_device_login_saved_under_identity(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(pending_polls=0)
        ident = AuthIdentity(
            test_server, "py-oidc-auth", Grant.AUTHORIZATION_CODE, scopes=("openid",)
        )
        with patch("py_oidc_auth_client.flows.pprint"):
            token = await authenticate_async(
                test_server, store=tmp_store, identity=ident, timeout=10
            )
        assert tmp_store.get(ident) == token
        assert len(tmp_store.entries()) == 1

    @pytest.mark.asyncio
    async def test_code_flow_fallback_gets_identity(self, tmp_store: TokenStore):
        ident = _py_identity(scopes=("openid",))
        token = make_token()
        no_device = AsyncMock(side_effect=AuthError("no device", status_code=503))
        with patch.object(DeviceFlow, "authenticate", no_device):
            with patch.object(CodeFlow, "_run_code_flow", autospec=True) as run:
                run.return_value = token
                result = await authenticate_async(HOST, store=tmp_store, identity=ident)
        assert result == token
        assert run.call_args.args[0].identity is ident
