"""Tests for token exchange (RFC 8693): backend, ExchangeFlow, exchange()."""

from __future__ import annotations

import time
import urllib.parse
from unittest.mock import AsyncMock, patch

import httpx
import jwt
import pytest

from py_oidc_auth_client import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_JWT,
    exchange,
    exchange_async,
)
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.flows import CodeFlow, DeviceFlow, ExchangeFlow, _subject_id
from py_oidc_auth_client.identity import AuthIdentity, Grant
from py_oidc_auth_client.token_store import TokenStore

from .conftest import (
    JWT_SECRET,
    MockTransport,
    make_raw_token_response,
    make_refresh_only_token,
    make_token,
)

HOST = "https://a.example.com"


def _form(request: httpx.Request) -> dict:
    return urllib.parse.parse_qs(request.content.decode())


def _claims(token: dict) -> dict:
    return jwt.decode(token["access_token"], options={"verify_signature": False})


def _login(host: str, store: TokenStore, **kwargs) -> DeviceFlow:
    """A device flow with a valid cached token."""
    flow = DeviceFlow(host, store=store, **kwargs)
    store.put(flow.identity, make_token())
    return flow


class TestBackendExchange:
    """PyOIDCAuth.exchange_token request shape."""

    @pytest.mark.asyncio
    async def test_form_fields(self):
        transport = MockTransport().add(200, make_raw_token_response())
        flow = DeviceFlow(HOST)
        flow.provider.session = httpx.AsyncClient(transport=transport)
        await flow.provider.exchange_token(
            subject_token="SUBJECT",
            audience="s3",
            scope="read write",
            resource="https://s3.example.com",
            requested_token_type=TOKEN_TYPE_JWT,
        )
        request = transport.requests[0]
        assert str(request.url) == f"{HOST}/auth/v2/token"
        assert _form(request) == {
            "grant_type": ["urn:ietf:params:oauth:grant-type:token-exchange"],
            "subject_token": ["SUBJECT"],
            "subject_token_type": [TOKEN_TYPE_ACCESS],
            "requested_token_type": [TOKEN_TYPE_JWT],
            "audience": ["s3"],
            "scope": ["read write"],
            "resource": ["https://s3.example.com"],
        }

    @pytest.mark.asyncio
    async def test_optional_fields_are_left_out(self):
        transport = MockTransport().add(200, make_raw_token_response())
        flow = DeviceFlow(HOST)
        flow.provider.session = httpx.AsyncClient(transport=transport)
        await flow.provider.exchange_token(subject_token="SUBJECT")
        assert set(_form(transport.requests[0])) == {
            "grant_type",
            "subject_token",
            "subject_token_type",
        }


class TestExchangeIdentity:
    """The cache key of an exchanged token."""

    def test_derived_from_subject_flow(self, tmp_store: TokenStore):
        login = DeviceFlow(HOST, store=tmp_store)
        flow = ExchangeFlow(HOST, subject=login, audience="s3", store=tmp_store)
        assert flow.identity == login.identity.for_exchange(audience="s3", scopes=())
        assert flow.identity.grant is Grant.TOKEN_EXCHANGE

    def test_default_subject_is_device_login_on_host(self, tmp_store: TokenStore):
        flow = ExchangeFlow(HOST, store=tmp_store, token_route="/x/token")
        assert isinstance(flow.subject, DeviceFlow)
        assert flow.subject.identity == DeviceFlow(HOST, store=tmp_store).identity
        assert flow.subject.provider.config.token_route == "/x/token"
        assert flow.subject.store is tmp_store

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"audience": "other"},
            {"scopes": "read"},
            {"resource": "https://r"},
            {"requested_token_type": TOKEN_TYPE_JWT},
        ],
    )
    def test_parameters_change_key(self, tmp_store: TokenStore, kwargs):
        login = DeviceFlow(HOST, store=tmp_store)
        base = ExchangeFlow(HOST, subject=login, audience="s3", store=tmp_store)
        kwargs = {"audience": "s3", **kwargs}
        other = ExchangeFlow(HOST, subject=login, store=tmp_store, **kwargs)
        assert base.identity.digest != other.identity.digest

    def test_cross_host_key(self, tmp_store: TokenStore):
        login = DeviceFlow("https://b.example.com", store=tmp_store)
        flow = ExchangeFlow(HOST, subject=login, store=tmp_store)
        assert flow.identity.host == HOST
        assert flow._parent == login.identity

    def test_identity_subject(self, tmp_store: TokenStore):
        ident = AuthIdentity(HOST, "py-oidc-auth", Grant.DEVICE_CODE)
        flow = ExchangeFlow(HOST, subject=ident, store=tmp_store)
        assert flow.identity == ident.for_exchange(scopes=())
        assert flow._parent == ident

    def test_string_subject_key_survives_renewal(self, tmp_store: TokenStore):
        first = make_token(subject="alice")["access_token"]
        time.sleep(1.1)
        renewed = make_token(subject="alice")["access_token"]
        assert first != renewed
        a = ExchangeFlow(HOST, subject=first, store=tmp_store)
        b = ExchangeFlow(HOST, subject=renewed, store=tmp_store)
        c = ExchangeFlow(
            HOST, subject=make_token(subject="bob")["access_token"], store=tmp_store
        )
        assert a.identity == b.identity
        assert a.identity != c.identity
        assert a._parent is None

    def test_explicit_identity(self, tmp_store: TokenStore):
        ident = DeviceFlow(HOST, store=tmp_store).identity.for_exchange(audience="x")
        flow = ExchangeFlow(HOST, store=tmp_store, identity=ident)
        assert flow.identity is ident

    def test_explicit_identity_with_scopes(self, tmp_store: TokenStore):
        ident = DeviceFlow(HOST, store=tmp_store).identity.for_exchange()
        with pytest.raises(TypeError):
            ExchangeFlow(HOST, store=tmp_store, identity=ident, scopes="openid")

    def test_explicit_identity_other_host(self, tmp_store: TokenStore):
        ident = DeviceFlow("https://b.example.com", store=tmp_store).identity
        with pytest.raises(ValueError, match="b.example.com"):
            ExchangeFlow(HOST, store=tmp_store, identity=ident.for_exchange())

    def test_explicit_identity_wrong_grant(self, tmp_store: TokenStore):
        ident = DeviceFlow(HOST, store=tmp_store).identity
        with pytest.raises(ValueError, match="token_exchange"):
            ExchangeFlow(HOST, store=tmp_store, identity=ident)


class TestSubjectId:
    """Stable identifiers for external subject tokens."""

    def test_jwt_uses_stable_claims(self):
        a = jwt.encode({"sub": "u", "iss": "i", "exp": 1}, JWT_SECRET)
        b = jwt.encode({"sub": "u", "iss": "i", "exp": 2}, JWT_SECRET)
        assert _subject_id(a) == _subject_id(b)
        assert _subject_id(a) != _subject_id(jwt.encode({"sub": "v"}, JWT_SECRET))

    def test_opaque_token_is_hashed(self):
        assert _subject_id("opaque") == _subject_id("opaque")
        assert _subject_id("opaque") != _subject_id("other")
        assert len(_subject_id("opaque")) == 16

    def test_jwt_without_sub_is_hashed(self):
        token = jwt.encode({"iss": "i"}, JWT_SECRET)
        assert _subject_id(token) != _subject_id(jwt.encode({"iss": "j"}, JWT_SECRET))

    def test_garbage_payload_is_hashed(self):
        assert len(_subject_id("a.!!!.c")) == 16


class TestExchangeFlow:
    """Exchanges against the test server."""

    @pytest.mark.asyncio
    async def test_exchange_and_cache(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        login = _login(test_server, tmp_store)
        flow = ExchangeFlow(
            test_server, subject=login, audience="s3", scopes="read", store=tmp_store
        )
        token = await flow.authenticate()
        assert _claims(token)["aud"] == "s3"
        assert token["issued_token_type"] == TOKEN_TYPE_ACCESS
        assert token["refresh_token"] == ""
        assert token["refresh_expires"] == 0
        sent = exchanges()
        assert len(sent) == 1
        assert sent[0]["subject_token"] == tmp_store.get(login.identity)["access_token"]
        assert sent[0]["scope"] == "read"
        entry = tmp_store.get_entry(flow.identity)
        assert entry.token == token
        assert entry.parent == login.identity.digest
        # Cached: no second exchange
        assert await flow.authenticate() == token
        assert len(exchanges()) == 1

    @pytest.mark.asyncio
    async def test_force_exchanges_again(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        flow = ExchangeFlow(test_server, subject=_login(test_server, tmp_store))
        flow.store = tmp_store
        first = await flow.authenticate()
        second = await flow.authenticate(force=True)
        assert first != second
        assert len(exchanges()) == 2

    @pytest.mark.asyncio
    async def test_expired_token_is_minted_again(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        login = _login(test_server, tmp_store)
        flow = ExchangeFlow(test_server, subject=login, store=tmp_store)
        token = await flow.authenticate()
        token["expires"] = int(time.time()) - 10
        tmp_store.put(flow.identity, token, parent=login.identity)
        new = await flow.authenticate()
        assert new["access_token"] != token["access_token"]
        assert len(exchanges()) == 2

    @pytest.mark.asyncio
    async def test_subject_is_refreshed_first(
        self, test_server: str, tmp_store: TokenStore, configure_server, exchanges
    ):
        login = DeviceFlow(test_server, store=tmp_store)
        old = make_refresh_only_token()
        configure_server(add_refresh_token=old["refresh_token"])
        tmp_store.put(login.identity, old)
        flow = ExchangeFlow(test_server, subject=login, store=tmp_store)
        await flow.authenticate()
        refreshed = tmp_store.get(login.identity)
        assert refreshed["access_token"] != old["access_token"]
        assert exchanges()[0]["subject_token"] == refreshed["access_token"]

    @pytest.mark.asyncio
    async def test_parent_is_the_entry_holding_the_subject_token(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        """A code flow subject served by a cached device login."""
        device = _login(test_server, tmp_store)
        code = CodeFlow(test_server, store=tmp_store)
        flow = ExchangeFlow(test_server, subject=code, store=tmp_store)
        await flow.authenticate()
        assert tmp_store.get_entry(flow.identity).parent == device.identity.digest
        # Logging out of the device login drops the exchanged token too
        assert tmp_store.remove(device.identity) == 2
        assert tmp_store.get(flow.identity) is None

    @pytest.mark.asyncio
    async def test_subject_token_not_from_store(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        """A subject flow whose token is not cached keeps its own identity."""
        login = DeviceFlow(test_server, store=tmp_store)
        outside = make_token(subject="frank")
        with patch.object(login, "authenticate", AsyncMock(return_value=outside)):
            flow = ExchangeFlow(test_server, subject=login, store=tmp_store)
            await flow.authenticate()
        assert exchanges()[0]["subject_token"] == outside["access_token"]
        assert tmp_store.get_entry(flow.identity).parent == login.identity.digest

    @pytest.mark.asyncio
    async def test_cross_host_exchange(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        """A token of another server exchanged here (federation)."""
        login = _login("https://peer.example.com", tmp_store)
        flow = ExchangeFlow(test_server, subject=login, store=tmp_store)
        token = await flow.authenticate()
        assert tmp_store.get(flow.identity) == token
        assert len(exchanges()) == 1

    @pytest.mark.asyncio
    async def test_chained_exchange(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        login = _login(test_server, tmp_store)
        first = ExchangeFlow(test_server, subject=login, audience="a", store=tmp_store)
        second = ExchangeFlow(test_server, subject=first, audience="b", store=tmp_store)
        token = await second.authenticate()
        assert _claims(token)["aud"] == "b"
        assert len(exchanges()) == 2
        assert tmp_store.get_entry(second.identity).parent == first.identity.digest

    @pytest.mark.asyncio
    async def test_string_subject(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        subject = make_token(subject="carol")["access_token"]
        flow = ExchangeFlow(test_server, subject=subject, store=tmp_store)
        token = await flow.authenticate()
        assert _claims(token)["sub"] == "carol"
        assert exchanges()[0]["subject_token"] == subject
        assert tmp_store.get_entry(flow.identity).parent is None

    @pytest.mark.asyncio
    async def test_refused_exchange(self, test_server: str, tmp_store: TokenStore):
        flow = ExchangeFlow(
            test_server,
            subject=_login(test_server, tmp_store),
            audience="forbidden",
            store=tmp_store,
        )
        with pytest.raises(AuthError, match="no way") as exc_info:
            await flow.authenticate()
        assert exc_info.value.error == "invalid_target"
        assert tmp_store.get(flow.identity) is None


class TestIdentitySubject:
    """Subjects named by the identity of a cached token."""

    @pytest.mark.asyncio
    async def test_cached_subject(self, test_server: str, tmp_store: TokenStore):
        login = _login(test_server, tmp_store)
        flow = ExchangeFlow(test_server, subject=login.identity, store=tmp_store)
        token = await flow.authenticate()
        assert tmp_store.get_entry(flow.identity).parent == login.identity.digest
        assert token["issued_token_type"] == TOKEN_TYPE_ACCESS

    @pytest.mark.asyncio
    async def test_subject_is_refreshed(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        ident = DeviceFlow(test_server, store=tmp_store).identity
        old = make_refresh_only_token()
        configure_server(add_refresh_token=old["refresh_token"])
        tmp_store.put(ident, old)
        flow = ExchangeFlow(test_server, subject=ident, store=tmp_store)
        await flow.authenticate()
        assert tmp_store.get(ident)["access_token"] != old["access_token"]

    @pytest.mark.asyncio
    async def test_subject_on_other_host(
        self, test_server: str, tmp_store: TokenStore
    ):
        login = _login("https://peer.example.com", tmp_store)
        flow = ExchangeFlow(test_server, subject=login.identity, store=tmp_store)
        assert "access_token" in await flow.authenticate()

    @pytest.mark.asyncio
    async def test_missing_subject(self, test_server: str, tmp_store: TokenStore):
        ident = DeviceFlow(test_server, store=tmp_store).identity
        flow = ExchangeFlow(test_server, subject=ident, store=tmp_store)
        with pytest.raises(AuthError, match="authenticate first") as exc_info:
            await flow.authenticate()
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_exchanged_subject(self, test_server: str, tmp_store: TokenStore):
        login = _login(test_server, tmp_store)
        first = ExchangeFlow(test_server, subject=login, audience="a", store=tmp_store)
        await first.authenticate()
        second = ExchangeFlow(
            test_server, subject=first.identity, audience="b", store=tmp_store
        )
        assert _claims(await second.authenticate())["aud"] == "b"

    @pytest.mark.asyncio
    async def test_missing_exchanged_subject(
        self, test_server: str, tmp_store: TokenStore
    ):
        ident = DeviceFlow(test_server, store=tmp_store).identity.for_exchange()
        flow = ExchangeFlow(test_server, subject=ident, store=tmp_store)
        with pytest.raises(AuthError, match="authenticate first"):
            await flow.authenticate()


class TestExchangeFunctions:
    """exchange() and exchange_async()."""

    def test_exchange_with_default_subject(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        login = _login(test_server, tmp_store)
        token = exchange(test_server, audience="s3", store=tmp_store)
        assert _claims(token)["aud"] == "s3"
        sent = exchanges()[0]
        assert sent["subject_token"] == tmp_store.get(login.identity)["access_token"]

    @pytest.mark.asyncio
    async def test_exchange_async_passes_everything(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        subject = make_token(subject="dave")["access_token"]
        token = await exchange_async(
            test_server,
            subject=subject,
            audience="s3",
            scopes=["read", "write"],
            resource="https://s3.example.com",
            requested_token_type=TOKEN_TYPE_JWT,
            store=tmp_store,
        )
        assert token["issued_token_type"] == TOKEN_TYPE_JWT
        sent = exchanges()[0]
        assert sent["scope"] == "read write"
        assert sent["resource"] == "https://s3.example.com"
        again = await exchange_async(
            test_server,
            subject=subject,
            audience="s3",
            scopes="write read",
            resource="https://s3.example.com",
            requested_token_type=TOKEN_TYPE_JWT,
            store=tmp_store,
        )
        assert again == token
        assert len(exchanges()) == 1

    @pytest.mark.asyncio
    async def test_exchange_async_default_store(
        self, test_server: str, tmp_path, monkeypatch, exchanges
    ):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        subject = make_token(subject="erin")["access_token"]
        token = await exchange_async(test_server, subject=subject, app_name="xtest")
        store = TokenStore(app_name="xtest")
        assert store.path.is_relative_to(tmp_path)
        assert store.entries()[0].token == token


class TestForExchange:
    """AuthIdentity.for_exchange additions."""

    def test_host(self):
        parent = AuthIdentity(HOST, "py-oidc-auth", Grant.DEVICE_CODE)
        child = parent.for_exchange(host="https://Peer.example.com:443/")
        assert child.host == "https://peer.example.com"
        assert child.digest != parent.for_exchange().digest

    def test_resource(self):
        parent = AuthIdentity(HOST, "py-oidc-auth", Grant.DEVICE_CODE)
        assert (
            parent.for_exchange(resource="https://r").digest
            != parent.for_exchange().digest
        )


def test_jwt_secret_is_shared():
    """The exchange tests rely on the server decoding make_token() JWTs."""
    assert jwt.decode(make_token()["access_token"], JWT_SECRET, algorithms=["HS256"])
