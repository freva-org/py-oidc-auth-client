"""Tests for plain OpenID Connect providers: Config, OIDCBackend, flows, CLI."""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from py_oidc_auth_client import Config, authenticate, authenticate_async
from py_oidc_auth_client.__main__ import main
from py_oidc_auth_client.backends import OIDCBackend, PyOIDCAuth, make_backend
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.flows import (
    ClientCredentialsFlow,
    CodeFlow,
    DeviceFlow,
    ExchangeFlow,
    LoginFlow,
)
from py_oidc_auth_client.identity import AuthIdentity, Grant, normalise_host
from py_oidc_auth_client.token_store import TokenStore

from . import fake_idp
from .test_flows import _free_port


def _config(issuer: str, **kwargs) -> Config:
    kwargs.setdefault("client_id", "public-cli")
    return Config.from_discovery(issuer, **kwargs)


def _browse(url: str) -> None:
    requests.get(url, timeout=5)


def _write_key(path: Path, key) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def _cli(store: TokenStore, argv, env=None):
    with patch("py_oidc_auth_client.__main__.TokenStore", return_value=store):
        with patch.dict("os.environ", env or {}, clear=False):
            with patch("py_oidc_auth_client.flows.pprint"):
                return main(argv)


class TestConfig:
    """Config.from_discovery and the oidc helpers."""

    def test_issuer_url(self):
        cfg = Config.from_discovery("https://kc.example.org/realms/freva/")
        assert cfg.backend == "oidc"
        assert cfg.host == "https://kc.example.org/realms/freva"
        assert cfg.discovery_document_url == (
            "https://kc.example.org/realms/freva/.well-known/openid-configuration"
        )
        assert cfg.effective_client_id == cfg.app_name

    def test_document_url(self):
        url = "https://kc.example.org/realms/freva/.well-known/openid-configuration"
        cfg = Config.from_discovery(url, client_id="cli", scopes=["openid", "email"])
        assert cfg.host == "https://kc.example.org/realms/freva"
        assert cfg.discovery_document_url == url
        assert cfg.effective_client_id == "cli"
        assert cfg.scopes == ["openid", "email"]

    def test_redirect_ports(self):
        cfg = Config.from_discovery("https://kc/realms/a", redirect_ports=[1234])
        assert cfg.redirect_ports == [1234]

    def test_client_auth(self):
        assert Config.from_discovery("https://kc/r").client_auth is None
        assert Config.from_discovery("https://kc/r", client_secret="s").client_auth == (
            "client_secret"
        )
        assert Config.from_discovery("https://kc/r", server_key="k").client_auth == (
            "private_key_jwt"
        )
        assert Config(host="https://h", client_secret="s").client_auth is None

    def test_make_backend(self):
        assert isinstance(make_backend(Config(host="https://h")), PyOIDCAuth)
        assert isinstance(make_backend(Config.from_discovery("https://kc/r")), OIDCBackend)


class TestIdentity:
    """oidc identities keep the issuer path; py-oidc-auth ones do not."""

    def test_realms_are_told_apart(self):
        a = AuthIdentity("https://kc/realms/a", "oidc", Grant.DEVICE_CODE, client_id="x")
        b = AuthIdentity("https://kc/realms/b", "oidc", Grant.DEVICE_CODE, client_id="x")
        assert a.host == "https://kc/realms/a"
        assert a.digest != b.digest

    def test_py_oidc_auth_keys_unchanged(self):
        ident = AuthIdentity("https://h/api/x", "py-oidc-auth", Grant.DEVICE_CODE)
        assert ident.host == "https://h"

    def test_normalise_host(self):
        assert normalise_host("https://H/a/", keep_path=True) == "https://h/a"
        assert normalise_host("https://H/a/") == "https://h"

    def test_find_and_remove_by_issuer(self, tmp_store: TokenStore):
        ident = AuthIdentity("https://kc/realms/a", "oidc", Grant.DEVICE_CODE)
        other = AuthIdentity("https://kc/realms/b", "oidc", Grant.DEVICE_CODE)
        tmp_store.put(ident, {"access_token": "a", "expires": int(time.time()) + 600})
        tmp_store.put(other, {"access_token": "b", "expires": int(time.time()) + 600})
        assert [e.identity for e in tmp_store.find(host="https://kc/realms/a/")] == [
            ident
        ]
        assert tmp_store.remove("https://kc/realms/a") == 1
        assert tmp_store.get(other) is not None

    def test_flow_identity(self, tmp_store: TokenStore):
        cfg = Config.from_discovery("https://kc/realms/a", client_id="cli", client_secret="s")
        flow = DeviceFlow(config=cfg, store=tmp_store, scopes="openid")
        assert flow.identity == AuthIdentity(
            "https://kc/realms/a",
            "oidc",
            Grant.DEVICE_CODE,
            client_id="cli",
            scopes=("openid",),
            client_auth="client_secret",
        )

    def test_explicit_identity_for_other_realm(self, tmp_store: TokenStore):
        cfg = Config.from_discovery("https://kc/realms/a", client_id="cli")
        ident = AuthIdentity("https://kc/realms/b", "oidc", Grant.DEVICE_CODE)
        with pytest.raises(ValueError, match="realms/b"):
            DeviceFlow(config=cfg, store=tmp_store, identity=ident)


class TestDiscovery:
    """Fetching the discovery document."""

    @pytest.mark.asyncio
    async def test_fetched_once(self, issuer: str, idp):
        backend = OIDCBackend(_config(issuer))
        first = await backend.discovery()
        assert first["issuer"] == issuer
        assert await backend.discovery() is first
        assert idp.discovery_hits == 1

    @pytest.mark.parametrize("path", ["/_test/exchanges"])
    @pytest.mark.asyncio
    async def test_not_a_discovery_document(self, test_server: str, path: str):
        """A JSON list instead of an object."""
        cfg = Config(host=test_server, backend="oidc", discovery_url=test_server + path)
        with pytest.raises(AuthError, match="no OpenID Connect discovery document"):
            await OIDCBackend(cfg).discovery()

    @pytest.mark.asyncio
    async def test_document_without_token_endpoint(self, issuer: str):
        cfg = Config(
            host=issuer, backend="oidc", discovery_url=f"{issuer}/protocol/openid-connect/x"
        )
        with pytest.raises(AuthError):
            await OIDCBackend(cfg).discovery()

    @pytest.mark.asyncio
    async def test_unreachable(self):
        backend = OIDCBackend(Config.from_discovery("http://127.0.0.1:9/realms/x"))
        with pytest.raises(AuthError, match="Cannot reach") as exc_info:
            await backend.discovery()
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_unreachable_post(self):
        backend = OIDCBackend(Config.from_discovery("http://127.0.0.1:9/realms/x"))
        with pytest.raises(AuthError, match="Cannot reach"):
            await backend.post_form("http://127.0.0.1:9/token", {"a": "b"})


class TestCacheSeparation:
    """Logins of different clients or auth methods never mix."""

    def test_other_client_auth_is_ignored(self, tmp_store: TokenStore):
        public = DeviceFlow(config=_config("https://kc/realms/a"), store=tmp_store)
        tmp_store.put(public.identity, {"access_token": "t",
                                        "expires": int(time.time()) + 600})
        secret = DeviceFlow(
            config=_config("https://kc/realms/a", client_secret="s"), store=tmp_store
        )
        other = DeviceFlow(
            config=_config("https://kc/realms/a", client_id="other"), store=tmp_store
        )
        assert public.token is not None
        assert secret.token is None
        assert other.token is None


class TestPublicClient:
    """A public client: PKCE only."""

    @pytest.mark.asyncio
    async def test_device_flow(self, issuer: str, idp, tmp_store: TokenStore):
        flow = DeviceFlow(config=_config(issuer), store=tmp_store, timeout=10,
                          interactive=False)
        code = await flow.get_device_code()
        token = await flow.poll(code["device_code"], interval=0)
        assert token["scope"] == "openid"
        assert tmp_store.get(flow.identity) == token
        assert flow.identity.host == issuer
        sent = idp.requests[-1]
        assert sent["authorization"] is None
        assert sent["form"]["client_id"] == "public-cli"
        assert "code_verifier" in sent["form"]

    @pytest.mark.asyncio
    async def test_code_flow(self, issuer: str, idp, tmp_store: TokenStore):
        flow = CodeFlow(
            config=_config(issuer, redirect_ports=[_free_port()]),
            store=tmp_store,
            timeout=10,
            scopes="openid email",
        )
        seen = []

        def browse(url: str) -> None:
            seen.append(url)
            _browse(url)

        with patch("webbrowser.open", side_effect=browse):
            token = await flow.authenticate()
        query = urllib.parse.parse_qs(urllib.parse.urlparse(seen[0]).query)
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["public-cli"]
        assert query["scope"] == ["email openid"]
        assert query["code_challenge_method"] == ["S256"]
        assert token["scope"] == "email openid"

    @pytest.mark.asyncio
    async def test_foreign_state_is_refused(self, issuer: str):
        backend = OIDCBackend(_config(issuer))
        with pytest.raises(AuthError, match="state mismatch"):
            await backend.exchange_authorization_code(
                redirect_uri="http://localhost:1/callback", code="c", state="nope"
            )

    @pytest.mark.asyncio
    async def test_refresh_through_login_flow(self, issuer: str, idp, tmp_store: TokenStore):
        cfg = _config(issuer)
        device = DeviceFlow(config=cfg, store=tmp_store, timeout=10, interactive=False)
        code = await device.get_device_code()
        token = await device.poll(code["device_code"], interval=0)
        token["expires"] = int(time.time()) - 10
        tmp_store.put(device.identity, token)
        refreshed = await LoginFlow(config=cfg, store=tmp_store).authenticate()
        assert refreshed["access_token"] != token["access_token"]
        assert idp.requests[-1]["form"]["grant_type"] == "refresh_token"

    @pytest.mark.asyncio
    async def test_no_device_endpoint_falls_back_to_code_flow(
        self, issuer: str, idp, tmp_store: TokenStore
    ):
        idp.device_enabled = False
        flow = LoginFlow(
            config=_config(issuer, redirect_ports=[_free_port()]),
            store=tmp_store,
            timeout=10,
        )
        with patch("webbrowser.open", side_effect=_browse):
            token = await flow.authenticate()
        assert idp.requests[-1]["form"]["grant_type"] == "authorization_code"
        code_identity = CodeFlow(config=_config(issuer), store=tmp_store).identity
        assert tmp_store.get(code_identity) == token

    @pytest.mark.asyncio
    async def test_no_device_endpoint_error(self, issuer: str, idp):
        idp.device_enabled = False
        with pytest.raises(AuthError, match="offers no device flow") as exc_info:
            await OIDCBackend(_config(issuer)).device_authorization()
        assert exc_info.value.status_code == 501

    @pytest.mark.asyncio
    async def test_no_authorization_endpoint(self, issuer: str):
        backend = OIDCBackend(_config(issuer))
        await backend.discovery()
        backend._discovery.pop("authorization_endpoint")  # type: ignore[union-attr]
        with pytest.raises(AuthError, match="offers no code flow"):
            await backend.get_authorization_url(redirect_uri="http://localhost/cb")


class TestClientSecret:
    """Confidential clients with a secret."""

    @pytest.mark.asyncio
    async def test_basic_auth_with_encoded_secret(self, issuer: str, idp):
        cfg = _config(issuer, client_id="conf", client_secret="s3:cr/et x")
        token = await OIDCBackend(cfg).client_credentials()
        assert token["access_token"]
        header = idp.requests[-1]["authorization"]
        decoded = base64.b64decode(header.split()[1]).decode()
        assert decoded == "conf:s3%3Acr%2Fet%20x"
        assert "client_secret" not in idp.requests[-1]["form"]

    @pytest.mark.asyncio
    async def test_post_when_basic_is_not_offered(self, issuer: str, idp):
        idp.auth_methods = ["client_secret_post", "private_key_jwt"]
        cfg = _config(issuer, client_id="conf", client_secret="s3:cr/et x")
        await OIDCBackend(cfg).client_credentials(scope="api")
        sent = idp.requests[-1]
        assert sent["authorization"] is None
        assert sent["form"]["client_secret"] == "s3:cr/et x"
        assert sent["form"]["scope"] == "api"

    @pytest.mark.asyncio
    async def test_wrong_secret(self, issuer: str):
        cfg = _config(issuer, client_id="conf", client_secret="wrong")
        with pytest.raises(AuthError) as exc_info:
            await OIDCBackend(cfg).client_credentials()
        assert exc_info.value.error == "invalid_client"

    @pytest.mark.asyncio
    async def test_device_flow_with_secret(self, issuer: str, idp, tmp_store: TokenStore):
        cfg = _config(issuer, client_id="conf", client_secret="s3:cr/et x")
        flow = DeviceFlow(config=cfg, store=tmp_store, timeout=10, interactive=False)
        code = await flow.get_device_code()
        await flow.poll(code["device_code"], interval=0)
        assert idp.requests[-1]["authorization"].startswith("Basic ")


class TestPrivateKeyJwt:
    """private_key_jwt client authentication (RFC 7523)."""

    @pytest.mark.parametrize(
        "make_key",
        [
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
            lambda: ec.generate_private_key(ec.SECP256R1()),
            lambda: ec.generate_private_key(ec.SECP384R1()),
            lambda: ed25519.Ed25519PrivateKey.generate(),
        ],
        ids=["rsa", "p256", "p384", "ed25519"],
    )
    @pytest.mark.asyncio
    async def test_signed_assertion(self, issuer: str, idp, tmp_path: Path, make_key):
        key = make_key()
        idp.clients["svc"] = fake_idp.Client(public_key=key.public_key())
        cfg = _config(
            issuer,
            client_id="svc",
            server_key=_write_key(tmp_path / "svc.pem", key),
            key_id="key-1",
        )
        token = await OIDCBackend(cfg).client_credentials()
        assert token["access_token"]
        form = idp.requests[-1]["form"]
        assert form["client_assertion_type"].endswith("jwt-bearer")
        header = jwt.get_unverified_header(form["client_assertion"])
        assert header["kid"] == "key-1"

    @pytest.mark.asyncio
    async def test_unreadable_key(self, issuer: str, tmp_path: Path):
        cfg = _config(issuer, client_id="svc", server_key=tmp_path / "missing.pem")
        with pytest.raises(AuthError, match="Cannot read the private key"):
            await OIDCBackend(cfg).client_credentials()

    @pytest.mark.asyncio
    async def test_unsupported_key_type(self, issuer: str, tmp_path: Path):
        key = dsa.generate_private_key(key_size=1024)
        cfg = _config(issuer, client_id="svc", server_key=_write_key(tmp_path / "k", key))
        with pytest.raises(AuthError, match="RSA, EC or Ed25519"):
            await OIDCBackend(cfg).client_credentials()


class TestClientCredentialsFlow:
    """Tokens for the client itself."""

    @pytest.mark.asyncio
    async def test_cached(self, issuer: str, idp, tmp_store: TokenStore):
        cfg = _config(issuer, client_id="conf", client_secret="s3:cr/et x")
        flow = ClientCredentialsFlow(config=cfg, store=tmp_store, scopes="api")
        token = await flow.authenticate()
        assert await flow.authenticate() == token
        assert len(idp.requests) == 1
        assert flow.identity.grant is Grant.CLIENT_CREDENTIALS
        assert jwt.decode(token["access_token"], options={"verify_signature": False})[
            "sub"
        ] == "service-account-conf"

    @pytest.mark.asyncio
    async def test_public_client(self, issuer: str, tmp_store: TokenStore):
        flow = ClientCredentialsFlow(config=_config(issuer), store=tmp_store)
        with pytest.raises(AuthError, match="needs a client secret or a key"):
            await flow.authenticate()

    @pytest.mark.asyncio
    async def test_py_oidc_auth_server(self, tmp_store: TokenStore):
        flow = ClientCredentialsFlow("https://a.example.com", store=tmp_store)
        with pytest.raises(AuthError, match="does not support") as exc_info:
            await flow.authenticate()
        assert exc_info.value.status_code == 501

    def test_identity_checks(self, tmp_store: TokenStore):
        cfg = _config("https://kc/realms/a")
        good = AuthIdentity("https://kc/realms/a", "oidc", Grant.CLIENT_CREDENTIALS)
        assert ClientCredentialsFlow(config=cfg, store=tmp_store, identity=good).identity == good
        with pytest.raises(ValueError, match="client_credentials identity"):
            ClientCredentialsFlow(
                config=cfg,
                store=tmp_store,
                identity=AuthIdentity("https://kc/realms/a", "oidc", Grant.DEVICE_CODE),
            )
        with pytest.raises(TypeError):
            ClientCredentialsFlow(config=cfg, store=tmp_store, identity=good, scopes="a")
        with pytest.raises(ValueError, match="realms/b"):
            ClientCredentialsFlow(
                config=cfg,
                store=tmp_store,
                identity=AuthIdentity("https://kc/realms/b", "oidc", Grant.CLIENT_CREDENTIALS),
            )


class TestExchangeAtProvider:
    """RFC 8693 at the provider, and across backends."""

    @pytest.mark.asyncio
    async def test_exchange_at_provider(self, issuer: str, idp, tmp_store: TokenStore):
        cfg = _config(issuer, client_id="conf", client_secret="s3:cr/et x")
        login = DeviceFlow(config=cfg, store=tmp_store, timeout=10, interactive=False)
        code = await login.get_device_code()
        await login.poll(code["device_code"], interval=0)
        flow = ExchangeFlow(config=cfg, subject=login, audience="api", store=tmp_store)
        token = await flow.authenticate()
        assert token["issued_token_type"].endswith("access_token")
        assert idp.requests[-1]["form"]["audience"] == "api"
        assert flow.identity.backend == "oidc"
        assert flow.identity.client_id == "conf"

    @pytest.mark.asyncio
    async def test_oidc_login_exchanged_at_py_oidc_auth_server(
        self, test_server: str, issuer: str, idp, tmp_store: TokenStore, exchanges
    ):
        login = DeviceFlow(config=_config(issuer), store=tmp_store, timeout=10,
                           interactive=False)
        code = await login.get_device_code()
        await login.poll(code["device_code"], interval=0)
        flow = ExchangeFlow(test_server, subject=login, store=tmp_store)
        await flow.authenticate()
        assert flow.identity.backend == "py-oidc-auth"
        assert flow.identity.host == test_server
        assert flow.identity.client_id is None
        assert tmp_store.get_entry(flow.identity).parent == login.identity.digest


class TestPublicFunctions:
    """authenticate() and exchange() with config=."""

    def test_authenticate_with_config(self, issuer: str, idp, tmp_store: TokenStore):
        with patch("py_oidc_auth_client.flows.pprint"):
            token = authenticate(config=_config(issuer), store=tmp_store, timeout=10)
        assert token["scope"] == "openid"

    @pytest.mark.asyncio
    async def test_host_or_config_required(self):
        with pytest.raises(ValueError, match="host or a config"):
            await authenticate_async()


class TestCli:
    """--discovery-url and friends."""

    def test_device_login(self, issuer: str, idp, tmp_store: TokenStore, capsys):
        rc = _cli(tmp_store, ["--discovery-url", issuer, "--client-id", "public-cli"])
        assert rc == 0
        assert f"Authenticated to {issuer}" in capsys.readouterr().out
        assert tmp_store.entries()[0].identity.backend == "oidc"

    def test_client_credentials_from_env(self, issuer: str, idp, tmp_store: TokenStore, capsys):
        rc = _cli(
            tmp_store,
            [
                f"--discovery-url={issuer}/.well-known/openid-configuration",
                "--client-id",
                "conf",
                "--flow",
                "client-credentials",
                "--json",
            ],
            env={"OIDC_CLIENT_SECRET": "s3:cr/et x"},
        )
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["access_token"]

    def test_client_secret_file(self, issuer: str, idp, tmp_store: TokenStore, tmp_path):
        secret = tmp_path / "secret"
        secret.write_text("s3:cr/et x\n")
        rc = _cli(
            tmp_store,
            ["--discovery-url", issuer, "--client-id", "conf",
             "--client-secret-file", str(secret), "--flow", "client-credentials"],
        )
        assert rc == 0

    def test_client_secret_flag_warns(self, issuer: str, idp, tmp_store: TokenStore, capsys):
        rc = _cli(
            tmp_store,
            ["--discovery-url", issuer, "--client-id", "conf",
             "--client-secret", "s3:cr/et x", "--flow", "client-credentials"],
        )
        assert rc == 0
        assert "visible to other users" in capsys.readouterr().err

    def test_exchange_at_provider(self, issuer: str, idp, tmp_store: TokenStore, capsys):
        env = {"OIDC_CLIENT_SECRET": "s3:cr/et x"}
        assert _cli(tmp_store, ["--discovery-url", issuer, "--client-id", "conf"], env) == 0
        rc = _cli(
            tmp_store,
            ["--discovery-url", issuer, "--client-id", "conf", "--audience", "api"],
            env,
        )
        assert rc == 0
        assert f"Exchanged a token at {issuer}" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "argv, message",
        [
            (["https://a.example.com", "--client-id", "x"], "only work with --discovery-url"),
            (["https://a", "--discovery-url", "https://kc/r"], "either HOST or --discovery-url"),
            (["https://a.example.com", "--flow", "client-credentials"], "needs --discovery-url"),
        ],
    )
    def test_usage_errors(self, tmp_store: TokenStore, capsys, argv, message):
        with pytest.raises(SystemExit):
            _cli(tmp_store, argv)
        assert message in capsys.readouterr().err

    def test_failure_message(self, tmp_store: TokenStore, capsys):
        rc = _cli(tmp_store, ["--discovery-url", "http://127.0.0.1:9/realms/x"])
        assert rc == 1
        assert "Authentication failed: Cannot reach" in capsys.readouterr().err
