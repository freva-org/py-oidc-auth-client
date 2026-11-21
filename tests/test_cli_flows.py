"""Tests for choosing the flow on the command line and for LoginFlow."""

from __future__ import annotations

import io
import json
from unittest.mock import AsyncMock, patch

import jwt
import pytest
import requests

from py_oidc_auth_client.__main__ import main
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.flows import (
    CodeFlow,
    DeviceFlow,
    LoginFlow,
    device_flow_unavailable,
)
from py_oidc_auth_client.token_store import TokenStore
from py_oidc_auth_client.types import TOKEN_TYPE_ID, TOKEN_TYPE_JWT

from .conftest import make_token
from .test_flows import _free_port


def _cli(store: TokenStore, argv, stdin: str = ""):
    with patch("py_oidc_auth_client.__main__.TokenStore", return_value=store):
        with patch("sys.stdin", io.StringIO(stdin)):
            return main(argv)


def _login(host: str, store: TokenStore) -> DeviceFlow:
    flow = DeviceFlow(host, store=store)
    store.put(flow.identity, make_token())
    return flow


def _browse(url: str) -> None:
    requests.get(url, timeout=5)


class TestDeviceFlowUnavailable:
    """Which errors make LoginFlow fall back to the code flow."""

    @pytest.mark.parametrize("status", [404, 405, 501, 503])
    def test_missing_endpoint(self, status):
        assert device_flow_unavailable(AuthError("x", status_code=status))

    @pytest.mark.parametrize("code", ["unauthorized_client", "unsupported_grant_type"])
    def test_client_may_not(self, code):
        assert device_flow_unavailable(
            AuthError("x", detail={"error": code}, status_code=400)
        )

    @pytest.mark.parametrize(
        "error",
        [
            AuthError("x", detail={"error": "access_denied"}, status_code=400),
            AuthError("Login did not complete within the allotted time"),
            AuthError("x", status_code=401),
        ],
    )
    def test_login_failures_do_not_fall_back(self, error):
        assert not device_flow_unavailable(error)


class TestLoginFlow:
    """Device first, code flow where the server has no device flow."""

    @pytest.mark.asyncio
    async def test_cached_token(self, tmp_store: TokenStore):
        _login("https://a.example.com", tmp_store)
        flow = LoginFlow("https://a.example.com", store=tmp_store)
        assert await flow.authenticate() == tmp_store.entries()[0].token

    @pytest.mark.asyncio
    async def test_device_flow(
        self, test_server: str, tmp_store: TokenStore, configure_server
    ):
        configure_server(pending_polls=0)
        flow = LoginFlow(test_server, store=tmp_store, timeout=10, scopes="openid")
        with patch("py_oidc_auth_client.flows.pprint"):
            token = await flow.authenticate()
        assert tmp_store.get(flow.identity) == token
        assert flow.identity.scopes == ("openid",)

    @pytest.mark.asyncio
    async def test_unauthorized_client_falls_back(
        self, test_server: str, tmp_store: TokenStore
    ):
        refused = AuthError(
            "x", detail={"error": "unauthorized_client"}, status_code=400
        )
        flow = LoginFlow(
            test_server,
            store=tmp_store,
            timeout=10,
            redirect_ports=[_free_port()],
            scopes="email",
        )
        with patch.object(DeviceFlow, "_run_device_flow", AsyncMock(side_effect=refused)):
            with patch("webbrowser.open", side_effect=_browse):
                token = await flow.authenticate()
        code_identity = CodeFlow(test_server, store=tmp_store, scopes="email").identity
        assert tmp_store.get(code_identity) == token

    @pytest.mark.asyncio
    async def test_denied_login_does_not_fall_back(self, tmp_store: TokenStore):
        denied = AuthError("denied", detail={"error": "access_denied"}, status_code=400)
        run_code = AsyncMock()
        flow = LoginFlow("https://a.example.com", store=tmp_store)
        with patch.object(DeviceFlow, "_run_device_flow", AsyncMock(side_effect=denied)):
            with patch.object(CodeFlow, "_run_code_flow", run_code):
                with pytest.raises(AuthError, match="denied"):
                    await flow.authenticate()
        run_code.assert_not_awaited()


class TestCliFlowChoice:
    """--flow and how auto resolves."""

    def _patched(self, tmp_store: TokenStore, argv):
        with patch("py_oidc_auth_client.__main__.authenticate") as auth:
            with patch("py_oidc_auth_client.__main__.exchange") as exch:
                auth.return_value = make_token()
                exch.return_value = make_token()
                rc = _cli(tmp_store, argv)
        return rc, auth, exch

    def test_auto_logs_in(self, tmp_store: TokenStore):
        rc, auth, exch = self._patched(tmp_store, ["https://a.example.com"])
        assert rc == 0
        auth.assert_called_once()
        exch.assert_not_called()

    def test_auto_with_exchange_option_exchanges(self, tmp_store: TokenStore, capsys):
        rc, auth, exch = self._patched(
            tmp_store, ["https://a.example.com", "--audience", "s3"]
        )
        assert rc == 0
        auth.assert_not_called()
        assert exch.call_args.kwargs["audience"] == "s3"
        assert exch.call_args.kwargs["subject"] is None
        assert "Exchanged a token at https://a.example.com" in capsys.readouterr().out

    def test_exchange_option_with_login_flow_is_an_error(
        self, tmp_store: TokenStore, capsys
    ):
        with pytest.raises(SystemExit):
            _cli(tmp_store, ["https://a.example.com", "--flow", "device", "--audience", "x"])
        assert "only work with --flow exchange" in capsys.readouterr().err

    def test_subject_options_exclude_each_other(self, tmp_store: TokenStore):
        with pytest.raises(SystemExit):
            _cli(
                tmp_store,
                [
                    "https://a.example.com",
                    "--subject-host",
                    "https://b.example.com",
                    "--subject-token",
                    "t",
                ],
            )

    @pytest.mark.parametrize("flow, cls", [("device", DeviceFlow), ("code", CodeFlow)])
    def test_forced_login_flow(self, tmp_store: TokenStore, flow, cls):
        run = AsyncMock(return_value=make_token())
        with patch.object(cls, "authenticate", run):
            rc = _cli(tmp_store, ["https://a.example.com", "--flow", flow, "-s", "openid"])
        assert rc == 0
        run.assert_awaited_once_with(force=False)

    def test_forced_code_flow_against_server(self, test_server: str, tmp_store: TokenStore):
        with patch("webbrowser.open", side_effect=_browse):
            rc = _cli(
                tmp_store,
                [test_server, "--flow", "code", "--ports", str(_free_port())],
            )
        assert rc == 0
        code_identity = CodeFlow(test_server, store=tmp_store).identity
        assert tmp_store.get(code_identity) is not None


class TestCliExchange:
    """Token exchange from the command line, against the test server."""

    def test_exchange_own_login(
        self, test_server: str, tmp_store: TokenStore, exchanges, capsys
    ):
        login = _login(test_server, tmp_store)
        rc = _cli(
            tmp_store,
            [test_server, "--flow", "exchange", "--audience", "s3", "-s", "read", "--json"],
        )
        assert rc == 0
        token = json.loads(capsys.readouterr().out)
        assert jwt.decode(token["access_token"], options={"verify_signature": False})[
            "aud"
        ] == "s3"
        sent = exchanges()[0]
        assert sent["subject_token"] == tmp_store.get(login.identity)["access_token"]
        assert sent["scope"] == "read"

    def test_subject_host(self, test_server: str, tmp_store: TokenStore, exchanges):
        peer = "https://peer.example.org"
        login = _login(peer, tmp_store)
        rc = _cli(tmp_store, [test_server, "--subject-host", peer])
        assert rc == 0
        assert exchanges()[0]["subject_token"] == tmp_store.get(login.identity)[
            "access_token"
        ]

    def test_subject_token_from_stdin(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        subject = make_token(subject="gina")["access_token"]
        rc = _cli(
            tmp_store,
            [test_server, "--subject-token", "-", "--requested-token-type", "jwt"],
            stdin=subject + "\n",
        )
        assert rc == 0
        sent = exchanges()[0]
        assert sent["subject_token"] == subject
        assert sent["requested_token_type"] == TOKEN_TYPE_JWT

    def test_subject_token_argument(
        self, test_server: str, tmp_store: TokenStore, exchanges
    ):
        subject = make_token(subject="hank")["access_token"]
        rc = _cli(
            tmp_store,
            [test_server, "--subject-token", subject, "--requested-token-type", "id"],
        )
        assert rc == 0
        assert exchanges()[0]["requested_token_type"] == TOKEN_TYPE_ID

    def test_empty_stdin(self, test_server: str, tmp_store: TokenStore, capsys):
        rc = _cli(tmp_store, [test_server, "--subject-token", "-"], stdin="\n")
        assert rc == 1
        assert "Token exchange failed: No subject token" in capsys.readouterr().err

    def test_refused_exchange(self, test_server: str, tmp_store: TokenStore, capsys):
        _login(test_server, tmp_store)
        rc = _cli(tmp_store, [test_server, "--audience", "forbidden"])
        assert rc == 1
        assert "invalid_target" in capsys.readouterr().err
