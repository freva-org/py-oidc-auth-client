"""Tests for py_oidc_auth_client.__main__ CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from py_oidc_auth_client.__main__ import main
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.token_store import TokenStore

from py_oidc_auth_client.identity import Grant

from .conftest import (
    make_access_only_token,
    make_identity,
    make_refresh_only_token,
    make_token,
)


class TestCLIStoreManagement:
    """CLI commands for listing, removing, and clearing cached tokens."""

    @staticmethod
    def colliding_identities():
        """Two identities whose digests share a leading character.

        Searched rather than hardcoded so the test does not break if the
        digest construction ever changes.
        """
        seen = {}
        for index in range(2000):
            identity = make_identity(client_id=f"cli-{index}")
            first = identity.digest[0]
            if first in seen:
                return seen[first], identity
            seen[first] = identity
        raise AssertionError("no colliding digest prefix found")

    def run(self, store: TokenStore, argv):
        with patch(
            "py_oidc_auth_client.__main__.TokenStore",
            return_value=store,
        ):
            return main(argv)

    def test_list_empty(self, tmp_store: TokenStore, capsys):
        assert self.run(tmp_store, ["--list"]) == 0
        assert "No cached tokens" in capsys.readouterr().out

    def test_list_groups_by_host(self, tmp_store: TokenStore, capsys):
        tmp_store.put(make_identity(host="https://a.example.com"), make_token())
        tmp_store.put(make_identity(host="https://b.example.com"), make_token())
        assert self.run(tmp_store, ["--list"]) == 0
        out = capsys.readouterr().out
        assert "https://a.example.com" in out
        assert "https://b.example.com" in out

    def test_list_names_the_grant(self, tmp_store: TokenStore, capsys):
        """Users need to see which principal each token belongs to."""
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        tmp_store.put(
            make_identity(grant=Grant.CLIENT_CREDENTIALS, client_id="svc"),
            make_access_only_token(),
        )
        out = capsys.readouterr()  # drain
        self.run(tmp_store, ["--list"])
        out = capsys.readouterr().out
        assert "device_code" in out
        assert "client_credentials" in out
        assert "client=svc" in out

    def test_list_shows_one_host_header_per_host(
        self, tmp_store: TokenStore, capsys
    ):
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        tmp_store.put(make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token())
        self.run(tmp_store, ["--list"])
        out = capsys.readouterr().out
        assert out.count("https://myapp.example.com\n") == 1

    def test_list_nests_exchanged_tokens_under_their_subject(
        self, tmp_store: TokenStore, capsys
    ):
        """The indent is what explains why removing a parent takes the
        child with it."""
        parent = make_identity(client_id="cli")
        child = parent.for_exchange(audience="waterpark.dkrz.de")
        tmp_store.put(parent, make_token())
        tmp_store.put(child, make_access_only_token(), parent=parent)
        self.run(tmp_store, ["--list"])
        lines = capsys.readouterr().out.splitlines()
        nested = [line for line in lines if "audience=waterpark.dkrz.de" in line]
        assert nested and nested[0].startswith("    ")

    def test_list_marks_migrated_entries(self, tmp_store: TokenStore, capsys):
        tmp_store.put(make_identity(grant=None), make_token())
        self.run(tmp_store, ["--list"])
        out = capsys.readouterr().out
        assert "unknown grant" in out
        assert "migrated" in out

    def test_list_reports_refresh_only_entries(
        self, tmp_store: TokenStore, capsys
    ):
        tmp_store.put(make_identity(), make_refresh_only_token())
        self.run(tmp_store, ["--list"])
        assert "refresh only" in capsys.readouterr().out

    def test_list_truncates_digests_by_default(
        self, tmp_store: TokenStore, capsys
    ):
        identity = make_identity()
        tmp_store.put(identity, make_token())
        self.run(tmp_store, ["--list"])
        out = capsys.readouterr().out
        assert identity.digest[:8] in out
        assert identity.digest not in out

    def test_verbose_shows_full_digest_and_issuer(
        self, tmp_store: TokenStore, capsys
    ):
        identity = make_identity(issuer="https://kc.example.com/realms/x")
        tmp_store.put(identity, make_token())
        self.run(tmp_store, ["--list", "--verbose"])
        out = capsys.readouterr().out
        assert identity.digest in out
        assert "issuer=https://kc.example.com/realms/x" in out

    def test_clear(self, tmp_store: TokenStore, capsys):
        tmp_store.put(make_identity(), make_token())
        assert self.run(tmp_store, ["--clear"]) == 0
        assert "removed" in capsys.readouterr().out.lower()
        assert tmp_store.entries() == []

    def test_remove_by_host_takes_every_grant(
        self, tmp_store: TokenStore, capsys
    ):
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        tmp_store.put(make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token())
        assert self.run(tmp_store, ["--remove", "https://myapp.example.com"]) == 0
        assert "Removed 2 tokens" in capsys.readouterr().out
        assert tmp_store.entries() == []

    def test_remove_reports_singular(self, tmp_store: TokenStore, capsys):
        tmp_store.put(make_identity(), make_token())
        self.run(tmp_store, ["--remove", "https://myapp.example.com"])
        assert "Removed 1 token for" in capsys.readouterr().out

    def test_remove_by_full_digest(self, tmp_store: TokenStore, capsys):
        identity = make_identity()
        tmp_store.put(identity, make_token())
        assert self.run(tmp_store, ["--remove", identity.digest]) == 0
        assert tmp_store.entries() == []

    def test_remove_by_truncated_digest_from_the_listing(
        self, tmp_store: TokenStore, capsys
    ):
        """--list truncates, so the value users copy is a prefix."""
        identity = make_identity()
        tmp_store.put(identity, make_token())
        assert self.run(tmp_store, ["--remove", identity.digest[:8]]) == 0
        assert tmp_store.entries() == []

    def test_remove_cascades_to_exchanged_tokens(
        self, tmp_store: TokenStore, capsys
    ):
        parent = make_identity()
        child = parent.for_exchange(audience="s3.dkrz.de")
        tmp_store.put(parent, make_token())
        tmp_store.put(child, make_access_only_token(), parent=parent)
        self.run(tmp_store, ["--remove", parent.digest])
        assert "Removed 2 tokens" in capsys.readouterr().out
        assert tmp_store.entries() == []

    def test_ambiguous_digest_prefix_is_an_error(
        self, tmp_store: TokenStore, capsys
    ):
        a, b = self.colliding_identities()
        prefix = a.digest[:1]
        tmp_store.put(a, make_token())
        tmp_store.put(b, make_token())
        assert self.run(tmp_store, ["--remove", prefix]) == 1
        assert "Ambiguous" in capsys.readouterr().err
        assert len(tmp_store.entries()) == 2

    def test_remove_missing(self, tmp_store: TokenStore, capsys):
        assert self.run(tmp_store, ["--remove", "https://nope.example.com"]) == 0
        assert "No cached token" in capsys.readouterr().out


class TestCLIOptionPassthrough:
    """Regression: several options were parsed and then discarded."""

    def call_args(self, argv):
        with patch("py_oidc_auth_client.__main__.authenticate") as auth:
            auth.return_value = make_token()
            main(argv)
        return auth.call_args

    def test_routes_reach_authenticate(self):
        kwargs = self.call_args(
            [
                "https://a.example.com",
                "--login-route", "/oauth/login",
                "--token-route", "/oauth/token",
                "--device-route", "/oauth/device",
            ]
        ).kwargs
        assert kwargs["login_route"] == "/oauth/login"
        assert kwargs["token_route"] == "/oauth/token"
        assert kwargs["device_route"] == "/oauth/device"

    def test_ports_reach_authenticate_as_integers(self):
        kwargs = self.call_args(
            ["https://a.example.com", "--ports", "9000", "9001"]
        ).kwargs
        assert kwargs["redirect_ports"] == [9000, 9001]


class TestCLIAuthenticate:
    """CLI authentication invocation."""

    def test_success_summary_output(self, capsys):
        token = make_token()
        with patch(
            "py_oidc_auth_client.__main__.authenticate",
            return_value=token,
        ):
            exit_code = main(["https://myapp.example.com"])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "Authenticated to" in out
        assert "access_token" in out

    def test_success_json_output(self, capsys):
        token = make_token()
        with patch(
            "py_oidc_auth_client.__main__.authenticate",
            return_value=token,
        ):
            exit_code = main(["https://myapp.example.com", "--json"])
        assert exit_code == 0
        parsed = json.loads(capsys.readouterr().out)
        assert "access_token" in parsed
        assert "refresh_token" in parsed

    def test_auth_failure_returns_1(self, capsys):
        with patch(
            "py_oidc_auth_client.__main__.authenticate",
            side_effect=AuthError("timed out"),
        ):
            exit_code = main(["https://myapp.example.com"])
        assert exit_code == 1
        assert "Authentication failed" in capsys.readouterr().err

    def test_missing_host_exits_with_error(self):
        with pytest.raises(SystemExit):
            main([])


class TestCLIOptions:
    """CLI flag forwarding."""

    def test_force_flag(self):
        token = make_token()
        with patch(
            "py_oidc_auth_client.__main__.authenticate",
            return_value=token,
        ) as mock_auth:
            main(["https://myapp.example.com", "--force"])
        _, kwargs = mock_auth.call_args
        assert kwargs["force"] is True

    def test_timeout_flag(self):
        token = make_token()
        with patch(
            "py_oidc_auth_client.__main__.authenticate",
            return_value=token,
        ) as mock_auth:
            main(["https://myapp.example.com", "--timeout", "120"])
        _, kwargs = mock_auth.call_args
        assert kwargs["timeout"] == 120

    def test_app_name_flag(self):
        token = make_token()
        with patch(
            "py_oidc_auth_client.__main__.authenticate",
            return_value=token,
        ) as mock_auth:
            main(["https://myapp.example.com", "--app-name", "my-project"])
        _, kwargs = mock_auth.call_args
        assert kwargs["app_name"] == "my-project"
