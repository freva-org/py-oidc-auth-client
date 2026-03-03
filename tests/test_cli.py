"""Tests for py_oidc_auth_client.__main__ CLI."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from py_oidc_auth_client.__main__ import main
from py_oidc_auth_client.exceptions import AuthError
from py_oidc_auth_client.token_store import TokenStore

from .conftest import make_expired_token, make_token


class TestCLIStoreManagement:
    """CLI commands for listing, removing, and clearing cached tokens."""

    def test_list_empty(self, tmp_path: Path, capsys):
        store = TokenStore(path=tmp_path / "tokens.json")
        with patch(
            "py_oidc_auth_client.__main__.TokenStore",
            return_value=store,
        ):
            exit_code = main(["--list"])
        assert exit_code == 0
        assert "No cached tokens" in capsys.readouterr().out

    def test_list_with_entries(self, tmp_path: Path, capsys):
        store = TokenStore(path=tmp_path / "tokens.json")
        store.put("https://a.example.com", make_token())
        store.put("https://b.example.com", make_token())
        with patch(
            "py_oidc_auth_client.__main__.TokenStore",
            return_value=store,
        ):
            exit_code = main(["--list"])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "a.example.com" in out
        assert "b.example.com" in out
        assert "valid" in out

    def test_clear(self, tmp_path: Path, capsys):
        store = TokenStore(path=tmp_path / "tokens.json")
        store.put("https://a.example.com", make_token())
        with patch(
            "py_oidc_auth_client.__main__.TokenStore",
            return_value=store,
        ):
            exit_code = main(["--clear"])
        assert exit_code == 0
        assert "removed" in capsys.readouterr().out.lower()
        assert store.hosts() == []

    def test_remove_existing(self, tmp_path: Path, capsys):
        store = TokenStore(path=tmp_path / "tokens.json")
        store.put("https://a.example.com", make_token())
        with patch(
            "py_oidc_auth_client.__main__.TokenStore",
            return_value=store,
        ):
            exit_code = main(["--remove", "https://a.example.com"])
        assert exit_code == 0
        assert "Removed" in capsys.readouterr().out

    def test_remove_missing(self, tmp_path: Path, capsys):
        store = TokenStore(path=tmp_path / "tokens.json")
        with patch(
            "py_oidc_auth_client.__main__.TokenStore",
            return_value=store,
        ):
            exit_code = main(["--remove", "https://nope.example.com"])
        assert exit_code == 0
        assert "No cached token" in capsys.readouterr().out


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
