"""Tests for py_oidc_auth_client.token_store."""

import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from py_oidc_auth_client.token_store import TokenStore, _is_expired, _normalise_host

from .conftest import make_expired_token, make_token


class TestNormaliseHost:
    """Host URL normalisation for cache keys."""

    def test_lowercase(self):
        assert _normalise_host("https://MyApp.Example.COM") == "https://myapp.example.com"

    def test_strips_trailing_slash(self):
        assert _normalise_host("https://example.com/") == "https://example.com"

    def test_drops_default_https_port(self):
        assert _normalise_host("https://example.com:443") == "https://example.com"

    def test_drops_default_http_port(self):
        assert _normalise_host("http://example.com:80") == "http://example.com"

    def test_keeps_non_default_port(self):
        assert _normalise_host("http://localhost:8080") == "http://localhost:8080"
        assert _normalise_host("https://example.com:8443") == "https://example.com:8443"

    def test_defaults_to_https_scheme(self):
        result = _normalise_host("://example.com")
        assert result.startswith("https://")

    def test_empty_string(self):
        result = _normalise_host("")
        assert result == "https://"


class TestIsExpired:
    """Entry expiry check logic."""

    def test_valid_token_not_expired(self):
        entry = {"token": {"refresh_expires": time.time() + 3600, "expires": time.time() + 300}}
        assert _is_expired(entry, time.time()) is False

    def test_expired_refresh(self):
        entry = {"token": {"refresh_expires": time.time() - 100, "expires": time.time() - 200}}
        assert _is_expired(entry, time.time()) is True

    def test_missing_expiry_fields_treated_as_expired(self):
        entry = {"token": {}}
        assert _is_expired(entry, time.time()) is True

    def test_access_valid_refresh_expired_uses_max(self):
        """The entry is kept alive as long as *either* expiry is in the future."""
        now = time.time()
        entry = {"token": {"expires": now + 600, "refresh_expires": now - 100}}
        assert _is_expired(entry, now) is False


class TestTokenStoreCRUD:
    """Basic put/get/remove/hosts/clear operations."""

    def test_put_and_get(self, tmp_store: TokenStore):
        token = make_token()
        tmp_store.put("https://a.example.com", token)
        result = tmp_store.get("https://a.example.com")
        assert result is not None
        assert result["access_token"] == token["access_token"]

    def test_get_missing_returns_none(self, tmp_store: TokenStore):
        assert tmp_store.get("https://nope.example.com") is None

    def test_put_overwrites(self, tmp_store: TokenStore):
        token1 = make_token()
        token2 = make_token(expires_in=999)
        tmp_store.put("https://a.example.com", token1)
        tmp_store.put("https://a.example.com", token2)
        result = tmp_store.get("https://a.example.com")
        assert result["expires"] == token2["expires"]

    def test_remove_existing(self, tmp_store: TokenStore):
        tmp_store.put("https://a.example.com", make_token())
        assert tmp_store.remove("https://a.example.com") is True
        assert tmp_store.get("https://a.example.com") is None

    def test_remove_missing(self, tmp_store: TokenStore):
        assert tmp_store.remove("https://nope.example.com") is False

    def test_hosts(self, tmp_store: TokenStore):
        tmp_store.put("https://a.example.com", make_token())
        tmp_store.put("https://b.example.com", make_token())
        hosts = tmp_store.hosts()
        assert sorted(hosts) == ["https://a.example.com", "https://b.example.com"]

    def test_clear(self, tmp_store: TokenStore):
        tmp_store.put("https://a.example.com", make_token())
        tmp_store.put("https://b.example.com", make_token())
        tmp_store.clear()
        assert tmp_store.hosts() == []

    def test_empty_store_hosts(self, tmp_store: TokenStore):
        assert tmp_store.hosts() == []


class TestTokenStoreMultiHost:
    """Multiple hosts are stored independently."""

    def test_different_hosts_independent(self, tmp_store: TokenStore):
        token_a = make_token(expires_in=100)
        token_b = make_token(expires_in=200)
        tmp_store.put("https://a.example.com", token_a)
        tmp_store.put("https://b.example.com", token_b)
        assert tmp_store.get("https://a.example.com")["expires"] == token_a["expires"]
        assert tmp_store.get("https://b.example.com")["expires"] == token_b["expires"]

    def test_host_normalisation_on_lookup(self, tmp_store: TokenStore):
        tmp_store.put("https://example.com/", make_token())
        assert tmp_store.get("https://example.com") is not None

    def test_case_insensitive_host(self, tmp_store: TokenStore):
        tmp_store.put("https://Example.COM", make_token())
        assert tmp_store.get("https://example.com") is not None


class TestTokenStoreEviction:
    """Automatic TTL based eviction."""

    def test_expired_entries_evicted_on_get(self, tmp_store: TokenStore):
        tmp_store.put("https://expired.example.com", make_expired_token())
        tmp_store.put("https://valid.example.com", make_token())
        assert tmp_store.get("https://expired.example.com") is None
        assert tmp_store.get("https://valid.example.com") is not None

    def test_expired_entries_evicted_from_hosts(self, tmp_store: TokenStore):
        tmp_store.put("https://expired.example.com", make_expired_token())
        tmp_store.put("https://valid.example.com", make_token())
        hosts = tmp_store.hosts()
        assert "https://valid.example.com" in hosts
        assert "https://expired.example.com" not in hosts

    def test_put_does_not_evict_itself(self, tmp_store: TokenStore):
        """Regression: eviction must run before insert, not after."""
        token = make_token()
        tmp_store.put("https://a.example.com", token)
        result = tmp_store.get("https://a.example.com")
        assert result is not None


class TestTokenStorePersistence:
    """File based persistence and error handling."""

    def test_survives_reload(self, tmp_path: Path):
        path = tmp_path / "store.json"
        store1 = TokenStore(path=path)
        store1.put("https://a.example.com", make_token())
        store2 = TokenStore(path=path)
        assert store2.get("https://a.example.com") is not None

    def test_corrupted_file_returns_empty(self, tmp_path: Path):
        path = tmp_path / "store.json"
        path.write_text("NOT JSON")
        store = TokenStore(path=path)
        assert store.get("https://a.example.com") is None
        assert store.hosts() == []

    def test_missing_file_returns_empty(self, tmp_path: Path):
        store = TokenStore(path=tmp_path / "nonexistent.json")
        assert store.hosts() == []

    def test_file_permissions(self, tmp_path: Path):
        path = tmp_path / "store.json"
        store = TokenStore(path=path)
        store.put("https://a.example.com", make_token())
        assert path.exists()
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_atomic_write_no_leftover_tmp(self, tmp_path: Path):
        path = tmp_path / "store.json"
        store = TokenStore(path=path)
        store.put("https://a.example.com", make_token())
        assert not (tmp_path / "store.tmp").exists()

    def test_save_oserror_logs_warning(self, tmp_path: Path, caplog):
        """When the store file can't be written, _save logs a warning
        but doesn't raise."""
        path = tmp_path / "store.json"
        store = TokenStore(path=path)
        store.put("https://a.example.com", make_token())
        # Make directory read-only so the .tmp file can't be created
        tmp_path.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            import logging
            with caplog.at_level(logging.WARNING, logger="py_oidc_auth_client.token_store"):
                store.put("https://b.example.com", make_token())
            assert "Failed to write token store" in caplog.text
        finally:
            # Restore permissions so pytest can clean up
            tmp_path.chmod(stat.S_IRWXU)

    def test_save_oserror_cleans_up_tmp(self, tmp_path: Path):
        """If the atomic rename fails, the temp file is cleaned up."""
        path = tmp_path / "store.json"
        store = TokenStore(path=path)
        # Simulate rename failure by patching Path.replace
        with patch.object(Path, "replace", side_effect=OSError("disk full")):
            store.put("https://a.example.com", make_token())
        # The .tmp file should have been cleaned up
        assert not path.with_suffix(".tmp").exists()
