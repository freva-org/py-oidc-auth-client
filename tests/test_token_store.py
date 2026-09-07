"""Tests for py_oidc_auth_client.token_store."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from py_oidc_auth_client.identity import INTERACTIVE_GRANTS, Grant
from py_oidc_auth_client.token_store import StoreEntry, TokenStore

from .conftest import (
    make_access_only_token,
    make_expired_token,
    make_identity,
    make_refresh_only_token,
    make_token,
)

HOST = "https://myapp.example.com"
OTHER = "https://other.example.com"


def entry_files(store: TokenStore) -> list[Path]:
    """Entry files backing *store*, excluding metadata."""
    return [p for p in store.path.glob("*.json") if p.name != "meta.json"]


class TestStoreEntry:
    """Credential validity and ranking of a single entry."""

    def make(self, token) -> StoreEntry:
        return StoreEntry(identity=make_identity(), token=token)

    def test_live_token_is_valid(self):
        entry = self.make(make_token())
        assert entry.access_valid() is True
        assert entry.refresh_valid() is True
        assert entry.expired() is False
        assert entry.usefulness() == 2

    def test_refresh_only_survives(self):
        entry = self.make(make_refresh_only_token())
        assert entry.access_valid() is False
        assert entry.refresh_valid() is True
        assert entry.expired() is False
        assert entry.usefulness() == 1

    def test_fully_expired(self):
        entry = self.make(make_expired_token())
        assert entry.expired() is True
        assert entry.usefulness() == 0

    def test_access_only_token_dies_with_its_access_token(self):
        """A token with no refresh token expires with its access token.

        Client credentials and exchange results usually arrive without a
        refresh token, and there is nothing left to renew them with.
        """
        entry = self.make(make_access_only_token(expires_in=300))
        assert entry.refresh_valid() is False
        assert entry.expired() is False

        dead = self.make(make_access_only_token(expires_in=-10))
        assert dead.expired() is True

    def test_refresh_token_field_required_for_refresh_validity(self):
        """A refresh_expires with no refresh_token is not a credential."""
        entry = self.make(
            {"access_token": "a", "refresh_expires": time.time() + 3600}
        )
        assert entry.refresh_valid() is False
        assert entry.expired() is True

    def test_empty_token_is_expired(self):
        assert self.make({}).expired() is True

    def test_expiry_buffer_applied(self):
        """A token dying within the buffer is already treated as gone."""
        entry = self.make(make_access_only_token(expires_in=5))
        assert entry.access_valid() is False

    def test_digest_matches_identity(self):
        entry = self.make(make_token())
        assert entry.digest == entry.identity.digest

    def test_roundtrip(self):
        original = StoreEntry(
            identity=make_identity(client_id="cli"),
            token=make_token(),
            stored_at=1234.5,
            parent="0123456789abcdef",
        )
        restored = StoreEntry.from_dict(
            json.loads(json.dumps(original.to_dict()))
        )
        assert restored.digest == original.digest
        assert restored.parent == "0123456789abcdef"
        assert restored.stored_at == 1234.5
        assert restored.token["access_token"] == original.token["access_token"]


class TestCRUD:
    """put / get / remove / entries / clear against identities."""

    def test_put_and_get(self, tmp_store: TokenStore):
        ident = make_identity()
        token = make_token()
        tmp_store.put(ident, token)
        result = tmp_store.get(ident)
        assert result is not None
        assert result["access_token"] == token["access_token"]

    def test_get_missing_returns_none(self, tmp_store: TokenStore):
        assert (
            tmp_store.get(make_identity(host="https://nope.example.com"))
            is None
        )

    def test_get_entry_exposes_identity(self, tmp_store: TokenStore):
        ident = make_identity(client_id="cli")
        tmp_store.put(ident, make_token())
        entry = tmp_store.get_entry(ident)
        assert entry is not None
        assert entry.identity.client_id == "cli"

    def test_put_overwrites_same_identity(self, tmp_store: TokenStore):
        ident = make_identity()
        tmp_store.put(ident, make_token())
        tmp_store.put(ident, make_token(expires_in=999))
        assert len(entry_files(tmp_store)) == 1
        assert tmp_store.get(ident)["expires"] == pytest.approx(
            int(time.time()) + 999, abs=5
        )

    def test_put_returns_written_entry(self, tmp_store: TokenStore):
        ident = make_identity()
        entry = tmp_store.put(ident, make_token())
        assert entry.digest == ident.digest

    def test_remove_returns_count(self, tmp_store: TokenStore):
        ident = make_identity()
        tmp_store.put(ident, make_token())
        assert tmp_store.remove(ident) == 1
        assert tmp_store.get(ident) is None

    def test_remove_missing_returns_zero(self, tmp_store: TokenStore):
        assert (
            tmp_store.remove(make_identity(host="https://nope.example.com"))
            == 0
        )

    def test_remove_by_digest(self, tmp_store: TokenStore):
        ident = make_identity()
        tmp_store.put(ident, make_token())
        assert tmp_store.remove(ident.digest) == 1

    def test_remove_by_host_takes_every_grant(self, tmp_store: TokenStore):
        """ "Log me out of this server" means all of it, not one grant."""
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        tmp_store.put(
            make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token()
        )
        tmp_store.put(make_identity(host=OTHER), make_token())
        assert tmp_store.remove(HOST) == 2
        assert tmp_store.hosts() == [OTHER]

    def test_remove_by_host_normalises(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_token())
        assert tmp_store.remove("https://MyApp.Example.COM/") == 1

    def test_hosts_deduplicates_and_sorts(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        tmp_store.put(
            make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token()
        )
        tmp_store.put(make_identity(host=OTHER), make_token())
        assert tmp_store.hosts() == [HOST, OTHER]

    def test_clear(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_token())
        tmp_store.put(make_identity(host=OTHER), make_token())
        tmp_store.clear()
        assert tmp_store.entries() == []

    def test_clear_keeps_metadata(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_token())
        tmp_store.clear()
        assert (tmp_store.path / "meta.json").exists()

    def test_empty_store(self, tmp_store: TokenStore):
        assert tmp_store.hosts() == []
        assert tmp_store.entries() == []


class TestGrantIsolation:
    """The invariant the identity rework exists to protect."""

    def test_grants_do_not_clobber_each_other(self, tmp_store: TokenStore):
        """A service token must never overwrite a user's login.

        Under the old host keyed store these three shared one key and
        the last writer silently won.
        """
        device = make_identity(grant=Grant.DEVICE_CODE, scopes=("openid",))
        code = make_identity(
            grant=Grant.AUTHORIZATION_CODE, scopes=("openid",)
        )
        service = make_identity(grant=Grant.CLIENT_CREDENTIALS)

        tmp_store.put(device, make_token(subject="device"))
        tmp_store.put(code, make_token(subject="code"))
        tmp_store.put(service, make_access_only_token(subject="service"))

        assert len(entry_files(tmp_store)) == 3
        tokens = {
            tmp_store.get(device)["access_token"],
            tmp_store.get(code)["access_token"],
            tmp_store.get(service)["access_token"],
        }
        assert len(tokens) == 3

    def test_scopes_isolate(self, tmp_store: TokenStore):
        narrow = make_identity(scopes=("openid",))
        wide = make_identity(scopes=("openid", "email"))
        tmp_store.put(narrow, make_token(subject="narrow"))
        tmp_store.put(wide, make_token(subject="wide"))
        assert (
            tmp_store.get(narrow)["access_token"]
            != tmp_store.get(wide)["access_token"]
        )

    def test_audiences_isolate(self, tmp_store: TokenStore):
        a = make_identity(audience="waterpark.dkrz.de")
        b = make_identity(audience="s3.dkrz.de")
        tmp_store.put(a, make_token(subject="waterpark"))
        tmp_store.put(b, make_token(subject="s3"))
        assert (
            tmp_store.get(a)["access_token"]
            != tmp_store.get(b)["access_token"]
        )

    def test_clients_isolate(self, tmp_store: TokenStore):
        a = make_identity(client_id="cli-a")
        b = make_identity(client_id="cli-b")
        tmp_store.put(a, make_token(subject="a"))
        tmp_store.put(b, make_token(subject="b"))
        assert (
            tmp_store.get(a)["access_token"]
            != tmp_store.get(b)["access_token"]
        )

    def test_scope_order_shares_one_entry(self, tmp_store: TokenStore):
        tmp_store.put(
            make_identity(scopes=("openid", "profile")), make_token()
        )
        tmp_store.put(
            make_identity(scopes=("profile", "openid")), make_token()
        )
        assert len(entry_files(tmp_store)) == 1


class TestFind:
    """Partial identity lookup before a flow is chosen."""

    def test_finds_sibling_interactive_grant(self, tmp_store: TokenStore):
        """Isolation must not cost a redundant login.

        A caller willing to accept any interactive token has to ask
        before it picks a flow, not after.
        """
        code = make_identity(
            grant=Grant.AUTHORIZATION_CODE, scopes=("openid",)
        )
        tmp_store.put(code, make_token())
        found = tmp_store.find(host=HOST, grants=INTERACTIVE_GRANTS)
        assert [e.identity.grant for e in found] == [Grant.AUTHORIZATION_CODE]

    def test_excludes_non_interactive_grants(self, tmp_store: TokenStore):
        tmp_store.put(
            make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token()
        )
        assert tmp_store.find(host=HOST, grants=INTERACTIVE_GRANTS) == []

    def test_filters_by_host(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_token())
        tmp_store.put(make_identity(host=OTHER), make_token())
        found = tmp_store.find(host=OTHER)
        assert [e.identity.host for e in found] == [OTHER]

    def test_filters_by_client_id(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(client_id="a"), make_token())
        tmp_store.put(make_identity(client_id="b"), make_token())
        assert len(tmp_store.find(host=HOST, client_id="a")) == 1

    def test_scope_superset_is_a_hit(self, tmp_store: TokenStore):
        tmp_store.put(
            make_identity(scopes=("openid", "profile")), make_token()
        )
        assert len(tmp_store.find(host=HOST, scopes=["openid"])) == 1

    def test_scope_subset_is_a_miss(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(scopes=("openid",)), make_token())
        assert tmp_store.find(host=HOST, scopes=["openid", "email"]) == []

    def test_ranks_live_access_above_refresh_only(self, tmp_store: TokenStore):
        stale = make_identity(grant=Grant.AUTHORIZATION_CODE)
        live = make_identity(grant=Grant.DEVICE_CODE)
        tmp_store.put(stale, make_refresh_only_token())
        tmp_store.put(live, make_token())
        ranked = tmp_store.find(host=HOST, grants=INTERACTIVE_GRANTS)
        assert [e.usefulness() for e in ranked] == [2, 1]
        assert ranked[0].identity.grant is Grant.DEVICE_CODE

    def test_ranks_longer_lived_first(self, tmp_store: TokenStore):
        short = make_identity(grant=Grant.DEVICE_CODE)
        long = make_identity(grant=Grant.AUTHORIZATION_CODE)
        tmp_store.put(short, make_token(expires_in=100))
        tmp_store.put(long, make_token(expires_in=5000))
        ranked = tmp_store.find(host=HOST, grants=INTERACTIVE_GRANTS)
        assert ranked[0].identity.grant is Grant.AUTHORIZATION_CODE

    def test_usable_only_drops_spent_entries(self, tmp_store: TokenStore):
        ident = make_identity()
        tmp_store.put(ident, make_refresh_only_token())
        assert len(tmp_store.find(host=HOST)) == 1
        assert tmp_store.find(host=HOST, usable_only=True)[0].usefulness() == 1

    def test_usable_only_false_keeps_spent_entries(
        self, tmp_store: TokenStore
    ):
        """Callers inspecting the cache may want the dead ones too."""
        tmp_store.put(make_identity(), make_expired_token())
        assert tmp_store.find(host=HOST, usable_only=False) == []
        entry = StoreEntry(
            identity=make_identity(host=OTHER), token=make_expired_token()
        )
        tmp_store._write(entry)
        found = tmp_store.find(host=OTHER, usable_only=False)
        assert [e.digest for e in found] == []

    def test_no_constraints_returns_everything(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_token())
        tmp_store.put(make_identity(host=OTHER), make_token())
        assert len(tmp_store.find()) == 2


class TestExchangeLinkage:
    """Parent and child entries for RFC 8693 results."""

    def setup_tree(self, store: TokenStore):
        parent = make_identity(client_id="cli")
        child_a = parent.for_exchange(audience="waterpark.dkrz.de")
        child_b = parent.for_exchange(audience="s3.dkrz.de")
        store.put(parent, make_token())
        store.put(child_a, make_access_only_token(), parent=parent)
        store.put(child_b, make_access_only_token(), parent=parent)
        return parent, child_a, child_b

    def test_children_are_linked_to_parent(self, tmp_store: TokenStore):
        parent, child_a, child_b = self.setup_tree(tmp_store)
        digests = {e.digest for e in tmp_store.children(parent)}
        assert digests == {child_a.digest, child_b.digest}

    def test_children_accepts_a_digest(self, tmp_store: TokenStore):
        parent, _, _ = self.setup_tree(tmp_store)
        assert len(tmp_store.children(parent.digest)) == 2

    def test_parent_recorded_on_entry(self, tmp_store: TokenStore):
        parent, child_a, _ = self.setup_tree(tmp_store)
        assert tmp_store.get_entry(child_a).parent == parent.digest

    def test_put_accepts_parent_as_digest(self, tmp_store: TokenStore):
        parent = make_identity()
        child = parent.for_exchange(audience="s3")
        tmp_store.put(parent, make_token())
        tmp_store.put(child, make_access_only_token(), parent=parent.digest)
        assert len(tmp_store.children(parent)) == 1

    def test_removing_parent_cascades(self, tmp_store: TokenStore):
        """An exchanged token is worthless once its subject is gone."""
        parent, _, _ = self.setup_tree(tmp_store)
        assert tmp_store.remove(parent) == 3
        assert tmp_store.entries() == []

    def test_removing_host_cascades(self, tmp_store: TokenStore):
        self.setup_tree(tmp_store)
        tmp_store.remove(HOST)
        assert tmp_store.entries() == []

    def test_removing_child_leaves_parent(self, tmp_store: TokenStore):
        parent, child_a, child_b = self.setup_tree(tmp_store)
        assert tmp_store.remove(child_a) == 1
        assert tmp_store.get(parent) is not None
        assert tmp_store.get(child_b) is not None

    def test_grandchildren_cascade(self, tmp_store: TokenStore):
        parent = make_identity()
        child = parent.for_exchange(audience="s3")
        grandchild = child.for_exchange(audience="downstream")
        tmp_store.put(parent, make_token())
        tmp_store.put(child, make_access_only_token(), parent=parent)
        tmp_store.put(grandchild, make_access_only_token(), parent=child)
        assert tmp_store.remove(parent) == 3

    def test_child_outlives_nothing_when_parent_expires(
        self, tmp_store: TokenStore
    ):
        """An expired parent is pruned; the child is then an orphan.

        The child stays until its own expiry, which is correct: it is
        still a usable token. Re-minting it needs the parent, and that
        is the flow layer's problem, not the store's.
        """
        parent = make_identity()
        child = parent.for_exchange(audience="s3")
        tmp_store.put(parent, make_expired_token())
        tmp_store.put(child, make_access_only_token(), parent=parent)
        assert tmp_store.get(parent) is None
        assert tmp_store.get(child) is not None


class TestEviction:
    """Lazy TTL pruning."""

    def test_expired_entry_not_returned(self, tmp_store: TokenStore):
        ident = make_identity()
        tmp_store.put(ident, make_expired_token())
        assert tmp_store.get(ident) is None

    def test_expired_entry_file_removed(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_expired_token())
        tmp_store.prune()
        assert entry_files(tmp_store) == []

    def test_reading_an_expired_entry_evicts_it(self, tmp_store: TokenStore):
        """A read cleans up after itself, so prune is only a sweep."""
        identity = make_identity()
        tmp_store.put(identity, make_expired_token())
        assert tmp_store.get_entry(identity) is None
        assert entry_files(tmp_store) == []

    def test_get_does_not_touch_unrelated_entries(self, tmp_store: TokenStore):
        """Looking up one identity must not read the whole store.

        get() used to sweep every file before answering, which made a
        single lookup O(number of cached tokens).
        """
        wanted = make_identity(grant=Grant.DEVICE_CODE)
        other = make_identity(host=OTHER)
        tmp_store.put(wanted, make_token())
        tmp_store.put(other, make_token())
        other_path = tmp_store.path / f"{other.digest}.json"
        with patch.object(
            TokenStore,
            "_read_path",
            autospec=True,
            side_effect=TokenStore._read_path,
        ) as spy:
            tmp_store.get(wanted)
        read = {call.args[1] for call in spy.call_args_list}
        assert other_path not in read

    def test_prune_returns_count(self, tmp_store: TokenStore):
        tmp_store.put(
            make_identity(grant=Grant.DEVICE_CODE), make_expired_token()
        )
        tmp_store.put(
            make_identity(grant=Grant.AUTHORIZATION_CODE), make_token()
        )
        assert tmp_store.prune() == 1

    def test_expired_excluded_from_entries(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_expired_token())
        tmp_store.put(make_identity(host=OTHER), make_token())
        assert [e.identity.host for e in tmp_store.entries()] == [OTHER]

    def test_put_does_not_evict_itself(self, tmp_store: TokenStore):
        """Regression: a fresh write must survive its own prune pass."""
        ident = make_identity()
        tmp_store.put(ident, make_token())
        assert tmp_store.get(ident) is not None


class TestPersistence:
    """On disk layout, atomicity and error handling."""

    def test_survives_reload(self, tmp_path: Path):
        ident = make_identity()
        TokenStore(path=tmp_path / "store").put(ident, make_token())
        assert TokenStore(path=tmp_path / "store").get(ident) is not None

    def test_one_file_per_identity(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        tmp_store.put(
            make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token()
        )
        names = sorted(p.stem for p in entry_files(tmp_store))
        assert names == sorted(
            [
                make_identity(grant=Grant.DEVICE_CODE).digest,
                make_identity(grant=Grant.CLIENT_CREDENTIALS).digest,
            ]
        )

    def test_writes_metadata_version(self, tmp_store: TokenStore):
        meta = json.loads((tmp_store.path / "meta.json").read_text())
        assert meta["version"] == 2

    def test_entry_file_permissions(self, tmp_store: TokenStore):
        tmp_store.put(make_identity(), make_token())
        mode = entry_files(tmp_store)[0].stat().st_mode & 0o777
        assert mode == 0o600

    def test_directory_permissions(self, tmp_path: Path):
        store = TokenStore(path=tmp_path / "store")
        assert store.path.stat().st_mode & 0o777 == 0o700

    def test_missing_directory_is_created(self, tmp_path: Path):
        store = TokenStore(path=tmp_path / "deep" / "nested" / "store")
        assert store.path.is_dir()
        assert store.entries() == []

    def test_corrupt_entry_is_discarded_not_fatal(self, tmp_store: TokenStore):
        """The cache is disposable: a bad file costs a login, not a crash."""
        tmp_store.put(make_identity(), make_token())
        (tmp_store.path / "deadbeefdeadbeef.json").write_text("NOT JSON")
        assert len(tmp_store.entries()) == 1
        assert not (tmp_store.path / "deadbeefdeadbeef.json").exists()

    def test_unreadable_entry_is_left_alone(self, tmp_store: TokenStore):
        """A permissions or I/O error is not the entry's fault.

        Deleting on a transient read failure would turn a temporary
        problem into permanent token loss.
        """
        identity = make_identity()
        tmp_store.put(identity, make_token())
        path = tmp_store.path / f"{identity.digest}.json"
        with patch.object(Path, "read_text", side_effect=OSError("EIO")):
            assert tmp_store.entries() == []
        assert path.exists()
        assert tmp_store.get(identity) is not None

    def test_malformed_entry_is_discarded(self, tmp_store: TokenStore):
        (tmp_store.path / "deadbeefdeadbeef.json").write_text('{"token": {}}')
        assert tmp_store.entries() == []

    def test_no_leftover_temp_files(self, tmp_store: TokenStore):
        for grant in (Grant.DEVICE_CODE, Grant.CLIENT_CREDENTIALS):
            tmp_store.put(make_identity(grant=grant), make_token())
        assert list(tmp_store.path.glob("*.tmp")) == []
        assert list(tmp_store.path.glob(".*")) == []

    def test_write_failure_logs_warning(self, tmp_store: TokenStore, caplog):
        with (
            patch("os.replace", side_effect=OSError("read only")),
            caplog.at_level(
                logging.WARNING, logger="py_oidc_auth_client.token_store"
            ),
        ):
            tmp_store.put(make_identity(), make_token())
        assert "Failed to write token store" in caplog.text

    def test_unlink_failure_is_not_fatal(self, tmp_store: TokenStore, caplog):
        """Removal is best effort; a locked file must not crash a read."""
        tmp_store.put(make_identity(), make_expired_token())
        with (
            patch.object(Path, "unlink", side_effect=OSError("in use")),
            caplog.at_level(
                logging.DEBUG, logger="py_oidc_auth_client.token_store"
            ),
        ):
            assert tmp_store.prune() == 1
        assert "Failed to remove" in caplog.text

    def test_write_failure_cleans_up_temp_file(self, tmp_store: TokenStore):
        with patch("os.replace", side_effect=OSError("disk full")):
            tmp_store.put(make_identity(), make_token())
        assert list(tmp_store.path.glob(".*")) == []
        assert entry_files(tmp_store) == []

    def test_concurrent_writes_do_not_lose_tokens(self, tmp_path: Path):
        """The failure mode a shared store file had.

        Under read-modify-write on one file, concurrent writers each
        loaded, mutated and saved, and all but the last token vanished.
        """
        import multiprocessing as mp

        directory = tmp_path / "store"
        # "spawn", not the default fork: the test process is multi
        # threaded and forking from it is unsafe (and warns on 3.12+).
        with mp.get_context("spawn").Pool(8) as pool:
            pool.map(_write_one, [(directory, i) for i in range(32)])
        assert len(TokenStore(path=directory).entries()) == 32


def _write_one(args) -> None:
    """Module level worker so it survives pickling on spawn platforms."""
    directory, index = args
    store = TokenStore(path=directory)
    store.put(
        make_identity(
            host=f"https://h{index}.example.com", client_id=f"c{index}"
        ),
        make_token(),
    )


class TestLegacyMigration:
    """Upgrade from the v1 host keyed single file store."""

    def write_legacy(self, path: Path, **hosts) -> Path:
        path.write_text(
            json.dumps(
                {
                    host: {"token": token, "stored_at": time.time()}
                    for host, token in hosts.items()
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_live_token_survives_upgrade(self, tmp_path: Path):
        """Nobody logs in again just because they upgraded."""
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        store = TokenStore(path=legacy)
        assert store.hosts() == [HOST]

    def test_legacy_file_removed_after_migration(self, tmp_path: Path):
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        TokenStore(path=legacy)
        assert not legacy.exists()

    def test_directory_derived_from_legacy_path(self, tmp_path: Path):
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        store = TokenStore(path=legacy)
        assert store.path == tmp_path / "tokens"

    def test_migrated_entry_carries_the_sentinel_grant(self, tmp_path: Path):
        """A v1 entry cannot say which interactive grant produced it."""
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        store = TokenStore(path=legacy)
        identity = store.entries()[0].identity
        assert identity.grant is None
        assert identity.backend == "py-oidc-auth"

    def test_sentinel_is_found_by_an_interactive_probe(self, tmp_path: Path):
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        store = TokenStore(path=legacy)
        assert len(store.find(host=HOST, grants=INTERACTIVE_GRANTS)) == 1

    def test_scopes_recovered_from_token(self, tmp_path: Path):
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        store = TokenStore(path=legacy)
        assert store.entries()[0].identity.scopes == (
            "email",
            "openid",
            "profile",
        )

    def test_expired_legacy_entries_dropped(self, tmp_path: Path):
        legacy = self.write_legacy(
            tmp_path / "tokens.json",
            **{HOST: make_token(), OTHER: make_expired_token()},
        )
        store = TokenStore(path=legacy)
        assert store.hosts() == [HOST]

    def test_malformed_legacy_entries_skipped(self, tmp_path: Path):
        legacy = tmp_path / "tokens.json"
        legacy.write_text(
            json.dumps({HOST: {"token": make_token()}, OTHER: "not an entry"})
        )
        store = TokenStore(path=legacy)
        assert store.hosts() == [HOST]

    def test_unreadable_legacy_file_discarded(self, tmp_path: Path):
        legacy = tmp_path / "tokens.json"
        legacy.write_text("NOT JSON")
        store = TokenStore(path=legacy)
        assert store.entries() == []
        assert not legacy.exists()

    def test_migration_is_idempotent(self, tmp_path: Path):
        legacy = self.write_legacy(
            tmp_path / "tokens.json", **{HOST: make_token()}
        )
        TokenStore(path=legacy)
        store = TokenStore(path=legacy)
        assert len(store.entries()) == 1

    def test_no_legacy_file_is_a_no_op(self, tmp_path: Path):
        assert TokenStore(path=tmp_path / "tokens.json").entries() == []

    def test_versioned_file_is_not_treated_as_legacy(self, tmp_path: Path):
        """A file already carrying a version is not a v1 store."""
        legacy = tmp_path / "tokens.json"
        legacy.write_text(json.dumps({"version": 2, "entries": {}}))
        store = TokenStore(path=legacy)
        assert store.entries() == []
        assert not legacy.exists()

    def test_non_object_legacy_file_is_discarded(self, tmp_path: Path):
        legacy = tmp_path / "tokens.json"
        legacy.write_text(json.dumps(["not", "a", "store"]))
        store = TokenStore(path=legacy)
        assert store.entries() == []
        assert not legacy.exists()


class TestDeprecatedHostAccess:
    """The one release compatibility shim for host keyed calls."""

    def test_put_with_host_warns(self, tmp_store: TokenStore):
        with pytest.deprecated_call():
            tmp_store.put(HOST, make_token())

    def test_get_with_host_warns(self, tmp_store: TokenStore):
        with pytest.deprecated_call():
            tmp_store.get(HOST)

    def test_host_roundtrip_still_works(self, tmp_store: TokenStore):
        with pytest.warns(DeprecationWarning):
            tmp_store.put(HOST, make_token())
            assert tmp_store.get(HOST) is not None

    def test_host_lookup_falls_back_to_interactive_entries(
        self, tmp_store: TokenStore
    ):
        """A host string resolves to the best interactive token."""
        tmp_store.put(make_identity(grant=Grant.DEVICE_CODE), make_token())
        with pytest.warns(DeprecationWarning):
            assert tmp_store.get(HOST) is not None

    def test_host_lookup_ignores_service_tokens(self, tmp_store: TokenStore):
        """A host string never resolves to a client credentials token."""
        tmp_store.put(
            make_identity(grant=Grant.CLIENT_CREDENTIALS), make_token()
        )
        with pytest.warns(DeprecationWarning):
            assert tmp_store.get(HOST) is None

    def test_host_normalisation_on_lookup(self, tmp_store: TokenStore):
        with pytest.warns(DeprecationWarning):
            tmp_store.put("https://Example.COM/", make_token())
            assert tmp_store.get("https://example.com") is not None
