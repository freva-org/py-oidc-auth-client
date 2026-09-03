"""
Token Store
===========

Token cache keyed by :class:`~.identity.AuthIdentity`.

Each cached token lives in its own JSON file, named after the identity
digest that produced it::

    ~/.cache/py-oidc-auth/tokens/
        meta.json                 {"version": 2}
        a3f1c9d2e8b40571.json
        0f4b77c1d9ae2b30.json

One file per entry rather than one shared file, because a shared file
forces every write to be a read-modify-write of the whole store.  Two
processes authenticating at the same time would each load, mutate and
save, and one of the two tokens would be lost silently.  That is a real
scenario on a batch system where every rank of a job array calls
:func:`~py_oidc_auth_client.authenticate` at once.  With one file per
identity, writes to different identities never touch the same path and
:func:`os.replace` gives genuine atomicity without a lock.

Entries carry the identity that produced them, so ``--list`` can explain
what is cached, and an optional ``parent`` digest linking an exchanged
token back to the identity whose token was used as the exchange subject.
Removing a parent cascades to its children, and an exchanged token that
expires without a refresh token of its own is re-minted by walking that
link back to the parent.

Stale entries are pruned lazily on every read.

Legacy host keyed stores (``token-store.json``, no ``version`` key) are
migrated in place on first use.  A legacy entry cannot say which
interactive grant produced it, so it is migrated with ``grant=None``,
the sentinel that :meth:`~.identity.AuthIdentity.matches` treats as
compatible with any interactive grant.  Nobody has to log in again after
upgrading, and the next successful mint rewrites the entry properly.
"""

import json
import logging
import os
import tempfile
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union, cast

from platformdirs import user_cache_path

from .identity import (
    INTERACTIVE_GRANTS,
    AuthIdentity,
    Grant,
    normalise_host,
    normalise_scopes,
)
from .schema import Token
from .utils import DEFAULT_APP_NAME

logger = logging.getLogger(__name__)

__all__ = ["TokenStore", "StoreEntry"]

#: Seconds of headroom before an expiry is treated as reached.  Avoids
#: handing out a token that dies in flight.
_EXPIRY_BUFFER = 30

#: Current on disk layout version.
STORE_VERSION = 2

#: Legacy single file store, migrated on first use.
_LEGACY_FILENAME = "token-store.json"

# Retained under its old private name: ``_normalise_host`` moved to
# .identity, and this alias keeps any importer working for one release.
_normalise_host = normalise_host


@dataclass
class StoreEntry:
    """A cached token together with the identity that produced it.

    Parameters
    ----------
    identity : AuthIdentity
        Everything that made this token unique.
    token : Token
        The cached token payload.
    stored_at : float
        Unix timestamp of when the entry was written.
    parent : str or None
        Digest of the identity whose token was used as the exchange
        subject, for entries produced by a token exchange.
    """

    identity: AuthIdentity
    token: Token
    stored_at: float = field(default_factory=time.time)
    parent: Optional[str] = None

    @property
    def digest(self) -> str:
        """Digest of :attr:`identity`, and therefore the entry filename."""
        return self.identity.digest

    def access_valid(self, now: Optional[float] = None) -> bool:
        """Whether the access token is still usable.

        Parameters
        ----------
        now : float or None
            Timestamp to compare against.  Defaults to the current time.

        Returns
        -------
        bool
            ``True`` when the access token has not expired.
        """
        now = time.time() if now is None else now
        return now < (self.token.get("expires", 0) - _EXPIRY_BUFFER)

    def refresh_valid(self, now: Optional[float] = None) -> bool:
        """Whether a usable refresh token is present.

        Parameters
        ----------
        now : float or None
            Timestamp to compare against.  Defaults to the current time.

        Returns
        -------
        bool
            ``True`` when a refresh token exists and has not expired.
        """
        now = time.time() if now is None else now
        if not self.token.get("refresh_token"):
            return False
        return now < (self.token.get("refresh_expires", 0) - _EXPIRY_BUFFER)

    def expired(self, now: Optional[float] = None) -> bool:
        """Whether the entry is dead and should be evicted.

        An entry survives while either credential is usable.  A token
        with no refresh token, such as a client credentials or exchange
        result, therefore dies with its access token, which is correct:
        there is nothing left to renew it with.

        Parameters
        ----------
        now : float or None
            Timestamp to compare against.  Defaults to the current time.

        Returns
        -------
        bool
            ``True`` when neither credential is usable.
        """
        now = time.time() if now is None else now
        return not (self.access_valid(now) or self.refresh_valid(now))

    def usefulness(self, now: Optional[float] = None) -> int:
        """Rank this entry against siblings for :meth:`TokenStore.find`.

        Returns
        -------
        int
            ``2`` when the access token is live, ``1`` when only a
            refresh is available, ``0`` when the entry is spent.
        """
        now = time.time() if now is None else now
        if self.access_valid(now):
            return 2
        if self.refresh_valid(now):
            return 1
        return 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the entry for storage."""
        return {
            "identity": self.identity.to_dict(),
            "token": dict(self.token),
            "stored_at": self.stored_at,
            "parent": self.parent,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StoreEntry":
        """Rebuild an entry from its stored representation.

        Parameters
        ----------
        data : dict
            Mapping as produced by :meth:`to_dict`.

        Returns
        -------
        StoreEntry
            The reconstructed entry.
        """
        return cls(
            identity=AuthIdentity.from_dict(data["identity"]),
            token=cast(Token, data.get("token", {})),
            stored_at=float(data.get("stored_at", 0.0)),
            parent=data.get("parent"),
        )


class TokenStore:
    """Identity keyed token cache with automatic TTL eviction.

    Parameters
    ----------
    path : str or Path or None
        Directory holding the store.  Defaults to the platform cache
        directory (``~/.cache/py-oidc-auth/tokens`` on Linux).  A path
        ending in ``.json`` is accepted for compatibility with the old
        single file store: the directory becomes the path with the
        suffix dropped, and the old file is migrated into it.
    app_name : str
        Application name for the cache directory.  Only used when
        *path* is ``None``.

    Examples
    --------
    .. code-block:: python

        from py_oidc_auth_client.identity import AuthIdentity, Grant
        from py_oidc_auth_client.token_store import TokenStore

        store = TokenStore()
        ident = AuthIdentity(
            host="https://myapp.example.com",
            backend="oidc",
            grant=Grant.DEVICE_CODE,
            client_id="my-cli",
            scopes=("openid",),
        )

        store.put(ident, token)
        cached = store.get(ident)

        # "Is there any interactive token I could reuse here?", asked
        # before choosing a flow rather than after.
        for entry in store.find(
            host="https://myapp.example.com", grants=INTERACTIVE_GRANTS
        ):
            print(entry.identity.label, entry.usefulness())
    """

    def __init__(
        self,
        path: Optional[Union[str, Path]] = None,
        app_name: str = DEFAULT_APP_NAME,
    ) -> None:
        legacy: Optional[Path]
        if path:
            given = Path(path).expanduser().absolute()
            if given.suffix == ".json":
                self._dir = given.with_suffix("")
                legacy = given
            else:
                self._dir = given
                legacy = given / _LEGACY_FILENAME
        else:
            cache = user_cache_path(app_name, ensure_exists=True)
            self._dir = cache / "tokens"
            legacy = cache / _LEGACY_FILENAME
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._legacy_path = legacy
        self._migrate_legacy()

    # -- Public API -----------------------------------------------------

    def get(self, identity: Union[AuthIdentity, str]) -> Optional[Token]:
        """Look up a cached token.

        Triggers a cleanup pass that removes expired entries.

        Parameters
        ----------
        identity : AuthIdentity or str
            The identity to look up.  Passing a bare host string is
            deprecated: it resolves to the best cached interactive token
            for that host, which is ambiguous once several clients or
            scopes are in play.

        Returns
        -------
        Token or None
            The cached token when present and usable, else ``None``.
        """
        entry = self.get_entry(identity)
        return entry.token if entry else None

    def get_entry(self, identity: Union[AuthIdentity, str]) -> Optional[StoreEntry]:
        """Look up a cached entry, with its identity and parent link.

        Parameters
        ----------
        identity : AuthIdentity or str
            The identity to look up.  See :meth:`get` on strings.

        Returns
        -------
        StoreEntry or None
            The cached entry when present and usable, else ``None``.
        """
        self.prune()
        if isinstance(identity, str):
            legacy_id = self._legacy_lookup(identity, "get")
            if legacy_id is None:
                return None
            identity = legacy_id
        return self._read(identity.digest)

    def put(
        self,
        identity: Union[AuthIdentity, str],
        token: Token,
        parent: Optional[Union[AuthIdentity, str]] = None,
    ) -> StoreEntry:
        """Store a token, overwriting any previous entry for *identity*.

        Parameters
        ----------
        identity : AuthIdentity or str
            The identity the token belongs to.  A bare host string is
            deprecated and is recorded as a legacy interactive entry.
        token : Token
            The token to cache.
        parent : AuthIdentity or str or None
            For an exchanged token, the identity (or digest) whose token
            was the exchange subject.  Removing that parent later
            cascades to this entry, and its expiry can be recovered by
            re-running the exchange against the refreshed parent.

        Returns
        -------
        StoreEntry
            The entry as written.
        """
        if isinstance(identity, str):
            identity = self._legacy_identity(identity, "put")
        parent_digest = parent.digest if isinstance(parent, AuthIdentity) else parent
        entry = StoreEntry(
            identity=identity,
            token=token,
            stored_at=time.time(),
            parent=parent_digest,
        )
        self._write(entry)
        return entry

    def remove(self, target: Union[AuthIdentity, str]) -> int:
        """Remove cached entries, cascading to any derived tokens.

        Parameters
        ----------
        target : AuthIdentity or str
            An identity, a digest, or a host URL.  A host removes every
            entry for that host regardless of grant, client or scopes,
            which is what a user means by "log me out of this server".

        Returns
        -------
        int
            Number of entries removed, including cascaded children.
        """
        if isinstance(target, AuthIdentity):
            digests = [target.digest]
        elif self._is_digest(target):
            digests = [target]
        else:
            host = normalise_host(target)
            digests = [e.digest for e in self.entries() if e.identity.host == host]
        removed = 0
        for digest in digests:
            removed += self._remove_cascade(digest)
        return removed

    def find(
        self,
        *,
        host: Optional[str] = None,
        backend: Optional[str] = None,
        grants: Optional[Iterable[Optional[Grant]]] = None,
        client_id: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        audience: Optional[str] = None,
        usable_only: bool = True,
    ) -> List[StoreEntry]:
        """Find cached entries matching a partial identity.

        This is what keeps grant isolation from costing a redundant
        login.  A device flow token and an authorization code token are
        cached separately, so a caller that is willing to accept either
        must ask before it picks a flow, not after.

        Parameters
        ----------
        host, backend, client_id, audience : str or None
            Exact match when given, ignored when ``None``.
        grants : iterable of Grant or None
            Acceptable grants.  Entries carrying the legacy ``None``
            sentinel match any grant.
        scopes : iterable of str or None
            Required scopes.  An entry matches when its granted scopes
            are a superset, so a token granted more than was asked for
            is still a hit.
        usable_only : bool
            Drop entries with neither a live access token nor a usable
            refresh token.

        Returns
        -------
        list of StoreEntry
            Matches, best first: live access tokens before refreshable
            ones, and within each group the longest lived first.
        """
        now = time.time()
        wanted = None if grants is None else set(grants)
        matches = [
            entry
            for entry in self.entries()
            if entry.identity.matches(
                host=host,
                backend=cast(Any, backend),
                grants=wanted,
                client_id=client_id,
                scopes=scopes,
                audience=audience,
            )
        ]
        if usable_only:
            matches = [entry for entry in matches if entry.usefulness(now)]
        matches.sort(
            key=lambda e: (
                e.usefulness(now),
                e.token.get("expires", 0),
                e.stored_at,
            ),
            reverse=True,
        )
        return matches

    def entries(self) -> List[StoreEntry]:
        """Return every live entry in the store.

        Expired entries are pruned first.

        Returns
        -------
        list of StoreEntry
            All cached entries, in unspecified order.
        """
        self.prune()
        found = []
        for path in self._dir.glob("*.json"):
            if path.name == "meta.json":
                continue
            entry = self._read_path(path)
            if entry is not None:
                found.append(entry)
        return found

    def children(self, digest: Union[AuthIdentity, str]) -> List[StoreEntry]:
        """Return entries derived from *digest* by token exchange.

        Parameters
        ----------
        digest : AuthIdentity or str
            The parent identity or its digest.

        Returns
        -------
        list of StoreEntry
            Entries whose ``parent`` is *digest*.
        """
        if isinstance(digest, AuthIdentity):
            digest = digest.digest
        return [e for e in self.entries() if e.parent == digest]

    def hosts(self) -> List[str]:
        """Return the distinct hosts that have cached tokens.

        Returns
        -------
        list of str
            Normalised host URLs, deduplicated and sorted.
        """
        return sorted({entry.identity.host for entry in self.entries()})

    def clear(self) -> None:
        """Remove all cached tokens."""
        for path in self._dir.glob("*.json"):
            if path.name != "meta.json":
                self._unlink(path)

    def prune(self) -> int:
        """Delete expired entries from disk.

        Returns
        -------
        int
            Number of entries removed.
        """
        now = time.time()
        removed = 0
        for path in self._dir.glob("*.json"):
            if path.name == "meta.json":
                continue
            entry = self._read_path(path, prune=False)
            if entry is None or entry.expired(now):
                logger.debug("Evicting expired token %s", path.stem)
                self._unlink(path)
                removed += 1
        return removed

    # -- Internals ------------------------------------------------------

    @property
    def path(self) -> Path:
        """Directory backing this store."""
        return self._dir

    @staticmethod
    def _is_digest(value: str) -> bool:
        """Whether *value* looks like an entry digest rather than a URL."""
        return (
            len(value) == 16
            and "/" not in value
            and all(char in "0123456789abcdef" for char in value)
        )

    def _entry_path(self, digest: str) -> Path:
        """Path of the file backing *digest*."""
        return self._dir / f"{digest}.json"

    def _read(self, digest: str) -> Optional[StoreEntry]:
        """Read one entry by digest, or ``None`` when absent or dead."""
        return self._read_path(self._entry_path(digest))

    def _read_path(self, path: Path, prune: bool = True) -> Optional[StoreEntry]:
        """Read and parse one entry file.

        A malformed file is treated as absent rather than fatal: the
        cache is disposable, and a corrupt entry should cost a fresh
        login, not a crash.
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            logger.debug("Unreadable token entry %s: %s", path.name, exc)
            return None
        try:
            entry = StoreEntry.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Discarding malformed token entry %s: %s", path.name, exc)
            self._unlink(path)
            return None
        if prune and entry.expired():
            self._unlink(path)
            return None
        return entry

    def _write(self, entry: StoreEntry) -> None:
        """Atomically write one entry with restricted permissions."""
        target = self._entry_path(entry.digest)
        payload = json.dumps(entry.to_dict(), indent=2, default=str)
        handle, tmp_name = tempfile.mkstemp(
            dir=str(self._dir), prefix=f".{entry.digest}.", suffix=".tmp"
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            tmp.chmod(0o600)
            os.replace(tmp, target)
        except OSError as exc:
            logger.warning("Failed to write token store: %s", exc)
            self._unlink(tmp)

    @staticmethod
    def _unlink(path: Path) -> None:
        """Best effort removal of a store file."""
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            logger.debug("Failed to remove %s: %s", path, exc)

    def _remove_cascade(self, digest: str) -> int:
        """Remove *digest* and everything derived from it."""
        removed = 0
        path = self._entry_path(digest)
        if path.exists():
            self._unlink(path)
            removed += 1
        for child in self.children(digest):
            removed += self._remove_cascade(child.digest)
        return removed

    # -- Deprecated host keyed access -----------------------------------

    @staticmethod
    def _legacy_identity(host: str, operation: str) -> AuthIdentity:
        """Build the legacy sentinel identity for a bare host string."""
        warnings.warn(
            f"TokenStore.{operation}() with a host string is deprecated and "
            "will be removed in a future release; pass an AuthIdentity so "
            "that tokens for different clients, grants, scopes and "
            "audiences do not collide.",
            DeprecationWarning,
            stacklevel=3,
        )
        return AuthIdentity(host=host, backend="py-oidc-auth", grant=None)

    def _legacy_lookup(self, host: str, operation: str) -> Optional[AuthIdentity]:
        """Resolve a bare host string to the best interactive identity."""
        identity = self._legacy_identity(host, operation)
        if self._entry_path(identity.digest).exists():
            return identity
        candidates = self.find(host=host, grants=INTERACTIVE_GRANTS)
        return candidates[0].identity if candidates else None

    # -- Migration ------------------------------------------------------

    def _migrate_legacy(self) -> int:
        """Convert a v1 host keyed store into per identity entries.

        The originating grant of a legacy entry is unrecoverable, so
        each is written with ``grant=None``, which
        :meth:`~.identity.AuthIdentity.matches` accepts for any
        interactive grant.  The upgrade therefore costs no logins, and
        the next successful mint replaces the sentinel with a real
        grant.

        Returns
        -------
        int
            Number of entries migrated.
        """
        meta = self._dir / "meta.json"
        if not meta.exists():
            try:
                meta.write_text(
                    json.dumps({"version": STORE_VERSION}), encoding="utf-8"
                )
            except OSError as exc:  # pragma: no cover - unwritable cache dir
                logger.debug("Could not write store metadata: %s", exc)
        legacy = self._legacy_path
        if legacy is None or not legacy.is_file():
            return 0
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Discarding unreadable legacy token store: %s", exc)
            self._unlink(legacy)
            return 0
        if not isinstance(data, dict) or "version" in data:
            self._unlink(legacy)
            return 0
        migrated = 0
        for host, raw in data.items():
            if not isinstance(raw, dict) or "token" not in raw:
                continue
            token = cast(Token, raw["token"])
            identity = AuthIdentity(
                host=host,
                backend="py-oidc-auth",
                grant=None,
                scopes=normalise_scopes(token.get("scope")),
            )
            entry = StoreEntry(
                identity=identity,
                token=token,
                stored_at=float(raw.get("stored_at", time.time())),
            )
            if entry.expired():
                continue
            self._write(entry)
            migrated += 1
        logger.info("Migrated %d token(s) from %s to %s", migrated, legacy, self._dir)
        self._unlink(legacy)
        return migrated
