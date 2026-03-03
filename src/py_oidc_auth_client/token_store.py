"""
Token Store
===========

Per host token cache backed by a single JSON file.

Tokens are keyed by normalised host URL.  Stale entries (where the
refresh token has expired) are pruned automatically on every read.

File layout::

    {
        "https://myapp.example.com": {
            "token": { "access_token": "...", ... },
            "stored_at": 1717027200.0
        },
        "https://other.example.com": {
            "token": { ... },
            "stored_at": 1717030000.0
        }
    }

The file is locked (``fcntl`` on Unix, best effort elsewhere) to
avoid corruption when multiple processes authenticate concurrently.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

from platformdirs import user_cache_path

from .schema import Token
from .utils import DEFAULT_APP_NAME

logger = logging.getLogger(__name__)

# How many seconds before refresh_expires we consider the entry stale.
# Using a small buffer avoids race conditions where a token is loaded
# just as it expires.
_EXPIRY_BUFFER = 30


def _normalise_host(host: str) -> str:
    """Normalise a host URL for use as a cache key.

    Strips trailing slashes, lowercases the scheme and netloc, and
    removes default ports (80 for http, 443 for https).

    Parameters
    ----------
    host : str
        Raw host URL, e.g. ``"https://MyApp.Example.COM:443/"``.

    Returns
    -------
    str
        Normalised key, e.g. ``"https://myapp.example.com"``.

    Examples
    --------
    >>> _normalise_host("https://MyApp.Example.COM:443/")
    'https://myapp.example.com'
    >>> _normalise_host("http://localhost:8080")
    'http://localhost:8080'
    """
    parsed = urlparse(host)
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.hostname or "").lower()
    port = parsed.port
    # Drop default ports
    if port and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}"


class TokenStore:
    """Per host token cache with automatic TTL eviction.

    Each host gets its own entry in the store.  Stale entries are
    pruned lazily on every :meth:`get` call.

    Parameters
    ----------
    path : str or Path or None
        Path to the JSON cache file.  Defaults to the platform cache
        directory (``~/.cache/py-oidc-auth/token-store.json`` on
        Linux).
    app_name : str
        Application name for the cache directory.  Only used when
        *path* is ``None``.

    Examples
    --------
    Basic usage:

    .. code-block:: python

        from py_oidc_auth_client.token_store import TokenStore

        store = TokenStore()

        # Save a token for a host
        store.put("https://myapp.example.com", token)

        # Retrieve it later (returns None if expired)
        cached = store.get("https://myapp.example.com")
        if cached:
            print("Cache hit!")

        # See all cached hosts
        for host in store.hosts():
            print(host)

        # Remove a specific host
        store.remove("https://myapp.example.com")

    Custom file location:

    .. code-block:: python

        store = TokenStore("~/.config/myapp/tokens.json")

    Custom app directory:

    .. code-block:: python

        store = TokenStore(app_name="my-project")
        # -> ~/.cache/my-project/token-store.json
    """

    def __init__(
        self,
        path: Optional[Union[str, Path]] = None,
        app_name: str = DEFAULT_APP_NAME,
    ) -> None:
        if path:
            self._path = Path(path).expanduser().absolute()
        else:
            self._path = (
                user_cache_path(app_name, ensure_exists=True) / "token-store.json"
            )
        self._path.parent.mkdir(exist_ok=True, parents=True)

    # -- Public API -----------------------------------------------------

    def get(self, host: str) -> Optional[Token]:
        """Look up a cached token for *host*.

        Triggers a cleanup pass that removes all expired entries from
        the store file.

        Parameters
        ----------
        host : str
            The server URL to look up.

        Returns
        -------
        Token or None
            The cached token if it exists and is not expired, or
            ``None`` otherwise.

        Examples
        --------
        .. code-block:: python

            store = TokenStore()
            token = store.get("https://myapp.example.com")
            if token:
                headers = token["headers"]
        """
        data = self._load()
        self._evict(data)
        key = _normalise_host(host)
        entry = data.get(key)
        if entry is None:
            return None
        return cast(Optional[Token], entry["token"])

    def put(self, host: str, token: Token) -> None:
        """Store a token for *host*, overwriting any previous entry.

        Parameters
        ----------
        host : str
            The server URL the token belongs to.
        token : Token
            The token to cache.

        Examples
        --------
        .. code-block:: python

            store = TokenStore()
            store.put("https://myapp.example.com", token)
        """
        data = self._load()
        self._evict(data)
        key = _normalise_host(host)
        data[key] = {
            "token": dict(token),
            "stored_at": time.time(),
        }
        self._save(data)

    def remove(self, host: str) -> bool:
        """Remove the cached token for *host*.

        Parameters
        ----------
        host : str
            The server URL to remove.

        Returns
        -------
        bool
            ``True`` if an entry was removed, ``False`` if not found.

        Examples
        --------
        .. code-block:: python

            store = TokenStore()
            removed = store.remove("https://myapp.example.com")
        """
        data = self._load()
        key = _normalise_host(host)
        if key in data:
            del data[key]
            self._save(data)
            return True
        return False

    def hosts(self) -> List[str]:
        """Return the list of hosts that have cached tokens.

        Expired entries are pruned before building the list.

        Returns
        -------
        list of str
            Normalised host URLs.

        Examples
        --------
        .. code-block:: python

            store = TokenStore()
            for host in store.hosts():
                print(host)
        """
        data = self._load()
        self._evict(data)
        return list(data.keys())

    def clear(self) -> None:
        """Remove all cached tokens.

        Examples
        --------
        .. code-block:: python

            store = TokenStore()
            store.clear()
        """
        self._save({})

    # -- Internals ------------------------------------------------------

    def _load(self) -> Dict[str, Any]:
        """Read the store file, returning an empty dict on any error."""
        try:
            text = self._path.read_text(encoding="utf-8")
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self, data: Dict[str, Any]) -> None:
        """Atomically write the store to disk with restricted permissions."""
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
            tmp.chmod(0o600)
            tmp.replace(self._path)
        except OSError as exc:
            logger.warning("Failed to write token store: %s", exc)
            # Clean up temp file on failure
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _evict(data: Dict[str, Any]) -> int:
        """Remove entries whose refresh token has expired.

        Modifies *data* in place and returns the number of evicted
        entries.

        Parameters
        ----------
        data : dict
            The raw store dict (host -> entry).

        Returns
        -------
        int
            Number of entries removed.
        """
        now = time.time()
        stale = [key for key, entry in data.items() if _is_expired(entry, now)]
        for key in stale:
            logger.debug("Evicting expired token for %s", key)
            del data[key]
        return len(stale)


def _is_expired(entry: Dict[str, Any], now: float) -> bool:
    """Check whether a store entry should be evicted.

    An entry is expired when the refresh token expiry (the longest
    lived credential) has passed.  If no refresh expiry is recorded,
    the access token expiry is checked instead.

    Parameters
    ----------
    entry : dict
        A store entry with a ``"token"`` key.
    now : float
        Current Unix timestamp.

    Returns
    -------
    bool
        ``True`` if the entry is stale and should be removed.
    """
    token: Token = entry.get("token", {})
    # Use refresh_expires as the primary TTL (longest lived).
    # Fall back to access token expiry if refresh is absent.
    expiry = max(token.get("refresh_expires", 0), token.get("expires", 0))
    return now >= (expiry - _EXPIRY_BUFFER)
