"""
Auth Identity
=============

Cache identity for an authentication result.

A token is only interchangeable with another token when every input that
influenced its issuance matches: the provider it came from, the grant
that produced it, the client that asked for it, the scopes granted, and
the audience it was minted for.  :class:`AuthIdentity` captures those
inputs, and its :attr:`~AuthIdentity.digest` is the key under which the
resulting token is cached.

Only *configured* inputs take part in the digest, never discovered ones.
Keying on a discovery document's ``issuer`` would be more precise, but
resolving it requires a network round trip, and a cache key that cannot
be computed offline makes "do I already have a token?" an async
question.  The resolved issuer is recorded alongside the entry as
metadata instead.

Secrets never take part either.  ``client_auth`` records the *method*
(``"secret_post"``, ``"private_key_jwt"``, ...) and not the credential,
so rotating a client secret does not orphan every cached token.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

from .types import AuthBackend

__all__ = ["Grant", "AuthIdentity", "normalise_host", "normalise_scopes"]

_DIGEST_LENGTH = 16
"""Hex characters kept from the sha256 digest (64 bits)."""


class Grant(str, Enum):
    """OAuth 2.0 grant types the client can drive.

    The values are the wire representations, so members can be passed
    straight to a token endpoint as ``grant_type``.
    """

    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

    def __str__(self) -> str:
        """Represent the grant by its wire value."""
        return self.value

    @property
    def display(self) -> str:
        """Short human readable name, for CLI listings and log lines.

        The enum values are wire representations, and the URN spelled
        ones are far too long to tabulate.

        Returns
        -------
        str
            e.g. ``"device_code"`` for the device code grant URN.

        Examples
        --------
        >>> Grant.DEVICE_CODE.display
        'device_code'
        >>> Grant.TOKEN_EXCHANGE.display
        'token_exchange'
        >>> Grant.CLIENT_CREDENTIALS.display
        'client_credentials'
        """
        _, _, tail = self.value.rpartition("grant-type:")
        return (tail or self.value).replace("-", "_")


#: Grants that mint a token on behalf of an end user, and are therefore
#: interchangeable candidates when resolving a cached interactive login.
INTERACTIVE_GRANTS = frozenset(
    {Grant.AUTHORIZATION_CODE, Grant.DEVICE_CODE}
)


def normalise_host(host: str) -> str:
    """Normalise a host URL for use in a cache identity.

    Lowercases scheme and hostname, drops default ports and any path,
    query or fragment.

    Parameters
    ----------
    host : str
        Raw host URL, e.g. ``"https://MyApp.Example.COM:443/"``.

    Returns
    -------
    str
        Normalised origin, e.g. ``"https://myapp.example.com"``.

    Examples
    --------
    >>> normalise_host("https://MyApp.Example.COM:443/")
    'https://myapp.example.com'
    >>> normalise_host("http://localhost:8080")
    'http://localhost:8080'
    """
    parsed = urlparse(host)
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.hostname or "").lower()
    port = parsed.port
    if port and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}"


def normalise_scopes(scopes: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Canonicalise a scope collection for use in a cache identity.

    Accepts either a sequence of scopes or a single space separated
    string, splits on whitespace, drops duplicates and empties, and
    sorts the result.  ``"openid profile"`` and ``["profile", "openid"]``
    request the same token and must therefore share a cache entry.

    Parameters
    ----------
    scopes : iterable of str or None
        Scopes to canonicalise.

    Returns
    -------
    tuple of str
        Sorted, deduplicated scopes.

    Examples
    --------
    >>> normalise_scopes("openid profile openid")
    ('openid', 'profile')
    >>> normalise_scopes(["profile", "openid"])
    ('openid', 'profile')
    >>> normalise_scopes(None)
    ()
    """
    if scopes is None:
        return ()
    if isinstance(scopes, str):
        scopes = [scopes]
    parts = {part for scope in scopes for part in scope.split() if part}
    return tuple(sorted(parts))


@dataclass(frozen=True)
class AuthIdentity:
    """Everything that makes one authentication result unique.

    Instances are immutable and hashable, and their :attr:`digest` is
    the token store key.  Two flows that produce interchangeable tokens
    must build equal identities; two flows that do not must differ in at
    least one field.

    Parameters
    ----------
    host : str
        Base URL of the provider or application server.  Normalised on
        construction, so callers may pass a raw URL.
    backend : str
        Which provider backend drives the flow, ``"py-oidc-auth"`` or
        ``"oidc"``.
    grant : Grant or None
        The grant that produced the token.  Grants are isolated from one
        another: a device flow token and an authorization code token for
        the same client and scopes are cached separately.  ``None`` is
        the migration sentinel for a legacy entry whose originating
        interactive grant is unknown; see :meth:`matches`.
    client_id : str or None
        OIDC client the token was issued to.  ``None`` for
        ``py-oidc-auth`` backends, where the server owns the client
        registration.
    scopes : tuple of str
        Granted scopes, canonicalised via :func:`normalise_scopes`.
    audience : str or None
        Audience or resource the token was minted for.  A token issued
        for one audience is not usable at another, so this must take
        part in the key.
    client_auth : str or None
        Label of the client authentication method, never the credential
        itself.
    exchange : str or None
        Discriminator for :attr:`Grant.TOKEN_EXCHANGE` results, tying
        the entry to the parent identity and requested token type it was
        derived from.  See :meth:`for_exchange`.
    issuer : str or None
        Issuer as resolved from a discovery document.  Recorded for
        display and debugging and deliberately excluded from
        :attr:`digest`.

    Examples
    --------
    >>> user = AuthIdentity(
    ...     host="https://myapp.example.com",
    ...     backend="oidc",
    ...     grant=Grant.DEVICE_CODE,
    ...     client_id="my-cli",
    ...     scopes=("openid", "profile"),
    ... )
    >>> service = replace(user, grant=Grant.CLIENT_CREDENTIALS)
    >>> user.digest == service.digest
    False

    Scope order does not matter:

    >>> a = AuthIdentity("https://h", "oidc", Grant.DEVICE_CODE,
    ...                  scopes=("profile", "openid"))
    >>> b = AuthIdentity("https://h", "oidc", Grant.DEVICE_CODE,
    ...                  scopes=("openid", "profile"))
    >>> a.digest == b.digest
    True
    """

    host: str
    backend: AuthBackend
    grant: Optional[Grant]
    client_id: Optional[str] = None
    scopes: Tuple[str, ...] = ()
    audience: Optional[str] = None
    client_auth: Optional[str] = None
    exchange: Optional[str] = None
    issuer: Optional[str] = field(default=None, compare=False)

    def __post_init__(self) -> None:
        """Canonicalise host and scopes so equal inputs compare equal."""
        object.__setattr__(self, "host", normalise_host(self.host))
        object.__setattr__(self, "scopes", normalise_scopes(self.scopes))

    # -- Key ------------------------------------------------------------

    @property
    def key_components(self) -> Dict[str, Any]:
        """Return the fields that take part in :attr:`digest`.

        Excludes :attr:`issuer`, which is resolved metadata rather than
        configured input.

        Returns
        -------
        dict
            JSON serialisable mapping of key fields.
        """
        return {
            "host": self.host,
            "backend": str(self.backend),
            "grant": str(self.grant),
            "client_id": self.client_id,
            "scopes": list(self.scopes),
            "audience": self.audience,
            "client_auth": self.client_auth,
            "exchange": self.exchange,
        }

    @property
    def digest(self) -> str:
        """Stable short hash identifying this identity.

        Returns
        -------
        str
            The first 16 hex characters of the sha256 digest over the
            canonically serialised :attr:`key_components`.

        Examples
        --------
        >>> ident = AuthIdentity("https://h", "oidc", Grant.DEVICE_CODE)
        >>> len(ident.digest)
        16
        >>> ident.digest == AuthIdentity(
        ...     "https://H/", "oidc", Grant.DEVICE_CODE
        ... ).digest
        True
        """
        blob = json.dumps(
            self.key_components,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:_DIGEST_LENGTH]

    @property
    def label(self) -> str:
        """Human readable one line summary for ``--list`` output.

        Returns
        -------
        str
            Summary of the form
            ``"https://host [grant] client=... scopes=... (digest)"``.

        Examples
        --------
        >>> ident = AuthIdentity(
        ...     "https://h", "oidc", Grant.CLIENT_CREDENTIALS,
        ...     client_id="svc",
        ... )
        >>> ident.label == (
        ...     f"https://h [client_credentials] client=svc ({ident.digest})"
        ... )
        True
        """
        parts = [self.host, f"[{self.grant}]"]
        if self.client_id:
            parts.append(f"client={self.client_id}")
        if self.scopes:
            parts.append("scopes=" + ",".join(self.scopes))
        if self.audience:
            parts.append(f"audience={self.audience}")
        parts.append(f"({self.digest})")
        return " ".join(parts)

    # -- Derivation -----------------------------------------------------

    def for_exchange(
        self,
        *,
        audience: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        requested_token_type: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> "AuthIdentity":
        """Derive the identity of a token exchanged from this one.

        The subject token cannot itself take part in the key: it is a
        bearer credential that changes on every refresh, so hashing it
        would churn the key and the cache would never hit.  The parent
        :attr:`digest` is stable across refreshes and is used instead,
        which also records the link needed to re-mint the exchanged
        token once it expires without a refresh token of its own.

        Parameters
        ----------
        audience : str or None
            Audience requested for the exchanged token.
        scopes : iterable of str or None
            Scopes requested for the exchanged token.  Inherits this
            identity's scopes when ``None``.
        requested_token_type : str or None
            RFC 8693 ``requested_token_type``.
        subject : str or None
            Stable identifier of an externally supplied subject token,
            for use when the subject did not come from this store.
            Derive it from stable claims (``iss``, ``sub``, ``azp``) and
            never from the token string.  Defaults to this identity's
            digest.

        Returns
        -------
        AuthIdentity
            Identity for the exchanged token, with :attr:`grant` set to
            :attr:`Grant.TOKEN_EXCHANGE`.

        Examples
        --------
        >>> parent = AuthIdentity(
        ...     "https://h", "oidc", Grant.DEVICE_CODE, client_id="cli"
        ... )
        >>> child = parent.for_exchange(audience="s3.example.com")
        >>> child.grant is Grant.TOKEN_EXCHANGE
        True
        >>> child.digest == parent.for_exchange(
        ...     audience="s3.example.com"
        ... ).digest
        True
        >>> child.digest == parent.for_exchange(audience="other").digest
        False
        """
        material = json.dumps(
            {
                "subject": subject or self.digest,
                "requested_token_type": requested_token_type,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        token = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return replace(
            self,
            grant=Grant.TOKEN_EXCHANGE,
            audience=audience,
            scopes=normalise_scopes(scopes) if scopes is not None else self.scopes,
            exchange=token[:_DIGEST_LENGTH],
        )

    # -- Serialisation --------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for storage next to the cached token.

        Returns
        -------
        dict
            All fields including :attr:`issuer`.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthIdentity":
        """Rebuild an identity from its stored representation.

        Unknown keys are ignored so that a store written by a newer
        version stays readable.

        Parameters
        ----------
        data : dict
            Mapping as produced by :meth:`to_dict`.

        Returns
        -------
        AuthIdentity
            The reconstructed identity.
        """
        grant = data.get("grant")
        return cls(
            host=data["host"],
            backend=data.get("backend", "py-oidc-auth"),
            grant=Grant(grant) if grant else None,
            client_id=data.get("client_id"),
            scopes=normalise_scopes(data.get("scopes")),
            audience=data.get("audience"),
            client_auth=data.get("client_auth"),
            exchange=data.get("exchange"),
            issuer=data.get("issuer"),
        )

    def matches(
        self,
        *,
        host: Optional[str] = None,
        backend: Optional[AuthBackend] = None,
        grants: Optional[Iterable[Optional[Grant]]] = None,
        client_id: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        audience: Optional[str] = None,
    ) -> bool:
        """Test this identity against a partial specification.

        Used by the token store to answer "is there any cached token I
        could use here?" before a flow is chosen, which is what keeps
        grant isolation from forcing a redundant interactive login when
        a sibling grant already holds a usable token.

        A ``grant`` of ``None`` on *this* identity is the migration
        sentinel for a legacy entry of unknown interactive grant, and
        matches any requested grant.

        Parameters
        ----------
        host, backend, client_id, audience : str or None
            Exact match when given, ignored when ``None``.
        grants : iterable of Grant or None
            Acceptable grants.  Ignored when ``None``.
        scopes : iterable of str or None
            Required scopes.  Matches when this identity's scopes are a
            superset, so a token granted more than asked for is still a
            hit.

        Returns
        -------
        bool
            ``True`` when every given constraint holds.
        """
        if host is not None and self.host != normalise_host(host):
            return False
        if backend is not None and self.backend != backend:
            return False
        if grants is not None and self.grant is not None:
            if self.grant not in set(grants):
                return False
        if client_id is not None and self.client_id != client_id:
            return False
        if audience is not None and self.audience != audience:
            return False
        if scopes is not None:
            if not set(normalise_scopes(scopes)).issubset(self.scopes):
                return False
        return True
