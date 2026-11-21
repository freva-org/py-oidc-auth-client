"""
Exceptions
==========

All exceptions raised by the py_oidc_auth_client library.
"""

from typing import Any, Dict, Optional, Tuple

#: OAuth error codes that older py-oidc-auth servers only reported inside
#: the free text ``detail`` field, not as ``error``.
_KNOWN_ERROR_CODES: Tuple[str, ...] = (
    "authorization_pending",
    "slow_down",
    "expired_token",
    "access_denied",
    "invalid_grant",
    "invalid_client",
    "invalid_request",
    "invalid_scope",
    "invalid_target",
    "unauthorized_client",
    "unsupported_grant_type",
)


class AuthError(Exception):
    """Authentication or token exchange failed.

    Parameters
    ----------
    message : str
        Human readable summary of what went wrong.
    detail : dict, optional
        Raw error payload from the OIDC provider, typically containing
        ``"error"`` and ``"error_description"`` keys.
    status_code : int
        HTTP status code from the upstream response.  Defaults to 500
        when the error did not originate from an HTTP call.

    Attributes
    ----------
    message : str
        The error summary.
    detail : dict
        Provider error payload (empty dict if not available).
    status_code : int
        HTTP status code.
    error : str or None
        The OAuth error code (``invalid_grant``, ``access_denied``, ...)
        from ``detail``, or ``None`` when the provider sent none.

    Examples
    --------
    Catching authentication failures:

    .. code-block:: python

        from py_oidc_auth_client import authenticate
        from py_oidc_auth_client.exceptions import AuthError

        try:
            token = authenticate(host="https://myapp.example.com")
        except AuthError as exc:
            print(f"Login failed ({exc.status_code}): {exc}")
    """

    def __init__(
        self,
        message: str,
        detail: Optional[Dict[str, Any]] = None,
        status_code: int = 500,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}
        self.status_code = status_code

    @property
    def error(self) -> Optional[str]:
        """The OAuth error code of the provider response, if any.

        Read from ``detail["error"]``.  Older py-oidc-auth servers only
        sent a free text ``detail`` that embeds the upstream response;
        a known OAuth error code found in that text is returned too.
        """
        code = self.detail.get("error")
        if isinstance(code, str) and code:
            return code
        text = self.detail.get("detail")
        if isinstance(text, str):
            for known in _KNOWN_ERROR_CODES:
                if known in text:
                    return known
        return None

    def __str__(self) -> str:
        """Represent Error class as String."""
        if not self.detail:
            return self.message
        description = self.detail.get("error_description") or self.detail.get(
            "detail"
        )
        parts = [str(p) for p in (self.detail.get("error"), description) if p]
        if parts:
            return f"{self.message}: {': '.join(parts)}"
        return f"{self.message}: {self.detail}"
