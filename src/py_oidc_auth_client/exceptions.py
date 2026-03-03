"""
Exceptions
==========

All exceptions raised by the py_oidc_auth_client library.
"""

from typing import Any, Dict, Optional


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

    def __str__(self) -> str:
        """Represent Error class as String."""
        if self.detail:
            return f"{self.message}: {self.detail}"
        return self.message
