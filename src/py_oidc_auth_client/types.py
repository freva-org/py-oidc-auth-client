"""Type annotations."""

from typing import Dict, List, Literal, Optional, Union

from typing_extensions import NotRequired, TypedDict

AuthBackend = Literal["py-oidc-auth", "oidc"]

#: RFC 8693 token type identifiers.
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_REFRESH = "urn:ietf:params:oauth:token-type:refresh_token"
TOKEN_TYPE_ID = "urn:ietf:params:oauth:token-type:id_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

#: Short names for the RFC 8693 token types.
TOKEN_TYPES = {
    "access": TOKEN_TYPE_ACCESS,
    "refresh": TOKEN_TYPE_REFRESH,
    "id": TOKEN_TYPE_ID,
    "jwt": TOKEN_TYPE_JWT,
}


def token_type_urn(value: Optional[str]) -> Optional[str]:
    """Turn a token type short name into its RFC 8693 URN.

    URNs and ``None`` pass through unchanged.

    >>> token_type_urn("access")
    'urn:ietf:params:oauth:token-type:access_token'
    >>> token_type_urn("urn:ietf:params:oauth:token-type:jwt")
    'urn:ietf:params:oauth:token-type:jwt'
    >>> token_type_urn(None) is None
    True
    """
    if value is None:
        return None
    return TOKEN_TYPES.get(value.lower(), value)


class DeviceAuthorizationResponse(TypedDict):
    """Response body from the OOIDC device endpoint query."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    verification_uri_complete: NotRequired[str]
    interval: NotRequired[int]


class TokenResponse(TypedDict):
    """Response body from the OOIDC token endpoint query."""

    access_token: str
    token_type: NotRequired[str]
    expires_in: NotRequired[int]
    refresh_token: NotRequired[str]
    refresh_expires_in: NotRequired[int]
    scope: NotRequired[str]
    issued_token_type: NotRequired[str]

    # Supported compatibility fields
    expires: NotRequired[int]
    exp: NotRequired[int]
    expires_at: NotRequired[int]
    refresh_expires: NotRequired[int]
    refresh_exp: NotRequired[int]
    refresh_expires_at: NotRequired[int]


class OAuthErrorResponse(TypedDict):
    """Response body for an OAuthError."""

    error: str
    error_description: NotRequired[str]
    error_uri: NotRequired[str]


class OIDCDiscoveryDocument(TypedDict):
    """Information held by a oidc discovery document."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str

    userinfo_endpoint: NotRequired[str]
    end_session_endpoint: NotRequired[str]
    device_authorization_endpoint: NotRequired[str]
    introspection_endpoint: NotRequired[str]

    scopes_supported: NotRequired[list[str]]
    response_types_supported: NotRequired[list[str]]
    grant_types_supported: NotRequired[list[str]]
    token_endpoint_auth_methods_supported: NotRequired[list[str]]


JSONValue = Union[
    str, int, float, bool, None, List["JSONValue"], Dict[str, "JSONValue"]
]


JSONResponse = dict[str, JSONValue]
"""Nested JSON Body response."""
