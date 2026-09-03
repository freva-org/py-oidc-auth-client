"""Type annotations."""

from typing import Dict, List, Literal, Union

from typing_extensions import NotRequired, TypedDict

AuthBackend = Literal["py-oidc-auth", "oidc"]


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
