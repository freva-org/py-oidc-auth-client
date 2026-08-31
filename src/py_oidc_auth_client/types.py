"""Type annotations."""

from typing import Literal

from typing_extensions import NotRequired, TypedDict

AuthBackend = Literal["py-oidc-auth", "oidc"]


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
