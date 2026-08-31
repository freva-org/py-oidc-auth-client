"""Tests for public typing helpers."""

from typing import get_args

from py_oidc_auth_client.types import AuthBackend, OIDCDiscoveryDocument


def test_auth_backend_values():
    assert set(get_args(AuthBackend)) == {"py-oidc-auth", "oidc"}


def test_discovery_document_shape():
    document: OIDCDiscoveryDocument = {
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "jwks_uri": "https://issuer.example.com/jwks",
        "device_authorization_endpoint": "https://issuer.example.com/device",
        "scopes_supported": ["openid", "profile"],
    }
    assert document["issuer"] == "https://issuer.example.com"
