"""Tests for py_oidc_auth_client.identity."""

from __future__ import annotations

import pytest

from py_oidc_auth_client.identity import (
    INTERACTIVE_GRANTS,
    AuthIdentity,
    Grant,
    normalise_host,
    normalise_scopes,
)

HOST = "https://myapp.example.com"


def ident(**kwargs) -> AuthIdentity:
    """Build an identity with sensible defaults for the tests."""
    kwargs.setdefault("host", HOST)
    kwargs.setdefault("backend", "oidc")
    kwargs.setdefault("grant", Grant.DEVICE_CODE)
    return AuthIdentity(**kwargs)


class TestNormaliseHost:
    """Host URL normalisation. Moved here from token_store."""

    def test_lowercase(self):
        assert normalise_host("https://MyApp.Example.COM") == "https://myapp.example.com"

    def test_strips_trailing_slash(self):
        assert normalise_host("https://example.com/") == "https://example.com"

    def test_strips_path_and_query(self):
        assert normalise_host("https://example.com/auth/v2?x=1") == "https://example.com"

    def test_drops_default_https_port(self):
        assert normalise_host("https://example.com:443") == "https://example.com"

    def test_drops_default_http_port(self):
        assert normalise_host("http://example.com:80") == "http://example.com"

    def test_keeps_non_default_port(self):
        assert normalise_host("http://localhost:8080") == "http://localhost:8080"
        assert normalise_host("https://example.com:8443") == "https://example.com:8443"

    def test_defaults_to_https_scheme(self):
        assert normalise_host("://example.com").startswith("https://")

    def test_empty_string(self):
        assert normalise_host("") == "https://"


class TestNormaliseScopes:
    """Scope canonicalisation."""

    def test_none_is_empty(self):
        assert normalise_scopes(None) == ()

    def test_splits_space_separated_string(self):
        assert normalise_scopes("openid profile") == ("openid", "profile")

    def test_sorts_and_dedupes(self):
        assert normalise_scopes(["profile", "openid", "profile"]) == (
            "openid",
            "profile",
        )

    def test_splits_within_sequence_items(self):
        assert normalise_scopes(["openid profile", "email"]) == (
            "email",
            "openid",
            "profile",
        )

    def test_drops_empties_and_extra_whitespace(self):
        assert normalise_scopes(["  openid   profile ", ""]) == ("openid", "profile")


class TestDigest:
    """Digest stability and the fields that feed it."""

    def test_is_short_hex(self):
        digest = ident().digest
        assert len(digest) == 16
        assert all(char in "0123456789abcdef" for char in digest)

    def test_stable_across_instances(self):
        assert ident().digest == ident().digest

    def test_host_normalised_before_hashing(self):
        assert ident(host="https://MyApp.Example.COM:443/").digest == ident().digest

    def test_scope_order_irrelevant(self):
        a = ident(scopes=("profile", "openid"))
        b = ident(scopes=("openid", "profile"))
        assert a.digest == b.digest

    def test_scope_string_and_sequence_agree(self):
        assert ident(scopes="openid profile").digest == ident(
            scopes=["profile", "openid"]
        ).digest

    def test_different_scopes_differ(self):
        assert ident(scopes=("openid",)).digest != ident(scopes=("openid", "email")).digest

    def test_different_client_differs(self):
        assert ident(client_id="a").digest != ident(client_id="b").digest

    def test_different_backend_differs(self):
        assert ident(backend="oidc").digest != ident(backend="py-oidc-auth").digest

    def test_different_audience_differs(self):
        assert ident(audience="s3").digest != ident(audience="waterpark").digest

    def test_client_auth_method_participates(self):
        assert ident(client_auth="secret_post").digest != ident(
            client_auth="private_key_jwt"
        ).digest

    def test_issuer_excluded_from_digest(self):
        """Issuer is resolved metadata, not configured input.

        Including it would make the cache key depend on a network round
        trip, so it must not change the digest.
        """
        assert ident(issuer="https://kc.example.com/realms/x").digest == ident().digest

    def test_issuer_excluded_from_equality(self):
        assert ident(issuer="https://a") == ident(issuer="https://b")

    def test_hashable(self):
        assert len({ident(), ident(), ident(client_id="other")}) == 2


class TestGrantIsolation:
    """Per flow isolation: each grant caches separately."""

    @pytest.mark.parametrize(
        "left,right",
        [
            (Grant.DEVICE_CODE, Grant.AUTHORIZATION_CODE),
            (Grant.DEVICE_CODE, Grant.CLIENT_CREDENTIALS),
            (Grant.AUTHORIZATION_CODE, Grant.CLIENT_CREDENTIALS),
            (Grant.DEVICE_CODE, Grant.TOKEN_EXCHANGE),
        ],
    )
    def test_grants_do_not_collide(self, left: Grant, right: Grant):
        assert ident(grant=left).digest != ident(grant=right).digest

    def test_interactive_grants_membership(self):
        assert Grant.DEVICE_CODE in INTERACTIVE_GRANTS
        assert Grant.AUTHORIZATION_CODE in INTERACTIVE_GRANTS
        assert Grant.CLIENT_CREDENTIALS not in INTERACTIVE_GRANTS
        assert Grant.TOKEN_EXCHANGE not in INTERACTIVE_GRANTS

    def test_grant_str_is_wire_value(self):
        assert str(Grant.DEVICE_CODE) == "urn:ietf:params:oauth:grant-type:device_code"
        assert str(Grant.CLIENT_CREDENTIALS) == "client_credentials"


class TestForExchange:
    """Derived identities for RFC 8693 results."""

    def test_grant_is_token_exchange(self):
        assert ident().for_exchange(audience="s3").grant is Grant.TOKEN_EXCHANGE

    def test_stable_for_same_request(self):
        parent = ident()
        assert (
            parent.for_exchange(audience="s3").digest
            == parent.for_exchange(audience="s3").digest
        )

    def test_audience_discriminates(self):
        parent = ident()
        assert (
            parent.for_exchange(audience="s3").digest
            != parent.for_exchange(audience="waterpark").digest
        )

    def test_requested_token_type_discriminates(self):
        parent = ident()
        access = parent.for_exchange(
            audience="s3",
            requested_token_type="urn:ietf:params:oauth:token-type:access_token",
        )
        saml = parent.for_exchange(
            audience="s3",
            requested_token_type="urn:ietf:params:oauth:token-type:saml2",
        )
        assert access.digest != saml.digest

    def test_different_parents_discriminate(self):
        a = ident(client_id="a").for_exchange(audience="s3")
        b = ident(client_id="b").for_exchange(audience="s3")
        assert a.digest != b.digest

    def test_inherits_parent_scopes_by_default(self):
        parent = ident(scopes=("openid", "profile"))
        assert parent.for_exchange(audience="s3").scopes == ("openid", "profile")

    def test_explicit_scopes_override(self):
        parent = ident(scopes=("openid", "profile"))
        child = parent.for_exchange(audience="s3", scopes=["email"])
        assert child.scopes == ("email",)

    def test_narrowed_scopes_discriminate(self):
        parent = ident(scopes=("openid", "profile"))
        assert (
            parent.for_exchange(audience="s3", scopes=["openid"]).digest
            != parent.for_exchange(audience="s3", scopes=["profile"]).digest
        )

    def test_external_subject_keeps_key_off_the_token_string(self):
        """An externally supplied subject token is identified by claims.

        The raw token cannot take part: it changes on every refresh,
        so the key would churn and never hit.
        """
        parent = ident()
        alice = parent.for_exchange(audience="s3", subject="https://idp|alice")
        bob = parent.for_exchange(audience="s3", subject="https://idp|bob")
        assert alice.digest != bob.digest
        assert (
            alice.digest
            == parent.for_exchange(audience="s3", subject="https://idp|alice").digest
        )

    def test_exchange_of_exchange(self):
        first = ident().for_exchange(audience="s3")
        second = first.for_exchange(audience="downstream")
        assert second.digest not in {first.digest, ident().digest}


class TestSerialisation:
    """Round tripping through the token store."""

    def test_roundtrip_preserves_digest(self):
        original = ident(
            client_id="cli",
            scopes=("openid", "profile"),
            audience="s3",
            client_auth="secret_post",
            issuer="https://kc.example.com",
        )
        assert AuthIdentity.from_dict(original.to_dict()).digest == original.digest

    def test_roundtrip_preserves_issuer(self):
        original = ident(issuer="https://kc.example.com")
        assert AuthIdentity.from_dict(original.to_dict()).issuer == (
            "https://kc.example.com"
        )

    def test_roundtrip_of_exchange_identity(self):
        child = ident().for_exchange(audience="s3")
        assert AuthIdentity.from_dict(child.to_dict()).digest == child.digest

    def test_from_dict_tolerates_unknown_keys(self):
        data = ident().to_dict()
        data["something_from_the_future"] = True
        assert AuthIdentity.from_dict(data).digest == ident().digest

    def test_from_dict_defaults_backend_for_legacy_entries(self):
        restored = AuthIdentity.from_dict({"host": HOST})
        assert restored.backend == "py-oidc-auth"
        assert restored.grant is None

    def test_to_dict_is_json_serialisable(self):
        import json

        json.dumps(ident(scopes=("openid",)).to_dict())


class TestMatches:
    """Partial identity lookup, used by TokenStore.find."""

    def test_empty_specification_matches_everything(self):
        assert ident().matches() is True

    def test_host_is_normalised(self):
        assert ident().matches(host="https://MyApp.Example.COM/") is True

    def test_host_mismatch(self):
        assert ident().matches(host="https://other.example.com") is False

    def test_backend_mismatch(self):
        assert ident(backend="oidc").matches(backend="py-oidc-auth") is False

    def test_client_id_mismatch(self):
        assert ident(client_id="a").matches(client_id="b") is False

    def test_audience_mismatch(self):
        assert ident(audience="s3").matches(audience="waterpark") is False

    def test_grant_in_set(self):
        assert ident(grant=Grant.DEVICE_CODE).matches(grants=INTERACTIVE_GRANTS) is True

    def test_grant_outside_set(self):
        assert (
            ident(grant=Grant.CLIENT_CREDENTIALS).matches(grants=INTERACTIVE_GRANTS)
            is False
        )

    def test_legacy_sentinel_matches_any_grant(self):
        """A migrated v1 entry cannot name its grant, so it matches all.

        This is what keeps the upgrade from forcing a fresh login.
        """
        legacy = ident(grant=None)
        assert legacy.matches(grants=INTERACTIVE_GRANTS) is True
        assert legacy.matches(grants=[Grant.CLIENT_CREDENTIALS]) is True

    def test_scopes_superset_hits(self):
        assert ident(scopes=("openid", "profile")).matches(scopes=["openid"]) is True

    def test_scopes_subset_misses(self):
        assert ident(scopes=("openid",)).matches(scopes=["openid", "email"]) is False

    def test_scopeless_entry_misses_scoped_probe(self):
        """A client credentials entry with no scopes is not a hit."""
        assert ident(scopes=()).matches(scopes=["openid"]) is False

    def test_scope_probe_is_normalised(self):
        assert ident(scopes=("openid", "profile")).matches(
            scopes=["profile openid"]
        ) is True

    def test_all_constraints_must_hold(self):
        subject = ident(client_id="cli", scopes=("openid",), audience="s3")
        assert (
            subject.matches(
                host=HOST,
                backend="oidc",
                grants=INTERACTIVE_GRANTS,
                client_id="cli",
                scopes=["openid"],
                audience="s3",
            )
            is True
        )
        assert subject.matches(host=HOST, client_id="other") is False
