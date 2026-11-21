"""Tests for py_oidc_auth_client.exceptions."""

from __future__ import annotations

import pytest

from py_oidc_auth_client.exceptions import AuthError


class TestAuthError:
    """AuthError construction and string representation."""

    def test_basic_message(self):
        exc = AuthError("something broke")
        assert str(exc) == "something broke"
        assert exc.message == "something broke"
        assert exc.detail == {}
        assert exc.status_code == 500

    def test_with_detail_and_status(self):
        detail = {"error": "invalid_grant", "error_description": "bad token"}
        exc = AuthError("token exchange failed", detail=detail, status_code=400)
        assert exc.status_code == 400
        assert exc.detail == detail
        assert "invalid_grant" in str(exc)

    def test_is_exception(self):
        with pytest.raises(AuthError):
            raise AuthError("boom")

    def test_str_without_detail(self):
        assert str(AuthError("no detail")) == "no detail"

    def test_str_with_detail(self):
        exc = AuthError("msg", detail={"error": "oops"})
        assert "msg" in str(exc)
        assert "oops" in str(exc)


class TestAuthErrorCode:
    """The OAuth error code, from new and old server responses."""

    def test_error_field(self):
        assert AuthError("x", detail={"error": "invalid_grant"}).error == (
            "invalid_grant"
        )

    def test_no_detail(self):
        assert AuthError("x").error is None

    def test_code_in_legacy_detail_text(self):
        detail = {
            "detail": 'Upstream OIDC error: {"error":"authorization_pending"}'
        }
        assert AuthError("x", detail=detail).error == "authorization_pending"

    def test_legacy_detail_without_code(self):
        assert AuthError("x", detail={"detail": "boom"}).error is None

    def test_non_string_error_is_ignored(self):
        assert AuthError("x", detail={"error": 42}).error is None


class TestAuthErrorStr:
    """Readable messages from the provider's error fields."""

    def test_error_and_description(self):
        exc = AuthError(
            "token failed",
            detail={"error": "invalid_grant", "error_description": "Token expired"},
        )
        assert str(exc) == "token failed: invalid_grant: Token expired"

    def test_legacy_detail_text(self):
        exc = AuthError("token failed", detail={"detail": "Missing code"})
        assert str(exc) == "token failed: Missing code"

    def test_unknown_payload_is_shown_as_is(self):
        exc = AuthError("token failed", detail={"foo": "bar"})
        assert str(exc) == "token failed: {'foo': 'bar'}"
