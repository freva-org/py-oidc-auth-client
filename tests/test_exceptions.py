"""Tests for py_oidc_auth_client.exceptions."""

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
