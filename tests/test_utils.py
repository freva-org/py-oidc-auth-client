"""Tests for py_oidc_auth_client.utils."""

import os
from unittest.mock import patch

import pytest

from py_oidc_auth_client.utils import (
    Config,
    _clock,
    build_url,
    choose_token_strategy,
    is_interactive_auth_possible,
    is_job_env,
    is_token_valid,
)

from .conftest import make_expired_token, make_refresh_only_token, make_token


class TestBuildUrl:
    """URL joining that preserves the base path."""

    def test_simple_join(self):
        assert (
            build_url("http://localhost:7777/api/nextgen", "/token/foo")
            == "http://localhost:7777/api/nextgen/token/foo"
        )

    def test_trailing_slash_on_base(self):
        assert (
            build_url("http://localhost:7777/api/nextgen/", "token", "foo")
            == "http://localhost:7777/api/nextgen/token/foo"
        )

    def test_leading_slash_on_part(self):
        assert (
            build_url("http://localhost:7777", "/auth/v2/device")
            == "http://localhost:7777/auth/v2/device"
        )

    def test_multiple_parts(self):
        assert (
            build_url("https://example.com", "api", "v2", "token")
            == "https://example.com/api/v2/token"
        )

    def test_no_double_slashes(self):
        result = build_url("https://example.com/", "/path/")
        assert "//" not in result.split("://")[1]


class TestConfig:
    """Config dataclass defaults."""

    def test_defaults(self):
        cfg = Config(host="https://example.com")
        assert cfg.host == "https://example.com"
        assert cfg.login_route == "/auth/v2/login"
        assert cfg.token_route == "/auth/v2/token"
        assert cfg.device_route == "/auth/v2/device"
        assert isinstance(cfg.redirect_ports, list)
        assert len(cfg.redirect_ports) > 0

    def test_custom_routes(self):
        cfg = Config(
            host="https://example.com",
            login_route="/custom/login",
            token_route="/custom/token",
            device_route="/custom/device",
        )
        assert cfg.login_route == "/custom/login"


class TestIsTokenValid:
    """Token validity checks with expiry buffer."""

    def test_valid_access_token(self):
        assert is_token_valid(make_token(expires_in=300), "access_token") is True

    def test_expired_access_token(self):
        assert is_token_valid(make_token(expires_in=-100), "access_token") is False

    def test_valid_refresh_token(self):
        assert is_token_valid(make_token(refresh_expires_in=3600), "refresh_token") is True

    def test_expired_refresh_token(self):
        assert is_token_valid(make_token(refresh_expires_in=-100), "refresh_token") is False

    def test_none_token(self):
        assert is_token_valid(None, "access_token") is False

    def test_missing_key(self):
        token = make_token()
        del token["refresh_token"]
        assert is_token_valid(token, "refresh_token") is False

    def test_buffer_zone(self):
        """Token expiring within the buffer (60s) is treated as invalid."""
        assert is_token_valid(make_token(expires_in=30), "access_token") is False


class TestChooseTokenStrategy:
    """Strategy selection based on token state and environment."""

    def test_valid_access_token(self):
        assert choose_token_strategy(make_token()) == "use_token"

    def test_refresh_only(self):
        assert choose_token_strategy(make_refresh_only_token()) == "refresh_token"

    def test_no_token_interactive(self):
        with patch(
            "py_oidc_auth_client.utils.is_interactive_auth_possible",
            return_value=True,
        ):
            assert choose_token_strategy(None) == "interactive_auth"

    def test_no_token_non_interactive(self):
        with patch(
            "py_oidc_auth_client.utils.is_interactive_auth_possible",
            return_value=False,
        ):
            assert choose_token_strategy(None) == "fail"

    def test_fully_expired_interactive(self):
        with patch(
            "py_oidc_auth_client.utils.is_interactive_auth_possible",
            return_value=True,
        ):
            assert choose_token_strategy(make_expired_token()) == "interactive_auth"


class TestEnvironmentDetection:
    """Batch scheduler and interactivity detection."""

    def test_is_job_env_with_slurm(self):
        with patch.dict(os.environ, {"SLURM_JOB_ID": "12345"}):
            assert is_job_env() is True

    def test_is_job_env_with_pbs(self):
        with patch.dict(os.environ, {"PBS_JOBID": "67890"}):
            assert is_job_env() is True

    def test_is_job_env_clean(self):
        job_vars = {
            "SLURM_JOB_ID", "SLURM_NODELIST", "PBS_JOBID",
            "PBS_ENVIRONMENT", "PBS_NODEFILE", "JOB_ID", "SGE_TASK_ID",
            "PE_HOSTFILE", "LSB_JOBID", "LSB_HOSTS", "OAR_JOB_ID",
            "OAR_NODEFILE", "OMPI_COMM_WORLD_SIZE", "PMI_RANK",
            "MPI_LOCALRANKID", "KUBERNETES_SERVICE_HOST",
            "KUBERNETES_PORT", "FREVA_BATCH_JOB", "JUPYTERHUB_USER",
        }
        clean_env = {k: v for k, v in os.environ.items() if k not in job_vars}
        with patch.dict(os.environ, clean_env, clear=True):
            assert is_job_env() is False

    def test_interactive_auth_blocked_in_job(self):
        with patch("py_oidc_auth_client.utils.is_job_env", return_value=True):
            assert is_interactive_auth_possible() is False


class TestClock:
    """The _clock context manager spinner branch."""

    def test_spinner_runs_when_interactive(self):
        """Cover the spinner branch by forcing interactive=True."""
        entered = False
        with _clock(timeout=5, interactive=True):
            entered = True
        assert entered

    def test_no_spinner_when_non_interactive(self):
        """The non-interactive branch is a plain yield."""
        entered = False
        with patch.dict(os.environ, {"INTERACTIVE_SESSION": "0"}):
            with _clock(timeout=5, interactive=False):
                entered = True
        assert entered

    def test_spinner_without_timeout(self):
        """Cover the branch where timeout is None."""
        with _clock(timeout=None, interactive=True):
            pass
