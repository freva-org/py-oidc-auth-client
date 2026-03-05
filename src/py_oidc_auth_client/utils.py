"""
Utilities
=========

Configuration, token persistence, and environment detection helpers.
"""

import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import partial
from typing import (
    Iterator,
    List,
    Literal,
    Optional,
    Union,
    cast,
)

import rich.console
import rich.spinner
from rich.live import Live

from .schema import Token

TOKEN_EXPIRY_BUFFER = 60  # seconds
TOKEN_ENV_VAR = "OIDC_TOKEN_FILE"
DEFAULT_APP_NAME = "py-oidc-auth"


def pprint(text: str, **args: Union[str, int]) -> None:
    """Pritty print a text to stderr."""
    console = rich.console.Console(
        force_terminal=is_interactive_shell(), stderr=True
    )
    _pprint = (
        console.print if console.is_terminal else partial(print, file=sys.stderr)
    )
    b, b_end = ("[b]", "[/b]") if console.is_terminal else ("", "")
    _pprint(text.format(b=b, b_end=b_end, **args))


@dataclass
class Config:
    """Connection and routing configuration for an OIDC enabled server.

    Parameters
    ----------
    host : str
        Base URL of the application server
        (e.g. ``"https://myapp.example.com"``).
    redirect_ports : list of int, optional
        Ports to try when starting a local HTTP server for the
        authorization code callback.  The first available port is used.
        Defaults to ``[53100, 53101, 53102, 53103, 53104, 53105]``.
    token_env_var : str
        Name of the environment variable that points to a token file.
    app_name : str
        Application name used to locate the platform specific cache
        directory for token storage (via ``platformdirs``).
    login_route : str
        Server side route for the authorization code login endpoint.
    token_route : str
        Server side route for the token exchange endpoint.
    device_route : str
        Server side route for the device authorization endpoint.

    Examples
    --------
    .. code-block:: python

        from py_oidc_auth_client.utils import Config

        cfg = Config(
            host="https://myapp.example.com",
            app_name="my-project",
            login_route="/auth/v2/login",
            token_route="/auth/v2/token",
            device_route="/auth/v2/device",
        )
    """

    host: str
    redirect_ports: List[int] = field(
        default_factory=lambda: [53100, 53101, 53102, 53103, 53104, 53105]
    )
    token_env_var: str = TOKEN_ENV_VAR
    app_name: str = DEFAULT_APP_NAME
    login_route: str = "/auth/v2/login"
    token_route: str = "/auth/v2/token"
    device_route: str = "/auth/v2/device"


def build_url(base: str, *parts: str) -> str:
    """Join a base URL with path segments.

    >>> build_url("http://localhost:7777/api/freva-nextgen", "/token/foo")
    'http://localhost:7777/api/freva-nextgen/token/foo'

    >>> build_url("http://localhost:7777/api/freva-nextgen/", "token", "foo")
    'http://localhost:7777/api/freva-nextgen/token/foo'
    """
    result = base.rstrip("/")
    for part in parts:
        result = result + "/" + part.strip("/")
    return result


@contextmanager
def clock(
    timeout: Optional[int] = None, interactive: Optional[bool] = None
) -> Iterator[None]:
    """Show a rich spinner while waiting for user approval.

    Parameters
    ----------
    timeout : int or None
        Total seconds to wait.  Shown in the spinner text.
    interactive : bool or None
        Force interactive mode on or off.  ``None`` auto detects.
    """
    console = rich.console.Console(
        force_terminal=is_interactive_shell(), stderr=True
    )
    txt = f"Timeout: {timeout:>3,.0f}s " if timeout else ""
    interactive = interactive if interactive is not None else console.is_terminal
    if int(os.getenv("INTERACTIVE_SESSION", str(int(interactive)))):
        spinner = rich.spinner.Spinner(
            "moon", text=f"[b]Waiting for code {txt}... [/]"
        )
        live = Live(
            spinner, console=console, refresh_per_second=2.5, transient=True
        )
        try:
            live.start()
            yield
        finally:
            live.stop()
    else:
        yield


def is_job_env() -> bool:
    """Detect whether the process runs inside a batch scheduler.

    Checks for environment variables set by Slurm, PBS, SGE, LSF,
    OAR, MPI, Kubernetes, JupyterHub, and FREVA batch jobs.

    Returns
    -------
    bool
        ``True`` if a batch environment is detected.
    """
    job_env_vars = [
        "SLURM_JOB_ID",
        "SLURM_NODELIST",
        "PBS_JOBID",
        "PBS_ENVIRONMENT",
        "PBS_NODEFILE",
        "JOB_ID",
        "SGE_TASK_ID",
        "PE_HOSTFILE",
        "LSB_JOBID",
        "LSB_HOSTS",
        "OAR_JOB_ID",
        "OAR_NODEFILE",
        "OMPI_COMM_WORLD_SIZE",
        "PMI_RANK",
        "MPI_LOCALRANKID",
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_PORT",
        "FREVA_BATCH_JOB",
        "JUPYTERHUB_USER",
    ]
    return any(var in os.environ for var in job_env_vars)


def is_jupyter_notebook() -> bool:
    """Check if the process runs inside a Jupyter kernel.

    Returns
    -------
    bool
        ``True`` if an IPython kernel is active.
    """
    try:
        from IPython.core.getipython import get_ipython

        return get_ipython() is not None  # pragma: no cover
    except Exception:
        return False


def is_interactive_shell() -> bool:
    """Check whether stdin and stdout are connected to a terminal.

    Returns
    -------
    bool
        ``True`` if both stdin and stdout are TTYs.
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def is_interactive_auth_possible() -> bool:
    """Decide if a browser based login flow can be attempted.

    Returns ``True`` when the session is interactive (TTY or local
    Jupyter) **and** not running inside a batch scheduler.

    Returns
    -------
    bool
        ``True`` if interactive authentication is feasible.
    """
    return (is_interactive_shell() or is_jupyter_notebook()) and not (
        is_job_env()
    )


def is_token_valid(
    token: Optional[Token],
    token_type: Literal["access_token", "refresh_token"],
) -> bool:
    """Check whether a token is present and not expired.

    Applies a safety buffer of :data:`TOKEN_EXPIRY_BUFFER` seconds
    (default 60) so that tokens close to expiry are treated as
    invalid.

    Parameters
    ----------
    token : Token or None
        Token dictionary to inspect.
    token_type : ``"access_token"`` or ``"refresh_token"``
        Which token (and corresponding expiry field) to check.

    Returns
    -------
    bool
        ``True`` if the token exists and will remain valid for at
        least :data:`TOKEN_EXPIRY_BUFFER` more seconds.
    """
    if not token:
        return False
    exp_key = cast(
        Literal["refresh_expires", "expires"],
        {
            "refresh_token": "refresh_expires",
            "access_token": "expires",
        }[token_type],
    )
    return (
        token_type in token
        and exp_key in token
        and (time.time() + TOKEN_EXPIRY_BUFFER < token[exp_key])
    )


def choose_token_strategy(
    token: Optional[Token] = None,
) -> Literal["use_token", "refresh_token", "interactive_auth", "fail"]:
    """Decide the best authentication action for the current state.

    Parameters
    ----------
    token : Token or None
        Previously cached token, or ``None`` if unavailable.

    Returns
    -------
    str
        One of:

        ``"use_token"``
            The access token is still valid.
        ``"refresh_token"``
            The access token expired but the refresh token is valid.
        ``"interactive_auth"``
            No usable tokens; a browser login should be attempted.
        ``"fail"``
            No usable tokens and no interactive session available.
    """
    if is_token_valid(token, "access_token"):
        return "use_token"
    if is_token_valid(token, "refresh_token"):
        return "refresh_token"
    if is_interactive_auth_possible():
        return "interactive_auth"
    return "fail"
