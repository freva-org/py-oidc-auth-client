"""
Utilities
=========

Configuration, token persistence, and environment detection helpers.
"""

import base64
import hashlib
import os
import secrets
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import partial
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
    cast,
)

import rich.console
import rich.spinner
from rich.live import Live

from .schema import Token
from .types import AuthBackend

TOKEN_EXPIRY_BUFFER = 60  # seconds
TOKEN_ENV_VAR = "OIDC_TOKEN_FILE"
DEFAULT_APP_NAME = "py-oidc-auth"


def pkce_pair() -> Tuple[str, str]:
    """Create a PKCE code verifier and its S256 challenge (RFC 7636).

    Returns
    -------
    tuple of str
        ``(code_verifier, code_challenge)``.  The verifier stays with
        the client; the challenge goes to the authorization request.
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def pprint(text: str, **args: Union[str, int]) -> None:
    """Pritty print a text to stderr."""
    console = rich.console.Console(force_terminal=is_interactive_shell(), stderr=True)
    _pprint = console.print if console.is_terminal else partial(print, file=sys.stderr)
    b, b_end = ("[b]", "[/b]") if console.is_terminal else ("", "")
    _pprint(text.format(b=b, b_end=b_end, **args))


@dataclass
class Config:
    """Connection and routing configuration for a py-oidc-auth enabled server.

    Parameters
    ----------
    host : str
        Base URL of the application server
        (e.g. ``"https://myapp.example.com"``).
    backend: str, py-oidc-auth, oidc
        The IDP backend that is used.  ``py-oidc-auth`` talks to the
        routes of a py-oidc-auth server; ``oidc`` talks to an OpenID
        Connect provider (Keycloak, ...) directly, with the endpoints
        taken from its discovery document.  See :meth:`from_discovery`.
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
    discovery_document_route: str, default: .well-known/openid-configuration
        Route of the discovery document, relative to *host* (oidc only).
    scopes: list[str], optional
        Default scopes for OIDC connections (not for py-oidc-auth).
        ``openid`` when empty.
    client_id: str, optional
        OIDC Client id used for oidc backends (not for py-oidc-auth).
        Defaults to ``app_name``.
    client_secret: str, default: None
        OIDC Client secret used for oidc backends (not for py-oidc-auth)
        this is only needed for client_id/client_secret based authentication.
    server_key: Path, str: default None
        Path to a PEM private key for ``private_key_jwt`` client
        authentication (RFC 7523, oidc only): the client signs a short
        lived assertion instead of sending a secret.  Needs the ``keys``
        extra.
    discovery_url: str, optional
        Full URL of the discovery document, when it is not *host* plus
        *discovery_document_route* (oidc only).
    key_id: str, optional
        ``kid`` header for ``private_key_jwt`` assertions, for providers
        that pick the verification key by it.

    Examples
    --------
    .. code-block:: python

        from py_oidc_auth_client.utils import Config

        py_oidc_auth_cfg = Config(
            host="https://myapp.example.com",
            app_name="my-project",
            login_route="/auth/v2/login",
            token_route="/auth/v2/token",
            device_route="/auth/v2/device",
        )

        oidc_auth_cfg = Config(
            host="https://keycloak.example.com/realms/myrealm",
            backend="oidc",
            client_id="my-project",
            client_secret="my-secret"
        )

        oidc_auth_cfg_with_key = Config.from_discovery(
            "https://example.com/realms/myrealm",
            client_id="my-service",
            server_key="~/.server.key",
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
    discovery_document_route: str = ".well-known/openid-configuration"
    scopes: List[str] = field(default_factory=list)
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    server_key: Optional[Union[str, "os.PathLike[str]"]] = None
    backend: AuthBackend = "py-oidc-auth"
    discovery_url: Optional[str] = None
    key_id: Optional[str] = None

    @classmethod
    def from_discovery(
        cls,
        url: str,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        server_key: Optional[Union[str, "os.PathLike[str]"]] = None,
        key_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        redirect_ports: Optional[List[int]] = None,
        app_name: str = DEFAULT_APP_NAME,
    ) -> "Config":
        """Configure a plain OpenID Connect provider from its discovery URL.

        Parameters
        ----------
        url : str
            The discovery document's URL
            (``https://kc.example.org/realms/freva/.well-known/openid-configuration``)
            or the issuer it belongs to
            (``https://kc.example.org/realms/freva``).
        client_id : str or None
            Client registered at the provider.  Defaults to *app_name*.
        client_secret : str or None
            Secret of a confidential client.
        server_key : path or None
            PEM private key for ``private_key_jwt`` client authentication.
        key_id : str or None
            ``kid`` for ``private_key_jwt`` assertions.
        scopes : list of str or None
            Default scopes, ``openid`` when not given.
        redirect_ports : list of int or None
            Local ports for the code flow callback.
        app_name : str
            Application name, the default *client_id*.

        Returns
        -------
        Config
            A config with ``backend="oidc"`` and *host* set to the issuer.

        Examples
        --------
        >>> cfg = Config.from_discovery("https://kc.example.org/realms/freva",
        ...                             client_id="cli")
        >>> cfg.host
        'https://kc.example.org/realms/freva'
        >>> cfg.discovery_document_url.endswith("/.well-known/openid-configuration")
        True
        """
        marker = "/.well-known/"
        if marker in url:
            host = url.split(marker, 1)[0]
            discovery: Optional[str] = url
        else:
            host = url.rstrip("/")
            discovery = None
        extra: Dict[str, Any] = {}
        if redirect_ports:
            extra["redirect_ports"] = redirect_ports
        return cls(
            host=host,
            backend="oidc",
            discovery_url=discovery,
            client_id=client_id,
            client_secret=client_secret,
            server_key=server_key,
            key_id=key_id,
            scopes=list(scopes or []),
            app_name=app_name,
            **extra,
        )

    @property
    def discovery_document_url(self) -> str:
        """Where the discovery document is (oidc backends)."""
        return self.discovery_url or build_url(
            self.host, self.discovery_document_route
        )

    @property
    def effective_client_id(self) -> str:
        """The client id, *app_name* when none is set."""
        return self.client_id or self.app_name

    @property
    def client_auth(self) -> Optional[str]:
        """How the client authenticates (oidc backends).

        ``private_key_jwt`` with a *server_key*, ``client_secret`` with a
        *client_secret*, ``None`` for a public client.  The method, never
        the credential, takes part in the cache key.
        """
        if self.backend != "oidc":
            return None
        if self.server_key:
            return "private_key_jwt"
        if self.client_secret:
            return "client_secret"
        return None


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
    console = rich.console.Console(force_terminal=is_interactive_shell(), stderr=True)
    txt = f"Timeout: {timeout:>3,.0f}s " if timeout else ""
    interactive = interactive if interactive is not None else console.is_terminal
    if int(os.getenv("INTERACTIVE_SESSION", str(int(interactive)))):
        spinner = rich.spinner.Spinner("moon", text=f"[b]Waiting for code {txt}... [/]")
        live = Live(spinner, console=console, refresh_per_second=2.5, transient=True)
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
    return (is_interactive_shell() or is_jupyter_notebook()) and not (is_job_env())


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
        bool(token.get(token_type))
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
