"""
Data Models
===========

Typed data structures for tokens and device codes used throughout
the client library.
"""

from typing import Dict

from typing_extensions import TypedDict


class Token(TypedDict, total=False):
    """OAuth 2.0 token payload.

    Attributes
    ----------
    access_token : str
        The bearer access token (JWT).
    token_type : str
        Token type, typically ``"Bearer"``.
    expires : int
        Access token expiry as a Unix timestamp (seconds).
    refresh_token : str
        The refresh token for obtaining new access tokens.
    refresh_expires : int
        Refresh token expiry as a Unix timestamp (seconds).
    scope : str
        Space separated list of granted scopes.
    headers : dict of str to str
        Pre built ``Authorization`` header ready for use with HTTP
        clients (e.g. ``{"Authorization": "Bearer eyJ..."}``)

    Examples
    --------
    Using the token with ``httpx``:

    .. code-block:: python

        from py_oidc_auth_client import authenticate

        token = authenticate(host="https://myapp.example.com")
        headers = token["headers"]

        import httpx
        resp = httpx.get(
            "https://myapp.example.com/api/data",
            headers=headers,
        )
    """

    access_token: str
    token_type: str
    expires: int
    refresh_token: str
    refresh_expires: int
    scope: str
    headers: Dict[str, str]


class DeviceCode(TypedDict):
    """Device authorization response.

    Returned by :meth:`~DeviceFlow.get_device_code`.  Pass
    ``device_code`` and ``interval`` to
    :meth:`~DeviceFlow.poll` to complete the flow.

    Attributes
    ----------
    uri : str
        Verification URL the user should open in a browser.
        This is ``verification_uri_complete`` when the provider
        supports it, otherwise ``verification_uri``.
    user_code : str
        Short code the user enters at the verification URI
        (e.g. ``"ABCD-EFGH"``).
    device_code : str
        Opaque code used to poll the token endpoint.
    interval : int
        Minimum polling interval in seconds.

    Examples
    --------
    Manual device flow:

    .. code-block:: python

        from py_oidc_auth_client import DeviceFlow

        flow = DeviceFlow("https://myapp.example.com")
        code = await flow.get_device_code()

        print(f"Open {code['uri']} and enter: {code['user_code']}")

        token = await flow.poll(
            device_code=code["device_code"],
            interval=code["interval"],
        )
    """

    uri: str
    user_code: str
    device_code: str
    interval: int
