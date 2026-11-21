Recipes
=======

This page collects short task-oriented examples that are easy to adapt to your own
application or client library.

Call a protected API with ``httpx``
-----------------------------------

.. code-block:: python

   import httpx
   from py_oidc_auth_client import authenticate

   token = authenticate(host="https://auth.example.org")

   with httpx.Client() as client:
       response = client.get(
           "https://service.example.org/protected",
           headers=token["headers"],
       )
       response.raise_for_status()
       print(response.json())

Use a dedicated token cache location
------------------------------------

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   token = authenticate(
       host="https://auth.example.org",
       store=TokenStore(path="~/.cache/py-oidc-auth-client/my-app-token"),
   )

Integrate the token into another client library
-----------------------------------------------

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   def build_auth_headers(host: str) -> dict[str, str]:
       store = TokenStore(path="~/.cache/py-oidc-auth-client/my-client")
       token = authenticate(host=host, store=store)
       return token["headers"]

   headers = build_auth_headers("https://auth.example.org")

Handle authentication errors
----------------------------

.. code-block:: python

   from py_oidc_auth_client import AuthError, authenticate

   try:
       token = authenticate(host="https://auth.example.org")
   except AuthError as exc:
       print(f"Authentication failed: {exc}")
       raise

Use device flow in a headless session
-------------------------------------

.. code-block:: python

   import asyncio
   from py_oidc_auth_client import Config, DeviceFlow, TokenStore, authenticate

   store = TokenStore(path="~/.cache/py-oidc-auth-client/headless")
   token = authenticate(
       host="https://auth.example.org",
       store=store,
   )
   print(token["headers"])

   async def main() -> None:
       flow = DeviceFlow(config=Config(host="https://auth.example.org"))
       device = await flow.get_device_code()
       print("Visit:", device["uri"])
       print("Code:", device["user_code"])
       token = await flow.poll(device.device_code, device.interval)
       print(token["headers"])

   asyncio.run(main())

Use multiple auth servers with one ``TokenStore``
-------------------------------------------------

When you talk to more than one auth service, one shared ``TokenStore`` is often enough.
The store separates tokens by identity internally, so the same token database can safely hold
entries for more than one auth server.

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   store = TokenStore(app_name="my-app")

   token_a = authenticate(
       host="https://auth-a.example.org",
       store=store,
   )

   token_b = authenticate(
       host="https://auth-b.example.org",
       store=store,
   )


Exchange a token for another service
------------------------------------

Token exchange (RFC 8693) turns a token you have into one for another audience or with
fewer scopes.  Without a ``subject``, :func:`~py_oidc_auth_client.exchange` exchanges
your login on the same server, logging in first if needed:

.. code-block:: python

   from py_oidc_auth_client import TokenStore, exchange

   store = TokenStore(app_name="my-app")
   token = exchange(
       host="https://auth.example.org",
       audience="s3-gateway",
       scopes="read",
       store=store,
   )

Exchanged tokens usually have no refresh token.  The result is cached and linked to the
login it came from: once it expires, the next call exchanges a fresh subject token, and
removing the login from the store removes the exchanged token too.

The subject can be any flow, the identity of a cached token, or a token you got
elsewhere:

.. code-block:: python

   import os

   from py_oidc_auth_client import CodeFlow, exchange

   token = exchange(
       host="https://auth.example.org",
       subject=CodeFlow("https://auth.example.org", store=store),
       audience="s3-gateway",
       store=store,
   )
   token = exchange(host="https://auth.example.org", subject=os.environ["CI_TOKEN"])


Use a login at a trusting peer server
-------------------------------------

A py-oidc-auth server in broker mode accepts tokens of the peer servers it trusts as
exchange subjects.  Exchange your login on one server at the other one:

.. code-block:: python

   from py_oidc_auth_client import DeviceFlow, exchange

   login = DeviceFlow("https://freva.dkrz.de", store=store)
   token = exchange(host="https://freva.example.org", subject=login, store=store)

The token is minted by the peer and expires with the subject token.
