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
       store=TokenStore(path="~/.cache/py-oidc-auth-client/my-app-token.json"),
   )

Integrate the token into another client library
-----------------------------------------------

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   def build_auth_headers(host: str) -> dict[str, str]:
       store = TokenStore(path="~/.cache/py-oidc-auth-client/my-client.json")
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

   store = TokenStore(path="~/.cache/py-oidc-auth-client/headless.json")
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
The store separates tokens by host internally, so the same token database can safely hold
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
