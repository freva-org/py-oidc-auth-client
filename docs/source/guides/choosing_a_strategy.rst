Choosing an authentication strategy
===================================

The library offers a high level helper, two flow classes, and an explicit token storage
component. In practice, the main building blocks are ``authenticate()``, ``CodeFlow``,
``DeviceFlow``, and ``TokenStore``.

Recommended default: ``authenticate()``
---------------------------------------

Use :func:`py_oidc_auth_client.authenticate` when you want the client to choose the
best available authentication strategy automatically.

It will usually try the following steps in order:

1. Reuse a valid cached access token.
2. Refresh the token if a refresh token is available.
3. Fall back to an interactive flow if the environment allows it.
4. Raise a helpful error in strictly non-interactive environments when no valid token is available.

.. code-block:: python

   from py_oidc_auth_client import authenticate

   token = authenticate(host="https://auth.example.org", app_name="my-app")
   headers = token["headers"]

Use ``TokenStore`` explicitly
-----------------------------

Use :class:`py_oidc_auth_client.TokenStore` when you want control over where token state
is stored and refreshed. This matters just as much as choosing the right flow, because the
store determines whether later runs can reuse or refresh existing credentials.

Typical cases are:

* application-specific token cache files
* separate auth state for development, staging, and production
* remote or batch jobs that depend on refresh tokens between runs
* tools that talk to multiple auth servers and want one shared host-aware token database

``TokenStore`` already separates tokens by host internally, so multiple auth servers do
not usually require multiple store instances.

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   store = TokenStore(app_name="my-app")

   token = authenticate(
       host="https://auth.example.org",
       store=store,
   )

Use ``CodeFlow`` directly
-------------------------

Use :class:`py_oidc_auth_client.CodeFlow` when you explicitly want a browser-based
interactive login with local callback handling and you do not want the library to
choose a different strategy first.

Typical cases are:

* desktop tools
* developer CLIs launched from a local shell
* situations where you need to control timeout or callback behaviour more precisely

.. code-block:: python

   import asyncio
   from py_oidc_auth_client import CodeFlow, Config

   async def main() -> None:
       flow = CodeFlow(config=Config(host="https://auth.example.org"))
       token = await flow.authenticate()
       print(token["headers"])

   asyncio.run(main())

Use ``DeviceFlow`` directly
---------------------------

Use :class:`py_oidc_auth_client.DeviceFlow` when a browser callback on the local machine
is not practical or not possible. This is usually the best fit for:

* remote shells
* HPC and batch jobs
* CI or automation environments that still permit a user approval step
* headless servers

.. code-block:: python

   import asyncio
   from py_oidc_auth_client import Config, DeviceFlow

   async def main() -> None:
       flow = DeviceFlow(config=Config(host="https://auth.example.org"))
       device = await flow.get_device_code()
       print("Open:", device["uri"])
       print("Code:", device["user_code"])
       token = await flow.poll(device.device_code, device.interval)
       print(token["headers"])

   asyncio.run(main())

Which option should I use?
--------------------------

Use this rule of thumb:

* start with :func:`py_oidc_auth_client.authenticate`
* configure :class:`py_oidc_auth_client.TokenStore` explicitly when token persistence matters
* keep one ``TokenStore`` per application or environment unless you need stricter isolation
* switch to :class:`py_oidc_auth_client.CodeFlow` when you need explicit interactive browser handling
* switch to :class:`py_oidc_auth_client.DeviceFlow` when you are running headless

For most applications, the high level helper plus an explicit ``TokenStore`` is the right
place to begin.
