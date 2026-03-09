Non interactive environments
============================

In batch jobs and remote sessions, a browser based login might not be possible. The client detects
common job environments and can use the device flow.

Recommended approach
--------------------

Store a refresh token on disk and point to it via a dedicated :class:`py_oidc_auth_client.TokenStore`.
The high level helper reads and updates this store across runs.

You usually do not need a different ``TokenStore`` for every host. ``TokenStore`` separates
tokens by host internally, so one store file per application or environment is often enough.

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   token = authenticate(
       host="https://auth.example.org",
       app_name="my-app",
       store=TokenStore(path="~/.cache/py-oidc-auth-client/my-app.json"),
   )

Why ``TokenStore`` is important here
------------------------------------

In non-interactive environments, the storage layer is often the difference between a smooth
unattended run and an authentication failure. A persisted refresh token lets the client renew
access without forcing a fresh browser-based login every time.

Device flow manual steps
------------------------

For advanced usage, use :class:`py_oidc_auth_client.DeviceFlow` directly.

.. code-block:: python

   import asyncio
   from py_oidc_auth_client import Config, DeviceFlow

   async def main() -> None:
       flow = DeviceFlow(config=Config(host="https://auth.example.org"))
       device = await flow.get_device_code()
       print(device["uri"])
       print(device["user_code"])
       token = await flow.poll(device.device_code, device.interval)
       print(token["headers"])

   asyncio.run(main())

Manual code flow
----------------

Browser based code flow can be realised by using the
:class:`py_oidc_auth_client.CodeFlow` class.

.. code-block:: python

   import asyncio
   from py_oidc_auth_client import CodeFlow, Config

   async def main() -> None:
       flow = CodeFlow(config=Config(host="https://auth.example.org"))
       token = await flow.authenticate()
       print(token["headers"])

   asyncio.run(main())
