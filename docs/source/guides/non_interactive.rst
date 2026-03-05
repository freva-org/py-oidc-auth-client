Non interactive environments
==========================

In batch jobs and remote sessions, a browser based login might not be possible. The client detects
common job environments and can use the device flow.

Recommended approach
--------------------

Store a refresh token on disk and point to it via a token file. The high level helper reads
and updates this file.

.. code-block:: python

   from py_oidc_auth_client import authenticate

   token = authenticate(
       host="https://auth.example.org",
       app_name="my-app",
   )

Device flow manual steps
------------------------

For advanced usage, use :class:`py_oidc_auth_client.DeviceFlow` directly.

.. code-block:: python

   import asyncio
   from py_oidc_auth_client import Config, DeviceFlow

   async def main():
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
    from py_oidc_auth_client import Config, CodeFlow

    async def main():
       flow = CodeFlow(config=Config(host="https://auth.example.org"))
       token = await flow.authenticate()
       print(token["headers"])

    asyncio.run(main())
