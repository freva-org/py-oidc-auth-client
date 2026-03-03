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
       token_file="~/.oidc-token.json",
   )

Device flow manual steps
------------------------

For advanced usage, use :class:`py_oidc_auth_client.auth.DeviceFlowResponse` directly.

.. code-block:: python

   import asyncio
   from py_oidc_auth_client.auth import DeviceFlowResponse
   from py_oidc_auth_client.utils import Config

   async def main():
       flow = DeviceFlowResponse(config=Config(host="https://auth.example.org"), token=None)
       device = await flow.get_device_code()
       print(device.uri)
       print(device.user_code)
       await flow.poll_for_token(device.device_code, device.interval)
       print(flow.token.headers)

   asyncio.run(main())
