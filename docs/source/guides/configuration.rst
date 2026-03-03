Configuration
=============

Most users only need to specify the server host. For custom deployments, the client exposes
a configuration object.

Config
------

:class:`py_oidc_auth_client.Config` defines:

* the server host
* route paths for login, token and device endpoints
* a set of redirect ports used for the local browser callback

Example:

.. code-block:: python

   from py_oidc_auth_client import Config

   config = Config(
       host="https://auth.example.org",
       login_route="/auth/v2/login",
       token_route="/auth/v2/token",
       device_route="/auth/v2/device",
   )

Token file location
-------------------

The high level helper uses a token file to store and refresh tokens across sessions.

.. code-block:: python

   from py_oidc_auth_client import authenticate, TokenStore

   token = authenticate(
       host="https://auth.example.org",
       store=TokenStore(path="~/.cache/py-oidc-auth-client/token.json"),
   )
