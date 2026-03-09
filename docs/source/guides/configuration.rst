Configuration
=============

Most users only need to specify the server host. For custom deployments, the client exposes
a configuration object and an explicit token storage layer.

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

``TokenStore``
--------------

:class:`py_oidc_auth_client.TokenStore` controls where tokens are persisted between runs.
It separates tokens by host internally, so one store file can usually serve several auth
servers safely. ``authenticate()``, ``CodeFlow``, and ``DeviceFlow`` obtain tokens. ``TokenStore`` keeps
those tokens available between runs so the client can:

Use it when you want:

* a predictable token cache path
* separate storage per application or environment
* refresh-token based reuse in remote or automated sessions
* one shared host-aware token database for the same tool

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   token = authenticate(
       host="https://auth.example.org",
       store=TokenStore(app_anme="my-app"),
   )



In practice, the storage layer is as important as the flow classes, because
it turns a one-off login into a usable day-to-day authentication workflow.

Best practice
^^^^^^^^^^^^^

A dedicated store per tool or environment is often the safest layout.
Separate stores are usually about operational boundaries such as
dev vs. prod, not about host separation.

.. code-block:: python

   from py_oidc_auth_client import TokenStore, authenticate

   prod_store = TokenStore(path="my-app")
   dev_store = TokenStore(path="~/.cache/py-oidc-auth-client/dev.json")

   dev_token = authenticate(
       host="https://auth-dev.example.org",
       store=dev_store,
   )

   prod_token = authenticate(
       host="https://auth.example.org",
       store=prod_store,
   )


Token file environment variable
-------------------------------

If your deployment uses an environment-based token location, configure the path via:

* ``OIDC_TOKEN_FILE``
