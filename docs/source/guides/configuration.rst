Configuration
=============

Most users only need to specify the server host. For custom deployments, the client exposes
a configuration object.

Config
------

:class:`py_oidc_auth_client.utils.Config` defines:

* the server host
* route paths for login, token and device endpoints
* a set of redirect ports used for the local browser callback

Example:

.. code-block:: python

   from py_oidc_auth_client.utils import Config

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

   from py_oidc_auth_client import authenticate

   token = authenticate(
       host="https://auth.example.org",
       token_file="~/.cache/py-oidc-auth-client/token.json",
   )

Building docs
-------------

If your documentation build does not install optional dependencies, add the following to
your Sphinx ``conf.py``:

.. code-block:: python

   autodoc_mock_imports = [
       "httpx",
       "rich",
       "rich.console",
       "rich.spinner",
       "rich.live",
   ]
