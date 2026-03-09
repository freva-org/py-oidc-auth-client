.. image:: _static/logo.png
   :alt: py-oidc-auth-client logo
   :width: 560px
   :align: center

.. centered:: *Typed client library for the authentication routes exposed by py-oidc-auth.*

.. image:: https://img.shields.io/badge/License-BSD-purple.svg
   :target: LICENSE

.. image:: https://readthedocs.org/projects/py-oidc-auth-client/badge/?version=latest
   :target: https://py-oidc-auth-client.readthedocs.io/en/latest/?badge=latest

.. image:: https://codecov.io/gh/freva-org/py-oidc-auth-client/graph/badge.svg?token=9JP9UWixaf
   :target: https://codecov.io/gh/freva-org/py-oidc-auth-client

.. image:: https://img.shields.io/pypi/v/py-oidc-auth-client
   :target: https://pypi.org/project/py-oidc-auth-client/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/py-oidc-auth-client
   :target: https://pypi.org/project/py-oidc-auth-client/
   :alt: Supported Python versions

py-oidc-auth-client is a small Python client that authenticates against the routes provided
by the companion server side library ``py-oidc-auth``. It helps applications and scripts obtain and refresh access tokens against an auth server
that exposes the standard routes (login, token, device).

Key features
------------

* A simple high level helper :func:`py_oidc_auth_client.authenticate`
* Authorization code flow with a local browser callback
* Device flow for headless sessions
* Persistent host-aware token storage with :class:`py_oidc_auth_client.TokenStore`
* Token caching and refresh token support
* Fully typed public API

When to use this library
------------------------

Use py-oidc-auth-client when you need to:

* call a service protected by bearer tokens issued by your auth server
* perform interactive login in a local session
* run in a headless environment (batch job, remote shell) and still obtain tokens
* reuse cached or refreshed tokens instead of re-authenticating every time



Quick start
-----------

.. dropdown:: High level ``authenticate`` function.
    :icon: code

    The high level helper performs the best available strategy:

    1. Use a cached token if it is still valid.
    2. Refresh an access token if a refresh token is available.
    3. Fall back to an interactive flow (browser or device) if possible.

    .. code-block:: python

        from py_oidc_auth_client import authenticate

        token = authenticate(host="https://auth.example.org")
        headers = token["headers"]

.. dropdown:: Device flow
    :icon: code

    Directly use device flow logins without fall back to code flow:

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


.. dropdown:: Code flow
    :icon: code

    Use code flow for IDP's that do not support/allow device flow:

    .. code-block:: python

        import asyncio
        from py_oidc_auth_client import Config, CodeFlow

        async def main():
           flow = CodeFlow(config=Config(host="https://auth.example.org"))
           token = await flow.authenticate()
           print(token["headers"])

        asyncio.run(main())

.. dropdown:: Token storage with ``TokenStore``
    :icon: code

    A single ``TokenStore`` can safely hold tokens for multiple hosts because entries are
    separated by host internally.

    .. code-block:: python

        from py_oidc_auth_client import TokenStore, authenticate

        store = TokenStore(app_name="my-app")
        token = authenticate(
            host="https://auth.example.org",
            store=store,
        )
        print(token["headers"])

Guides and reference
--------------------

.. toctree::
   :maxdepth: 1
   :caption: Guides

   guides/choosing_a_strategy
   guides/non_interactive
   guides/configuration
   guides/recipes

.. toctree::
   :maxdepth: 1
   :caption: API reference

   api/index

.. toctree::
   :maxdepth: 1
   :caption: Misc

   whatsnew
   code-of-conduct
.. seealso::

   `py-oidc-auth (server library) <https://pypi.org/project/py-oidc-auth/>`_
