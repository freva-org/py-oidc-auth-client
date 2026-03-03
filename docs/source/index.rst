py-oidc-auth-client
================

.. image:: _static/logo.png
   :alt: py-oidc-auth-client logo
   :width: 560px
   :align: center

.. centered:: *Typed client library for the authentication routes exposed by py-oidc-auth.*

The package is designed as the counterpart of the server side library ``py-oidc-auth``.
It helps applications and scripts obtain and refresh access tokens against an auth server
that exposes the standard routes (login, token, device).

Key features
------------

* A simple high level helper :func:`py_oidc_auth_client.authenticate`
* Authorization code flow with a local browser callback
* Device flow for headless sessions
* Token caching and refresh token support
* Fully typed public API

Quick start
-----------

.. code-block:: python

   from py_oidc_auth_client import authenticate

   token = authenticate(host="https://auth.example.org")
   headers = token.headers

Guides and reference
--------------------

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/overview
   guides/quickstart
   guides/non_interactive
   guides/configuration
   whatsnew
   code-of-conduct

.. toctree::
   :maxdepth: 2
   :caption: API reference

   api/index
