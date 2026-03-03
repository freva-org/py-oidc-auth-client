py-oidc-auth-client
================

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


.. seealso::

   `py-oidc-auth (server library) <https://pypi.org/project/py-oidc-auth/>`_
