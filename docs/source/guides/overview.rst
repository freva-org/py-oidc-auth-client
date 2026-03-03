Overview
========

py-oidc-auth-client is a small Python client that authenticates against the routes provided
by the companion server side library ``py-oidc-auth``.

Relationship to py-oidc-auth
----------------------------

The server library provides framework adapters that expose common OpenID Connect routes such as:

* ``GET  /auth/v2/login``
* ``POST /auth/v2/token``
* ``POST /auth/v2/device``

This client library calls those routes and returns a :class:`py_oidc_auth_client.schema.Token`
dictionary that can be used to authorize requests.

When to use this library
------------------------

Use py-oidc-auth-client when you need to:

* call a service protected by bearer tokens issued by your auth server
* perform interactive login in a local session
* run in a headless environment (batch job, remote shell) and still obtain tokens
