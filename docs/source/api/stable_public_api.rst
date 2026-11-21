Stable public API
=================

The following objects are the main public building blocks that user code should rely on.
They form the stable API surface for common integrations.

Primary building blocks
-----------------------

* :func:`py_oidc_auth_client.authenticate`
* :func:`py_oidc_auth_client.authenticate_async`
* :func:`py_oidc_auth_client.exchange`
* :func:`py_oidc_auth_client.exchange_async`
* :class:`py_oidc_auth_client.CodeFlow`
* :class:`py_oidc_auth_client.DeviceFlow`
* :class:`py_oidc_auth_client.ExchangeFlow`
* :class:`py_oidc_auth_client.TokenStore`

Supporting public types
-----------------------

* :class:`py_oidc_auth_client.Config`
* :class:`py_oidc_auth_client.Token`
* :class:`py_oidc_auth_client.AuthError`
* :class:`py_oidc_auth_client.AuthIdentity`
* :class:`py_oidc_auth_client.Grant`
* :class:`py_oidc_auth_client.StoreEntry`

``Grant`` and ``StoreEntry`` are types you read rather than build, and usually so is
``AuthIdentity``: flows derive their own identity from the parameters you give them
(``flow.identity``), and the store hands identities and entries back when you inspect
the cache.  Build an ``AuthIdentity`` yourself only to choose the exact store entry a
login is saved under, with the ``identity`` argument of ``authenticate()`` and the flows.

Why ``TokenStore`` is listed with the main entry points
-------------------------------------------------------

``TokenStore`` is not just a utility type. It is the public persistence layer that makes
token reuse, refresh, and environment-specific separation possible. For many applications,
choosing the right token storage layout is as important as choosing between
``authenticate()``, ``CodeFlow``, and ``DeviceFlow``.

It also separates tokens by identity internally, which means a single store can usually
back multiple auth servers, clients and grants for the same application.

Guidance
--------

Prefer the names above in application code, examples, and downstream integrations.
If you need lower level helpers from internal modules, document that dependency
explicitly because internal helpers may change more often than the public surface.
