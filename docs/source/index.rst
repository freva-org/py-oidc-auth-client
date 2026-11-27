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
* Persistent identity-aware token storage with :class:`py_oidc_auth_client.TokenStore`
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

    A single ``TokenStore`` can safely hold tokens for multiple hosts, and for several
    identities on the same host, because entries are keyed by an
    :class:`py_oidc_auth_client.AuthIdentity`: the host together with the grant, client,
    scopes and audience that produced the token. Usually you do not build an identity
    yourself: each flow derives its own and exposes it as ``flow.identity``.

    Pass ``scopes`` to request only some scopes. Such a token is cached next to the
    default login and never stands in for it:

    .. code-block:: python

        token = authenticate(host="https://auth.example.org", scopes="openid email")

    To decide yourself which entry a login is stored under, pass an ``identity``. Only
    that entry is read and written, and its scopes are what the login requests:

    .. code-block:: python

        from py_oidc_auth_client import AuthIdentity, Grant, authenticate

        ident = AuthIdentity(
            host="https://auth.example.org",
            backend="py-oidc-auth",
            grant=Grant.DEVICE_CODE,
            scopes=("openid", "email"),
        )
        token = authenticate(host="https://auth.example.org", store=store, identity=ident)
        assert store.get(ident) == token

    The identity's grant must be an interactive one. ``authenticate`` may still fall
    back from the device flow to the code flow; the token is stored under the given
    identity either way.

    Pass ``app_name`` to keep your tokens in their own directory under the platform
    cache (``~/.cache/my-app/tokens`` on Linux):

    .. code-block:: python

        from py_oidc_auth_client import TokenStore, authenticate

        store = TokenStore(app_name="my-app")
        token = authenticate(
            host="https://auth.example.org",
            store=store,
        )
        print(token["headers"])

    Pass ``path`` instead to put the store somewhere specific, for example on a shared
    filesystem or inside a container volume. The same store serves any number of hosts:

    .. code-block:: python

        store = TokenStore(path="/srv/jobs/.auth/tokens")

        staging = authenticate(host="https://staging.example.org", store=store)
        prod = authenticate(host="https://auth.example.org", store=store)

    Each entry is written to its own file, so several processes authenticating at the
    same time do not overwrite one another. That matters for batch jobs that start many
    workers at once.

.. dropdown:: Inspecting and clearing cached tokens
    :icon: code

    ``entries()`` returns what is cached, each with the identity that produced it.
    ``label`` is a one line summary of that identity, and is what the command line
    ``--list`` prints:

    .. code-block:: python

        store = TokenStore(app_name="my-app")

        for entry in store.entries():
            print(entry.identity.label, entry.usefulness())

    ``find()`` looks entries up by partial identity, which is how you ask "is there a
    token here I could reuse?" without knowing which flow produced it:

    .. code-block:: python

        from py_oidc_auth_client import Grant

        matches = store.find(
            host="https://auth.example.org",
            grants=[Grant.DEVICE_CODE, Grant.AUTHORIZATION_CODE],
            scopes=["openid"],
        )
        if matches:
            token = matches[0].token

    Matches come back best first: a live access token before one that only has a refresh
    token left. Scopes match on a superset, so a token granted more than you asked for is
    still a hit.

    Removing a host removes every token for that server, including any obtained from it
    by token exchange:

    .. code-block:: python

        store.remove("https://auth.example.org")

    The same from the command line, where ``--list`` groups by host and shows the grant,
    client, scopes and remaining lifetime of each entry:

    .. code-block:: console

        $ python -m py_oidc_auth_client --list
        $ python -m py_oidc_auth_client --remove https://auth.example.org

Command line
------------

``python -m py_oidc_auth_client HOST`` (or ``oidc-auth HOST``) gets a token for a
server and prints it, as JSON with ``--json``.  ``--flow`` picks how:

``auto`` (default)
    A token exchange when an exchange option is given; otherwise a login with the
    device flow, or with the code flow where the server has no device flow.
``device``, ``code``
    That login flow, and nothing else.
``exchange``
    Exchange a token (RFC 8693).  The subject is your login on ``HOST`` unless
    ``--subject-host`` names another server or ``--subject-token`` passes a token
    (``-`` reads it from stdin).

.. code-block:: console

    $ oidc-auth https://auth.example.org                         # log in
    $ oidc-auth https://auth.example.org --flow code              # with the browser
    $ oidc-auth https://auth.example.org --audience s3-gateway --scope read --json
    $ oidc-auth https://peer.example.org --subject-host https://auth.example.org
    $ echo "$TOKEN" | oidc-auth https://auth.example.org --subject-token - \
        --requested-token-type jwt

Exchanged tokens are cached like logins; ``--force`` exchanges again.

Plain OpenID Connect providers
------------------------------

To log in at Keycloak (or any OpenID Connect provider) directly, without a
py-oidc-auth server, give the discovery URL or the issuer and a client id.  The
endpoints come from the discovery document:

.. code-block:: python

    from py_oidc_auth_client import Config, authenticate, exchange

    config = Config.from_discovery(
        "https://kc.example.org/realms/freva", client_id="freva-cli"
    )
    token = authenticate(config=config)
    other = exchange(config=config, audience="other-app")

.. code-block:: console

    $ oidc-auth --discovery-url https://kc.example.org/realms/freva --client-id freva-cli
    $ OIDC_CLIENT_SECRET=... oidc-auth --discovery-url https://kc.example.org/realms/freva \
        --client-id ingest-job --flow client-credentials

The client is public by default (PKCE only).  A confidential client gives its secret
(``client_secret``, or ``--client-secret-file`` / ``$OIDC_CLIENT_SECRET`` on the command
line) or a private key (``server_key``, ``--server-key``) for ``private_key_jwt``, which
needs ``pip install py-oidc-auth-client[keys]``.

On the Keycloak side the client needs:

* *OAuth 2.0 Device Authorization Grant* enabled, for the device flow;
* ``http://localhost:*`` (or ``http://127.0.0.1:*``) among its valid redirect URIs, for
  the code flow, which listens on the ``redirect_ports``;
* *Client authentication* on, and *Service accounts roles* for the client credentials
  grant; *Standard token exchange* for token exchange (Keycloak 26.2+), where the
  client must also be in the subject token's audience;
* for ``private_key_jwt``, *Client Authenticator* set to *Signed JWT* with the public
  key or a JWKS URL.  Pass ``key_id`` (``--key-id``) if Keycloak matches keys by
  ``kid``.

Guides and reference
--------------------

.. toctree::
   :maxdepth: 1
   :caption: Guides

   guides/index

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
