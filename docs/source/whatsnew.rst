What's new
==========

This document highlights major changes and additions across releases.

Unreleased
----------
* The command line picks the flow with ``--flow auto|device|code|exchange``.
  ``auto``, the default, exchanges a token when an exchange option is given
  and otherwise logs in with the device flow, or with the code flow where
  the server has no device flow.
* Token exchange from the command line: ``--audience``, ``--resource``,
  ``--requested-token-type``, and ``--subject-host`` (your login on another
  server) or ``--subject-token`` (a token, ``-`` for stdin) as the subject.
* :class:`~py_oidc_auth_client.flows.LoginFlow` is the device-then-code
  login behind ``authenticate()``, and the default subject of
  ``exchange()``, which used to try the device flow only.  It falls back to
  the code flow on a missing device endpoint (404, 405, 501, 503) or an
  ``unauthorized_client`` / ``unsupported_grant_type`` reply; before, only a
  503 did.
* Token types can be given by short name: ``access``, ``refresh``, ``id``,
  ``jwt`` (``TOKEN_TYPES``).

v2611.0.0
----------
* Tokens without a refresh token, such as exchanged tokens, are no longer
  treated as refreshable for three minutes: ``refresh_expires`` is ``0``.
* Device flow polling stops at once on a real error instead of waiting
  for the timeout.  Only ``authorization_pending``, ``slow_down`` and
  server side (5xx) errors keep it polling.  Error codes of older
  py-oidc-auth servers, which only sent a free text ``detail``, are
  still recognised.
* :class:`~py_oidc_auth_client.exceptions.AuthError` has a new ``error``
  attribute with the OAuth error code, and its message shows the
  provider's ``error_description``.
* Token requests send ``grant_type`` and the standard ``device_code`` and
  ``refresh_token`` fields, next to the older ``device-code`` and
  ``refresh-token`` names.
* The code flow and the device flow use client side PKCE: the verifier
  never leaves the client, and only the S256 challenge is sent to the
  server.  This works with servers that set ``require_client_pkce``.
  Servers that ignore the challenge keep working: for the code flow the
  verifier they put into ``state`` is used, as before.
* The code flow sends its own ``state`` and refuses callbacks that do not
  carry it.
* ``authenticate``, ``authenticate_async``, ``DeviceFlow`` and ``CodeFlow``
  accept ``scopes`` to request fewer scopes than the server's default, and
  ``identity`` to choose the token store entry a login is stored under
  (`#35 <https://github.com/freva-org/py-oidc-auth-client/issues/35>`_).
  The command line has a matching ``--scope`` option.
* Flows expose their cache key as ``flow.identity`` and read and write the
  store by identity, so they no longer trigger the deprecation warning for
  host keyed store access.  A device flow login is reused by a later code
  flow and the other way round.
* Token exchange (RFC 8693): ``exchange()``, ``exchange_async()`` and
  ``ExchangeFlow``.  The subject token comes from another flow, a cached
  identity or a token string; the exchanging server can be another one
  than the subject's, for broker federation.  Exchanged tokens are cached
  with a link to the subject's entry and exchanged again once they
  expire.  Tokens carry ``issued_token_type``, and the ``TOKEN_TYPE_*``
  constants name the RFC 8693 token types.
* ``AuthIdentity.for_exchange`` takes ``host`` and ``resource``.
* Device logins send the requested ``scope`` too.  Servers that ignore it
  grant their default scopes; a warning is logged when requested scopes
  are missing from the granted ones.

v2609.0.0
---------
* Tokens are now cached per authentication identity rather than per host.
  An identity covers the host together with the grant, client, scopes and
  audience that produced the token.  Previously every token for a host
  shared one cache key, so a client credentials or exchanged token would
  silently overwrite a user's interactive login.
* Each cached token is stored in its own file under
  ``~/.cache/<app-name>/tokens/`` instead of a single ``token-store.json``.
  Concurrent authentications no longer lose tokens to a last-writer-wins
  race, which previously affected batch jobs starting many processes at
  once.  Existing stores are migrated automatically on first use and no
  re-authentication is required.
* Refactoring to enable more generic OIDC authentication backends.

v2603.0.1
---------
* Improve documentation.


v2603.0.0
---------
* Fix PKCE bug in code flow.
* Improve documentation.

v2602.0.2
---------
* Initial release.
