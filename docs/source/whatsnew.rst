What's new
==========

This document highlights major changes and additions across releases.

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
