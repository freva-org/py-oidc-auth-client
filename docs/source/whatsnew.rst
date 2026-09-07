What's new
==========

This document highlights major changes and additions across releases.

v209.0.0
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
