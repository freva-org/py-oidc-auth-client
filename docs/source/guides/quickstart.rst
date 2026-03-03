Quickstart
==========

Install
-------

.. code-block:: console

   python -m pip install py-oidc-auth-client

Authenticate
------------

The high level helper performs the best available strategy:

1. Use a cached token if it is still valid.
2. Refresh an access token if a refresh token is available.
3. Fall back to an interactive flow (browser or device) if possible.

.. code-block:: python

   from py_oidc_auth_client import authenticate

   token = authenticate(host="https://auth.example.org")
   print(token["access_token"])
   print(token["headers"])

Using the token with httpx
--------------------------

.. code-block:: python

   import httpx
   from py_oidc_auth_client import authenticate

   token = authenticate(host="https://auth.example.org")

   with httpx.Client() as client:
       r = client.get("https://service.example.org/protected", headers=token["headers"])
       r.raise_for_status()
       print(r.json())
