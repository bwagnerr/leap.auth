***************
LEAP Authentication client
**************************

This library can be used to authenticate and manage passwords in a `LEAP <https://leap.se/>`_ platform.
It uses the `Secure Remote Password protocol <http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol>`_.

To install it:

.. code-block:: shell

    $ pip install leap.auth

To use it:

.. code-block:: python

    from leap.auth import SRPAuth

    api_uri = 'https://api.leap.platform:4430/'
    ca_cert_path = './path_to_certificate.crt'
    # TIP: the certificate is usually at https://api.leap.platform/ca.crt

    user = 'username'
    password = 'longandsecurepassword'

    srp_auth = SRPAuth(api_uri, ca_cert_path)

    # register a user
    srp_auth.register(user, password)

    # authenticate with the defined LEAP server using the registered credentials
    auth = srp_auth.authenticate(user, password)
    # then you can access:
    auth.username
    auth.session_id
    auth.uuid
    auth.token

    # changes the authenticated user password using the authentication data
    srp_auth.change_password(username, current_password, new_password, auth.token, auth.uuid)

    # deletes the session on the server and resets the session locally
    srp_auth.logout()
