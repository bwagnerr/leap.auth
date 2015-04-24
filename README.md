# Leap SRP client


## Register an user

** Create the verification key and registers with the LEAP server **

```python
from leap.srp_auth import SRPAuth

api_uri = "<leap_api_uri>"
ca_cert_path = '<path_for_the_api_cert>'

user = "<user_for_authentication>"
password = "<password_for_authentication>"

srp_auth = SRPAuth(api_uri, ca_cert_path)

srp_auth.register(user, password)
```

## Authenticate

** Authenticate with the defined LEAP server using the registered credentials **

```python
from leap.srp_auth import SRPAuth

api_uri = "<leap_api_uri>"
ca_cert_path = '<path_for_the_api_cert>'

user = "<user_for_authentication>"
password = "<password_for_authentication>"

srp_auth = SRPAuth(api_uri, ca_cert_path)

auth = srp_auth.authenticate(user,
password)

print("----------------- SRP Data:")
print(auth.username)
print(auth.session_id)
print(auth.uuid)
print(auth.token)
```

## Logout

** Deletes session on the server and resets the session locally **


```python
<anytime after authenticating>

srp_auth.logout()
```

## Change password

** Changes the authenticated user password using the authentication data **

```python
<anytime after authenticating>

srp_auth.change_password(username, current_password, new_password, token, uuid)
```
