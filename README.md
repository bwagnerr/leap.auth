# Leap SRP client

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
