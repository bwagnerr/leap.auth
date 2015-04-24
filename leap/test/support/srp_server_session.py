import binascii
import requests
import json
import srp
from requests.models import Response
from leap.srp_auth import _safe_unhexlify


def srp_server_session(srp_auth_instance,
                       username='test',
                       password='test',
                       connection_error=False):
    srp_auth_instance._session = MockSession(username,
                                             password,
                                             connection_error)


class MockSession(object):

    def __init__(self, username, password, connection_error=False):
        self.connection_error = connection_error
        self.salt, self.vkey = srp.create_salted_verification_key(
            username,
            password,
            hash_alg=srp.SHA256,
            ng_type=srp.NG_1024)
        self.cookies = {'_session_id': 'session_id'}

    def post(self, *args, **kwargs):
        self.validate_connection()
        self.svr = srp.Verifier(kwargs['data']['login'],
                                self.salt,
                                self.vkey,
                                _safe_unhexlify(kwargs['data']['A']),
                                hash_alg=srp.SHA256,
                                ng_type=srp.NG_1024)
        salt, B = self.svr.get_challenge()
        response = Response()
        response.status_code = 200
        response._content = json.dumps(
            {'B': binascii.hexlify(B),
             'salt': binascii.hexlify(self.salt)}
        )
        return response

    def put(self, *args, **kwargs):
        self.validate_connection()
        unhex_client_auth = binascii.unhexlify(kwargs['data']['client_auth'])
        hamk = self.svr.verify_session(unhex_client_auth)
        response = Response()
        if hamk is None:
            response.status_code = 422
            response._content = ""
        else:
            response.status_code = 200
            response._content = json.dumps(
                {'M2': binascii.hexlify(hamk),
                 'id': 'id', 'token': 'token'}
            )
        return response

    def delete(self, *args, **kwargs):
        return Response()

    def validate_connection(self):
        if self.connection_error:
            raise requests.exceptions.ConnectionError('failing connection')
