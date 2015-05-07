import os
import unittest
from leap.exceptions import SRPAuthBadUserOrPassword, SRPAuthConnectionError
from leap.auth import SRPAuth
from leap.test.support.srp_server_session import srp_server_session


base_folder = os.path.dirname(os.path.abspath(__file__))
verify_certificate = base_folder + '/cert.crt'


class TestSRPAuth(unittest.TestCase):

    def setUp(self):
        self.api_uri = 'https://testapi:4430'
        self.verify_certificate = verify_certificate
        self.username = 'test'
        self.password = 'testtest'

        def reset_to_test_session():
            return srp_server_session(self.srp_auth,
                                      self.username,
                                      self.password)

        self.srp_auth = SRPAuth(self.api_uri, self.verify_certificate)
        self.srp_auth.reset_session = reset_to_test_session

    def test_auth_accepts_valid_ca_path(self):
        srp_auth = SRPAuth(self.api_uri, self.verify_certificate)
        self.assertEqual(srp_auth.verify_certificate, self.verify_certificate)

    def test_auth_errors_invalid_ca_path(self):
        with self.assertRaises(ValueError):
            self.srp_auth = SRPAuth(self.api_uri, '')

    def test_auth_accepts_ca_boolean(self):
        srp_auth = SRPAuth(self.api_uri, True)
        self.assertTrue(srp_auth.verify_certificate)

    def test_auth_cant_connect_to_server(self):

        def connection_error_test_session():
            return srp_server_session(self.srp_auth, connection_error=True)
        self.srp_auth.reset_session = connection_error_test_session

        with self.assertRaises(SRPAuthConnectionError):
            self.srp_auth.authenticate(self.username, self.password)

    def test_auth_successful(self):
        session = self.srp_auth.authenticate(self.username, self.password)
        self.assertEqual(session.username, self.username)

    def test_auth_wrong_password(self):
        password = 'doesnotexist'

        with self.assertRaises(SRPAuthBadUserOrPassword):
            self.srp_auth.authenticate(self.username, password)

    def test_auth_wrong_username(self):
        username = 'doesnotexist'

        with self.assertRaises(SRPAuthBadUserOrPassword):
            self.srp_auth.authenticate(username, self.password)
