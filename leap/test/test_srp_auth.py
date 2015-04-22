import unittest
from leap.exceptions import SRPAuthBadUserOrPassword, SRPAuthConnectionError
from leap.srp_auth import SRPAuth
from leap.test.support.srp_server_session import mock_session


class TestSRPAuth(unittest.TestCase):

    def setUp(self):
        self.api_uri = 'https://testapi:4430'
        self.ca_cert_path = 'cert'
        self.username = 'test'
        self.password = 'testtest'

        self.srp_auth = SRPAuth(self.api_uri, self.ca_cert_path)
        mock_session(self.srp_auth, self.username, self.password)


    def test_auth_successful(self):

        session = self.srp_auth.authenticate(self.username, self.password)

        self.assertEqual(session.username, self.username)


    def test_auth_cant_connect_to_server(self):

        mock_session(self.srp_auth, connection_error=True)

        with self.assertRaises(SRPAuthConnectionError):
            self.srp_auth.authenticate(self.username, self.password)


    def test_auth_wrong_password(self):
        password = 'doesnotexist'

        with self.assertRaises(SRPAuthBadUserOrPassword):
            self.srp_auth.authenticate(self.username, password)

    def test_auth_wrong_username(self):
        username = 'doesnotexist'

        with self.assertRaises(SRPAuthBadUserOrPassword):
            self.srp_auth.authenticate(username, self.password)
