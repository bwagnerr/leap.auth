import binascii
import logging

import requests
import srp
import json

from requests.adapters import HTTPAdapter

from leap.exceptions import (SRPAuthenticationError,
                             SRPAuthConnectionError,
                             SRPAuthBadStatusCode,
                             SRPAuthNoSalt,
                             SRPAuthNoB,
                             SRPAuthBadDataFromServer,
                             SRPAuthBadUserOrPassword,
                             SRPAuthVerificationFailed,
                             SRPAuthNoSessionId)

from leap.srp_session import SRPSession

logger = logging.getLogger(__name__)


class SRPAuth(object):

    LOGIN_KEY = "login"
    A_KEY = "A"
    CLIENT_AUTH_KEY = "client_auth"
    SESSION_ID_KEY = "_session_id"
    USER_VERIFIER_KEY = 'user[password_verifier]'
    USER_SALT_KEY = 'user[password_salt]'
    AUTHORIZATION_KEY = "Authorization"

    def __init__(self, api_uri, ca_cert_path, api_version=1):

        self.api_uri = api_uri
        self.api_version = api_version
        self.ca_cert_path = ca_cert_path

        # **************************************************** #
        # Dependency injection helpers, override this for more
        # granular testing
        self._fetcher = requests
        # **************************************************** #

        self._reset_session()

        # User credentials stored for password changing checks
        self._username = None
        self._password = None

    def _reset_session(self):

        self._session = self._fetcher.session()

        adapter = HTTPAdapter(max_retries=30)

        self._session.mount('https://', adapter)

    def _authentication_preprocessing(self, username, password):

        logger.debug("Authentication preprocessing...")

        user = srp.User(username.encode('utf-8'),
                        password.encode('utf-8'),
                        srp.SHA256, srp.NG_1024)
        _, A = user.start_authentication()

        return user, A

    def _start_authentication(self, username, A):

        logger.debug("Starting authentication process...")
        try:
            auth_data = {
                self.LOGIN_KEY: username,
                self.A_KEY: binascii.hexlify(A)
            }
            sessions_url = "%s/%s/%s/" % \
                (self.api_uri,
                 self.api_version,
                 "sessions")

            ca_cert_path = self.ca_cert_path

            init_session = self._session.post(sessions_url,
                                              data=auth_data,
                                              verify=ca_cert_path,
                                              timeout=30)
        except requests.exceptions.ConnectionError as e:
            logger.error("No connection made (salt): {0!r}".format(e))
            raise SRPAuthConnectionError()
        except Exception as e:
            logger.error("Unknown error: %r" % (e,))
            raise SRPAuthenticationError()

        if init_session.status_code not in (200,):
            logger.error("No valid response (salt): "
                         "Status code = %r. Content: %r" %
                         (init_session.status_code, init_session.content))
            if init_session.status_code == 422:
                logger.error("Invalid username or password.")
                raise SRPAuthBadUserOrPassword()

            logger.error("There was a problem with authentication.")
            raise SRPAuthBadStatusCode()

        json_content = json.loads(init_session.content)
        salt = json_content.get("salt", None)
        B = json_content.get("B", None)

        if salt is None:
            logger.error("The server didn't send the salt parameter.")
            raise SRPAuthNoSalt()
        if B is None:
            logger.error("The server didn't send the B parameter.")
            raise SRPAuthNoB()

        return salt, B

    def _process_challenge(self, user, salt_B, username):
        logger.debug("Processing challenge...")
        try:
            salt, B = salt_B
            unhex_salt = _safe_unhexlify(salt)
            unhex_B = _safe_unhexlify(B)
        except (TypeError, ValueError) as e:
            logger.error("Bad data from server: %r" % (e,))
            raise SRPAuthBadDataFromServer()
        M = user.process_challenge(unhex_salt, unhex_B)

        auth_url = "%s/%s/%s/%s" % (self.api_uri,
                                    self.api_version,
                                    "sessions",
                                    username)

        auth_data = {
            self.CLIENT_AUTH_KEY: binascii.hexlify(M)
        }

        try:
            auth_result = self._session.put(auth_url,
                                            data=auth_data,
                                            verify=self.ca_cert_path,
                                            timeout=30)
        except requests.exceptions.ConnectionError as e:
            logger.error("No connection made (HAMK): %r" % (e,))
            raise SRPAuthConnectionError()

        if auth_result.status_code == 422:
            error = ""
            try:
                error = json.loads(auth_result.content).get("errors", "")
            except ValueError:
                logger.error("Problem parsing the received response: %s"
                             % (auth_result.content,))
            except AttributeError:
                logger.error("Expecting a dict but something else was "
                             "received: %s", (auth_result.content,))
            logger.error("[%s] Wrong password (HAMK): [%s]" %
                         (auth_result.status_code, error))
            raise SRPAuthBadUserOrPassword()

        if auth_result.status_code not in (200,):
            logger.error("No valid response (HAMK): "
                         "Status code = %s. Content = %r" %
                         (auth_result.status_code, auth_result.content))
            raise SRPAuthBadStatusCode()

        return json.loads(auth_result.content)

    def _extract_data(self, json_content):

        try:
            M2 = json_content.get("M2", None)
            uuid = json_content.get("id", None)
            token = json_content.get("token", None)
        except Exception as e:
            logger.error(e)
            raise SRPAuthBadDataFromServer()

        if M2 is None or uuid is None:
            logger.error("Something went wrong. Content = %r" %
                         (json_content,))
            raise SRPAuthBadDataFromServer()

        return uuid, token, M2

    def _verify_session(self, user, M2):

        logger.debug("Verifying session...")
        try:
            unhex_M2 = _safe_unhexlify(M2)
        except TypeError:
            logger.error("Bad data from server (HAWK)")
            raise SRPAuthBadDataFromServer()

        user.verify_session(unhex_M2)

        if not user.authenticated():
            logger.error("Auth verification failed.")
            raise SRPAuthVerificationFailed()
        logger.debug("Session verified.")

        session_id = self._session.cookies.get(self.SESSION_ID_KEY, None)
        if not session_id:
            logger.error("Bad cookie from server (missing _session_id)")
            raise SRPAuthNoSessionId()

        logger.debug("SUCCESS LOGIN")
        return session_id

    def change_password(self, current_password, new_password):

        if current_password != self._password:
            raise SRPAuthBadUserOrPassword

        url = "%s/%s/users/%s.json" % (
            self.api_uri,
            self.api_version,
            self.get_uuid())

        salt, verifier = _srp.create_salted_verification_key(
            self._username.encode('utf-8'), new_password.encode('utf-8'),
            self._hashfun, self._ng)

        cookies = {self.SESSION_ID_KEY: self._session_id}
        headers = {
            self.AUTHORIZATION_KEY:
            "Token token={0}".format(self.get_token())
        }
        user_data = {
            self.USER_VERIFIER_KEY: binascii.hexlify(verifier),
            self.USER_SALT_KEY: binascii.hexlify(salt)
        }

        change_password = self._session.put(
            url, data=user_data,
            verify=self.ca_cert_path,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT,
            headers=headers)

        change_password.raise_for_status()

        self._password = new_password

    def authenticate(self, username, password):

        self._username = username
        self._password = password

        user, A = self._authentication_preprocessing(username, password)
        salt_B = self._start_authentication(username, A)

        json_content = self._process_challenge(user, salt_B, username)

        uuid, token, M2 = self._extract_data(json_content)
        session_id = self._verify_session(user, M2)

        self.session_id = session_id

        return SRPSession(username, token, uuid, session_id)

    def logout(self, session_id):
        logger.debug("Starting logout...")

        if self.session_id is None:
            logger.debug("Already logged out")
            return

        logout_url = "%s/%s/%s/" % (self.api_uri,
                                    self.api_version,
                                    "logout")
        try:
            self._session.delete(logout_url,
                                 data=self.session_id,
                                 verify=self.ca_cert_path,
                                 timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.warning("Something went wrong with the logout: %r" %
                           (e,))
            raise
        else:
            self.session_id(None)
            self.set_uuid(None)
            self.set_token(None)
            # Also reset the session
            self._session = self._fetcher.session()
            logger.debug("Successfully logged out.")

    def is_authenticated(self, user):

        if user is not None:
            return user.authenticated()

        return False


def _safe_unhexlify(val):
    return binascii.unhexlify(val) \
        if (len(val) % 2 == 0) else binascii.unhexlify('0' + val)
