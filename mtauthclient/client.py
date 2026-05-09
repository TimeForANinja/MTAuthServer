import logging
import urllib.parse
import flask
import requests
from typing import Optional, List, Tuple, Union, cast

from .flask_auth import build_flask_auth
from shared_util import minimize_rsa_key, decode_and_cast, V2TokenData, get_expiring_in, generate_token


class MTAuthClient:
    def __init__(self, server_url: str, client_private_key: Optional[str] = None, client_public_key: Optional[str] = None):
        """
        Initialize the MTAuthClient.
        Client-Key is only required when trying to log in users, not if you just want to verify them.

        :param server_url: The base URL of the MTAuthServer (e.g., https://auth.example.com)
        :param client_private_key: The client's private key for signing challenges.
        :param client_public_key: The client's public key for verifying tokens.
        """
        self.server_url = server_url.rstrip('/')
        self.public_key = None
        self.client_private_key = client_private_key
        self.client_public_key = client_public_key
        self._auth = None

    def _fetch_public_key(self) -> str:
        """
        Fetch the public key from the server.
        """
        response = requests.get(f"{self.server_url}/api/v2/public-key")
        response.raise_for_status()
        return response.text

    def _check_initialized_for_login(self):
        if self.client_private_key is None or self.client_public_key is None:
            raise Exception("Client private key and public key are required for login-flows")


    def get_public_key(self) -> str:
        """Get the public key, fetching it if not already cached."""
        if self.public_key is None:
            self.public_key = self._fetch_public_key()
        return self.public_key

    def get_auth(self):
        """
        Provide a Flaks-compatible auth object.
        This allows for easier use than manually running verify_token.
        """
        if not self._auth:
            self._auth = build_flask_auth(self.verify_token)
        return self._auth


    def get_authorize_url(self, redirect_uri: str, scopes: List[str] = None) -> str:
        """
        Generate the URL to redirect the user to for authorization.

        :param redirect_uri: The URI to redirect back to after login.
        :param scopes: Optional list of scopes to request.
        :return: The authorization URL.
        """
        self._check_initialized_for_login()

        query = urllib.parse.urlencode({
            "redirect_uri": redirect_uri,
            "cpk": minimize_rsa_key(cast(str, self.client_public_key)),
        })
        if scopes:
            # we manually add the scopes, since the urlencode function does not properly support lists
            for s in scopes:
                query += f"&scopes={urllib.parse.quote(s)}"
        url = f"{self.server_url}/api/v2/authorize?{query}"
        return url

    def handle_callback(self, request: flask.Request) -> Union[Tuple[Exception, None, None], Tuple[None, V2TokenData, str]]:
        """Handle the callback from the auth server after a user logged in."""
        self._check_initialized_for_login()

        # callback from the auth server after a user logged in
        grant = request.args.get('grant')
        if not grant:
            logging.error("handle_callback failed: missing grant")
            return Exception("Missing grant"), None, None

        # check if the grant is valid
        if self.is_expired(grant):
            logging.error("handle_callback failed: grant invalid or expired")
            return Exception("Grant Expired"), None, None

        # (try to) exchange the grant for a token
        token = self._exchange_token(grant)
        if not token:
            logging.error("handle_callback failed: token exchange failed")
            return Exception("Failed to exchange token"), None, None

        # try to parse the token
        token_data = self.verify_token("Bearer " + token)
        if not token_data:
            logging.error("handle_callback failed: invalid token received")
            return Exception("Invalid token received"), None, None

        return None, token_data, token

    def _exchange_token(self, grant: str) -> Optional[str]:
        """
        Exchange a grant for an access token.

        :param grant: The grant received from the authorize endpoint.
        :return: The new JWT token if successful, None otherwise.
        """
        self._check_initialized_for_login()

        # create challenge: sign the grant with client's private key
        challenge = generate_token({"grant": grant}, cast(str, self.client_private_key), 30)

        try:
            response = requests.post(
                f"{self.server_url}/api/v2/token",
                json={
                    "grant": grant,
                    "challenge": challenge
                }
            )
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                return data.get("token")
            logging.error(f"Token exchange failed: {data.get('message')}")
            return None
        except Exception as e:
            logging.error(f"Error during token exchange: {e}")
            return None

    def rekey(self, token: str) -> Optional[str]:
        """
        Renew an expired token.

        :param token: The expired JWT token.
        :return: The new JWT token if successful, None otherwise.
        """
        self._check_initialized_for_login()

        # TODO: have this run automatically in background
        try:
            # Handle both raw tokens and Bearer tokens
            if token.startswith("Bearer "):
                token = token[7:]

            response = requests.post(
                f"{self.server_url}/api/v2/rekey",
                json={"token": token}
            )
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                return data.get("token")
            logging.error(f"Rekey failed: {data.get('message')}")
            return None
        except Exception as e:
            logging.error(f"Error during rekey: {e}")
            return None


    def is_expired(self, token: str) -> bool:
        err, exp = get_expiring_in(token, self.get_public_key())
        return err or exp >= 0

    def verify_token(self, token: str) -> Optional[V2TokenData]:
        """
        Verify and decode a JWT token.

        :param token: The JWT token received from MTAuthServer (including Bearer prefix).
        :return: The Token Data if valid (including the User), None otherwise.
        """
        # Check for Bearer prefix
        if not token.startswith("Bearer "):
            return None
        token = token[7:]

        err, td = decode_and_cast(token, self.get_public_key(), V2TokenData)
        if err:
            logging.error(f"Token verification failed: {err}")
            return None
        return td
