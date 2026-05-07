import urllib
import requests
import jwt
import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from mtauthserver.auth.rsa_util import minimize_rsa_key


@dataclass
class MTAuthUser:
    # identical to User from mtauthserver.auth.user
    username: str
    groups: List[str]
    attributes: Dict[str, Any]
    scopes: Optional[List[str]] = None


class MTAuthClient:
    def __init__(self, server_url: str, client_private_key: Optional[str] = None):
        """
        Initialize the MTAuthClient.

        :param server_url: The base URL of the MTAuthServer (e.g., https://auth.example.com)
        :param client_private_key: The client's private key for signing challenges.
        """
        self.server_url = server_url.rstrip('/')
        self.public_key = None
        self.client_private_key = client_private_key

    def _fetch_public_key(self) -> str:
        """
        Fetch the public key from the server.
        """
        response = requests.get(f"{self.server_url}/api/v2/public-key")
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            return data.get("public_key")
        raise Exception(f"Failed to fetch public key: {data.get('message')}")

    def get_public_key(self) -> str:
        """
        Get the public key, fetching it if not already cached.
        """
        if self.public_key is None:
            self.public_key = self._fetch_public_key()
        return self.public_key

    def get_authorize_url(self, redirect_uri: str, client_public_key: str, scopes: List[str] = None) -> str:
        """
        Generate the URL to redirect the user to for authorization.

        :param redirect_uri: The URI to redirect back to after login.
        :param client_public_key: The clients public key.
        :param scopes: Optional list of scopes to request.
        :return: The authorization URL.
        """
        query = urllib.parse.urlencode({
            "redirect_uri": redirect_uri,
            "client_public_key": minimize_rsa_key(client_public_key),
        })
        for s in scopes:
            query += f"&scopes={urllib.parse.quote(s)}"
        url = f"{self.server_url}/api/v2/authorize?{query}"
        return url

    def exchange_token(self, grant: str) -> Optional[str]:
        """
        Exchange a grant for an access token.

        :param grant: The grant received from the authorize endpoint.
        :return: The new JWT token if successful, None otherwise.
        """
        if not self.client_private_key:
            raise Exception("Client private key is required for token exchange")

        try:
            # Create challenge: sign the grant with client's private key
            challenge = jwt.encode(
                {"grant": grant, "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=30)},
                self.client_private_key,
                algorithm="RS256"
            )

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
            return None
        except Exception:
            return None

    def rekey(self, token: str) -> Optional[str]:
        """
        Renew an expired token.

        :param token: The expired JWT token.
        :return: The new JWT token if successful, None otherwise.
        """
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
            return None
        except Exception:
            return None

    def verify_token(self, token: str) -> Optional[MTAuthUser]:
        """
        Verify and decode a JWT token.

        :param token: The JWT token received from MTAuthServer.
        :return: An MTAuthUser object if valid, None otherwise.
        """
        try:
            # Handle both raw tokens and Bearer tokens
            if token.startswith("Bearer "):
                token = token[7:]

            decoded = jwt.decode(
                token,
                self.get_public_key(),
                algorithms=["RS256"]
            )

            return MTAuthUser(
                username=decoded.get("username"),
                groups=decoded.get("groups", []),
                attributes=decoded.get("attributes", {}),
                scopes=decoded.get("scopes")
            )
        except Exception:
            return None
