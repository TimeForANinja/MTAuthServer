import requests
import jwt
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class MTAuthUser:
    # identical to User from mtauthserver.auth.user
    username: str
    groups: List[str]
    attributes: Dict[str, Any]


class MTAuthClient:
    def __init__(self, server_url: str):
        """
        Initialize the MTAuthClient.

        :param server_url: The base URL of the MTAuthServer (e.g., https://auth.example.com)
        """
        self.server_url = server_url.rstrip('/')
        self.public_key = None

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

    def get_authorize_url(self, redirect_uri: str) -> str:
        """
        Generate the URL to redirect the user to for authorization.

        :param redirect_uri: The URI to redirect back to after login.
        :return: The authorization URL.
        """
        return f"{self.server_url}/api/v2/authorize?redirect_uri={redirect_uri}"

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
                attributes=decoded.get("attributes", {})
            )
        except Exception:
            return None
