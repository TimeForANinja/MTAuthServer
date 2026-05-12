from apiflask import HTTPTokenAuth
from typing import Optional, List, Callable

from shared_util import V2TokenData, JWT_HEADER_NAME


def build_flask_auth(verify_func: Callable[[str], Optional[V2TokenData]]):
    """
    Utility class to build the HTTPTokenAuth object.
    The object is required to use the APIFlask-integrated authentication mechanism.
    This is a simple process, since the AuthHandler defines all methods required.
    """
    auth = HTTPTokenAuth(
        scheme="Bearer",
        header=JWT_HEADER_NAME,
    )

    @auth.get_user_roles
    def get_user_roles(token: V2TokenData) -> List[str]:
        """
        retrieve user roles from an Authorization object.

        :param token: Authorization object
        :return: list of roles
        """
        return token.user.groups

    @auth.verify_token
    def verify_token(token: str) -> Optional[V2TokenData]:
        """
        Validate a User and the parsed User-Object that can later be accessed via the "current_user" property.

        :param token: The token to be validated
        :return: The Token Data if valid (including the User), None otherwise.
        """
        return verify_func(token)

    return auth
