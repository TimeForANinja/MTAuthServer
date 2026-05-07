from flask import g
from apiflask import HTTPTokenAuth, APIFlask
from .jwt import decode_token
from typing import Optional, List

from .user import User


def get_auth():
    # singleton pattern for getting the auth object using 'g'
    # TODO: do we need a "with app.app_context():"??
    if 'auth_singleton' not in g:
        g.auth_singleton = _build_flask_auth()
    return g.auth_singleton


def _build_flask_auth():
    """
    Utility class to build the HTTPTokenAuth object.
    The object is required to use the APIFlask-integrated authentication mechanism.
    This is a simple process, since the AuthHandler defines all methods required.
    """

    auth = HTTPTokenAuth(
        scheme="Bearer",
    )

    @auth.get_user_roles
    def get_user_roles(user: User) -> List[str]:
        """
        retrieve user roles from an Authorization object.

        :param user: Authorization object
        :return: list of roles
        """
        return user.groups

    @auth.verify_token
    def verify_token(token: str) -> Optional[User]:
        """
        Validate a User and the parsed User-Object that can later be used

        :param token: The token to be validated
        :return: AuthUser
        """
        return decode_token(token)

    return auth
