import logging
import jwt
import datetime
from flask import current_app
from typing import Optional

from mtauthserver.auth.user import User


def generate_token(user: User, rekey_count: int = 0) -> str:
    """
    Generate a JWT token for the given user.

    :param user: The User object to encode.
    :param rekey_count: Number of times this token has been renewed.
    :return: The encoded JWT token.
    """
    t_now = datetime.datetime.now(tz=datetime.timezone.utc)
    t_exp = t_now + datetime.timedelta(seconds=current_app.config['TOKEN_LIFETIME'])

    payload = {
        "username": user.username,
        "groups": user.groups,
        "attributes": user.attributes,
        "scopes": user.scopes,
        "exp": t_exp,
        "rekey_count": rekey_count,
    }

    token = jwt.encode(
        payload,
        current_app.config['JWT_PRIVATE_KEY'],
        algorithm="RS256",
    )
    return token

def decode_token(token: str) -> Optional[User]:
    """
    Decode (and verify) a JWT token.

    :param token: The JWT token to decode.
    :return: The User object if the token is valid, None otherwise.
    """
    try:
        decoded_token = jwt.decode(
            token,
            current_app.config['JWT_PUBLIC_KEY'],
            algorithms=["RS256"],
        )

        return User(
            username=decoded_token.get("username"),
            groups=decoded_token.get("groups", []),
            attributes=decoded_token.get("attributes", {}),
            scopes=decoded_token.get("scopes")
        )
    except jwt.ExpiredSignatureError:
        logging.error("Topen expired")
    except jwt.InvalidTokenError as e:
        logging.error(f"Invalid token: {e}")
    except Exception as e:
        logging.error(f"Error while validating JWT: {e}")
    return None
