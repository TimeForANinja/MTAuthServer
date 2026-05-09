from flask import current_app
from typing import Union, Tuple, TypeVar

from shared_util import generate_token, decode_and_cast, get_expiring_in

T = TypeVar('T')

def generate_api_token(payload: T) -> str:
    """Wrapper to generate a JWT token using the current app's configuration."""
    return generate_token(
        payload,
        current_app.config['JWT_PRIVATE_KEY'],
        current_app.config['TOKEN_LIFETIME'],
    )

def decode_api_token(token: str, cls: type[T], verify_exp: bool = True) -> Union[Tuple[Exception, None], Tuple[None, T]]:
    """Wrapper to decode a JWT token using the current app's configuration."""
    return decode_and_cast(token, current_app.config['JWT_PUBLIC_KEY'], cls, verify_exp=verify_exp)

def expire_in_api_token(token: str) -> Union[Tuple[Exception, None], Tuple[None, float]]:
    """Wrapper to get the expiration time of a JWT token using the current app's configuration."""
    return get_expiring_in(token, current_app.config['JWT_PUBLIC_KEY'])
