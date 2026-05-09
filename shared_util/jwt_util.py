import logging
from dataclasses import fields, is_dataclass

import jwt
import datetime
from typing import Union, Tuple, Dict, TypeVar, get_origin, get_args


def generate_token(payload: Dict, private_key: str, expiry: int) -> str:
    t_now = datetime.datetime.now(tz=datetime.timezone.utc)
    t_exp = t_now + datetime.timedelta(seconds=expiry)

    padded_pl = {
        "exp": t_exp,
        **payload
    }

    return jwt.encode(
        padded_pl,
        private_key,
        algorithm="RS256",
    )

def decode_token(token: str, pub_key: str, verify_exp: bool = True) -> Union[Tuple[Exception, None], Tuple[None, Dict]]:
    try:
        return None, jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            options={"verify_exp": verify_exp},
        )
    except jwt.ExpiredSignatureError as e:
        logging.warning("Token expired")
        return e, None
    except jwt.InvalidTokenError as e:
        logging.error(f"Invalid token: {e}")
        return e, None
    except Exception as e:
        logging.error(f"Error while validating JWT: {e}")
        return e, None

def get_expiring_in(token: str, pub_key: str) -> Union[Tuple[Exception, None], Tuple[None, float]]:
    try:
        exp = jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            options={"verify_exp": False}
        )["exp"]
        exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
        now_dt = datetime.datetime.now(tz=datetime.timezone.utc)
        return None, (now_dt - exp_dt).total_seconds()
    except Exception as e:
        logging.error(f"Error while getting token expiration: {e}")
        return e, None

T = TypeVar("T")
def _cast_dataclass_value(value, target_type):
    """
    Recursively cast a decoded value into the type expected by a dataclass field.

    This is needed because calling a dataclass constructor with ``cls(**data)``
    only creates the top-level dataclass instance. Nested dataclass fields remain
    plain dictionaries unless they are explicitly converted.

    Supported conversions:
    - ``dict`` -> nested dataclass, when the target type is a dataclass.
    - ``list`` items -> the list's declared item type.
    - ``dict`` keys and values -> the dict's declared key/value types.

    Values that do not require conversion are returned unchanged.
    """
    if value is None:
        return None

    # if the value is a dataclass, convert it recursively
    if is_dataclass(target_type) and isinstance(value, dict):
        return _cast_dataclass(value, target_type)

    # get the type arguments of the target type
    origin = get_origin(target_type)
    args = get_args(target_type)

    # handle conversation for lists
    if origin is list and args:
        return [_cast_dataclass_value(item, args[0]) for item in value]

    # handle conversation for dicts
    if origin is dict and len(args) == 2:
        return {
            _cast_dataclass_value(key, args[0]): _cast_dataclass_value(val, args[1])
            for key, val in value.items()
        }

    return value

def _cast_dataclass(data: Dict, cls: type[T]) -> T:
    """
    Build a dataclass instance from a dictionary, recursively casting its fields.

    Unlike a direct ``cls(**data)`` call, this function looks at the dataclass
    field annotations and converts nested values before constructing the class.
    For example, if a field is annotated as another dataclass and the decoded
    token contains a dictionary for that field, the dictionary is converted into
    that nested dataclass instance.

    Unknown fields are ignored here because only fields declared on the target
    dataclass are copied into the constructor arguments.
    """
    casted_data = {}

    for field in fields(cls):
        if field.name not in data:
            continue

        casted_data[field.name] = _cast_dataclass_value(
            data[field.name],
            field.type,
        )

    return cls(**casted_data)

def try_typecast_dataclass(data: Dict, cls: type[T]) -> Union[Tuple[Exception, None], Tuple[None, T]]:
    """
    Attempt to typecast a dict into a dataclass.
    :param data: The dict to typecast.
    :param cls: The dataclass to typecast into.
    :return: The typecast dataclass or an error.
    """
    try:
        return None, _cast_dataclass(data, cls)
    except Exception as e:
        logging.error(f"Error while typecasting dataclass: {e}")
        return e, None

def decode_and_cast(token: str, pub_key: str, cls: type[T], verify_exp: bool = True) -> Union[Tuple[Exception, None], Tuple[None, T]]:
    err, data = decode_token(token, pub_key, verify_exp=verify_exp)
    if err:
        return err, None

    # exp is reserved for the token, so we need to remove it before typecasting
    if 'exp' in data:
        del data["exp"]

    return try_typecast_dataclass(data, cls)
