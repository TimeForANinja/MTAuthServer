from dataclasses import dataclass
from typing import List as tList, Dict as tDict, TypeVar, Tuple
from apiflask.fields import String, List, Dict, Integer, Nested
from apiflask.validators import Length
from marshmallow_dataclass import class_schema

from shared_util import to_field, desc


T = TypeVar("T")
# response can be T, an Error or an Error + Status Code as Tuple
type V1OutCanError[T] = T | Tuple[V1ErrorResponse, int]

@dataclass
class V1ErrorResponseDetails:
    status: int = to_field(Integer(
        required=True,
        metadata=desc("HTTP (Error) Status Code")
    ))
    sub_code: int = to_field(Integer(
        required=True,
        metadata=desc("Sub-Code of the Error")
    ))
    action: str = to_field(String(
        required=True,
        metadata=desc("Action that was attempted")
    ))

V1ErrorResponseDetailsSchema = class_schema(V1ErrorResponseDetails)()

@dataclass
class V1ErrorResponse:
    message: str = to_field(String(
        required=True,
        metadata=desc("Error Message")
    ))
    detail: V1ErrorResponseDetails = to_field(Nested(
        V1ErrorResponseDetailsSchema,
        required=True,
    ))

V1ErrorResponseSchema = class_schema(V1ErrorResponse)()


@dataclass
class V1IntrospectInput:
    token: str = to_field(String(
        required=True,
        validate=Length(min=5, max=10000),
        metadata=desc('JWT token to introspect (without Bearer prefix)')
    ))

@dataclass
class V1IntrospectResponse:
    status: str = to_field(String(
        required=True,
        metadata=desc('"valid" if successfully')
    ))
    username: str = to_field(String(
        required=True,
        metadata=desc('Username from token')
    ))
    groups: tList[str] = to_field(List(
        String(),
        metadata=desc('Groups from token'),
    ))
    attributes: tDict[str, str] = to_field(Dict(
        metadata=desc('User attributes from token')
    ))

V1IntrospectInputSchema = class_schema(V1IntrospectInput)()
V1IntrospectResponseSchema = class_schema(V1IntrospectResponse)()


@dataclass
class V1VerifyAppResponse:
    username: str = to_field(String(
        required=True,
        metadata=desc('Username from token')
    ))
    groups: tList[str] = to_field(List(
        String(),
        metadata=desc('Groups from token'),
    ))
    attributes: tDict[str, str] = to_field(Dict(
        metadata=desc('User attributes from token')
    ))
    app: str = to_field(String(
        required=True,
        metadata=desc('App Scope'),
    ))

V1VerifyAppResponseSchema = class_schema(V1VerifyAppResponse)()


@dataclass
class V1AuthInput:
    username: str = to_field(String(
        required=True,
        validate=Length(min=5, max=50),
        metadata=desc('LDAP username')
    ))
    password: str = to_field(String(
        required=True,
        validate=Length(min=5, max=250),
        metadata=desc('LDAP password')
    ))

@dataclass
class V1AuthResponse:
    status: str = to_field(String(
        required=True,
        metadata=desc('"ok" if successfully')
    ))
    username: str = to_field(String(
        required=True,
        metadata=desc('Username from token')
    ))
    groups: tList[str] = to_field(List(
        String(),
        metadata=desc('Groups from token'),
    ))
    attributes: tDict[str, str] = to_field(Dict(
        metadata=desc('User attributes from token')
    ))
    token: str = to_field(String(
        required=True,
        metadata=desc('Generated JWT token (without Bearer prefix)')
    ))

V1AuthInputSchema = class_schema(V1AuthInput)()
V1AuthResponseSchema = class_schema(V1AuthResponse)()
