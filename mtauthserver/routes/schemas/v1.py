from dataclasses import dataclass
from typing import List as tList, Dict as tDict
from apiflask.fields import String, List, Dict
from apiflask.validators import Length
from marshmallow_dataclass import class_schema

from .common import SuccessResponse
from shared_util import to_field, desc


@dataclass
class V1IntrospectInput:
    token: str = to_field(String(
        required=True,
        validate=Length(min=5, max=10000),
        metadata=desc('JWT token to introspect')
    ))

@dataclass
class V1IntrospectResponse(SuccessResponse):
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
class V1VerifyAppResponse(V1IntrospectResponse):
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
class V1AuthResponse(V1IntrospectResponse):
    token: str = to_field(String(
        required=True,
        metadata=desc('Generated JWT token')
    ))

V1AuthInputSchema = class_schema(V1AuthInput)()
V1AuthResponseSchema = class_schema(V1AuthResponse)()
