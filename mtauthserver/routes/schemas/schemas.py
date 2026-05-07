from dataclasses import dataclass
from typing import List as tList, Dict as tDict
from apiflask.fields import String, List, Dict
from apiflask.validators import Length, Regexp
from marshmallow_dataclass import class_schema

from mtauthserver.routes.schemas.common import GenericOutput
from mtauthserver.routes.schemas.util import to_field, desc


@dataclass
class IntrospectInput:
    token: str = to_field(String(
        required=True,
        validate=Length(min=5, max=10000),
        metadata=desc('JWT token to introspect')
    ))

@dataclass
class IntrospectResponse(GenericOutput):
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

IntrospectInputSchema = class_schema(IntrospectInput)()
IntrospectResponseSchema = class_schema(IntrospectResponse)()


@dataclass
class AuthInput:
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
class AuthResponse(IntrospectResponse):
    token: str = to_field(String(
        required=True,
        metadata=desc('Generated JWT token')
    ))

AuthInputSchema = class_schema(AuthInput)()
AuthResponseSchema = class_schema(AuthResponse)()


@dataclass
class JWTHeaderInput:
    jwt_token: str = to_field(String(
        required=True,
        verify=[
            Length(min=5, max=10000),
            Regexp(
                r'^Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$',
                error='Invalid JWT format. Must be "Bearer <token>"',
            )
        ],
        metadata=desc("Value of the JWT Token"),
    ))

JWTHeaderInputSchema = class_schema(JWTHeaderInput)()
