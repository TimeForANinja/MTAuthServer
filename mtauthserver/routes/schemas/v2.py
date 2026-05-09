from dataclasses import dataclass, asdict
from typing import List as tList, Dict as tDict, Any as tAny
from apiflask.fields import String, List
from apiflask.validators import Length, Regexp
from marshmallow.fields import Nested
from marshmallow_dataclass import class_schema

from .common import SuccessResponse
from shared_util import to_field, desc, MTAuthUser, MTAuthUserSchema


@dataclass
class V2GrantPayload:
    user: MTAuthUser
    scopes: tList[str]
    client_public_key: str

    def to_dict(self) -> tDict[str, tAny]:
        return asdict(self)

@dataclass
class V2GrantChallenge:
    grant: str


@dataclass
class V2AskAuthInput:
    """An App is asking us to authenticate a user."""
    redirect_uri: str = to_field(String(
        required=True,
        validate=Regexp(r'^https?://', error='redirect_uri must start with http:// or https://'),
        metadata=desc('URL to redirect to after authentication.'),
    ))
    cpk: str = to_field(String(
        required=True,
        validate=Length(min=32),
        metadata=desc('The clients public key for the back-channel grant.')
    ))
    scopes: tList[str] = to_field(List(
        String(),
        load_default=[],
        metadata=desc('List of scopes to ask for')
    ))

V2AskAuthInputSchema = class_schema(V2AskAuthInput)()

@dataclass
class V2AuthDoneInput:
    """A user has authenticated on our Website."""
    username: str = to_field(String(
        required=True,
        validate=Length(min=5, max=50),
        metadata=desc('Username')
    ))
    password: str = to_field(String(
        required=True,
        validate=Length(min=5, max=250),
        metadata=desc('user password')
    ))

V2AuthDoneInputSchema = class_schema(V2AuthDoneInput)()


@dataclass
class V2TokenExchangeInput:
    """An App wants to exchange a grant for an access token."""
    grant: str = to_field(String(
        required=True,
        validate=Length(min=5, max=10000),
        metadata=desc('The grant received from the authorize endpoint.')
    ))
    challenge: str = to_field(String(
        required=True,
        validate=Length(min=5, max=10000),
        metadata=desc('The grant signed with the clients private key.')
    ))

V2TokenExchangeInputSchema = class_schema(V2TokenExchangeInput)()


@dataclass
class V2AuthResponse(SuccessResponse):
    """Standard Response for a successful token generation"""
    user: MTAuthUser = to_field(Nested(
        MTAuthUserSchema,
        required=True,
        metadata=desc('User object'),
    ))
    token: str = to_field(String(
        required=True,
        metadata=desc('Generated JWT token')
    ))
    scopes: tList[str] = to_field(List(
        String(),
        required=True,
        metadata=desc('Scopes granted to the user'),
    ))

V2AuthResponseSchema = class_schema(V2AuthResponse)()


@dataclass
class V2RekeyInput:
    """An App wants to renew a token."""
    token: str = to_field(String(
        required=True,
        validate=Length(min=5, max=10000),
        metadata=desc('Expired JWT token to renew')
    ))

V2RekeyInputSchema = class_schema(V2RekeyInput)()
