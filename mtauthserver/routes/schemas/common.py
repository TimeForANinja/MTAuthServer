from dataclasses import dataclass
from typing import TypeVar, Tuple
from apiflask.fields import String
from apiflask.validators import OneOf
from marshmallow.validate import Length, Regexp
from marshmallow_dataclass import class_schema

from shared_util import to_field, desc, JWT_HEADER_NAME


@dataclass
class GenericOutput:
    """Every Output Schema should inherit from this class."""
    message: str = to_field(String(
        required=True,
        metadata=desc("Message of the response"),
    ))
    status: str = to_field(String(
        required=True,
        validate=OneOf(["success", "failed"]),
        metadata=desc("Status of the response, e.g., 'success'"),
    ))


T = TypeVar("T")
# response can be T, an Error or an Error + Status Code as Tuple
type OutCanError[T] = T | ErrorResponse | Tuple[ErrorResponse, int]

@dataclass
class ErrorResponse(GenericOutput):
    status: str = to_field(String(
        required=True,
        validate=OneOf(["failed"]),
        metadata=desc("Status of the response, e.g., 'success'"),
    ), default="failed", kw_only=True)

    def __post_init__(self):
        # the combination of "kw_only=True", default, and "__post_init__" allows us
        # to set the status to "failed" automatically for all dataclasses
        # that inherit from this class
        self.status = "failed"

ErrorResponseSchema = class_schema(ErrorResponse)()


@dataclass
class SuccessResponse(GenericOutput):
    status: str = to_field(String(
        required=True,
        validate=OneOf(["success"]),
        metadata=desc("Status of the response, e.g., 'success'"),
    ), default="success", kw_only=True)

    def __post_init__(self):
        # the combination of "kw_only=True", default and "__post_init__" allows us
        # to set the status to "success" automatically for all dataclasses
        # that inherit from this class
        self.status = "success"

SuccessResponseSchema = class_schema(SuccessResponse)()


@dataclass
class JWTHeaderInput:
    jwt_token: str = to_field(String(
        required=True,
        # overwrite the key, since a= flask hates "_" in headers and b) it's stored in the Authorization-Header
        data_key=JWT_HEADER_NAME,
        validate=[
            Length(min=5, max=10000),
            Regexp(
                r'^Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$',
                error='Invalid JWT format. Must be "Bearer <token>"',
            )
        ],
        metadata=desc("Value of the JWT Token"),
    ))

JWTHeaderInputSchema = class_schema(JWTHeaderInput)()
