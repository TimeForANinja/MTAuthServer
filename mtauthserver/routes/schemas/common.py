from dataclasses import dataclass
from typing import TypeVar, Tuple

from apiflask.fields import String
from apiflask.validators import OneOf
from marshmallow_dataclass import class_schema

from mtauthserver.routes.schemas.util import desc, to_field


@dataclass
class GenericOutput:
    """Every Output Schema should inherit from this class."""
    status: str = to_field(String(
        required=True,
        validate=OneOf(["success", "failed"]),
        metadata=desc("Status of the response, e.g., 'success'"),
    ))

    message: str = to_field(String(
        required=True,
        metadata=desc("Message of the response"),
    ))


T = TypeVar("T")
# response can be T, an Error or an Error + Status Code as Tuple
type OutCanError[T] = T | ErrorResponse | Tuple[ErrorResponse, int]

@dataclass
class ErrorResponse(GenericOutput):
    def __init__(self, error: str):
        self.status = "failed"
        self.message = error

ErrorResponseSchema = class_schema(ErrorResponse)()
