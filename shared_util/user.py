from dataclasses import dataclass, asdict
from typing import List as tList, Dict as tDict, Any as tAny
from apiflask.fields import String, List, Dict
from marshmallow_dataclass import class_schema

from .schema_util import to_field, desc


@dataclass
class MTAuthUser:
    username: str = to_field(String(
        required=True,
        metadata=desc('Username from token')
    ))
    groups: tList[str] = to_field(List(
        String(),
        metadata=desc('(AD) Groups from token'),
    ))
    attributes: tDict[str, tAny] = to_field(Dict(
        metadata=desc('User attributes from token')
    ))

    def to_dict(self) -> tDict[str, tAny]:
        return asdict(self)

MTAuthUserSchema = class_schema(MTAuthUser)()
