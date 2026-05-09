from dataclasses import dataclass, asdict
from typing import List as tList, Dict as tDict, Any as tAny
from marshmallow.fields import Nested, List, String, Integer

from shared_util import to_field, desc
from shared_util import MTAuthUser, MTAuthUserSchema


@dataclass
class V1TokenData(MTAuthUser):
    pass

    def to_dict(self) -> tDict[str, tAny]:
        return asdict(self)


@dataclass
class V2TokenData:
    user: MTAuthUser = to_field(Nested(
        MTAuthUserSchema,
        required=True,
        metadata=desc('User associated with the token'),
    ))
    scopes: tList[str] = to_field(List(
        String(),
        required=True,
        metadata=desc('Scopes granted to the user'),
    ))
    rekey_count: int = to_field(Integer(
        required=True,
        metadata=desc('Number of times the token has been rekeyed')
    ))

    def to_dict(self) -> tDict[str, tAny]:
        return asdict(self)
