from dataclasses import dataclass, asdict
from typing import Dict, Any, List


@dataclass
class User:
    """
    Dataclass representing a user.
    """
    username: str
    groups: List[str]
    attributes: Dict[str, Any]
    scopes: List[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
