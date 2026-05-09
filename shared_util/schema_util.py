from dataclasses import field
from typing import Dict, Any
from apiflask.fields import Field as tField


def desc(description: str) -> Dict[str, Any]:
    """
    Utility function to simplify the nesting of descriptions in metadata.
    """
    return {"description": description}

def to_field(f: tField, **kwargs):
    """
    Convert an APIFlask Type to a Dataclass Type.
    This is required for any Dataclass being converted to a Schema using class_schema(xxx)()
    If not done so, the following warning will be raised:
    ```
    UserWarning: <class 'routes.schemas.url.ListURLOutput'> has already been added to the spec.
    ```
    """
    return field(
        metadata={
            "marshmallow_field": f,
        },
        **kwargs,
    )
