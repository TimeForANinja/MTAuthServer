from typing import Dict
from apiflask import Schema


def resp_wrapper(description: str, schema: Schema) -> Dict:
    """
    Build a response schema for the API that can be passed via the "docs" section.
    This is required to set response schemas for non-status-200 responses.
    """
    return {
        "description": description,
        "content": {
            "application/json": {
                "schema": schema
            }
        }
    }
