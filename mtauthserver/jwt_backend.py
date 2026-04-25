import jwt
import datetime
import json
from .config import load_config
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

def generate_token(username: str, groups: List[str]) -> str:
    cnf = load_config()
    
    # Matching Go's behavior: groups are a JSON string in the token
    json_groups: str = json.dumps(groups)
    
    payload: dict = {
        "username": username,
        "groups": json_groups,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    
    token: str = jwt.encode(payload, cnf.secret_key, algorithm="HS256")
    return token

def validate_token(token: str) -> Tuple[bool, str, str]:
    cnf = load_config()
    try:
        payload: dict = jwt.decode(token, cnf.secret_key, algorithms=["HS256"])
        
        username: str = payload.get("username", "")
        groups_str: str = payload.get("groups", "[]")
        
        # groups_str is a JSON string as per Go implementation
        return True, username, groups_str
    except jwt.ExpiredSignatureError:
        logger.error("Token expired")
        return False, "", ""
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return False, "", ""
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return False, "", ""
