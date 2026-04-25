import re
import json
from typing import Any, Dict, List, Tuple, Optional
from apiflask import APIBlueprint
from flask import request, current_app

from .models import UsernamePassword, Token, ResponseToken, ResponseVerify
from .ldap_backend import connect_ldap, check_authentication, get_groups_of_user
from .jwt_backend import generate_token, validate_token


api: APIBlueprint = APIBlueprint('api', __name__)


@api.post("/api/v1/auth")
@api.input(UsernamePassword, arg_name='data')
@api.output(ResponseToken)
def auth(data: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    username: str = data['username']
    password: str = data['password']

    if len(username) < 5 or len(username) > 50:
        return {"status": "failed", "msg": "error username too short or too long min. 5 max. 50"}, 400

    if len(password) < 5 or len(password) > 128:
        return {"status": "failed", "msg": "error password too short or too long min. 5 max. 128"}, 400

    conn = connect_ldap()
    if not conn:
        return {"status": "failed", "msg": "LDAP connection failed"}, 500

    if check_authentication(conn, username, password):
        groups: List[str] = get_groups_of_user(conn, username)
        token: str = generate_token(username, groups)
        return {"status": "ok", "username": username, "groups": groups, "token": token}, 200
    else:
        return {"status": "failed", "msg": "Authorization failed"}, 401


@api.post("/api/v1/introspect")
@api.input(Token, arg_name='data')
@api.output(ResponseVerify)
def introspect(data: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    token: str = data['token']
    valid, username, groups_str = validate_token(token)

    if valid:
        try:
            groups: List[str] = json.loads(groups_str)
        except Exception:
            groups = []
        return {"status": "valid", "username": username, "groups": groups}, 200
    else:
        return {"status": "failed", "msg": "token invalid"}, 401


@api.get("/api/v1/verify/<app_name>")
@api.output(ResponseVerify)
def verify_token(app_name: str) -> Tuple[Dict[str, Any], int]:
    if not re.match(r'^[A-Za-z_-]+$', app_name):
        return {"message": "app_name has invalid chars in it, only A-Z a-z and _-."}, 400

    auth_header: Optional[str] = request.headers.get("Authorization")
    if not auth_header:
        return {"message": "Authorization header missing."}, 401

    parts: List[str] = auth_header.split()
    if len(parts) != 2 or parts[0] != "Bearer":
        return {"message": "Authorization header format not valid."}, 401

    token: str = parts[1]
    valid, username, groups_str = validate_token(token)

    if valid:
        try:
            groups: List[str] = json.loads(groups_str)
        except Exception:
            groups = []
        current_app.logger.info(f"Authorization successful. user={username} app={app_name}")
        return {"status": "valid", "username": username, "groups": groups, "app_name": app_name}, 200
    else:
        current_app.logger.warning(f"Authorization failed. app={app_name}")
        return {"status": "failed", "msg": "token invalid", "app_name": app_name}, 401
