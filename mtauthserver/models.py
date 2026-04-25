from apiflask import Schema
from apiflask.fields import String, List, Integer

class UsernamePassword(Schema):
    username: String = String(required=True)
    password: String = String(required=True)

class Token(Schema):
    token: String = String(required=True)

class ResponseToken(Schema):
    groups: List = List(String())
    status: String = String()
    username: String = String()
    token: String = String()

class ResponseVerify(Schema):
    app_name: String = String()
    groups: List = List(String())
    status: String = String()
    username: String = String()

class ResponseAuthError(Schema):
    msg: String = String()
    status: String = String()

class ResponseError(Schema):
    message: String = String()
