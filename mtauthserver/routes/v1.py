import logging
import re
from typing import cast
from flask import request
from apiflask import APIBlueprint, APIFlask

from ..jwt_api_util import generate_api_token, decode_api_token
from ..ldap import fetch_user, check_credentials
from .route_util import resp_wrapper
from .schemas.common import ErrorResponseSchema, ErrorResponse, OutCanError, JWTHeaderInputSchema, \
    JWTHeaderInput
from .schemas.v1 import V1AuthInputSchema, V1AuthResponseSchema, V1AuthInput, V1AuthResponse, \
    V1IntrospectResponseSchema, V1IntrospectInput, V1IntrospectResponse, V1IntrospectInputSchema, \
    V1VerifyAppResponseSchema, V1VerifyAppResponse
from shared_util import V1TokenData


def register_routes_v1(app: APIFlask) -> None:
    api = APIBlueprint('api_v1', __name__, url_prefix="/api/v1", tag="API v1")

    @api.post("/auth")
    @api.input(V1AuthInputSchema, location="json", arg_name="auth_data")
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", V1AuthResponseSchema),
        401: resp_wrapper("Invalid Authentication Provided", ErrorResponseSchema),
        500: resp_wrapper("Internal Server Error", ErrorResponseSchema),
    })
    @api.output(V1AuthResponseSchema)
    def authentication(auth_data: V1AuthInput) -> OutCanError[V1AuthResponse]:
        """
        Authenticate a user against LDAP and return a JWT token.
        """
        try:
            if check_credentials(auth_data.username, auth_data.password):
                user = fetch_user(auth_data.username)
                token = generate_api_token(cast(V1TokenData, user).to_dict())

                logging.info(f"Login attempt from: {request.remote_addr} successful.")
                return V1AuthResponse(
                    message="Authentication successful",
                    username=auth_data.username,
                    groups=user.groups,
                    attributes=user.attributes,
                    token=token,
                )
            else:
                logging.warning(f"Login attempt from: {request.remote_addr} failed.")
                return ErrorResponse("Authentication failed"), 401
        except Exception as e:
            logging.error(f"Error during authentication: {e}")
            return ErrorResponse("Internal server error"), 500


    @api.post("/introspect")
    @api.input(V1IntrospectInputSchema, location="json", arg_name="introspect_data")
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", V1IntrospectResponseSchema),
        401: resp_wrapper("Invalid Authentication Provided", ErrorResponseSchema),
    })
    @api.output(V1IntrospectResponseSchema)
    def introspect(introspect_data: V1IntrospectInput) -> OutCanError[V1IntrospectResponse]:
        """
        Introspect a JWT token and return user information.
        """
        err, user = decode_api_token(introspect_data.token, V1TokenData)
        if err:
            logging.warning(f"Invalid token from: {request.remote_addr}: {err}")
            return ErrorResponse("Invalid token"), 401
        user = cast(V1TokenData, user)

        logging.info(f"Successfully Introspect from: {request.remote_addr} for user: {user.username}")
        return V1IntrospectResponse(
            message="Authentication successful",
            username=user.username,
            groups=user.groups,
            attributes=user.attributes
        )

    @api.get("/verify/<string:app_name>")
    @api.input(JWTHeaderInputSchema, location="headers", arg_name="token")
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", V1VerifyAppResponseSchema),
        400: resp_wrapper("Invalid App Provided", ErrorResponseSchema),
        401: resp_wrapper("Invalid Authentication Provided", ErrorResponseSchema),
    })
    @api.output(V1VerifyAppResponseSchema)
    def verify_app(app_name: str, token: JWTHeaderInput) -> OutCanError[V1VerifyAppResponse]:
        """
        Verify JWT token manually
        """
        if not token.jwt_token.startswith("Bearer "):
            logging.warning("Attempted Login with non-bearer token.")
            return ErrorResponse("Only Bearer-Tokens supported"), 401

        # remove the bearer prefix and decode the token
        raw_token = token.jwt_token.replace("Bearer ", "")
        err, user = decode_api_token(raw_token, V1TokenData)
        if err:
            logging.warning(f"Invalid token from: {request.remote_addr}: {err}")
            return ErrorResponse("Invalid token"), 401
        user = cast(V1TokenData, user)

        if not re.match(r'^[A-Za-z_-]+$', app_name):
            logging.warning(f"Invalid app name from: {request.remote_addr}: \"{app_name}\"")
            return ErrorResponse("Invalid app name"), 400

        logging.info(f"Successfully Verify from: {request.remote_addr} for user: {user.username}")
        return V1VerifyAppResponse(
            message="Authentication successful",
            username=user.username,
            groups=user.groups,
            attributes=user.attributes,
            app=app_name,
        )

    app.register_blueprint(api)
