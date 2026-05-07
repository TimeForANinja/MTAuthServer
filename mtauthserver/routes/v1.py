import logging
from flask import request
from apiflask import APIBlueprint, APIFlask

from mtauthserver.ldap import check_credentials, get_ldap_connection, fetch_user_data
from mtauthserver.auth import decode_token, generate_token, User
from mtauthserver.routes.schemas.schemas import AuthResponseSchema, IntrospectResponseSchema, IntrospectResponse, \
    IntrospectInput, \
    IntrospectInputSchema, AuthResponse, AuthInputSchema, AuthInput, JWTHeaderInputSchema
from mtauthserver.routes.schemas.common import ErrorResponseSchema, ErrorResponse, OutCanError
from mtauthserver.routes.schemas.schemas import JWTHeaderInput
from routes.schemas.util import resp_wrapper


def register_routes_v1(app: APIFlask) -> None:
    api = APIBlueprint('api_v1', __name__, tag="API v1")

    @api.post("/auth")
    @api.input(AuthInputSchema, location="json", arg_name="auth_data")
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", AuthResponseSchema),
        401: resp_wrapper("Invalid Authentication Provided", ErrorResponseSchema),
        500: resp_wrapper("Internal Server Error", ErrorResponseSchema),
    })
    def authentication(auth_data: AuthInput) -> OutCanError[AuthResponse]:
        """
        Authenticate a user against LDAP and return a JWT token.
        """
        try:
            conn = get_ldap_connection()
            if check_credentials(conn, auth_data.username, auth_data.password):
                groups, attributes = fetch_user_data(auth_data.username)

                user = User(username=auth_data.username, groups=groups, attributes=attributes)
                token = generate_token(user)

                logging.info(f"Login attempt from: {request.remote_addr} successful.")
                return AuthResponse(
                    username=auth_data.username,
                    groups=groups,
                    attributes=attributes,
                    token=token,
                    status="valid",
                )
            else:
                logging.warning(f"Login attempt from: {request.remote_addr} failed.")
                return ErrorResponse("Authentication failed"), 401
        except Exception as e:
            logging.error(f"Error during authentication: {e}")
            return ErrorResponse("Internal server error"), 500


    @api.post("/introspect")
    @api.input(IntrospectInputSchema, location="json", arg_name="introspect_data")
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", IntrospectResponseSchema),
        401: resp_wrapper("Invalid Authentication Provided", ErrorResponseSchema),
    })
    def introspect(introspect_data: IntrospectInput) -> OutCanError[IntrospectResponse]:
        """
        Introspect a JWT token and return user information.
        """
        decoded_token = decode_token(introspect_data.token)

        if not decoded_token:
            logging.warning(f"Invalid login attempt from: {request.remote_addr}")
            return ErrorResponse("Invalid token"), 401

        logging.info(f"Successfully Introspect from: {request.remote_addr} for user: {decoded_token.username}")
        return IntrospectResponse(
            username=decoded_token.username,
            groups=decoded_token.groups,
            status="valid",
            attributes=decoded_token.attributes
        )

    @api.get("/verify/<string:app_name>")
    @api.input(JWTHeaderInputSchema, location="headers", arg_name="token")
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", IntrospectResponseSchema),
        401: resp_wrapper("Invalid Authentication Provided", ErrorResponseSchema),
    })
    def verify_app(app_name: str, token: JWTHeaderInput) -> OutCanError[IntrospectResponse]:
        """
        Verify JWT token
        """
        # remove the bearer prefix
        raw_token = token.jwt_token.replace("Bearer ", "")
        decoded_token = decode_token(raw_token)

        if not decoded_token:
            logging.warning(f"Invalid login attempt from: {request.remote_addr}")
            return ErrorResponse("Invalid token"), 401

        logging.info(f"Successfully Verify from: {request.remote_addr} for user: {decoded_token.username}")
        return IntrospectResponse(
            username=decoded_token.username,
            groups=decoded_token.groups,
            status="valid",
            attributes=decoded_token.attributes
        )

    app.register_blueprint(api)
