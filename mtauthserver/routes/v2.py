import logging
from typing import Union

import jwt
import datetime
from flask import render_template, request, redirect, current_app, Response
from apiflask import APIBlueprint, APIFlask
from marshmallow import ValidationError

from mtauthserver.auth import generate_token, User
from mtauthserver.ldap import get_ldap_connection, check_credentials, get_groups_of_user, get_user_attributes
from routes.schemas.common import OutCanError, ErrorResponse, ErrorResponseSchema
from routes.schemas.schemas import AskAuthInputSchema, AskAuthInput, AuthDoneInputSchema, AuthDoneInput, \
    PublicKeyResponseSchema, RekeyResponseSchema, RekeyInputSchema, RekeyInput, PublicKeyResponse, RekeyResponse
from routes.schemas.util import resp_wrapper


def register_routes_v2(app: APIFlask) -> None:
    api = APIBlueprint('api_v2', __name__, url_prefix='/api/v2', tag="API v2")

    @api.get('/authorize')
    @api.input(AskAuthInputSchema, location="query", arg_name="auth_data")
    def authorize(auth_data: AskAuthInput) -> str:
        """
        The authorization endpoint where the user is redirected to.
        """
        return render_template('login.html', redirect_uri=auth_data.redirect_uri)

    @api.post('/authorize')
    @api.input(AuthDoneInputSchema, location="form", arg_name="raw_auth_data", validation=False)
    def login(raw_auth_data: AuthDoneInput) -> Union[str, Response]:
        """
        Handle the login form submission.
        """
        try:
            # we disable validation at the top, and manually parse and validate here
            # this allows us to catch the ValidationError and return a HTTP Page with error message
            auth_data = AuthDoneInputSchema.load(raw_auth_data)

            conn = get_ldap_connection()
            if check_credentials(conn, auth_data.username, auth_data.password):
                groups = get_groups_of_user(conn, auth_data.username)
                attributes = get_user_attributes(conn, auth_data.username)

                user = User(username=auth_data.username, groups=groups, attributes=attributes)
                token = generate_token(user, 0)

                logging.info(f"V2 Login successful for user: {auth_data.username} from {request.remote_addr}")

                return redirect(f"{auth_data.redirect_uri}?token={token}")
            else:
                logging.warning(f"V2 Login failed for user: {auth_data.username} from {request.remote_addr}")
                return render_template('login.html', redirect_uri=auth_data.redirect_uri, error="Invalid credentials")
        except ValidationError as e:
            logging.error(f"Validation error during V2 authentication: {e}")
            return render_template('login.html', redirect_uri="asdf", error="Invalid login data")
        except Exception as e:
            logging.error(f"Error during V2 authentication: {e}")
            return render_template('login.html', redirect_uri="asdf", error="Internal server error")

    @api.get('/public-key')
    @api.output(PublicKeyResponseSchema)
    def get_public_key() -> PublicKeyResponse:
        """
        Fetch the public key for JWT validation.
        """
        return PublicKeyResponse(
            message="Public key fetched successfully",
            public_key=current_app.config['JWT_PUBLIC_KEY'],
        )

    @api.post('/rekey')
    @api.input(RekeyInputSchema, arg_name="data")
    @api.output(RekeyResponseSchema)
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", RekeyResponseSchema),
        400: resp_wrapper("Invalid Token", ErrorResponseSchema),
        500: resp_wrapper("Internal Server Error", ErrorResponseSchema),
    })
    def rekey(data: RekeyInput) -> OutCanError[RekeyResponse]:
        """
        Renew an expired token.
        """
        try:
            # Decode token without verification to get data and exp
            # We want to check if it's expired and how long ago
            payload = jwt.decode(
                data.token,
                options={"verify_signature": False, "verify_exp": False}
            )

            exp = payload.get("exp")
            if not exp:
                return ErrorResponse("Invalid token: missing exp"), 400

            exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
            now_dt = datetime.datetime.now(tz=datetime.timezone.utc)

            if now_dt < exp_dt:
                return ErrorResponse("Token not yet expired"), 400

            diff = (now_dt - exp_dt).total_seconds()
            if diff > current_app.config['REKEY_MAX_TIME_DIFF']:
                return ErrorResponse("Token expired too long ago"), 400

            rekey_count = payload.get("rekey_count", 0)
            if rekey_count >= current_app.config['REKEY_MAX_COUNT']:
                return ErrorResponse("Max rekey count reached"), 400

            # Verify signature now
            try:
                jwt.decode(
                    data.token,
                    current_app.config['JWT_PUBLIC_KEY'],
                    algorithms=["RS256"],
                    options={"verify_exp": False} # we already checked exp manually
                )
            except jwt.InvalidTokenError as e:
                return ErrorResponse(f"Invalid token signature: {e}"), 400

            # Generate new token
            user = User(
                username=payload.get("username"),
                groups=payload.get("groups", []),
                attributes=payload.get("attributes", {})
            )

            # We need to pass rekey_count + 1 to generate_token
            new_token = generate_token(user, rekey_count + 1)

            return RekeyResponse(
                message="Token renewed successfully",
                username=user.username,
                groups=user.groups,
                attributes=user.attributes,
                token=new_token,
            )

        except Exception as e:
            logging.error(f"Error during rekey: {e}")
            return ErrorResponse("Internal server error"), 500

    app.register_blueprint(api)
