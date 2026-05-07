import logging
import jwt
import datetime
from typing import Union, List, Optional
from flask import render_template, request, redirect, current_app, Response
from apiflask import APIBlueprint, APIFlask
from marshmallow import ValidationError

from mtauthserver.auth import generate_token, User
from mtauthserver.ldap import get_ldap_connection, check_credentials, fetch_user_data
from routes.schemas.common import OutCanError, ErrorResponse, ErrorResponseSchema
from routes.schemas.schemas import AskAuthInputSchema, AskAuthInput, AuthDoneInputSchema, AuthDoneInput, \
    PublicKeyResponseSchema, RekeyResponseSchema, RekeyInputSchema, RekeyInput, PublicKeyResponse, RekeyResponse
from routes.schemas.util import resp_wrapper


def _render_login(uri: str, scopes: List[str], error: Optional[str] = None) -> str:
    return render_template(
        'login.html',
        redirect_uri=uri,
        scopes=scopes,
        error=error
    )


def register_routes_v2(app: APIFlask) -> None:
    api = APIBlueprint('api_v2', __name__, url_prefix='/api/v2', tag="API v2")

    @api.get('/authorize')
    @api.input(AskAuthInputSchema, location="query", arg_name="auth_query")
    def authorize(auth_query: AskAuthInput) -> str:
        """
        The authorization endpoint where the user is redirected to.
        """
        return _render_login(auth_query.redirect_uri, auth_query.scopes)

    @api.post('/authorize')
    @api.input(AskAuthInputSchema, location="query", arg_name="auth_query")
    @api.input(AuthDoneInputSchema, location="form", arg_name="raw_auth_data", validation=False)
    def login(auth_query: AskAuthInput, raw_auth_data: AuthDoneInput) -> Union[str, Response]:
        """
        Handle the login form submission.
        """
        try:
            # we disable validation at the top, and manually parse and validate here
            # this allows us to catch the ValidationError and return a HTTP Page with error message
            auth_data = AuthDoneInputSchema.load(raw_auth_data)

            conn = get_ldap_connection()
            if check_credentials(conn, auth_data.username, auth_data.password):
                groups, attributes = fetch_user_data(auth_data.username)

                # filter scopes: user can only have a permission that is identical to a group he is in
                user_scopes = [s for s in auth_data.scopes if s in groups]

                user = User(username=auth_data.username, groups=groups, attributes=attributes, scopes=user_scopes)
                token = generate_token(user, 0)

                logging.info(f"V2 Login successful for user: {auth_data.username} from {request.remote_addr}")

                return redirect(f"{auth_data.redirect_uri}?token={token}")
            else:
                logging.warning(f"V2 Login failed for user: {auth_data.username} from {request.remote_addr}")
                return _render_login(auth_query.redirect_uri, auth_query.scopes, error="Invalid credentials")
        except ValidationError as e:
            logging.error(f"Validation error during V2 authentication: {e}")
            return _render_login(auth_query.redirect_uri, auth_query.scopes, error="Invalid login data")
        except Exception as e:
            logging.error(f"Error during V2 authentication: {e}")
            return _render_login(auth_query.redirect_uri, auth_query.scopes, error="Internal server error")

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

            # Generate new token, with updated groups, attributes and scopes
            groups, attributes = fetch_user_data(payload.get("username"))
            # user must still be a member of the group
            user_scopes = [s for s in payload.get("scopes") if s in groups]

            user = User(
                username=payload.get("username"),
                groups=groups,
                attributes=attributes,
                scopes=user_scopes
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
