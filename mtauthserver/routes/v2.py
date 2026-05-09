import logging
from typing import Union, List, Optional, cast, Mapping, Any, Tuple
from flask import render_template, request, redirect, current_app, Response
from apiflask import APIBlueprint, APIFlask
from marshmallow import ValidationError

from ..jwt_api_util import generate_api_token, decode_api_token, expire_in_api_token
from ..ldap import fetch_user, check_credentials
from .route_util import resp_wrapper
from .schemas.common import OutCanError, ErrorResponse, ErrorResponseSchema
from .schemas.v2 import V2AskAuthInputSchema, V2AskAuthInput, V2AuthDoneInputSchema, V2AuthDoneInput, \
    V2RekeyInputSchema, V2RekeyInput, V2TokenExchangeInputSchema, V2TokenExchangeInput, V2GrantPayload, \
    V2GrantChallenge, V2AuthResponseSchema, V2AuthResponse
from shared_util import generate_token, decode_and_cast, restore_rsa_key, V2TokenData


# Time (in seconds) after which the grant expires
GRANT_MAX_AGE = 10


def _render_login(scopes: List[str], error: Optional[str] = None) -> str:
    """Render the login page with an optional error message and scopes."""
    return render_template(
        'login.html',
        scopes=scopes,
        error=error
    )


def register_routes_v2(app: APIFlask) -> None:
    api = APIBlueprint('api_v2', __name__, url_prefix='/api/v2', tag="API v2")


    @api.get('/public-key')
    @api.doc(responses={
        200: {'description': 'Token in PEM Format', 'content': {'text/plain': {}}},
    })
    def get_public_key() -> str:
        """Fetch the public key for JWT validation."""
        return current_app.config['JWT_PUBLIC_KEY']


    @api.get('/authorize')
    @api.input(V2AskAuthInputSchema, location="query", arg_name="auth_query")
    @api.doc(responses={
        200: {'description': 'Login Webpage', 'content': {'text/html': {}}},
    })
    def authorize(auth_query: V2AskAuthInput) -> str:
        """The authorization endpoint where the user is redirected to."""
        return _render_login(auth_query.scopes)

    @api.post('/authorize')
    @api.input(V2AskAuthInputSchema, location="query", arg_name="auth_query")
    @api.input(V2AuthDoneInputSchema, location="form", arg_name="raw_auth_data", validation=False)
    @api.doc(responses={
        200: {'title': 'asdf', 'description': 'Failed, back to Login Page', 'content': {'text/html': {}}},
        302: {'description': 'Successfully logged in, forwarding to App with Grant in Query.'},
    })
    def login(auth_query: V2AskAuthInput, raw_auth_data: Mapping[str, Any]) -> Union[str, Response]:
        """Handle the login form submission."""
        try:
            # we disable validation for the input so we can manually parse and validate it here
            # this allows us to catch the ValidationError and return a proper (html) error message
            auth_data: V2AuthDoneInput = V2AuthDoneInputSchema.load(raw_auth_data)

            if not check_credentials(auth_data.username, auth_data.password):
                logging.warning(f"V2 Login failed for user: {auth_data.username} from {request.remote_addr}")
                return _render_login(auth_query.scopes, error="Invalid credentials")

            user = fetch_user(auth_data.username)

            # filter scopes: user can only have a permission that is identical to a group he is in
            user_scopes = [s for s in auth_query.scopes if s in user.groups]

            # Instead of a full token, we generate a short-lived grant
            # The other side can then use a back-channel to exchange the grant for an access token
            pl = V2GrantPayload(user=user, scopes=user_scopes, client_public_key=restore_rsa_key(auth_query.cpk))
            grant = generate_token(pl.to_dict(), current_app.config['JWT_PRIVATE_KEY'], GRANT_MAX_AGE)

            logging.info(f"V2 Login successful for user: {auth_data.username} from {request.remote_addr}")
            return redirect(f"{auth_query.redirect_uri}?grant={grant}")
        except ValidationError as e:
            logging.error(f"Validation error during V2 authentication: {e}")
            return _render_login(auth_query.scopes, error="Invalid login data")
        except Exception as e:
            logging.error(f"Error during V2 authentication: {e}")
            return _render_login(auth_query.scopes, error="Internal server error")

    @api.post('/token')
    @api.input(V2TokenExchangeInputSchema, arg_name="data")
    @api.output(V2AuthResponseSchema)
    @api.doc(responses={
        200: resp_wrapper("Token exchanged successfully", V2AuthResponseSchema),
        400: resp_wrapper("Invalid Grant", ErrorResponseSchema),
        500: resp_wrapper("Internal Server Error", ErrorResponseSchema),
    })
    def exchange_token(data: V2TokenExchangeInput) -> OutCanError[V2AuthResponse]:
        """Exchange a grant for an access token."""
        # decrypt the grant with our key
        err, grant = decode_api_token(data.grant, V2GrantPayload)
        if err:
            logging.warning(f"Token exchange failed: invalid grant. IP: {request.remote_addr}. Error: {err}.")
            return ErrorResponse("Invalid Grant"), 400
        grant = cast(V2GrantPayload, grant)

        # Verify client challenge
        # The client signs the grant with their private key and includes it in the request
        err, challenge = decode_and_cast(data.challenge, grant.client_public_key, V2GrantChallenge)
        if err:
            logging.warning(f"Token exchange failed: invalid challenge. IP: {request.remote_addr}. Error: {err}.")
            return ErrorResponse("Invalid Challenge"), 400
        challenge = cast(V2GrantChallenge, challenge)
        if challenge.grant != data.grant:
            logging.warning(f"Token exchange failed: challenge grant mismatch. IP: {request.remote_addr}")
            return ErrorResponse("Challenge grant mismatch"), 400

        token = generate_api_token(V2TokenData(
            user=grant.user,
            scopes=grant.scopes,
            rekey_count=0,
        ).to_dict())

        return V2AuthResponse(
            message="Token exchanged successfully",
            user=grant.user,
            scopes=grant.scopes,
            token=token,
        )

    @api.post('/rekey')
    @api.input(V2RekeyInputSchema, arg_name="data")
    @api.output(V2AuthResponseSchema)
    @api.doc(responses={
        200: resp_wrapper("Successfully Request", V2AuthResponseSchema),
        400: resp_wrapper("Invalid Token", ErrorResponseSchema),
        500: resp_wrapper("Internal Server Error", ErrorResponseSchema),
    })
    def rekey(data: V2RekeyInput) -> OutCanError[V2AuthResponse]:
        """(Try to) renew an expired token."""
        # try to decode the token
        # ignore expiration since we have different constraints
        err, token = decode_api_token(data.token, V2TokenData, verify_exp=False)
        if err:
            logging.warning(f"Rekey failed: invalid token. IP: {request.remote_addr}. Error: {err}.")
            return ErrorResponse("Invalid Token"), 400
        token = cast(V2TokenData, token)

        # check token expiry
        err, exp = expire_in_api_token(data.token)
        if err:
            logging.warning(f"Rekey failed: invalid token. IP: {request.remote_addr}. Error: {err}.")
            return ErrorResponse("Invalid Token"), 400
        exp = cast(float, exp)
        if exp >= current_app.config['REKEY_MAX_TIME_DIFF']:
            logging.warning(f"Rekey failed: token expired too long ago ({exp:.2f}s). IP: {request.remote_addr}")
            return ErrorResponse("Invalid Token"), 400

        # check rekey count
        if token.rekey_count >= current_app.config['REKEY_MAX_COUNT']:
            logging.warning(f"Rekey failed: max rekey count reached ({token.rekey_count}). User: {token.user.username}, IP: {request.remote_addr}")
            return ErrorResponse("Invalid Token"), 400


        # Generate new token but force update the user data
        new_user = fetch_user(token.user.username)
        # user must still be a member of the scope groups
        new_scopes = [scope for scope in token.scopes if scope in new_user.groups]
        new_token = generate_api_token(V2TokenData(
            user=new_user,
            scopes=new_scopes,
            rekey_count=token.rekey_count + 1,
        ).to_dict())

        return V2AuthResponse(
            message="Token renewed successfully",
            user=new_user,
            token=new_token,
            scopes=new_scopes,
        )

    app.register_blueprint(api)
