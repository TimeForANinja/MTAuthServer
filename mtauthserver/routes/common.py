import logging
from apiflask import APIFlask

from mtauthserver.routes.schemas.common import ErrorResponse


def register_routes_common(app: APIFlask) -> None:
    # add "status" and "status_code" fields to the default flask errors
    @app.error_processor
    def handle_error(error) -> ErrorResponse:
        logging.error("APP", "FLASK Error", error)
        return ErrorResponse(error.message)
