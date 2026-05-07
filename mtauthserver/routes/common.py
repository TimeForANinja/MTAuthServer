import logging
from dataclasses import asdict
from typing import Tuple, Dict

from apiflask import APIFlask

from mtauthserver.routes.schemas.common import ErrorResponse


def register_routes_common(app: APIFlask) -> None:
    # add "status" and "status_code" fields to the default flask errors
    @app.error_processor
    def handle_error(error) -> Tuple[Dict, int, Dict]:
        logging.error(f"FLASK Error: {error.message}", {
            'status_code': error.status_code,
            'message': error.message,
            'detail': error.detail,
            **error.extra_data
        })
        return asdict(ErrorResponse(error.message)), error.status_code, error.headers


    @app.get("/favicon.ico")
    def favicon():
        return "", 204
