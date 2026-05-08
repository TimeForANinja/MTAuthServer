import json
import logging
import os
from dataclasses import asdict
from typing import Tuple, Dict, cast
from apiflask import APIFlask
from flask import send_from_directory

from mtauthserver.routes.schemas.common import ErrorResponse


def register_routes_common(app: APIFlask) -> None:
    # add "status" and "status_code" fields to the default flask errors
    @app.error_processor
    def handle_error(error) -> Tuple[Dict, int, Dict]:
        logging.error(f"FLASK Error: {error.message}" + json.dumps({
            'status_code': error.status_code,
            'message': error.message,
            'detail': error.detail,
            **error.extra_data
        }))
        return asdict(ErrorResponse(error.message)), error.status_code, error.headers

    # Serve index.html for the root route
    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def catch_all(path: str):
        """Catch-all route for non-API routes."""
        static_folder = os.path.abspath(cast(str, app.static_folder))
        static_file = os.path.join(static_folder, path)

        # Check if the requested static file exists
        if os.path.isfile(static_file):
            return send_from_directory(static_folder, path)

        # Fallback to serving index.html
        return send_from_directory(static_folder, "index.html")
