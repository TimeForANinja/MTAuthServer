import logging
from apiflask import APIFlask
from werkzeug.middleware.proxy_fix import ProxyFix

from mtauthserver.config import load_config
from mtauthserver.routes.common import register_routes_common
from mtauthserver.routes.v1 import register_routes_v1
from mtauthserver.routes.v2 import register_routes_v2


def create_app() -> APIFlask:
    new_app = APIFlask(
        __name__,
        "MTAuthServer",
        version="1.1.0",
        docs_path="/docs",
        template_folder="templates",
    )

    # use offline swagger ui
    new_app.config['SWAGGER_UI_CSS'] = 'static/css/swagger-ui.css'
    new_app.config['SWAGGER_UI_BUNDLE_JS'] = 'static/js/swagger-ui-bundle.js'
    new_app.config['SWAGGER_UI_STANDALONE_PRESET_JS'] = 'static/js/swagger-ui-standalone-preset.js'

    load_config(new_app)

    # fix for src_ip if used behind a reverse Proxy
    if new_app.config["PROXY_FIX"]:
        logging.info("applying reverse proxy fix")
        new_app.wsgi_app = ProxyFix(
            new_app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )

    register_routes_common(new_app)
    register_routes_v1(new_app)
    register_routes_v2(new_app)

    return new_app


app = create_app()


if __name__ == "__main__":
    app_port = app.config["PORT"]
    app.run(host="0.0.0.0", port=app_port)
