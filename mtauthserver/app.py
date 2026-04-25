import os
from apiflask import APIFlask
from werkzeug.middleware.proxy_fix import ProxyFix
from mtauthserver.config import load_config
from mtauthserver.routes import register_routes


def create_app() -> APIFlask:
    app = APIFlask(__name__, "MTAuthServer", version="1.0.0", docs_path="/")

    # load config
    cnf = load_config()
    app.config.from_object(cnf)

    # use offline swagger ui
    app.config['SWAGGER_UI_CSS'] = 'static/css/swagger-ui.css'
    app.config['SWAGGER_UI_BUNDLE_JS'] = 'static/js/swagger-ui-bundle.js'
    app.config['SWAGGER_UI_STANDALONE_PRESET_JS'] = 'static/js/swagger-ui-standalone-preset.js'

    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )

    register_routes(app)

    return app


app: APIFlask = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
