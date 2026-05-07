from apiflask import APIBlueprint, APIFlask


def register_routes_v2(app: APIFlask) -> None:
    api = APIBlueprint('api_v2', __name__, url_prefix='/api/v2')
    pass
