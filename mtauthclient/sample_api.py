from typing import cast
from apiflask import APIFlask

from mtauthclient.client import MTAuthClient, MTAuthUser


app = APIFlask(__name__)

# Configuration - should be read from config for prod
AUTH_SERVER_URL = "http://localhost:8443"

# init our client with the data
client = MTAuthClient(AUTH_SERVER_URL)
auth = client.get_auth()


@app.route('/')
@app.auth_required(auth, ['admin'])
def index():
    user = cast(MTAuthUser, auth.current_user)
    return f"Welcome {user.username} on a Protected Website", 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    app.run(port=5000, debug=True)
