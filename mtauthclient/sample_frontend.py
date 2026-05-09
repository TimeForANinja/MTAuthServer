from os import urandom
from flask import Flask, redirect, request, session, make_response

from auth.rsa_util import generate_dummy_keypair
from mtauthclient.client import MTAuthClient

app = Flask(__name__)

# set secret key so we can use flask session
app.secret_key = urandom(24)

# Configuration - should be read from config for prod
AUTH_SERVER_URL = "http://localhost:8443"
CALLACK_PATH = "/callback"
REDIRECT_URI = "http://localhost:5000" + CALLACK_PATH

# Generate a key pair for the client
# In a real app, you'd store these securely and just import
PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = generate_dummy_keypair()

# init our client with the data
client = MTAuthClient(AUTH_SERVER_URL, PRIVATE_KEY_PEM, PUBLIC_KEY_PEM)

@app.route('/')
def index():
    # Main page, either show our User or a Login-Page
    if 'username' in session:
        return f"Welcome, {session['username']}! <br><a href='/logout'>Logout</a>"

    return """<html><body><form action="/login" method="get"><button type="submit">Login</button></form></body></html>"""

@app.route('/login')
def login():
    # user wants to login, so we redirect them to the auth server
    url = client.get_authorize_url(REDIRECT_URI, scopes=["admin", "user"])
    return redirect(url)

@app.route(CALLACK_PATH)
def callback():
    # callback from the auth server after a user logged in
    err, user, token = client.handle_callback(request)
    if err:
        return f"""<html><body><div>Failed: {err}</div><div><form action="/login" method="get"><button type="submit">Retry</button></form></div></body></html>"""

    # use the build-in session feature of flask to store the user data
    session['username'] = user.username
    session['token'] = token

    return make_response(redirect('/'))

@app.route('/logout')
def logout():
    session.clear()
    return make_response(redirect('/'))

if __name__ == '__main__':
    app.run(port=5000, debug=True)
