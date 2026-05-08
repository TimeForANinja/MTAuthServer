from flask import Flask, redirect, request, session, make_response

from mtauthclient.client import MTAuthClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Configuration - should be read from config for prod
AUTH_SERVER_URL = "http://localhost:8080"
REDIRECT_URI = "http://localhost:5000/callback"

# Generate a key pair for the client
# In a real app, you'd store these securely and just import
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_KEY_PEM = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')
PUBLIC_KEY_PEM = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

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

@app.route('/callback')
def callback():
    # callback from the auth server after a user logged in
    err, user, token = client.handle_callback(request)
    if err:
        return "Failed: " + str(err), 400, {'Content-Type': 'text/plain'}

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
