import os
from flask import Flask, redirect, request, session, make_response
from mtauthclient.client import MTAuthClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# TODO: provide both a low-level and a high-level sample implementation

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration - should be env vars in real life
AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:8080")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")

# Generate a key pair for the client
# In a real app, you'd store these securely
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

PRIVATE_KEY_PEM = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

PUBLIC_KEY_PEM = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

client = MTAuthClient(AUTH_SERVER_URL, client_private_key=PRIVATE_KEY_PEM)

@app.route('/')
def index():
    if 'username' in session:
        return f"Welcome, {session['username']}! <br><a href='/logout'>Logout</a>", 200, {'Content-Type': 'text/plain'}
    
    return """
    <html>
        <body>
            <form action="/login" method="get">
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """

@app.route('/login')
def login():
    url = client.get_authorize_url(REDIRECT_URI, PUBLIC_KEY_PEM, scopes=["admin", "user"])
    return redirect(url)

@app.route('/callback')
def callback():
    grant = request.args.get('grant')
    if not grant:
        return "Missing grant", 400, {'Content-Type': 'text/plain'}
    
    token = client.exchange_token(grant)
    if not token:
        return "Failed to exchange token", 401, {'Content-Type': 'text/plain'}
    
    user = client.verify_token(token)
    if not user:
        return "Invalid token received", 401, {'Content-Type': 'text/plain'}
    
    session['username'] = user.username
    session['token'] = token
    
    # User said: "set a cookie, and relate that cookie to our api token"
    # Flask session already uses a cookie. But we can set an explicit one if needed.
    resp = make_response(redirect('/'))
    resp.set_cookie('api_token', token)
    return resp

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/'))
    resp.delete_cookie('api_token')
    return resp

if __name__ == '__main__':
    app.run(port=5000, debug=True)
