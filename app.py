import os
from flask import Flask, redirect, url_for, session, render_template, request
from google_auth_oauthlib.flow import Flow
from flask_cors import CORS


app = Flask(__name__)
CORS(app)  # This will enable CORS for all routes
# CORS(app, resources={r"/*": {"origins": "http://localhost:5000"}})
const port = process.env.PORT || 4000;

app.secret_key = 'your_secret_key'  # Change this to a random secret key
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow http for local testing

# Configure your OAuth 2.0 Client IDs
CLIENT_SECRETS_FILE = 'client_secrets.json'  # Download this from Google Cloud Console

@app.after_request
def add_security_headers(response):
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
    return response


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/drive.file'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/drive.file'],
        state=session['state'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('picker'))

@app.route('/picker')
def picker():
    # Here you would include the Google Picker JavaScript API code.
    return render_template('picker.html')

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

