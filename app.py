import os
import json
from flask import Flask, redirect, request, jsonify
from google_auth_oauthlib.flow import Flow

app = Flask(__name__)
# Secret key for Flask session signing
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key-change-me")

# Allow HTTP for local testing; Render handles HTTPS termination automatically
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

def get_google_oauth_flow():
    """Reconstructs Google OAuth client secrets from Render Environment Variables."""
    client_config = {
        "web": {
            "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [os.environ.get("REDIRECT_URI")]
        }
    }
    
    # Pass scopes required (e.g., userinfo or specific Google API access)
    scopes = [
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ]

    return Flow.from_client_config(
        client_config,
        scopes=scopes,
        redirect_uri=os.environ.get("REDIRECT_URI")
    )

@app.route("/")
def home():
    return '<a href="/login">Click here to Login with Google</a>'

@app.route("/login")
def login():
    flow = get_google_oauth_flow()

    # CRITICAL: prompt='consent' and access_type='offline' force Google to issue a refresh_token
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true"
    )
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = get_google_oauth_flow()
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    
    token_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }

    # Print to Render logs so you can copy the refresh token from your Render Dashboard
    print("\n" + "="*50)
    print("SUCCESSFULLY OBTAINED REFRESH TOKEN:")
    print(f"REFRESH TOKEN: {credentials.refresh_token}")
    print("="*50 + "\n")

    return jsonify({
        "status": "success",
        "message": "Authentication successful! Check your Render Dashboard logs to copy your refresh token.",
        "refresh_token_received": credentials.refresh_token is not None,
        "tokens": token_data
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
