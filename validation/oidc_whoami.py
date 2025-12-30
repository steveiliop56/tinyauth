#!/usr/bin/env python3
import os
import sys
import json
import webbrowser
import secrets
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie

import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt

# ---- config via env ----
ISSUER        = os.environ["OIDC_ISSUER"]
CLIENT_ID    = os.environ["CLIENT_ID"]
CLIENT_SECRET= os.environ.get("CLIENT_SECRET")  # optional (public clients ok)
REDIRECT_URI = "http://client.example.com/callback"
SCOPE        = "openid profile email"

# ---- discovery ----
# Retry discovery in case nginx isn't ready yet
discovery = None
for attempt in range(10):
    try:
        discovery = requests.get(
            f"{ISSUER.rstrip('/')}/api/.well-known/openid-configuration",
            timeout=5
        ).json()
        break
    except Exception as e:
        if attempt < 9:
            print(f"Discovery attempt {attempt + 1} failed: {e}, retrying...")
            time.sleep(2)
        else:
            raise

if discovery is None:
    raise RuntimeError("Failed to fetch OIDC discovery document after 10 attempts")

state = secrets.token_urlsafe(16)
nonce = secrets.token_urlsafe(16)

client = OAuth2Session(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    scope=SCOPE,
    redirect_uri=REDIRECT_URI,
)

auth_result = client.create_authorization_url(
    discovery["authorization_endpoint"],
    state=state,
    nonce=nonce,
    code_challenge_method="S256",
)
auth_url = auth_result[0]
code_verifier = auth_result[1] if len(auth_result) > 1 else None

# Cache JWKS for token validation
jwk_set_cache = None
jwk_set_cache_time = None

def get_jwk_set():
    """Get JWKS with caching"""
    global jwk_set_cache, jwk_set_cache_time
    # Cache for 1 hour
    if jwk_set_cache is None or (jwk_set_cache_time and time.time() - jwk_set_cache_time > 3600):
        jwk_set_cache = requests.get(discovery["jwks_uri"]).json()
        jwk_set_cache_time = time.time()
    return jwk_set_cache

def parse_cookies(cookie_header):
    """Parse cookies from Cookie header"""
    if not cookie_header:
        return {}
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    return {k: v.value for k, v in cookie.items()}

def validate_id_token(id_token):
    """Validate and decode ID token"""
    try:
        jwk_set = get_jwk_set()
        claims_options = {
            "iss": {"essential": True, "value": discovery["issuer"]},
            "aud": {"essential": True, "value": CLIENT_ID},
        }
        decoded = jwt.decode(
            id_token,
            key=jwk_set,
            claims_options=claims_options
        )
        decoded.validate()
        return dict(decoded)
    except Exception as e:
        print(f"Token validation failed: {e}")
        return None

# ---- tiny callback server ----
class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Handle root path - check if already logged in
        if self.path == "/" or self.path == "":
            cookies = parse_cookies(self.headers.get("Cookie"))
            id_token = cookies.get("id_token")
            
            # Check if we have a valid token
            if id_token:
                claims = validate_id_token(id_token)
                if claims and claims.get("exp", 0) > time.time():
                    # Already logged in - show main page
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>OIDC Test Client - Welcome</title>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                max-width: 800px;
                                margin: 50px auto;
                                padding: 20px;
                                background: #f5f5f5;
                            }}
                            .main-box {{
                                background: white;
                                border-radius: 8px;
                                padding: 30px;
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            }}
                            h1 {{
                                color: #4285f4;
                                margin-top: 0;
                            }}
                            .user-info {{
                                background: #f9f9f9;
                                padding: 20px;
                                border-radius: 4px;
                                margin: 20px 0;
                                border-left: 4px solid #4285f4;
                            }}
                            pre {{
                                background: #f9f9f9;
                                padding: 15px;
                                border-radius: 4px;
                                overflow-x: auto;
                                border: 1px solid #ddd;
                            }}
                            .logout-btn {{
                                display: inline-block;
                                padding: 10px 20px;
                                background: #dc3545;
                                color: white;
                                text-decoration: none;
                                border-radius: 4px;
                                margin-top: 20px;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="main-box">
                            <h1>✅ Welcome back!</h1>
                            <div class="user-info">
                                <h2>User Information</h2>
                                <p><strong>Username:</strong> {claims.get('preferred_username', claims.get('sub', 'N/A'))}</p>
                                <p><strong>Name:</strong> {claims.get('name', 'N/A')}</p>
                                <p><strong>Email:</strong> {claims.get('email', 'N/A')}</p>
                            </div>
                            <hr>
                            <h2>ID Token Claims:</h2>
                            <pre>{json.dumps(claims, indent=2)}</pre>
                            <a href="/logout" class="logout-btn">Logout</a>
                        </div>
                    </body>
                    </html>
                    """
                    self.wfile.write(html.encode())
                    return
            
            # Not logged in - show login page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>OIDC Test Client</title></head>
            <body>
                <h1>OIDC Test Client</h1>
                <p>Click the button below to start the OIDC flow:</p>
                <a href="{auth_url}" style="display: inline-block; padding: 10px 20px; background: #4285f4; color: white; text-decoration: none; border-radius: 4px;">Login with OIDC</a>
                <hr>
                <p><small>Authorization URL: <code>{auth_url}</code></small></p>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
            return
        
        # Handle logout
        if self.path == "/logout":
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "id_token=; Path=/; Max-Age=0")
            self.end_headers()
            return

        # Handle callback
        if not self.path.startswith("/callback"):
            self.send_error(404, "Not Found")
            return

        qs = parse_qs(urlparse(self.path).query)

        if qs.get("state", [None])[0] != state:
            self.send_error(400, "Invalid state")
            return

        code = qs.get("code", [None])[0]
        if not code:
            self.send_error(400, "Missing code")
            return

        token = client.fetch_token(
            discovery["token_endpoint"],
            code=code,
            code_verifier=code_verifier,
        )

        # ---- ID token validation ----
        # Decode and validate the ID token using cached JWKS
        jwk_set = get_jwk_set()
        
        # Decode the JWT - make nonce optional if not provided
        claims_options = {
            "iss": {"essential": True, "value": discovery["issuer"]},
            "aud": {"essential": True, "value": CLIENT_ID},
        }
        if nonce:
            claims_options["nonce"] = {"essential": True, "value": nonce}
        
        decoded = jwt.decode(
            token["id_token"],
            key=jwk_set,
            claims_options=claims_options
        )
        decoded.validate()
        
        # Convert JWTClaims to dict for display
        id_token_claims = dict(decoded)

        # Store ID token in cookie (expires when token expires)
        token_expiry = id_token_claims.get("exp", 0) - time.time()
        max_age = max(0, int(token_expiry))

        # Redirect to main page with cookie set
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"id_token={token['id_token']}; Path=/; Max-Age={max_age}; HttpOnly")
        self.end_headers()

        print("\n" + "=" * 60)
        print("✅ OIDC Authentication Successful!")
        print("=" * 60)
        print("\nID Token Claims:")
        print(json.dumps(id_token_claims, indent=2))
        print("\n" + "=" * 60)
        # Don't exit - keep server running for multiple test flows

# ---- run ----
print("=" * 60)
print("OIDC Test Client")
print("=" * 60)
print(f"\nAuthorization URL: {auth_url}")
print("\nTo test the OIDC flow:")
print("1. Open the authorization URL above in your browser")
print("2. Login with credentials: user / pass")
print("3. You will be redirected back to the callback")
print("4. The ID token claims will be displayed below")
print(f"\nWaiting for callback on {REDIRECT_URI}...")
print("=" * 60)

# Try to open browser (may fail in Docker, that's OK)
try:
    webbrowser.open(auth_url)
except Exception as e:
    print(f"Could not open browser automatically: {e}")
    print("Please open the authorization URL manually")

HTTPServer(("0.0.0.0", 8765), CallbackHandler).serve_forever()
