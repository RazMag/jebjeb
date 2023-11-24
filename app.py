
import os
from flask import Flask
from flask_login import LoginManager
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv
from api.models import User, db
from api.user import user_bp
from api.management import management_bp

load_dotenv()
login_manager = LoginManager()

def create_app(test_config=None): 

    app = Flask(__name__)
    app.secret_key = os.environ.get("APP_SECRET")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

    db.init_app(app)
    with app.app_context():
        db.create_all()

    login_manager.init_app(app)

    app.register_blueprint(user_bp)
    app.register_blueprint(management_bp)

    return app

@login_manager.user_loader
def load_user(username):
    """
    Load a user from the session by their ID.

    Args:
        user_id (int): The ID of the user to load.

    Returns:
        User: The user object corresponding to the given ID, or None if no such user exists.
    """
    return db.session.get(User, username)

# @app.route('/post')
# def post():
#     consumer_key = os.environ.get("API_KEY")
#     consumer_secret = os.environ.get("API_KEY_SECRET")

#     payload = {'text': 'Hello, World!'}

#     request_token_url = "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write"
#     oauth = OAuth1Session(consumer_key, client_secret=consumer_secret)

#     try:
#         fetch_response = oauth.fetch_request_token(request_token_url)
#     except ValueError:
#         print(
#             "There may have been an issue with the consumer_key or consumer_secret you entered."
#         )
    
#     resource_owner_key = fetch_response.get("oauth_token")
#     resource_owner_secret = fetch_response.get("oauth_token_secret")
#     print(f"Got OAuth token: {resource_owner_key}")

#     # Get authorization
#     base_authorization_url = "https://api.twitter.com/oauth/authorize"
#     authorization_url = oauth.authorization_url(base_authorization_url)
#     print(f"Please go here and authorize: {authorization_url}")
#     verifier = input("Paste the PIN here: ")

#     # Get the access token
#     access_token_url = "https://api.twitter.com/oauth/access_token"
#     oauth = OAuth1Session(
#         consumer_key,
#         client_secret=consumer_secret,
#         resource_owner_key=resource_owner_key,
#         resource_owner_secret=resource_owner_secret,
#         verifier=verifier,
#     )
#     oauth_tokens = oauth.fetch_access_token(access_token_url)

#     access_token = oauth_tokens["oauth_token"]
#     access_token_secret = oauth_tokens["oauth_token_secret"]

#     # Make the request
#     oauth = OAuth1Session(
#         consumer_key,
#         client_secret=consumer_secret,
#         resource_owner_key=access_token,
#         resource_owner_secret=access_token_secret,
#     )

#     # Making the request
#     response = oauth.post(
#         "https://api.twitter.com/2/tweets",
#         json=payload,
#     )

#     if response.status_code != 201:
#         raise Exception(
#             f"Request returned an error: {response.status_code} {response.text}"
#         )
    
#     return response.json()
    




if __name__ == '__main__':
    create_app().run(debug=True)
    