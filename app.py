
import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv
from api.models import User, db
from api.user import user_bp

app = Flask(__name__)
app.register_blueprint(user_bp)

load_dotenv()
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = os.environ.get("APP_SECRET")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)


class Tweet(db.Model):
    """
    Represents a tweet object in the database.

    Attributes:
    id (int): The unique identifier for the tweet.
    user_id (str): The unique identifier for the user who posted the tweet.
    datetime (datetime): The date and time the tweet should be posted.
    data (str): The content of the tweet.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'))
    datetime = db.Column(db.DateTime, nullable=False)
    data = db.Column(db.String(280), nullable=False)
    media = db.Column(db.String(1200), nullable=True)
    super_follows = db.Column(db.Boolean, nullable=False)
    posted = db.Column(db.Boolean, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    """
    Load a user from the session by their ID.

    Args:
        user_id (int): The ID of the user to load.

    Returns:
        User: The user object corresponding to the given ID, or None if no such user exists.
    """
    return User.session.get(user_id)

@app.route('/protected')
@login_required
def protected():
    """
    Returns a JSON response indicating that the route is protected.
    """
    return jsonify(message='This is a protected route')

@app.route('/reset_db', methods=['POST'])
def reset_db():
    """
    Resets the database by dropping all tables and recreating them.
    
    Returns:
        A JSON response with a success message and a 200 status code.
    """
    db.drop_all()
    db.create_all()
    return jsonify({"message": "Database reset successfully"}), 200



@app.route('/health_check')
def health_check():
    """
    Returns a JSON response indicating that the application is healthy.
    """
    return jsonify({"message": "Healthy"}), 200

@app.route('/post')
def post():
    consumer_key = os.environ.get("API_KEY")
    consumer_secret = os.environ.get("API_KEY_SECRET")

    payload = {'text': 'Hello, World!'}

    request_token_url = "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write"
    oauth = OAuth1Session(consumer_key, client_secret=consumer_secret)

    try:
        fetch_response = oauth.fetch_request_token(request_token_url)
    except ValueError:
        print(
            "There may have been an issue with the consumer_key or consumer_secret you entered."
        )
    
    resource_owner_key = fetch_response.get("oauth_token")
    resource_owner_secret = fetch_response.get("oauth_token_secret")
    print(f"Got OAuth token: {resource_owner_key}")

    # Get authorization
    base_authorization_url = "https://api.twitter.com/oauth/authorize"
    authorization_url = oauth.authorization_url(base_authorization_url)
    print(f"Please go here and authorize: {authorization_url}")
    verifier = input("Paste the PIN here: ")

    # Get the access token
    access_token_url = "https://api.twitter.com/oauth/access_token"
    oauth = OAuth1Session(
        consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=verifier,
    )
    oauth_tokens = oauth.fetch_access_token(access_token_url)

    access_token = oauth_tokens["oauth_token"]
    access_token_secret = oauth_tokens["oauth_token_secret"]

    # Make the request
    oauth = OAuth1Session(
        consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret,
    )

    # Making the request
    response = oauth.post(
        "https://api.twitter.com/2/tweets",
        json=payload,
    )

    if response.status_code != 201:
        raise Exception(
            f"Request returned an error: {response.status_code} {response.text}"
        )
    
    return response.json()
    




if __name__ == '__main__':
    app.run(debug=True)
