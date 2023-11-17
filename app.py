
import os
import re
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv



load_dotenv()
login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)
app.secret_key = os.environ.get("APP_SECRET")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    """
    Represents a user in the system.

    Attributes:
        id (str): The unique identifier for the user.
        password (str): The hashed password for the user.
    """
    id = db.Column(db.String(80), primary_key=True)
    password = db.Column(db.String(120))

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

with app.app_context():
    db.create_all()


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

def validate_password(password):
    """
    Validates a password based on the following criteria:
    - Must be at least 8 characters long
    - Must contain at least one lowercase letter
    - Must contain at least one uppercase letter
    - Must contain at least one digit
    
    Args:
    password (str): The password to be validated
    
    Returns:
    bool: True if the password is valid, False otherwise
    """
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    return True

@app.route('/signup', methods=['POST'])
def signup():
    """
    Registers a new user with the provided username and password.

    Returns:
        A JSON response containing a success or error message.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400
    username = data.get('username')
    password = data.get('password')
    if not validate_password(password):
        return jsonify({"error": "Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one digit"}), 400
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if User.session.get(username):
        return jsonify({"error": "User already exists"}), 400
    user = User(id=username, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    """
    Logs in a user with the provided username and password.

    Returns:
        A JSON response containing either an error message and a 401 status code,
        or a success message and a 200 status code.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.session.get(username)
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid username or password"}), 401
    login_user(user)
    return jsonify({"message": "Logged in successfully"}), 200

@app.route('/logout')
@login_required
def logout():
    """
    Logs out the current user.
    
    Returns:
        A tuple containing a JSON response with a success message and a 200 status code.
    """
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200

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
    app.run()
