import re
import os
from flask import Blueprint, jsonify, request
from flask_login import login_user, logout_user, login_required, current_user
from requests_oauthlib import OAuth1Session
from api.models import User, db

user_bp = Blueprint('user_bp', __name__)


@user_bp.route('/signup', methods=['POST'])
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
        return jsonify({"error": "Password must be at least 8 characters long and contain at "
                        "least one lowercase letter, one uppercase letter, and one digit"}), 400
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if User.query.get(username):
        return jsonify({"error": "User already exists"}), 400
    user = User(
        username=username
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@user_bp.route('/login', methods=['POST'])
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
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401
    login_user(user)
    return jsonify({"message": "Logged in successfully"}), 200

@user_bp.route('/logout')
@login_required
def logout():
    """
    Logs out the current user.
    
    Returns:
        A tuple containing a JSON response with a success message and a 200 status code.
    """
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200


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


@user_bp.route('/init_twitter_login')
@login_required
def init_twitter_login():
    """
    Initiate the OAuth flow for logging into Twitter.

    Returns:
        A tuple containing a JSON response with a success message and a 200 status code.
    """
    consumer_key = os.environ.get("API_KEY")
    consumer_secret = os.environ.get("API_KEY_SECRET")
    request_token_url = ("https://api.twitter.com"
                            "/oauth/request_token"
                            "?oauth_callback=oob&x_auth_access_type=write")
    oauth = OAuth1Session(consumer_key, client_secret=consumer_secret)
    try:
        fetch_response = oauth.fetch_request_token(request_token_url)
    except ValueError:
        print(
            "There may have been an issue with the consumer_key or consumer_secret you entered."
        )
    resource_owner_key = fetch_response.get("oauth_token")
    resource_owner_secret = fetch_response.get("oauth_token_secret")
    current_user.set_access_token_details(
        access_token = resource_owner_key,
        access_token_secret = resource_owner_secret,
        complete_login = False) #TODO: encrypt these
    base_authorization_url = "https://api.twitter.com/oauth/authorize"
    authorization_url = oauth.authorization_url(base_authorization_url)
    return jsonify({"auth_url": authorization_url}), 200


@user_bp.route('/complete_twitter_login', methods=['POST'])
@login_required
def complete_twitter_login():
    """
    Complete the OAuth flow for logging into Twitter.

    Returns:
        A tuple containing a JSON response with a success message and a 200 status code.
    """
    consumer_key = os.environ.get("API_KEY")
    consumer_secret = os.environ.get("API_KEY_SECRET")
    access_token_url = "https://api.twitter.com/oauth/access_token"
    oauth = OAuth1Session(
        consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=current_user.access_token,
        resource_owner_secret=current_user.access_token_secret,
        verifier=request.get_json().get('PIN'),
    )
    oauth_tokens = oauth.fetch_access_token(access_token_url)
    access_token = oauth_tokens["oauth_token"]
    access_token_secret = oauth_tokens["oauth_token_secret"]
    
    oauth = OAuth1Session(
        consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret,
    )
    response = oauth.get("https://api.twitter.com/2/users/me")
    if response.status_code != 200:
        return jsonify({"error": "Error logging in",
                        "error_info": response.content}), 400
    response = response.json()["data"]
    current_user.set_access_token_details(
        access_token, 
        access_token_secret,
        True) #TODO: encrypt these
    return jsonify({"message": "Logged in successfully",
                    "name": response["name"],
                    "username": response["username"]}), 200
    