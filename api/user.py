import re
from flask import Blueprint, jsonify, request
from flask_login import login_user, logout_user, login_required
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
        return jsonify({"error": "Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one digit"}), 400
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