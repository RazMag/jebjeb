from flask import Blueprint, jsonify
from flask_login import login_required
from .models import db

management_bp = Blueprint('management_bp', __name__)

@management_bp.route('/reset_db', methods=['POST'])
def reset_db():
    """
    Resets the database by dropping all tables and recreating them.
    
    Returns:
        A JSON response with a success message and a 200 status code.
    """
    db.drop_all()
    db.create_all()
    return jsonify({"message": "Database reset successfully"}), 200

@management_bp.route('/protected')
@login_required
def protected():
    """
    Returns a JSON response indicating that the route is protected.
    """
    return jsonify(message='This is a protected route')

@management_bp.route('/health_check')
def health_check():
    """
    Returns a JSON response indicating that the application is healthy.
    """
    return jsonify({"message": "Healthy"}), 200
