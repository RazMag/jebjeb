
import os
from flask import Flask
from flask_login import LoginManager
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


if __name__ == '__main__':
    create_app().run(debug=False)
    