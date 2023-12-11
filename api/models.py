from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    Represents a user in the system.

    Attributes:
        username (str): The username for the user.
        email (str): The email address for the user.
        password_hash (str): The hashed password for the user.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    access_token = db.Column(db.String(128), nullable=True)
    access_token_secret = db.Column(db.String(128), nullable=True)
    twitter_login_state = db.Column(db.String(32), nullable=True)

    def set_password(self, password):
        """
        Set the password for the user.

        Args:
            password (str): The password to set.

        Returns:
            None
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Check if the given password is correct.

        Args:
            password (str): The password to check.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        return check_password_hash(self.password_hash, password)

    def set_email(self, email):
        """
        Set the email address for the user.

        Args:
            email (str): The email address to set.

        Returns:
            None
        """
        self.email = email
        db.session.commit()

    def set_access_token_details(self, access_token, access_token_secret, complete_login=False):
        """
        Sets the access token details for a user.

        Args:
        access_token (str): The access token for the user.
        access_token_secret (str): The secret key associated with the access token.

        """
        self.access_token = access_token
        self.access_token_secret = access_token_secret
        if complete_login:
            self.twitter_login_state = "complete"
        else:
            self.twitter_login_state = "initiated"
        db.session.commit()

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
    text = db.Column(db.String(280), nullable=False)
    media_url = db.Column(db.String(1200), nullable=True)
    super_follows = db.Column(db.Boolean, nullable=False)
    posted = db.Column(db.Boolean, nullable=False)
