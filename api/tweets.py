from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from api.models import Tweet, db


tweets_bp = Blueprint('user_bp', __name__)

@tweets_bp.route('/tweets', methods=['GET'])
@login_required
def get_tweets():
    """
    Gets all tweets from the database for the logged in user.

    Returns:
        A JSON response containing all tweets for the logged in user.
    """
    tweets = Tweet.query.filter_by(user_id=current_user.id).all()
    return jsonify([tweet.to_dict() for tweet in tweets]), 200


@tweets_bp.route('/tweets', methods=['POST'])
@login_required
def create_tweet():
    """
    Creates a new tweet for the logged in user.

    Returns:
        A JSON response containing the newly created tweet.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400
    text = data.get('text')
    if not text:
        return jsonify({"error": "Missing text"}), 400
    tweet = Tweet(
        text=text,
        user_id=current_user.id
    )
    db.session.add(tweet)
    db.session.commit()
    return jsonify(tweet.to_dict()), 201
