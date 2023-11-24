
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy.exc import SQLAlchemyError
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
def create_tweets():
    """
    Creates new tweets for the logged in user.

    Returns:
        A JSON response containing the newly created tweets.
    """
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "Expected a list of tweets"}), 400

    tweets = []
    errors = []
    for tweet_data in data:
        try:
            valid, error = verify_tweet(tweet_data)
            if not valid:
                errors.append({"tweet": tweet_data, "error": error})
                continue
            tweet = Tweet(
                text=tweet_data.get('text'),
                datetime=tweet_data.get('datetime'),
                user_id=current_user.id
            )
            if tweet_data.get('media_url'):
                tweet.media_url = tweet_data.get('media_url')
            if tweet_data.get('super_follows'):
                tweet.super_follows = tweet_data.get('super_follows')
            else:
                tweet.super_follows = False
            tweet.posted = False
            db.session.add(tweet)
            tweets.append(tweet)
        except SQLAlchemyError as e:
            db.session.rollback()
            errors.append({"tweet": tweet_data, "error": str(e)})

    db.session.commit()
    return jsonify({"tweets": [tweet.to_dict() for tweet in tweets], "errors": errors}), 201

def verify_tweet(tweet):
    """
    Verifies that the given tweet is valid.

    Args:
        tweet (dict): The tweet to verify.

    Returns:
        bool: True if the tweet is valid, False otherwise.
        str: Error message if the tweet is invalid.
    """
    result = [True, ""]
    if not tweet:
        result = [False, "Missing Tweet data"]
    else:
        text = tweet.get('text')
        if not text:
            result = [False, "Missing Tweet text"]
        elif len(text) > 280:
            result = [False, "Tweet text exceeds 280 characters"]
        else:
            datetime_str = tweet.get('datetime')
            if not datetime_str:
                result = [False, "Missing post time info"]
            else:
                try:
                    datetime_obj = datetime.fromisoformat(datetime_str)
                    if datetime_obj <= datetime.now():
                        result = [False, "Tweet datetime should be in the future"]
                except ValueError:
                    result = [False, "Invalid datetime format"]
    return tuple(result)


@tweets_bp.route('/tweets/<int:tweet_id>', methods=['PUT'])
@login_required
def update_tweet(tweet_id):
    """
    Updates a tweet with the given tweet_id.

    Args:
        tweet_id (int): The unique identifier for the tweet.

    Returns:
        A JSON response containing the updated tweet.
    """
    tweet = Tweet.query.get(tweet_id)
    if not tweet:
        return jsonify({"error": "Tweet not found"}), 404
    if tweet.user_id != current_user.id:
        return jsonify({"error": "You do not have permission to update this tweet"}), 403
    data = request.get_json()
    valid, error = verify_tweet(data)
    if not valid:
        return jsonify({"error": error}), 400
    tweet.text = data.get('text')
    tweet.datetime = data.get('datetime')
    tweet.media_url = data.get('media_url')
    tweet.super_follows = data.get('super_follows')
    db.session.commit()
    return jsonify(tweet.to_dict()), 200

@tweets_bp.route('/tweets', methods=['DELETE'])
@login_required
def delete_tweets():
    """
    Deletes tweets with the given tweet_ids.

    Args:
        tweet_ids (list): The unique identifiers for the tweets.

    Returns:
        A tuple containing a JSON response with a success message and a 200 status code.
    """
    data = request.get_json()
    tweet_ids = data.get('tweet_ids', [])

    if not tweet_ids:
        return jsonify({"error": "No tweet IDs provided"}), 400

    tweets = Tweet.query.filter(Tweet.id.in_(tweet_ids)).all()

    if not tweets:
        return jsonify({"error": "Tweets not found"}), 404

    for tweet in tweets:
        if tweet.user_id != current_user.id:
            return jsonify({"error": "You do not have permission to delete some tweets"}), 403

    for tweet in tweets:
        db.session.delete(tweet)

    db.session.commit()
    return jsonify({"message": "Tweets deleted successfully"}), 200
