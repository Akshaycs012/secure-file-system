from functools import wraps

from flask import request, jsonify, g

from api.services.token_service import decode_access_token
from database.db import db
from database.models import User


def auth_required(function):
    @wraps(function)
    def decorated(*args, **kwargs):

        authorization = request.headers.get("Authorization")

        if not authorization:
            return jsonify({
                "error": "Authentication required."
            }), 401

        parts = authorization.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Invalid Authorization header."
            }), 401

        token = parts[1]

        try:
            payload = decode_access_token(token)

            user_id = payload.get("sub")

            if not user_id:
                return jsonify({
                    "error": "Invalid authentication token."
                }), 401

            user = db.session.get(User, user_id)

            if user is None:
                return jsonify({
                    "error": "User not found."
                }), 401

            g.current_user = user

            return function(*args, **kwargs)

        except ValueError as error:
            return jsonify({
                "error": str(error)
            }), 401

    return decorated