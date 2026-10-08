from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv

load_dotenv()
import jwt


JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 1


def get_secret_key():
    secret_key = os.getenv("JWT_SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not configured."
        )

    return secret_key


def create_access_token(user):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user.id,
        "username": user.username,
        "iat": now,
        "exp": now + timedelta(
            hours=JWT_EXPIRATION_HOURS
        )
    }

    return jwt.encode(
        payload,
        get_secret_key(),
        algorithm=JWT_ALGORITHM
    )


def decode_access_token(token):
    try:
        return jwt.decode(
            token,
            get_secret_key(),
            algorithms=[JWT_ALGORITHM]
        )

    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")

    except jwt.InvalidTokenError:
        raise ValueError("Invalid authentication token.")