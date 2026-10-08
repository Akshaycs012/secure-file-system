from database.db import db
from database.models import User


def register_user(username, email, password):
    if not username or not username.strip():
        raise ValueError("Username is required.")

    if not email or not email.strip():
        raise ValueError("Email is required.")

    if not password:
        raise ValueError("Password is required.")

    username = username.strip()
    email = email.strip().lower()

    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username is not None:
        raise ValueError("Username already exists.")

    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email is not None:
        raise ValueError("Email already exists.")

    user = User(
        username=username,
        email=email
    )

    user.set_password(password)

    db.session.add(user)

    # Generate the ID and make the user available to
    # workspace/membership operations without committing.
    db.session.flush()

    return user


def authenticate_user(email, password):
    if not email or not email.strip():
        raise ValueError("Email is required.")

    if not password:
        raise ValueError("Password is required.")

    email = email.strip().lower()

    user = User.query.filter_by(
        email=email
    ).first()

    if user is None:
        raise ValueError("Invalid email or password.")

    if not user.check_password(password):
        raise ValueError("Invalid email or password.")

    return user
