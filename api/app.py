from pathlib import Path

from flask import Flask

from api.routes.health import health_bp
from api.routes.files import files_bp
from api.routes.auth import auth_bp
from api.routes.pages import pages_bp
from api.routes.deletion_requests import deletion_bp

from database.db import db
from database import models
from api.routes.workspaces import workspaces_bp


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATABASE_PATH = (
    PROJECT_ROOT / "instance" / "secure_file_system.db"
)

TEMPLATES_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = PROJECT_ROOT / "static"


def create_app():

    app = Flask(
        __name__,
        template_folder=str(TEMPLATES_DIR),
        static_folder=str(STATIC_DIR)
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"sqlite:///{DATABASE_PATH}"
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    app.register_blueprint(health_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(workspaces_bp)
    app.register_blueprint(deletion_bp)

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )