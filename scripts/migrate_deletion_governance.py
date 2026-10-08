from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.app import app
from database.db import db
from database import models


def main():

    print("Starting deletion governance migration...")

    with app.app_context():

        db.create_all()

        inspector = db.inspect(db.engine)

        required_tables = [
            "deletion_requests",
            "deletion_approvals",
            "notifications"
        ]

        print()

        for table in required_tables:

            if inspector.has_table(table):
                print(f"[OK] {table}")
            else:
                print(f"[ERROR] {table} was not created.")

        print()
        print("Deletion governance migration completed.")


if __name__ == "__main__":
    main()