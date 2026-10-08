from pathlib import Path
import sqlite3
import uuid


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATABASE_PATH = (
    PROJECT_ROOT
    / "instance"
    / "secure_file_system.db"
)


def main():

    print("Starting workspace migration...")

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    # --------------------------------------------------------
    # 1. Create workspaces table
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspaces (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            required_approvals INTEGER NOT NULL DEFAULT 1,
            approval_delay_hours INTEGER NOT NULL DEFAULT 24,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (owner_id)
                REFERENCES users(id)
        )
    """)

    # --------------------------------------------------------
    # 2. Create workspace_members table
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspace_members (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'MEMBER',
            can_approve_deletion
                INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            UNIQUE(workspace_id, user_id),
            FOREIGN KEY (workspace_id)
                REFERENCES workspaces(id),
            FOREIGN KEY (user_id)
                REFERENCES users(id)
        )
    """)

    # --------------------------------------------------------
    # 3. Add workspace_id to files
    # --------------------------------------------------------

    cursor.execute(
        "PRAGMA table_info(files)"
    )

    columns = [
        row[1]
        for row in cursor.fetchall()
    ]

    if "workspace_id" not in columns:

        cursor.execute("""
            ALTER TABLE files
            ADD COLUMN workspace_id TEXT
        """)

        print(
            "Added workspace_id to files."
        )

    else:

        print(
            "workspace_id already exists."
        )

    # --------------------------------------------------------
    # 4. Create personal workspace for each user
    # --------------------------------------------------------

    cursor.execute("""
        SELECT id, username
        FROM users
    """)

    users = cursor.fetchall()

    for user_id, username in users:

        cursor.execute("""
            SELECT id
            FROM workspaces
            WHERE owner_id = ?
              AND type = 'PERSONAL'
        """, (user_id,))

        existing_workspace = cursor.fetchone()

        if existing_workspace:

            workspace_id = existing_workspace[0]

        else:

            workspace_id = str(
                uuid.uuid4()
            )

            cursor.execute("""
                INSERT INTO workspaces (
                    id,
                    name,
                    type,
                    owner_id,
                    required_approvals,
                    approval_delay_hours,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, (
                workspace_id,
                f"{username}'s Personal Workspace",
                "PERSONAL",
                user_id,
                1,
                0
            ))

            print(
                f"Created personal workspace "
                f"for {username}"
            )

        # ----------------------------------------------------
        # Add user as workspace owner/member
        # ----------------------------------------------------

        cursor.execute("""
            SELECT id
            FROM workspace_members
            WHERE workspace_id = ?
              AND user_id = ?
        """, (
            workspace_id,
            user_id
        ))

        existing_member = cursor.fetchone()

        if not existing_member:

            cursor.execute("""
                INSERT INTO workspace_members (
                    id,
                    workspace_id,
                    user_id,
                    role,
                    can_approve_deletion,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, (
                str(uuid.uuid4()),
                workspace_id,
                user_id,
                "OWNER",
                1
            ))

    # --------------------------------------------------------
    # 5. Assign existing files to owner's personal workspace
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            f.id,
            f.owner_id
        FROM files f
        WHERE f.workspace_id IS NULL
    """)

    files = cursor.fetchall()

    for file_id, owner_id in files:

        cursor.execute("""
            SELECT id
            FROM workspaces
            WHERE owner_id = ?
              AND type = 'PERSONAL'
            LIMIT 1
        """, (owner_id,))

        workspace = cursor.fetchone()

        if workspace:

            workspace_id = workspace[0]

            cursor.execute("""
                UPDATE files
                SET workspace_id = ?
                WHERE id = ?
            """, (
                workspace_id,
                file_id
            ))

    connection.commit()

    # --------------------------------------------------------
    # 6. Verification
    # --------------------------------------------------------

    cursor.execute(
        "SELECT COUNT(*) FROM workspaces"
    )

    workspace_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM workspace_members"
    )

    member_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM files
        WHERE workspace_id IS NULL
    """)

    unassigned_files = cursor.fetchone()[0]

    print()
    print("Migration completed.")
    print(
        f"Workspaces: {workspace_count}"
    )
    print(
        f"Workspace members: {member_count}"
    )
    print(
        f"Files without workspace: "
        f"{unassigned_files}"
    )

    connection.close()


if __name__ == "__main__":
    main()