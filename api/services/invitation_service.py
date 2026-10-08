import secrets
import uuid
from datetime import datetime, timedelta

from database.db import db
from database.models import (
    Workspace,
    WorkspaceInvitation,
    WorkspaceMember,
    User
)

INVITATION_EXPIRY_HOURS = 48


def create_invitation(
    workspace_id,
    invited_email,
    role="MEMBER",
    can_approve_deletion=False
):
    invited_email = invited_email.strip().lower()

    if not invited_email:
        raise ValueError("Invited email is required.")

    workspace = db.session.get(Workspace, workspace_id)

    if workspace is None:
        raise ValueError("Workspace not found.")

    if workspace.type != "ORGANIZATION":
        raise ValueError(
            "Invitations can only be created for organization workspaces."
        )

    if role not in ("MEMBER", "ADMIN"):
        raise ValueError("Invalid invitation role.")

    existing_member = (
        WorkspaceMember.query
        .join(WorkspaceMember.user)
        .filter(
            WorkspaceMember.workspace_id == workspace_id,
            User.email == invited_email
        )
        .first()
    )

    if existing_member:
        raise ValueError(
            "User is already a member of this organization."
        )

    existing_invitations = WorkspaceInvitation.query.filter_by(
        workspace_id=workspace_id,
        invited_email=invited_email,
        status="PENDING"
    ).all()

    for existing_invitation in existing_invitations:
        existing_invitation.status = "CANCELLED"

    invitation = WorkspaceInvitation(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        invited_email=invited_email,
        invitation_code=secrets.token_urlsafe(32),
        role=role,
        can_approve_deletion=can_approve_deletion,
        status="PENDING",
        expires_at=datetime.utcnow() + timedelta(
            hours=INVITATION_EXPIRY_HOURS
        )
    )

    db.session.add(invitation)

    # Do not commit here.
    # The caller controls the transaction.
    db.session.flush()

    return invitation


def get_invitation_by_code(invitation_code):

    invitation = WorkspaceInvitation.query.filter_by(
        invitation_code=invitation_code
    ).first()

    if invitation is None:
        raise ValueError("Invalid invitation code.")

    if invitation.status != "PENDING":
        raise ValueError("Invitation is no longer active.")

    if invitation.expires_at < datetime.utcnow():
        invitation.status = "EXPIRED"

        # Flush the status change without committing
        # the surrounding transaction.
        db.session.flush()

        raise ValueError("Invitation has expired.")

    return invitation


def accept_invitation(invitation_code, user):

    invitation = get_invitation_by_code(
        invitation_code
    )

    if user.email.lower() != invitation.invited_email.lower():
        raise PermissionError(
            "This invitation was issued for a different email address."
        )

    existing_member = WorkspaceMember.query.filter_by(
        workspace_id=invitation.workspace_id,
        user_id=user.id
    ).first()

    if existing_member:

        invitation.status = "ACCEPTED"

        db.session.flush()

        return existing_member

    member = WorkspaceMember(
        id=str(uuid.uuid4()),
        workspace_id=invitation.workspace_id,
        user_id=user.id,
        role=invitation.role,
        can_approve_deletion=invitation.can_approve_deletion
    )

    db.session.add(member)

    invitation.status = "ACCEPTED"

    # Do not commit here.
    # Registration controls the final commit.
    db.session.flush()

    return member


def list_workspace_invitations(workspace_id):

    return (
        WorkspaceInvitation.query
        .filter_by(workspace_id=workspace_id)
        .order_by(
            WorkspaceInvitation.created_at.desc()
        )
        .all()
    )
