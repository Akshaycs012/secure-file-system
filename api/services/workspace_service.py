from database.db import db
from database.models import (
    Workspace,
    WorkspaceMember
)


# ============================================================
# CREATE PERSONAL WORKSPACE
# ============================================================

def create_personal_workspace(user):

    workspace = Workspace(
        name=f"{user.username}'s Personal Workspace",
        type="PERSONAL",
        owner_id=user.id,
        required_approvals=1,
        approval_delay_hours=0
    )

    db.session.add(workspace)
    db.session.flush()

    member = WorkspaceMember(
        workspace_id=workspace.id,
        user_id=user.id,
        role="OWNER",
        can_approve_deletion=True
    )

    db.session.add(member)

    # Do NOT commit here.
    # The registration route controls the transaction.
    db.session.flush()

    return workspace


# ============================================================
# CREATE ORGANIZATION
# ============================================================

def create_organization(
    user,
    name,
    required_approvals=1,
    approval_delay_hours=24
):

    if not name or not name.strip():
        raise ValueError(
            "Organization name is required."
        )

    name = name.strip()

    if required_approvals < 1:
        raise ValueError(
            "Required approvals must be at least 1."
        )

    if approval_delay_hours < 0:
        raise ValueError(
            "Approval delay cannot be negative."
        )

    workspace = Workspace(
        name=name,
        type="ORGANIZATION",
        owner_id=user.id,
        required_approvals=required_approvals,
        approval_delay_hours=approval_delay_hours
    )

    db.session.add(workspace)
    db.session.flush()

    member = WorkspaceMember(
        workspace_id=workspace.id,
        user_id=user.id,
        role="OWNER",
        can_approve_deletion=True
    )

    db.session.add(member)

    # Do NOT commit here.
    # The registration route controls the transaction.
    db.session.flush()

    return workspace


# ============================================================
# GET USER WORKSPACES
# ============================================================

def get_user_workspaces(user_id):

    memberships = (
        WorkspaceMember.query
        .filter_by(user_id=user_id)
        .all()
    )

    return [
        membership.workspace
        for membership in memberships
    ]


# ============================================================
# GET MEMBERSHIP
# ============================================================

def get_workspace_membership(
    workspace_id,
    user_id
):

    return (
        WorkspaceMember.query
        .filter_by(
            workspace_id=workspace_id,
            user_id=user_id
        )
        .first()
    )


# ============================================================
# CHECK WORKSPACE ACCESS
# ============================================================

def require_workspace_membership(
    workspace_id,
    user_id
):

    membership = get_workspace_membership(
        workspace_id,
        user_id
    )

    if membership is None:
        raise PermissionError(
            "You are not a member of this workspace."
        )

    return membership


# ============================================================
# GET ELIGIBLE DELETION APPROVERS
# ============================================================

def get_deletion_approvers(workspace_id):

    return (
        WorkspaceMember.query
        .filter_by(
            workspace_id=workspace_id,
            can_approve_deletion=True
        )
        .all()
    )


# ============================================================
# VALIDATE DELETION POLICY
# ============================================================

def validate_deletion_policy(workspace):

    approvers = get_deletion_approvers(
        workspace.id
    )

    eligible_count = len(approvers)

    if workspace.required_approvals > eligible_count:

        raise ValueError(
            "Deletion policy is invalid: "
            "required approvals exceed the number "
            "of eligible approvers."
        )

    return True
