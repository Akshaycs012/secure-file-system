from flask import (
    Blueprint,
    jsonify,
    request,
    g
)

from database.db import db
from database.models import Workspace

from api.services.auth_middleware import (
    auth_required
)

from api.services.workspace_service import (
    create_organization,
    get_user_workspaces,
    require_workspace_membership,
    get_deletion_approvers,
    validate_deletion_policy
)

from api.services.invitation_service import (
    create_invitation,
    accept_invitation,
    list_workspace_invitations
)


workspaces_bp = Blueprint(
    "workspaces",
    __name__,
    url_prefix="/api/workspaces"
)


# ============================================================
# LIST USER WORKSPACES
# ============================================================

@workspaces_bp.get("")
@auth_required
def list_workspaces():

    try:

        workspaces = get_user_workspaces(
            g.current_user.id
        )

        return jsonify({
            "count": len(workspaces),
            "workspaces": [
                workspace.to_dict()
                for workspace in workspaces
            ]
        }), 200

    except Exception:

        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# CREATE ORGANIZATION
# ============================================================

@workspaces_bp.post("/organization")
@auth_required
def create_organization_route():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        name = data.get("name")

        required_approvals = data.get(
            "required_approvals",
            1
        )

        approval_delay_hours = data.get(
            "approval_delay_hours",
            24
        )

        try:

            required_approvals = int(
                required_approvals
            )

            approval_delay_hours = int(
                approval_delay_hours
            )

        except (TypeError, ValueError):

            return jsonify({
                "error": "Approval values must be integers."
            }), 400

        workspace = create_organization(
            g.current_user,
            name,
            required_approvals,
            approval_delay_hours
        )

        # This endpoint creates an organization outside
        # the registration transaction, so commit here.
        db.session.commit()

        return jsonify({
            "message": "Organization created successfully.",
            "workspace": workspace.to_dict()
        }), 201

    except ValueError as error:

        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# WORKSPACE DETAILS
# ============================================================

@workspaces_bp.get("/<workspace_id>")
@auth_required
def workspace_details(workspace_id):

    try:

        membership = require_workspace_membership(
            workspace_id,
            g.current_user.id
        )

        workspace = membership.workspace

        approvers = get_deletion_approvers(
            workspace.id
        )

        validate_deletion_policy(
            workspace
        )

        return jsonify({
            "workspace": workspace.to_dict(),
            "membership": membership.to_dict(),
            "eligible_approvers": len(approvers)
        }), 200

    except PermissionError as error:

        return jsonify({
            "error": str(error)
        }), 403

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 409

    except Exception:

        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# CREATE WORKSPACE INVITATION
# ============================================================

@workspaces_bp.post("/<workspace_id>/invitations")
@auth_required
def create_workspace_invitation(workspace_id):

    try:

        membership = require_workspace_membership(
            workspace_id,
            g.current_user.id
        )

        if membership.role not in ("OWNER", "ADMIN"):

            return jsonify({
                "error": (
                    "Only owners and admins can "
                    "create invitations."
                )
            }), 403

        # Make sure this is actually an organization.
        workspace = membership.workspace

        if workspace.type != "ORGANIZATION":

            return jsonify({
                "error": (
                    "Invitations can only be created "
                    "for organization workspaces."
                )
            }), 400

        data = request.get_json(
            silent=True
        ) or {}

        invited_email = data.get("email")

        role = data.get(
            "role",
            "MEMBER"
        )

        can_approve_deletion = bool(
            data.get(
                "can_approve_deletion",
                False
            )
        )

        invitation = create_invitation(
            workspace_id=workspace_id,
            invited_email=invited_email,
            role=role,
            can_approve_deletion=can_approve_deletion
        )

        # create_invitation() only flushes.
        # This endpoint owns the transaction.
        db.session.commit()

        return jsonify({
            "message": "Invitation created successfully.",
            "invitation": invitation.to_dict(),
            "invitation_code": invitation.invitation_code
        }), 201

    except PermissionError as error:

        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 403

    except ValueError as error:

        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# ACCEPT WORKSPACE INVITATION
# ============================================================

@workspaces_bp.post(
    "/invitations/<invitation_code>/accept"
)
@auth_required
def accept_workspace_invitation(invitation_code):

    try:

        member = accept_invitation(
            invitation_code,
            g.current_user
        )

        # accept_invitation() only flushes.
        # This endpoint owns the transaction.
        db.session.commit()

        return jsonify({
            "message": "Invitation accepted successfully.",
            "membership": member.to_dict()
        }), 200

    except PermissionError as error:

        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 403

    except ValueError as error:

        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# LIST WORKSPACE INVITATIONS
# ============================================================

@workspaces_bp.get(
    "/<workspace_id>/invitations"
)
@auth_required
def get_workspace_invitations(workspace_id):

    try:

        membership = require_workspace_membership(
            workspace_id,
            g.current_user.id
        )

        if membership.role not in ("OWNER", "ADMIN"):

            return jsonify({
                "error": (
                    "Only owners and admins can "
                    "view invitations."
                )
            }), 403

        workspace = membership.workspace

        if workspace.type != "ORGANIZATION":

            return jsonify({
                "error": (
                    "Invitations are only available "
                    "for organization workspaces."
                )
            }), 400

        invitations = list_workspace_invitations(
            workspace_id
        )

        return jsonify({
            "count": len(invitations),
            "invitations": [
                invitation.to_dict()
                for invitation in invitations
            ]
        }), 200

    except PermissionError as error:

        return jsonify({
            "error": str(error)
        }), 403

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 400

    except Exception:

        return jsonify({
            "error": "Internal server error."
        }), 500