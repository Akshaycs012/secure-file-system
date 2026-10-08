from flask import Blueprint, jsonify, request, g

from api.services.auth_service import (
    register_user,
    authenticate_user
)

from api.services.token_service import create_access_token
from api.services.auth_middleware import auth_required

from api.services.workspace_service import (
    create_personal_workspace,
    create_organization
)

from api.services.invitation_service import (
    accept_invitation,
    get_invitation_by_code
)

from database.db import db


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/api/auth"
)


@auth_bp.post("/register")
def register():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "error": "JSON request body is required."
            }), 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        workspace_type = (
            data.get("workspace_type") or "PERSONAL"
        ).strip().upper()

        organization_name = data.get("organization_name")
        required_approvals = data.get(
            "required_approvals",
            1
        )
        invitation_code = data.get("invitation_code")

        # -------------------------------------------------
        # Validate workspace type
        # -------------------------------------------------

        if workspace_type not in (
            "PERSONAL",
            "ORGANIZATION",
            "JOIN"
        ):
            return jsonify({
                "error": "Invalid workspace type."
            }), 400

        # -------------------------------------------------
        # Validate approval count
        # -------------------------------------------------

        try:
            required_approvals = int(required_approvals)
        except (TypeError, ValueError):
            return jsonify({
                "error": "Required approvals must be an integer."
            }), 400

        if required_approvals < 1:
            return jsonify({
                "error": "Required approvals must be at least 1."
            }), 400

        # -------------------------------------------------
        # Validate organization fields
        # -------------------------------------------------

        if workspace_type == "ORGANIZATION":
            if not organization_name or not organization_name.strip():
                return jsonify({
                    "error": "Organization name is required."
                }), 400

            # The creator is initially the only eligible
            # deletion approver.
            #
            # Therefore an organization cannot initially
            # require more than 1 approval.
            if required_approvals > 1:
                return jsonify({
                    "error": (
                        "A new organization can initially require "
                        "only 1 approval because the owner is the "
                        "only eligible approver."
                    )
                }), 400

        # -------------------------------------------------
        # Validate invitation
        # -------------------------------------------------

        invitation = None

        if workspace_type == "JOIN":
            if not invitation_code or not invitation_code.strip():
                return jsonify({
                    "error": "Invitation code is required."
                }), 400

            invitation_code = invitation_code.strip()

        # -------------------------------------------------
        # Create user
        # -------------------------------------------------

        user = register_user(
            username,
            email,
            password
        )

        try:
            # -------------------------------------------------
            # PERSONAL WORKSPACE
            # -------------------------------------------------

            if workspace_type == "PERSONAL":

                workspace = create_personal_workspace(user)

                workspace_info = workspace.to_dict()

            # -------------------------------------------------
            # ORGANIZATION WORKSPACE
            # -------------------------------------------------

            elif workspace_type == "ORGANIZATION":

                workspace = create_organization(
                    user=user,
                    name=organization_name,
                    required_approvals=required_approvals,
                    approval_delay_hours=24
                )

                workspace_info = workspace.to_dict()

            # -------------------------------------------------
            # JOIN ORGANIZATION
            # -------------------------------------------------

            else:

                invitation = get_invitation_by_code(
                    invitation_code
                )

                if user.email.lower() != invitation.invited_email.lower():
                    raise PermissionError(
                        "This invitation was issued for a different email address."
                    )

                membership = accept_invitation(
                    invitation_code,
                    user
                )

                workspace = membership.workspace
                workspace_info = workspace.to_dict()

        except Exception:
            # User was created by register_user().
            # Remove the user if workspace setup fails so
            # registration does not leave a half-created account.
            db.session.rollback()

            try:
                db.session.delete(user)
                db.session.commit()
            except Exception:
                db.session.rollback()

            raise
        # -------------------------------------------------
        # Commit complete registration transaction
        # -------------------------------------------------

        db.session.commit()
        # -------------------------------------------------
        # Create JWT
        # -------------------------------------------------

        access_token = create_access_token(user)

        return jsonify({
            "message": "User registered successfully.",
            "access_token": access_token,
            "token_type": "Bearer",
            "user": user.to_dict(),
            "workspace": workspace_info
        }), 201

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


@auth_bp.post("/login")
def login():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "error": "JSON request body is required."
            }), 400

        email = data.get("email")
        password = data.get("password")

        user = authenticate_user(
            email,
            password
        )

        access_token = create_access_token(user)

        return jsonify({
            "message": "Login successful.",
            "access_token": access_token,
            "token_type": "Bearer",
            "user": user.to_dict()
        }), 200

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 401

    except Exception:
        return jsonify({
            "error": "Internal server error."
        }), 500


@auth_bp.get("/me")
@auth_required
def me():
    return jsonify({
        "user": g.current_user.to_dict()
    }), 200
