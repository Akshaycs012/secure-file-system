from flask import Blueprint, jsonify, request, g

from database.db import db

from api.services.auth_middleware import auth_required

from api.services.deletion_service import (
    create_deletion_request,
    approve_deletion_request,
    reject_deletion_request,
    execute_deletion_request,
    get_deletion_request_for_user,
    list_user_deletion_requests,
)


deletion_bp = Blueprint(
    "deletion",
    __name__,
    url_prefix="/api/deletion-requests"
)


# ============================================================
# CREATE DELETION REQUEST
# ============================================================

@deletion_bp.post("/files/<file_id>")
@auth_required
def request_file_deletion(file_id):

    try:
        data = request.get_json(silent=True) or {}

        workspace_id = data.get("workspace_id")

        if not workspace_id:
            return jsonify({
                "error": "Workspace ID is required."
            }), 400

        result = create_deletion_request(
            file_id=file_id,
            workspace_id=workspace_id,
            requester_id=g.current_user.id
        )

        db.session.commit()

        # ----------------------------------------------------
        # PERSONAL WORKSPACE
        # ----------------------------------------------------

        if result["type"] == "IMMEDIATE":
            return jsonify({
                "message": result["message"],
                "type": result["type"]
            }), 200

        # ----------------------------------------------------
        # ORGANIZATION WORKSPACE
        # ----------------------------------------------------

        deletion_request = result["request"]

        return jsonify({
            "message": result["message"],
            "type": result["type"],
            "request": deletion_request.to_dict()
        }), 201

    except PermissionError as error:
        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 403

    except FileNotFoundError as error:
        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 404

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
# LIST DELETION REQUESTS
# ============================================================

@deletion_bp.get("")
@auth_required
def list_deletion_requests():

    try:
        deletion_requests = list_user_deletion_requests(
            g.current_user.id
        )

        return jsonify({
            "count": len(deletion_requests),
            "requests": [
                item.to_dict()
                for item in deletion_requests
            ]
        }), 200

    except Exception:
        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# GET DELETION REQUEST
# ============================================================

@deletion_bp.get("/<request_id>")
@auth_required
def get_deletion_request(request_id):

    try:
        deletion_request = get_deletion_request_for_user(
            request_id=request_id,
            user_id=g.current_user.id
        )

        return jsonify({
            "request": deletion_request.to_dict()
        }), 200

    except PermissionError as error:

        return jsonify({
            "error": str(error)
        }), 403

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 404

    except Exception:

        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# APPROVE DELETION REQUEST
# ============================================================

@deletion_bp.post("/<request_id>/approve")
@auth_required
def approve_request(request_id):

    try:
        data = request.get_json(silent=True) or {}

        comment = data.get("comment")

        deletion_request = approve_deletion_request(
            request_id=request_id,
            approver_id=g.current_user.id,
            comment=comment
        )

        db.session.commit()

        return jsonify({
            "message": "Deletion request approved.",
            "request": deletion_request.to_dict()
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
# REJECT DELETION REQUEST
# ============================================================

@deletion_bp.post("/<request_id>/reject")
@auth_required
def reject_request(request_id):

    try:
        data = request.get_json(silent=True) or {}

        comment = data.get("comment")

        deletion_request = reject_deletion_request(
            request_id=request_id,
            approver_id=g.current_user.id,
            comment=comment
        )

        db.session.commit()

        return jsonify({
            "message": "Deletion request rejected.",
            "request": deletion_request.to_dict()
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
# EXECUTE DELETION REQUEST
# ============================================================

@deletion_bp.post("/<request_id>/execute")
@auth_required
def execute_request(request_id):

    try:
        deletion_request = execute_deletion_request(
            request_id=request_id,
            executor_id=g.current_user.id
        )

        db.session.commit()

        return jsonify({
            "message": "Deletion request executed successfully.",
            "request": deletion_request.to_dict()
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

    except FileNotFoundError as error:
        db.session.rollback()

        return jsonify({
            "error": str(error)
        }), 404

    except Exception:
        db.session.rollback()

        return jsonify({
            "error": "Failed to execute deletion request."
        }), 500