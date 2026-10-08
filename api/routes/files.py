import tempfile
from pathlib import Path

from flask import (
    Blueprint,
    jsonify,
    request,
    send_file,
    g,
    after_this_request
)

from api.services.file_service import (
    encrypt_uploaded_file,
    list_files,
    verify_file_by_id,
    decrypt_stored_file_by_id,
    delete_file_by_id
)

from api.services.auth_middleware import auth_required
from api.services.workspace_service import require_workspace_membership


files_bp = Blueprint(
    "files",
    __name__,
    url_prefix="/api/files"
)


# ============================================================
# WORKSPACE HELPER
# ============================================================

def get_workspace_id():
    """
    Get workspace_id from the request.

    The client provides the workspace ID, but membership
    is always verified against the authenticated user.
    """

    workspace_id = (
        request.args.get("workspace_id")
        or request.form.get("workspace_id")
    )

    if not workspace_id:
        data = request.get_json(silent=True) or {}
        workspace_id = data.get("workspace_id")

    if not workspace_id:
        raise ValueError("Workspace ID is required.")

    # IMPORTANT:
    # Never trust workspace_id by itself.
    # Verify that the authenticated user belongs
    # to this workspace.
    require_workspace_membership(
        workspace_id,
        g.current_user.id
    )

    return workspace_id


# ============================================================
# UPLOAD
# ============================================================

@files_bp.post("/upload")
@auth_required
def upload_file():
    try:

        # Verify workspace membership first.
        workspace_id = get_workspace_id()

        if "file" not in request.files:
            return jsonify({
                "error": "No file provided."
            }), 400

        uploaded_file = request.files["file"]

        if uploaded_file.filename == "":
            return jsonify({
                "error": "Filename is required."
            }), 400

        filename = Path(
            uploaded_file.filename
        ).name

        if not filename:
            return jsonify({
                "error": "Invalid filename."
            }), 400

        # Store upload temporarily before encryption.
        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temporary_file:

            uploaded_file.save(
                temporary_file.name
            )

            temporary_path = Path(
                temporary_file.name
            )

        try:

            file_record = encrypt_uploaded_file(
                temporary_path,
                filename,
                g.current_user.id,
                workspace_id
            )

        finally:

            # Remove temporary plaintext.
            temporary_path.unlink(
                missing_ok=True
            )

        return jsonify({
            "message": "File encrypted successfully.",
            "file": file_record.to_dict()
        }), 201

    except PermissionError as error:
        return jsonify({
            "error": str(error)
        }), 403

    except FileExistsError as error:
        return jsonify({
            "error": str(error)
        }), 409

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# LIST WORKSPACE FILES
# ============================================================

@files_bp.get("")
@auth_required
def get_files():
    try:

        workspace_id = get_workspace_id()

        files = list_files(
            workspace_id
        )

        return jsonify({
            "count": len(files),
            "workspace_id": workspace_id,
            "files": files
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


# ============================================================
# CHECK FILE INTEGRITY
# ============================================================

@files_bp.get("/id/<file_id>/integrity")
@auth_required
def check_integrity_by_id(file_id):
    try:

        workspace_id = get_workspace_id()

        file_record = verify_file_by_id(
            file_id,
            workspace_id
        )

        return jsonify({
            "id": file_record.id,
            "filename": file_record.original_name,
            "workspace_id": workspace_id,
            "integrity": "VALID"
        }), 200

    except PermissionError as error:
        return jsonify({
            "error": str(error)
        }), 403

    except FileNotFoundError as error:
        return jsonify({
            "error": str(error)
        }), 404

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# DOWNLOAD FILE
# ============================================================

@files_bp.get("/id/<file_id>/download")
@auth_required
def download_file_by_id(file_id):
    try:

        workspace_id = get_workspace_id()

        file_record, decrypted_path = (
            decrypt_stored_file_by_id(
                file_id,
                workspace_id
            )
        )

        # Delete plaintext after response processing.
        @after_this_request
        def cleanup_decrypted_file(response):
            try:
                decrypted_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

            return response

        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=file_record.original_name
        )

    except PermissionError as error:
        return jsonify({
            "error": str(error)
        }), 403

    except FileNotFoundError as error:
        return jsonify({
            "error": str(error)
        }), 404

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        return jsonify({
            "error": "Internal server error."
        }), 500


# ============================================================
# DELETE FILE
# ============================================================

@files_bp.delete("/id/<file_id>")
@auth_required
def delete_file(file_id):
    try:

        workspace_id = get_workspace_id()

        delete_file_by_id(
            file_id,
            workspace_id,
            g.current_user.id
        )

        return jsonify({
            "message": "File deleted successfully.",
            "id": file_id,
            "workspace_id": workspace_id
        }), 200

    except PermissionError as error:
        return jsonify({
            "error": str(error)
        }), 403

    except FileNotFoundError as error:
        return jsonify({
            "error": str(error)
        }), 404

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        return jsonify({
            "error": "Internal server error."
        }), 500