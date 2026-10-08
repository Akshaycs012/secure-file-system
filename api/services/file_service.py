from pathlib import Path
from uuid import UUID

from crypto.secure_file import secure_encrypt
from crypto.integrity import verify_file_integrity
from crypto.decrypt import decrypt_file
from crypto.hashing import calculate_file_hash
from crypto.file_format import HEADER_SIZE, parse_header
from crypto.worm import unprotect_file, is_protected
from crypto.durability import fsync_directory
from crypto.integrity import load_audit_log

from crypto.audit import (
    DELETE_STARTED,
    DELETE_COMPLETED,
    DELETE_FAILED
)

from database.db import db
from database.models import File


PROJECT_ROOT = Path(__file__).resolve().parents[2]

STORAGE_DIR = PROJECT_ROOT / "data" / "storage"
DECRYPTED_DIR = PROJECT_ROOT / "data" / "decrypted"

AUDIT_FILE = PROJECT_ROOT / "data" / "audit.json"


def initialize_storage():
    """
    Create required storage directories if they do not exist.
    """

    STORAGE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    DECRYPTED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


def validate_filename(filename):
    """
    Validate the original uploaded filename.

    Directory traversal is rejected.
    """

    if not filename:
        raise ValueError("Filename is required.")

    path = Path(filename)

    if path.name != filename:
        raise ValueError("Invalid filename.")

    if filename in {".", ".."}:
        raise ValueError("Invalid filename.")

    return filename


def get_encrypted_path(filename, workspace_id):
    """
    Return the encrypted storage path for a file
    inside its workspace-specific directory.
    """

    filename = validate_filename(filename)

    if not workspace_id:
        raise ValueError("Workspace ID is required.")

    workspace_dir = STORAGE_DIR / workspace_id

    workspace_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    return workspace_dir / f"{filename}.sfs"

def get_key_id_from_encrypted_file(encrypted_path):
    """
    Read the key ID from the encrypted file header.
    """

    with open(encrypted_path, "rb") as file:
        header = file.read(HEADER_SIZE)

    if len(header) != HEADER_SIZE:
        raise ValueError(
            "Encrypted file header is incomplete."
        )

    metadata = parse_header(header)

    return metadata["key_id"].hex()


def encrypt_uploaded_file(
    source_path,
    filename,
    owner_id,
    workspace_id
):
    """
    Encrypt an uploaded file and create its database record.

    owner_id:
        Authenticated user who uploaded the file.

    workspace_id:
        Workspace where the file belongs.
    """

    initialize_storage()

    filename = validate_filename(filename)

    if not workspace_id:
        raise ValueError("Workspace ID is required.")

    output_path = get_encrypted_path(
        filename,
        workspace_id
    )

    
    if output_path.exists():
        raise FileExistsError(
            f"File already exists: {filename}"
        )

    secure_encrypt(
        source_path,
        output_path
    )

    encrypted_size = output_path.stat().st_size

    encrypted_hash = calculate_file_hash(
        output_path
    )

    key_id = get_key_id_from_encrypted_file(
        output_path
    )

    file_record = File(
        owner_id=owner_id,
        workspace_id=workspace_id,
        original_name=filename,
        encrypted_path=str(output_path),
        size=encrypted_size,
        sha256=encrypted_hash,
        key_id=key_id,
        status="PROTECTED"
    )

    try:
        db.session.add(file_record)
        db.session.commit()

    except Exception:
        db.session.rollback()

        # Remove encrypted file if database insertion fails.
        if output_path.exists():
            try:
                if is_protected(output_path):
                    unprotect_file(output_path)

                if output_path.exists():
                    output_path.unlink()

                fsync_directory(
                    output_path.parent
                )

            except Exception:
                pass

        raise

    return file_record


def list_files(workspace_id):
    """
    Return files belonging to a workspace.
    """

    initialize_storage()

    if not workspace_id:
        raise ValueError("Workspace ID is required.")

    records = (
        File.query
        .filter_by(
            workspace_id=workspace_id
        )
        .order_by(File.created_at.desc())
        .all()
    )

    return [
        record.to_dict()
        for record in records
    ]


def get_file_by_id(
    file_id,
    workspace_id
):
    """
    Get a file only if it belongs to the
    specified workspace.
    """

    try:
        UUID(file_id)
    except (ValueError, TypeError):
        raise ValueError("Invalid file ID.")

    if not workspace_id:
        raise ValueError("Workspace ID is required.")

    file_record = (
        File.query
        .filter_by(
            id=file_id,
            workspace_id=workspace_id
        )
        .first()
    )

    if file_record is None:
        raise FileNotFoundError(
            f"File not found: {file_id}"
        )

    return file_record


def verify_file_by_id(
    file_id,
    workspace_id
):
    """
    Verify integrity of a file belonging
    to the specified workspace.
    """

    file_record = get_file_by_id(
        file_id,
        workspace_id
    )

    encrypted_path = Path(
        file_record.encrypted_path
    )

    if not encrypted_path.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: "
            f"{file_record.original_name}"
        )

    verify_file_integrity(
        encrypted_path
    )

    return file_record


def decrypt_stored_file_by_id(
    file_id,
    workspace_id
):
    """
    Decrypt a file belonging to the
    specified workspace.

    The plaintext file is temporary and should
    be deleted by the API layer.
    """

    file_record = get_file_by_id(
        file_id,
        workspace_id
    )

    encrypted_path = Path(
        file_record.encrypted_path
    )

    if not encrypted_path.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: "
            f"{file_record.original_name}"
        )

    initialize_storage()

    output_path = (
        DECRYPTED_DIR /
        file_record.original_name
    )

    decrypt_file(
        encrypted_path,
        output_path
    )

    return file_record, output_path


def delete_file_by_id(
    file_id,
    workspace_id,
    requester_id
):
    """
    Securely delete a file belonging to
    a workspace.

    requester_id is recorded in the audit log.

    Steps:

    1. Verify workspace ownership of file.
    2. Verify encrypted file exists.
    3. Record DELETE_STARTED.
    4. Remove WORM protection.
    5. Delete encrypted file.
    6. Delete database record.
    7. Commit database transaction.
    8. Record DELETE_COMPLETED.
    """

    file_record = get_file_by_id(
        file_id,
        workspace_id
    )

    encrypted_path = Path(
        file_record.encrypted_path
    )

    if not encrypted_path.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: "
            f"{file_record.original_name}"
        )

    audit = load_audit_log()

    transaction_id = audit.create_transaction_id()

    try:

        # --------------------------------------------------
        # 1. DELETE STARTED
        # --------------------------------------------------

        audit.add_event(
            DELETE_STARTED,
            {
                "file_id": file_record.id,
                "workspace_id": workspace_id,
                "requester_id": requester_id,
                "owner_id": file_record.owner_id,
                "original_name": file_record.original_name,
                "encrypted_file": str(encrypted_path)
            },
            transaction_id
        )

        audit.save(AUDIT_FILE)

        # --------------------------------------------------
        # 2. REMOVE WORM PROTECTION
        # --------------------------------------------------

        if is_protected(encrypted_path):
            unprotect_file(encrypted_path)

        if is_protected(encrypted_path):
            raise PermissionError(
                "Unable to remove WORM protection."
            )

        # --------------------------------------------------
        # 3. DELETE ENCRYPTED FILE
        # --------------------------------------------------

        encrypted_path.unlink()

        # Ensure directory metadata is durable.
        fsync_directory(
            encrypted_path.parent
        )

        # --------------------------------------------------
        # 4. DELETE DATABASE RECORD
        # --------------------------------------------------

        db.session.delete(file_record)
        db.session.commit()

        # --------------------------------------------------
        # 5. DELETE COMPLETED
        # --------------------------------------------------

        audit.add_event(
            DELETE_COMPLETED,
            {
                "file_id": file_id,
                "workspace_id": workspace_id,
                "requester_id": requester_id,
                "owner_id": file_record.owner_id,
                "original_name": file_record.original_name,
                "encrypted_file": str(encrypted_path)
            },
            transaction_id
        )

        audit.save(AUDIT_FILE)

        return True

    except Exception as error:

        # Roll back any uncommitted database changes.
        db.session.rollback()

        # Try to record the failed deletion.
        try:

            audit.add_event(
                DELETE_FAILED,
                {
                    "file_id": file_id,
                    "workspace_id": workspace_id,
                    "requester_id": requester_id,
                    "owner_id": file_record.owner_id,
                    "original_name": file_record.original_name,
                    "encrypted_file": str(encrypted_path),
                    "error": str(error)
                },
                transaction_id
            )

            audit.save(AUDIT_FILE)

        except Exception:
            pass

        raise