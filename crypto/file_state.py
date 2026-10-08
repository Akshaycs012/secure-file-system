from pathlib import Path

from crypto.worm import is_protected
from crypto.integrity import verify_file_integrity


def get_file_state(file_path):
    """
    Determine the security state of an encrypted file.
    """

    file_path = Path(file_path)

    # -----------------------------------------
    # Step 1: Check whether file exists
    # -----------------------------------------

    if not file_path.exists():
        return "NOT_FOUND"

    # -----------------------------------------
    # Step 2: Check whether it is a regular file
    # -----------------------------------------

    if not file_path.is_file():
        return "INVALID"

    # -----------------------------------------
    # Step 3: Check SHA-256 integrity
    # -----------------------------------------

    try:

        verify_file_integrity(file_path)

        integrity_valid = True

    except (ValueError, FileNotFoundError):

        integrity_valid = False

    # -----------------------------------------
    # Step 4: Check WORM protection
    # -----------------------------------------

    try:

        worm_protected = is_protected(file_path)

    except (ValueError, FileNotFoundError):

        worm_protected = False

    # -----------------------------------------
    # Step 5: Determine final state
    # -----------------------------------------

    if integrity_valid and worm_protected:

        return "PROTECTED"

    if integrity_valid and not worm_protected:

        return "VERIFIED"

    if not integrity_valid and worm_protected:

        return "TAMPERED"

    return "UNVERIFIED"

