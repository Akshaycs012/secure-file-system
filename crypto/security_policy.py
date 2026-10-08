from crypto.file_state import get_file_state


def can_decrypt(file_path):
    """
    Determine whether an encrypted file is safe to decrypt.
    """

    state = get_file_state(file_path)

    if state == "PROTECTED":
        return True

    return False