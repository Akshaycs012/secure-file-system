import subprocess
from pathlib import Path


def _validate_file(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if path.is_symlink():
        raise ValueError(
            "Symlinks are not allowed."
        )

    if not path.is_file():
        raise ValueError(
            f"Not a regular file: {file_path}"
        )

    return path


def protect_file(file_path):
    path = _validate_file(file_path)

    result = subprocess.run(
        [
            "sudo",
            "-n",
            "chattr",
            "+i",
            str(path)
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        error_message = result.stderr.strip()

        if not error_message:
            error_message = (
                "chattr failed without an error message."
            )

        raise RuntimeError(
            f"WORM protection failed for {path}: "
            f"{error_message}"
        )

    return True


def unprotect_file(file_path):
    path = _validate_file(file_path)

    result = subprocess.run(
        [
            "sudo",
            "-n",
            "chattr",
            "-i",
            str(path)
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        error_message = result.stderr.strip()

        if not error_message:
            error_message = (
                "chattr failed without an error message."
            )

        raise RuntimeError(
            f"WORM unprotection failed for {path}: "
            f"{error_message}"
        )

    return True


def is_protected(file_path):
    path = _validate_file(file_path)

    result = subprocess.run(
        ["lsattr", str(path)],
        capture_output=True,
        text=True,
        check=True
    )

    attributes = result.stdout.split()[0]

    return "i" in attributes