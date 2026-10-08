import os
from pathlib import Path


def fsync_file(file_path):
    """
    Flush file contents and metadata to stable storage.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if file_path.is_symlink():
        raise ValueError(
            f"Refusing to fsync symbolic link: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Not a regular file: {file_path}"
        )

    with open(file_path, "rb") as file:
        os.fsync(file.fileno())


def fsync_directory(directory_path):
    """
    Flush directory metadata so operations such as
    atomic rename become durable.
    """
    directory_path = Path(directory_path)

    if not directory_path.exists():
        raise FileNotFoundError(
            f"Directory not found: {directory_path}"
        )

    if not directory_path.is_dir():
        raise ValueError(
            f"Not a directory: {directory_path}"
        )

    directory_fd = os.open(
        directory_path,
        os.O_RDONLY
    )

    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)