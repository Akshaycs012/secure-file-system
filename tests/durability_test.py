from pathlib import Path

from crypto.durability import (
    fsync_file,
    fsync_directory
)


TEST_DIR = Path("data/durability_test")
TEST_FILE = TEST_DIR / "test.txt"


def main():
    TEST_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    TEST_FILE.write_text(
        "Durability test",
        encoding="utf-8"
    )

    fsync_file(TEST_FILE)

    print("✓ File fsync successful")

    fsync_directory(TEST_DIR)

    print("✓ Directory fsync successful")

    TEST_FILE.unlink()
    TEST_DIR.rmdir()

    print("Durability test: PASSED")


if __name__ == "__main__":
    main()