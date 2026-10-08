from crypto.worm import (
    protect_file,
    unprotect_file,
    is_protected
)


TEST_FILE = "data/worm_test.enc"


# -----------------------------------
# 1. Create test file
# -----------------------------------

with open(TEST_FILE, "w") as file:
    file.write("WORM test file")

print("Initial protection:", is_protected(TEST_FILE))


# -----------------------------------
# 2. Protect the file
# -----------------------------------

print("\nProtecting file...")

protect_file(TEST_FILE)

print("Protection status:", is_protected(TEST_FILE))


# -----------------------------------
# 3. Try modifying the file
# -----------------------------------

print("\nTrying to modify protected file...")

try:
    with open(TEST_FILE, "w") as file:
        file.write("ATTACK")

    print("ERROR: File was modified!")

except PermissionError:
    print("Modification blocked: SUCCESS")


# -----------------------------------
# 4. Try deleting the file
# -----------------------------------

print("\nTrying to delete protected file...")

try:
    import os

    os.remove(TEST_FILE)

    print("ERROR: File was deleted!")

except PermissionError:
    print("Deletion blocked: SUCCESS")


# -----------------------------------
# 5. Remove protection
# -----------------------------------

print("\nRemoving protection...")

unprotect_file(TEST_FILE)

print("Protection status:", is_protected(TEST_FILE))


# -----------------------------------
# 6. Delete after unprotecting
# -----------------------------------

print("\nDeleting after removing protection...")

import os

os.remove(TEST_FILE)

print("Deletion successful: SUCCESS")