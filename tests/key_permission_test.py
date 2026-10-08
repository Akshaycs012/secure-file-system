from pathlib import Path
import stat


KEY_PATH = Path("keys/test_secret.key")


print("Checking key file permissions...")

if not KEY_PATH.exists():
    raise FileNotFoundError(
        f"Key file not found: {KEY_PATH}"
    )


mode = KEY_PATH.stat().st_mode

permissions = stat.S_IMODE(mode)

print(f"Permission mode: {oct(permissions)}")


if permissions == 0o600:
    print("Key permissions are secure: SUCCESS")
else:
    print("ERROR: Key permissions are insecure!")