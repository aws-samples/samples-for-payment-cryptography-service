"""
Keystore password helper with fallback for headless environments.

Uses the system keyring when available (macOS, desktop Linux with
GNOME Keyring / KWallet). Falls back to the KEYSTORE_PASSWORD
environment variable or an interactive prompt on headless systems.
"""

import getpass
import os
import sys


def _keyring_available():
    """Check if a usable keyring backend is available by doing a real probe."""
    try:
        import keyring
        backend = keyring.get_keyring()
        name = type(backend).__name__
        if "Fail" in name or "fail" in name:
            return False
        # Actually try a read — some backends (e.g. SecretService) look valid
        # but fail at runtime when no D-Bus / secret service daemon is running.
        keyring.get_password("__keyring_probe__", "__probe__")
        return True
    except Exception:
        return False


_USE_KEYRING = _keyring_available()


def get_password(service, username):
    """Retrieve a stored password, falling back to env var or None."""
    if _USE_KEYRING:
        import keyring
        return keyring.get_password(service, username)

    # Fallback: environment variable
    password = os.environ.get("KEYSTORE_PASSWORD")
    if password:
        return password

    return None


def set_password(service, username, password):
    """Store a password in the keyring, or advise the user on headless systems."""
    if _USE_KEYRING:
        import keyring
        keyring.set_password(service, username, password)
        print("✓ Password stored securely in system keyring")
    else:
        print("✓ Password accepted (no system keyring available)")
        print("  Tip: set KEYSTORE_PASSWORD env var to avoid prompts next time")


def get_or_prompt_password(service, username):
    """Get an existing password or prompt for a new one. Returns the password."""
    password = get_password(service, username)

    if password is not None:
        source = "system keyring" if _USE_KEYRING else "KEYSTORE_PASSWORD env var"
        print(f"✓ Retrieved existing password from {source}")
        return password

    # No stored password — prompt interactively
    password = getpass.getpass("Enter keystore password: ")
    set_password(service, username, password)
    return password
