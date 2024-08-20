import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

CRYPT_KEY_FILE = os.path.expanduser("~/.ftpsync.rand")


def load_key():
    """Loads the encryption key from the external file."""
    if os.path.exists(CRYPT_KEY_FILE):
        with open(CRYPT_KEY_FILE, "rb") as f:
            return f.read()
    else:
        # Generate a new key and save it to the file
        key = get_random_bytes(32)
        with open(CRYPT_KEY_FILE, "wb") as f:
            f.write(key)
        # Set permissions to 400 (read-only for owner)
        os.chmod(CRYPT_KEY_FILE, 0o400)
        return key


CRYPT = load_key()


def encrypt(password, key=CRYPT):
    """Encrypts the given password using the provided key."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_password = password.ljust(32)  # Pad password to 32 bytes (AES block size)
    encrypted_password = cipher.encrypt(padded_password.encode('utf-8'))
    return base64.b64encode(encrypted_password).decode('utf-8')


def decrypt(encrypted_password, key=CRYPT):
    """Decrypts the given encrypted password using the provided key."""
    encrypted_password = base64.b64decode(encrypted_password)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_password = cipher.decrypt(encrypted_password).decode('utf-8')
    return decrypted_password.strip()  # Remove padding
