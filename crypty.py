from Crypto.Cipher import AES
import base64

CRYPT = b'\xde\x89<\xee\x94\xfb\xd1\x96\xed\x12#V\xf7.\x98\x18\xae\xa66\x1e{\xf1d\xeaa\x9d\xa4o]`\x96\x06'


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


if __name__ == "__main__":
    from Crypto.Random import get_random_bytes
    print(f'# randomly generated key')
    print(f'CRYPT = {get_random_bytes(32)}')
