from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# SETTINGS
# SETTINGS
from cryptography.hazmat.backends import default_backend

with open("shared_password.txt", "r") as f:
    password = f.read().strip().encode()

salt = b'secure_salt_1234'
backend = default_backend()



# Derive key using PBKDF2
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)
key = kdf.derive(password)

# Message
plaintext = input("Enter your message to Alice: ").encode()

# Padding (for AES block size of 128 bits)
padder = padding.PKCS7(128).padder()
padded_data = padder.update(plaintext) + padder.finalize()

# Encryption
iv = os.urandom(16)  # AES block size IV
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

# Save iv + ciphertext to file
with open("bob_to_alice.txt", "wb") as f:
    f.write(iv + ciphertext)

print("Message encrypted and saved to bob_to_alice.txt")
print("IV:", base64.b64encode(iv).decode())
print("Ciphertext:", base64.b64encode(ciphertext).decode())
