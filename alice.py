from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# SETTINGS
# SETTINGS
with open("shared_password.txt", "r") as f:
    password = f.read().strip().encode()

salt = b'secure_salt_1234'
backend = default_backend()


# Derive key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)
key = kdf.derive(password)

# Read iv + ciphertext
with open("bob_to_alice.txt", "rb") as f:
    data = f.read()
    iv = data[:16]
    ciphertext = data[16:]

# Decrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
decryptor = cipher.decryptor()
padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Unpad
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

print("Decrypted message from Bob:")
print(plaintext.decode())

# Optional: Alice replies
reply = input("Enter your reply to Bob: ").encode()

# Pad reply
padder = padding.PKCS7(128).padder()
padded_reply = padder.update(reply) + padder.finalize()

# Encrypt reply with new IV
iv2 = os.urandom(16)
cipher2 = Cipher(algorithms.AES(key), modes.CBC(iv2), backend=backend)
encryptor2 = cipher2.encryptor()
ciphertext2 = encryptor2.update(padded_reply) + encryptor2.finalize()

# Save to file
with open("alice_to_bob.txt", "wb") as f:
    f.write(iv2 + ciphertext2)

print("Reply encrypted and saved to alice_to_bob.txt")
