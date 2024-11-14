from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), 
        length=16,  # AES-128 key length (16 bytes)
        salt=salt, 
        iterations=100000, 
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Padding function
def pad(data: str) -> bytes:
    pad_length = AES.block_size - (len(data) % AES.block_size)
    padding = chr(pad_length) * pad_length
    return (data + padding).encode()  # Ensure output is in bytes

# Unpadding function
def unpad(data: bytes) -> bytes:
    pad_length = data[-1]
    return data[:-pad_length]

# AES encryption function
def aes_encrypt(plaintext: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)    
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# AES decryption function
def aes_decrypt(iv: bytes, key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext)
    return plaintext

# Break down encoded message
def break_message(encoded_message: bytes):
    return [
        encoded_message[:AES.block_size], 
        encoded_message[AES.block_size:2 * AES.block_size], 
        encoded_message[2 * AES.block_size:]
    ]

# Create final encrypted message
def final_message(username: str, plain_message: str, key: bytes) -> bytes:
    username0 = pad(username)  # Padded username in bytes
    message0 = pad(plain_message)  # Padded message in bytes
    iv = get_random_bytes(AES.block_size)
    final_message_encrypt = (
        iv + aes_encrypt(username0, iv, key) + aes_encrypt(message0, iv, key)
    )
    return final_message_encrypt

# Test the encryption
def test():
    password = "my_password"
    salt = b"example_salt"
    username = "Alice"
    message = "This is a secure message."
    key = derive_key(password, salt)
    encrypted_message = final_message(username, message, key)
    print(encrypted_message)
    iv , get_user, get_message = break_message(encrypted_message)
    user0 = aes_decrypt(iv, key, get_user)
    message0 = aes_decrypt(iv, key, get_message)
    print(user0)
    print(message0)
# test()