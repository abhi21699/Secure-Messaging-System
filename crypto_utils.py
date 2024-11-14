from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import hmac

def generate_hmac(message: bytes, key: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_hmac(message: bytes, received_hmac: bytes, key: bytes) -> bool:
    computed_hmac = generate_hmac(message, key)
    return hmac.compare_digest(computed_hmac, received_hmac)

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

def break_message(encoded_message: bytes, key):
    
    iv = encoded_message[:AES.block_size]  # Corrected: now `iv` is 16 bytes, not a tuple
    hash_user = encoded_message[AES.block_size: 3 * AES.block_size]
    hash_message = encoded_message[3 * AES.block_size : 5 * AES.block_size]
    username = encoded_message[5 * AES.block_size : 6 * AES.block_size]
    message = encoded_message[6 * AES.block_size:]
    username1 = aes_decrypt(iv, key, username)
    message1 = aes_decrypt(iv, key, message)
    cnd = verify_hmac(message1, hash_message, key) and verify_hmac(username1, hash_user, key)
    return [
        cnd,
        username,
        message,
        username1,
        message1,
        iv
    ]

def final_message(username: str, plain_message: str, key: bytes) -> bytes:
    username0 = pad(username)  # Padded username in bytes
    hash_username0 = generate_hmac(username.encode(), key) #Hashing for original username. 

    message0 = pad(plain_message)  # Padded message in bytes
    hash_message0 = generate_hmac(plain_message.encode(), key) #hashing for original message.

    iv = get_random_bytes(AES.block_size)

    final_message_encrypt = (
        iv + hash_username0 + hash_message0 +  aes_encrypt(username0, iv, key) + aes_encrypt(message0, iv, key)
    )

    return final_message_encrypt

def server_response(response, key):
    response0 = pad(response)
    hash_response0 = generate_hmac(response.encode(), key)
    iv = get_random_bytes(AES.block_size)
    final_message_encrypt = (
        iv + hash_response0 + aes_encrypt(response0, iv, key)
    )
    return final_message_encrypt

def break_client(response, key):
    iv = response[:AES.block_size]
    hash_response0 = response[AES.block_size: 3 * AES.block_size]  
    decrypt_response = aes_decrypt(iv, key, response[3 * AES.block_size: ])
    cnd = verify_hmac(decrypt_response, hash_response0, key)
    if (cnd):
        print(f"The response from server is {decrypt_response}")
    else:
        print(f"Message tampered at large scale")