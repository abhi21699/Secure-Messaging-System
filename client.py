import socket
import crypto_utils as cu
import hmac
import hashlib

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
password = "Cabc"  # Shared password

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"Connected to server {SERVER_HOST}:{SERVER_PORT}")
        salt = client_socket.recv(16)  # 16 bytes for the salt
        print(f"Received salt: {salt.hex()}")
        key = cu.derive_key(password, salt)
        while True:
            username = input("Enter Your username : ") 
            message = input("Enter message to send (type 'exit' to close): ")
            if message.lower() == 'exit':
                break
            encrypted_message = cu.final_message(username, message, key)
            client_socket.sendall(encrypted_message)
            response = client_socket.recv(1024)
            cu.break_client(response, key)
    except ConnectionError:
        print("Error connecting to the server.")
    finally:
        client_socket.close()
        print("Disconnected from the server.")

if __name__ == "__main__":
    start_client()