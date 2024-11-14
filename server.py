import socket
import crypto_utils as cu
from Crypto.Random import get_random_bytes
import database_utils as db

HOST = '127.0.0.1'
PORT = 12345
password = "Cabc"  # Shared password

def handle_client(client_socket):
    salt = get_random_bytes(16)
    client_socket.sendall(salt)
    print(f"Sent salt: {salt.hex()}")
    key = cu.derive_key(password, salt)
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break 

            Integrity, username, message, username1, message1, iv = cu.break_message(encrypted_message, key)

            if(not Integrity):
                print(f"Received message is tampered")
                response = "Message Tampered!"
                encrypted_message = cu.server_response(response, key)
                client_socket.sendall(encrypted_message)
                continue
            else:
                print(f"Received message: {message1} && user is {username1}")
                response = "Message received!"
                encrypted_message = cu.server_response(response, key)
                client_socket.sendall(encrypted_message)
                db.store_message(username, message, iv)

        except Exception as e:
            print("Error in message handling:", e)
            break

    client_socket.close()
    print("Client disconnected")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[NEW CONNECTION] {client_address} connected.")
        handle_client(client_socket)

if __name__ == "__main__":
    db.setup_database()
    start_server()