# Cryptographic Secure Messaging System

## Assignment Overview

This project implements a secure client-server messaging application as part of the course **COL759: Cryptography & Computer Security**. The system ensures confidentiality, integrity, and freshness of messages by using AES encryption in CBC mode, a password-based key derivation function, and session-specific salts.

**Prepared By:**
- Abhinav Singh : 2021CS50746
- Pushpraj : 2021CS50596

**Guide:** Prof. Ashok K Bhateja, Department of Computer Science and Engineering, Indian Institute of Technology, Delhi

---

## Project Approach and Code Flow

This project creates a secure end-to-end encrypted messaging environment with four main components:

1. **Client Module**
2. **Cryptographic Utilities Module**
3. **Server Module**
4. **Database Utilities Module**

### 1. Client Module

The client module establishes a connection with the server, derives an encryption key using a shared password, encrypts the user’s messages, and sends them securely.

- **Server Connection**: The client initiates a connection to the server over a specified IP and port.
- **Key Derivation**: Upon connection, the server sends a unique salt to the client. Using this salt and a pre-shared password, the client generates a session-specific encryption key.
- **Encryption and Message Transmission**: The client encrypts the username and message, combines them with an initialization vector (IV), and sends the encrypted payload to the server.
- **Receiving Server Response**: The client waits for a server acknowledgment, confirming that the message was received.

### 2. Cryptographic Utilities Module

This module provides cryptographic functionalities, including key derivation, padding, and AES encryption/decryption.

- **Key Derivation**: Uses PBKDF2 with SHA-256 and the session salt to generate a secure encryption key.
- **Padding and Unpadding**: Ensures plaintext aligns with AES block size requirements.
- **AES Encryption and Decryption**: Encrypts and decrypts data in CBC mode with a generated IV for confidentiality.
- **Message Assembly**: Combines encrypted username and message with an IV into a single payload for transmission.

### 3. Server Module

The server module listens for client connections, securely processes received messages, and stores them in a database.

- **Server Setup**: Initializes a network socket to listen for incoming client connections.
- **Handling Client Connections**: For each client, the server generates a unique salt, sends it to the client, and derives a session-specific encryption key.
- **Message Reception and Decryption**: Receives and decrypts the encrypted username and message. The server parses the received data, separates the IV, and retrieves the original plaintext.
- **Database Storage and Response**: Logs each encrypted message with the encrypted username, IV, and a timestamp in the database. The server sends an acknowledgment to the client confirming message receipt.

### 4. Database Utilities Module

This module manages the secure storage of encrypted messages in an SQLite database.

- **Database Setup**: Initializes the database and creates a table for storing encrypted messages with fields for usernames, messages, IVs, and timestamps.
- **Message Storage**: Inserts each encrypted message into the database for persistent storage and later retrieval.

### Code Flow Summary

1. **Client Initialization**: The client connects to the server, receives a session-specific salt, derives an encryption key, and prompts the user for a username and message.
2. **Message Encryption**: The client encrypts the username and message, assembles them into an encrypted payload, and sends it to the server.
3. **Server Reception and Decryption**: The server receives, decrypts, and logs the message.
4. **Confirmation**: The server responds to the client, confirming message receipt.

---

## Important Points to Note

- **Security Objectives**: The application fulfills objectives of Confidentiality, Integrity, Message Freshness, Replay Attack Prevention, and Username Privacy.
- **End-to-End Encryption**: The client and server share a pre-defined password to derive a session-specific encryption key, ensuring that only the server can decrypt messages.
- **AES Encryption in CBC Mode**: AES-CBC mode ensures confidentiality, with unique ciphertexts for identical messages due to unique IVs.
- **Replay Attack Prevention**: Unique IVs for each message prevent attackers from replaying intercepted messages.
- **Integrity Verification with HMAC**: HMACs ensure message authenticity, detecting any tampering with the message.
- **Acknowledgment of Messages**: The server acknowledges each message, maintaining message integrity in both directions.
- **Salt Integrity**: The design also verifies the integrity of the session-specific salt to prevent tampering.

This secure messaging system serves as a practical implementation of cryptographic principles in real-world communications, reinforcing the concepts of encryption, secure key derivation, message integrity, and secure storage.
