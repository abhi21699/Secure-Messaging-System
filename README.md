# Cryptographic Secure Messaging System using AES

## Introduction and Motivation

This project implements a secure messaging system using cryptographic principles inspired by real-world applications like WhatsApp and Signal, which utilize end-to-end encryption (E2E) to ensure message confidentiality and privacy. This system’s design focuses on fundamental security requirements such as confidentiality, integrity, and freshness of data, providing a hands-on approach to building secure communications.

The primary security objectives include:
- **Confidentiality**: Ensuring that only the intended recipient can access the message content.
- **Integrity**: Protecting messages against tampering to confirm the content remains unaltered.
- **Message Freshness and Replay Prevention**: Using unique Initialization Vectors (IV) for each message to avoid replay attacks.
- **Username Privacy**: Encrypting usernames to maintain user identity confidentiality.

## Cryptographic Design Components

1. **Password-Derived Encryption Key**  
   The system derives a strong encryption key from a shared password using a password-based key derivation function (PBKDF2). This ensures that only users with the correct password can participate in the secure communication.

2. **AES Encryption with Random IV for Confidentiality**  
   AES encryption is used in Cipher Block Chaining (CBC) mode, with each message employing a unique 16-byte IV. This ensures that identical messages produce distinct encrypted outputs, maintaining message confidentiality and preventing recognizable patterns.

3. **Integrity and Replay Attack Prevention**  
   To mitigate replay attacks, each message is encrypted with a unique, random 16-byte IV, making it impossible for attackers to reuse intercepted messages.

4. **Socket-Based Client-Server Communication**  
   The server operates continuously, listening for client connections over a fixed IP address and port. This allows clients to securely send messages to the server, which functions similarly to a real-world messaging server.

5. **Database Storage for Encrypted Messages**  
   Messages are securely stored in an SQLite database, with both the username and message content encrypted. This approach safeguards user privacy and message confidentiality over time.

## Implementation Details

1. **Encrypting the Username for Privacy**  
   Usernames are limited to 16 bytes and are encrypted separately from the message. The server combines the encrypted username and message before storing them, ensuring both are protected.

2. **Database and Networking**  
   The server stores each encrypted message, username, and IV in the database, which is timestamped for tracking. This structure allows for easy message retrieval and secure record-keeping.

## Running the Application
0. **Run: pip install cryptography** 
1. **Start the Server**  
   Run the server.py file , which will continuously listen for incoming connections and messages.

2. **Client Connection**  
   Run client.py. The client connects to the server using the shared password and initiates secure communication.

3. **Message Transmission and Storage**  
   Encrypted messages are transmitted to the server, which decrypts each message for verification and securely logs it in the database.

## Conclusion

This project builds foundational skills in cryptographic implementations and secure messaging, with practical applications for real-world privacy-focused systems. The system achieves essential security principles of confidentiality, integrity, and freshness, with replay prevention for secure messaging.
