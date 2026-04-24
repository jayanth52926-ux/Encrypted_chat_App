# Encrypted_chat_App
How the Encrypted chat apps (like Signal, WhatsApp, and Session) use end-to-end encryption (E2EE) to ensure only the sender and recipient can read messages, protecting data from hackers, service providers, and governments. These apps provide privacy by storing encryption keys solely on user devices, rather than central servers.

# simple encrypted chat application
This project is a **simple encrypted chat application** built in Python using a **client-server model**. It allows multiple users to connect to one server and exchange messages securely over TCP sockets. The main goal is to make sure messages are not sent as plain text on the network.

The project has three core files: `server.py`, `client.py`, and `crypto_util.py` (plus `requirements.txt` for dependency setup).  
`server.py` starts a TCP server, listens for connections, and handles multiple clients using threads.  
`client.py` connects to the server and lets a user send/receive chat messages.  
`crypto_util.py` contains the encryption/decryption logic shared by both sides.

Security is implemented with **AES-256 in CBC mode** using PyCryptodome. A pre-shared passphrase (PSK) is entered on both server and client, and then converted into a fixed 32-byte key using SHA-256. This means both sides independently generate the same encryption key without sending it over the network.

For each message, the client creates a **new random IV (Initialization Vector)** of 16 bytes. This is very important because CBC mode should not reuse IVs. The message is padded using PKCS7, encrypted, and then sent in a framed format:
**4-byte length header + IV + ciphertext**.

On receive, the other side reads the frame, extracts IV and ciphertext, decrypts the message, removes padding, and prints plain text. If the key is wrong or data is corrupted, decryption fails safely.

The server supports **basic concurrency**: every connected client runs in its own thread. When one client sends a message, the server decrypts it (for logging/verification), logs it to `chat_server.log`, and then broadcasts the encrypted frame to the other clients.

So overall, this project demonstrates:
- TCP socket communication
- Symmetric encryption with AES
- Safe IV handling
- Pre-shared key usage
- Multi-client threaded handling
- Message logging on the server

It is intentionally simple and educational, but it follows better practices than fixed-IV examples: random IV per message, framing, and handling variable message lengths. In short, it is a beginner-friendly secure chat prototype that teaches networking plus cryptography fundamentals in one small project.
