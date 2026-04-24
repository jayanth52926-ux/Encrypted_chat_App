# Encrypted_chat_App
How the Encrypted chat apps (like Signal, WhatsApp, and Session) use end-to-end encryption (E2EE) to ensure only the sender and recipient can read messages, protecting data from hackers, service providers, and governments. These apps provide privacy by storing encryption keys solely on user devices, rather than central servers.

# Simple encrypted chat application
This project is a **simple encrypted chat application** built in Python using a **client-server model**. It allows multiple users to connect to one server and exchange messages securely over TCP sockets. The main goal is to make sure messages are not sent as plain text on the network.

The project has three core files: `server.py`, `client.py`, and `crypto_util.py` (plus `requirements.txt` for dependency setup).  
`server.py` starts a TCP server, listens for connections, and handles multiple clients using threads.  
`client.py` connects to the server and lets a user send/receive chat messages.  
`crypto_util.py` contains the encryption/decryption logic shared by both sides.

# Security
Security is implemented with **AES-256 in CBC mode** using PyCryptodome. A pre-shared passphrase (PSK) is entered on both server and client, and then converted into a fixed 32-byte key using SHA-256. This means both sides independently generate the same encryption key without sending it over the network.

For each message, the client creates a **new random IV (Initialization Vector)** of 16 bytes. This is very important because CBC mode should not reuse IVs. The message is padded using PKCS7, encrypted, and then sent in a framed format:
**4-byte length header + IV + ciphertext**.

On receive, the other side reads the frame, extracts IV and ciphertext, decrypts the message, removes padding, and prints plain text. If the key is wrong or data is corrupted, decryption fails safely.

The server supports **basic concurrency**: every connected client runs in its own thread. When one client sends a message, the server decrypts it (for logging/verification), logs it to `chat_server.log`, and then broadcasts the encrypted frame to the other clients.

# Project Demonstrates
So overall, this project demonstrates:
- TCP socket communication
- Symmetric encryption with AES
- Safe IV handling
- Pre-shared key usage
- Multi-client threaded handling
- Message logging on the server

It is intentionally simple and educational, but it follows better practices than fixed-IV examples: random IV per message, framing, and handling variable message lengths. In short, it is a beginner-friendly secure chat prototype that teaches networking plus cryptography fundamentals in one small project.


# Commands
1. cd - create a directory
   
2. python3 -m pip install -r requirements.txt
   
    * Installs required Python packages listed in requirements.txt.
    * In this project, it installs pycryptodome (AES encryption library).
      
3. python3 server.py --host --port --psk "my_shared_secret"
   Starts chat server:
   --host: listen on all network interfaces.
   --port: server runs on TCP port.
   --psk "my_shared_secret": pre-shared secret used to derive AES key.
Server accepts multiple clients, decrypts/logs messages, and relays encrypted data.

4. python3 client.py --host (1) --port --psk "my_shared_secret".
   Starts one chat client.
   --host: connect to server on same machine (localhost).
   --port: must match server port.
   --psk "my_shared_secret": must match server PSK exactly.
Type messages; client encrypts before sending and decrypts received messages.

5. python3 client.py --host --port --psk "my_shared_secret".
   * Run this in another terminal for second user/client.
   * Lets you test real multi-client chat.
  
6. python3 -c "print(open('chat_server.log').read())".
   * Opens and prints full server log file.
   * Useful to verify that server received/decrypted messages and tracked client events.

7. kill -9 $(lsof -ti : (port number)
   * Finds process ID using port and force kills it.
   * Use only if server fails with “Address already in use”.
   * lsof -ti : port gives PID; kill -9 terminates it immediately.

# Important Info
  For chat to work:
       * same --port on server and all clients.
       * same --psk on server and all clients.

# For Decryption

Already we have created the command check for the file `test decrypt.py`
 * python3 -c "from crypto_util import key_from_psk, encrypt_message, decrypt_message; k=key_from_psk('my_shared_secret'); f=encrypt_message(k,'hello'); print(decrypt_message(k,f))"
