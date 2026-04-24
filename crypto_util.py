"""
AES-CBC helpers aligned with common socket tutorials (PyCryptodome),
but with a random 16-byte IV per message and PKCS7 padding (any length).
Wire format: 4-byte big-endian length N, then N bytes = IV (16) + ciphertext.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY_SIZE = 32  # AES-256
IV_SIZE = 16
HEADER_STRUCT = struct.Struct("!I")  # unsigned 32-bit length prefix


def key_from_psk(psk: str) -> bytes:
    """Derive a 32-byte AES key from a passphrase (both sides must use the same PSK)."""
    return hashlib.sha256(psk.encode("utf-8")).digest()


def encrypt_message(key: bytes, plaintext: str) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes (AES-256).")
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    body = iv + cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return HEADER_STRUCT.pack(len(body)) + body


def decrypt_message(key: bytes, frame: bytes) -> str:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes (AES-256).")
    if len(frame) < HEADER_STRUCT.size + IV_SIZE:
        raise ValueError("Frame too short.")
    (body_len,) = HEADER_STRUCT.unpack_from(frame, 0)
    body = frame[HEADER_STRUCT.size : HEADER_STRUCT.size + body_len]
    if len(body) < IV_SIZE or len(body) != body_len:
        raise ValueError("Invalid body length.")
    iv, ct = body[:IV_SIZE], body[IV_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")


def read_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading.")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock) -> bytes:
    header = read_exact(sock, HEADER_STRUCT.size)
    (body_len,) = HEADER_STRUCT.unpack(header)
    if body_len > 1_000_000:  # simple sanity bound
        raise ValueError("Frame too large.")
    body = read_exact(sock, body_len)
    return header + body
