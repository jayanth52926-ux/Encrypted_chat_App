#!/usr/bin/env python3
"""
TCP chat client: encrypts with AES-CBC (random IV per message) before send; background recv.
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import threading

from crypto_util import decrypt_message, encrypt_message, key_from_psk, recv_frame

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000


def recv_loop(sock: socket.socket, aes_key: bytes) -> None:
    try:
        while True:
            frame = recv_frame(sock)
            try:
                msg = decrypt_message(aes_key, frame)
            except Exception as e:  # noqa: BLE001
                print(f"[decrypt error] {e}", file=sys.stderr)
                continue
            print(f"\rPeer: {msg}\nYou: ", end="", flush=True)
    except (ConnectionError, ValueError, OSError) as e:
        print(f"\n[disconnected] {e}", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser(description="Encrypted chat client (AES-CBC + PSK).")
    p.add_argument("--host", default=os.environ.get("CHAT_HOST", DEFAULT_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get("CHAT_PORT", DEFAULT_PORT)))
    p.add_argument(
        "--psk",
        default=os.environ.get("CHAT_PSK"),
        help="Same passphrase as server (or set CHAT_PSK).",
    )
    args = p.parse_args()
    if not args.psk:
        p.error("Set --psk or CHAT_PSK to match the server.")

    key = key_from_psk(args.psk)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((args.host, args.port))
        t = threading.Thread(target=recv_loop, args=(sock, key), daemon=True)
        t.start()
        print("Connected. Type messages (empty line to quit).")
        while True:
            try:
                line = input("You: ")
            except EOFError:
                break
            if not line.strip():
                break
            try:
                sock.sendall(encrypt_message(key, line))
            except OSError as e:
                print(f"[send failed] {e}", file=sys.stderr)
                break


if __name__ == "__main__":
    main()
