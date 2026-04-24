#!/usr/bin/env python3
"""
Multi-client TCP chat server: decrypts with PSK for logging, relays ciphertext to others.
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import threading
import time
from typing import List, Tuple

from crypto_util import decrypt_message, encrypt_message, key_from_psk, recv_frame

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000


class ChatServer:
    def __init__(self, host: str, port: int, aes_key: bytes, log_path: str) -> None:
        self.host = host
        self.port = port
        self.aes_key = aes_key
        self.clients: List[Tuple[socket.socket, str]] = []
        self.lock = threading.Lock()
        self._setup_logging(log_path)

    def _setup_logging(self, log_path: str) -> None:
        log_dir = os.path.dirname(os.path.abspath(log_path))
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger("chat_server")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(fmt)
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def broadcast(self, sender_sock: socket.socket, frame: bytes) -> None:
        with self.lock:
            targets = [c for c, _ in self.clients if c is not sender_sock]
        for c in targets:
            try:
                c.sendall(frame)
            except OSError:
                self.remove_client(c)

    def remove_client(self, sock: socket.socket) -> None:
        with self.lock:
            self.clients = [(c, name) for c, name in self.clients if c is not sock]
        try:
            sock.close()
        except OSError:
            pass

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int], name: str) -> None:
        self.logger.info("Client connected: %s (%s:%s)", name, addr[0], addr[1])
        try:
            while True:
                frame = recv_frame(conn)
                try:
                    plain = decrypt_message(self.aes_key, frame)
                except Exception as e:  # noqa: BLE001 — log bad crypto and drop client
                    self.logger.warning("Decrypt failed from %s: %s", name, e)
                    break
                self.logger.info("[%s] %s", name, plain)
                self.broadcast(conn, frame)
        except (ConnectionError, ValueError, OSError) as e:
            self.logger.info("Client %s disconnected: %s", name, e)
        finally:
            self.remove_client(conn)
            self.logger.info("Client left: %s", name)

    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen()
            self.logger.info("Listening on %s:%s (PSK chat)", self.host, self.port)
            client_no = 0
            while True:
                conn, addr = server_sock.accept()
                client_no += 1
                name = f"user-{client_no}"
                with self.lock:
                    self.clients.append((conn, name))
                t = threading.Thread(
                    target=self.handle_client, args=(conn, addr, name), daemon=True
                )
                t.start()


def main() -> None:
    p = argparse.ArgumentParser(description="Encrypted multi-client chat server (AES-CBC + PSK).")
    p.add_argument("--host", default=os.environ.get("CHAT_HOST", DEFAULT_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get("CHAT_PORT", DEFAULT_PORT)))
    p.add_argument(
        "--psk",
        default=os.environ.get("CHAT_PSK"),
        help="Pre-shared passphrase (or set CHAT_PSK).",
    )
    p.add_argument(
        "--log",
        default=os.environ.get("CHAT_LOG", "chat_server.log"),
        help="Path to message log file.",
    )
    args = p.parse_args()
    if not args.psk:
        p.error("Set --psk or CHAT_PSK so clients and server share the same key material.")
    key = key_from_psk(args.psk)
    ChatServer(args.host, args.port, key, args.log).run()


if __name__ == "__main__":
    main()
