#!/usr/bin/env python3
"""Quick local test for encrypt_message/decrypt_message."""

from crypto_util import decrypt_message, encrypt_message, key_from_psk


def main() -> None:
    psk = "my_shared_secret"
    original = "Hello encrypted chat!"
    key = key_from_psk(psk)

    frame = encrypt_message(key, original)
    recovered = decrypt_message(key, frame)

    print("Original :", original)
    print("Recovered:", recovered)
    print("Match    :", original == recovered)


if __name__ == "__main__":
    main()
