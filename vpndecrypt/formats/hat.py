"""Ha Tunnel Plus (``.hat``) exports.

The file is base64 wrapping AES-128-ECB ciphertext. The block key is the first
16 bytes of SHA-1 over the app's fixed import passphrase.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..errors import DecryptError
from .base import aes_ecb_decrypt, b64_decode, collect_links, load_json, pkcs7_unpad

IMPORT_PASSPHRASE = b"8515D40BD04D8C97"


def _key() -> bytes:
    return hashlib.sha1(IMPORT_PASSPHRASE).digest()[:16]


def decrypt(data: bytes | str) -> dict[str, Any]:
    text = data.decode("ascii", "ignore") if isinstance(data, bytes) else data
    blob = b64_decode(text)
    if len(blob) % 16 or not blob:
        raise DecryptError(".hat payload is not an AES block multiple")
    plain = pkcs7_unpad(aes_ecb_decrypt(_key(), blob), strict=False)
    config = load_json(plain, ".hat config")
    return {
        "format": "hat",
        "config": config,
        "links": collect_links(config),
        "notes": [],
    }
