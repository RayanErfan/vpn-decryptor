"""NetMod VPN (``.nm`` / ``nm-*://``) exports.

Base64 wrapping AES-128-ECB. NetMod has shipped more than one build key, so all
known keys are tried and the first one that yields valid padding wins.

Two plaintext shapes exist: a JSON settings document (``.nm`` exports) and a
bare share URI (``nm-vless://``-style links). Both are accepted, and a URI is
also extracted from the JSON when present.
"""

from __future__ import annotations

from typing import Any

from ..errors import DecryptError
from .base import aes_ecb_decrypt, b64_decode, collect_links, load_json, pkcs7_unpad

KNOWN_KEYS = (
    b"<n3t5yn4^n3tm0d>",
    b"_netsyna_netmod_",
    b"nicetrybuddygoon",
)


def decrypt(data: bytes | str, proto: str | None = None) -> dict[str, Any]:
    text = data.decode("ascii", "ignore") if isinstance(data, bytes) else data
    blob = b64_decode(text)
    if not blob or len(blob) % 16:
        raise DecryptError(".nm payload is not an AES block multiple")

    for key in KNOWN_KEYS:
        try:
            plain = pkcs7_unpad(aes_ecb_decrypt(key, blob), strict=True)
        except DecryptError:
            continue

        try:
            body = plain.decode("utf-8")
        except UnicodeDecodeError:
            continue

        try:
            config = load_json(body, ".nm config")
        except DecryptError:
            links = collect_links(body)
            if not links and proto and "://" not in body:
                # ``nm-<proto>://`` carries the scheme outside the ciphertext.
                links = [f"{proto}://{body}"]
            if links:
                return {
                    "format": "netmod",
                    "config": {"text": body, "proto": proto},
                    "links": links,
                    "notes": [],
                }
            continue

        return {
            "format": "netmod",
            "config": config,
            "links": collect_links(config),
            "notes": [],
        }

    raise DecryptError("no known NetMod key matched this file")
