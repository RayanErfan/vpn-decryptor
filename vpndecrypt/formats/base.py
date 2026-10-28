"""Small, dependency-light primitives shared by the format implementations."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from Crypto.Cipher import AES, ChaCha20

from ..errors import DecryptError

_WHITESPACE = re.compile(r"\s+")
_HEX_ONLY = re.compile(r"[^0-9a-fA-F]")


def b64_decode(value: str) -> bytes:
    """Decode base64 that may be padded, unpadded or url-safe."""
    text = _WHITESPACE.sub("", value)
    if not text:
        raise DecryptError("empty base64 payload")
    for candidate in (text, text.rstrip("=")):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return decoder(candidate + "=" * (-len(candidate) % 4))
            except (binascii.Error, ValueError):
                continue
    raise DecryptError("payload is not valid base64")


def pkcs7_unpad(data: bytes, block_size: int = 16, strict: bool = True) -> bytes:
    """Remove PKCS#7 padding.

    ``strict=False`` mimics the lenient trimming some apps do: if the padding
    is malformed, trailing whitespace is dropped instead of raising.
    """
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= block_size and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    if strict:
        if len(data) % block_size:
            raise DecryptError("ciphertext length is not a multiple of the block size")
        raise DecryptError("invalid PKCS#7 padding")
    return data.rstrip(b"\x00 \t\r\n")


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) %16:
        raise DecryptError("ciphertext length is not a multiple of 16")
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise DecryptError("ciphertext length is not a multiple of 16")
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """IETF ChaCha20, starting at ``counter`` (the formats here use 1)."""
    if len(nonce) == 8:
        nonce = b"\x00" * 4 + nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(counter * 64)
    return cipher.decrypt(data)


def xchacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """XChaCha20: 24-byte nonce, same keystream rules as above."""
    if len(nonce) != 24:
        raise DecryptError("XChaCha20 needs a 24-byte nonce")
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(counter * 64)
    return cipher.decrypt(data)


def xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise DecryptError("empty xor key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def hex_chars_only(text: str) -> str:
    return _HEX_ONLY.sub("", text)


def looks_hex(value: str, minimum: int = 16) -> bool:
    return len(value) >= minimum and not _HEX_ONLY.search(value)


def latin1_repair(data: bytes) -> bytes:
    """Undo the UTF-8-of-latin-1 mangling some exporters produce."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    if all(ord(ch) <= 0xFF for ch in text):
        return text.encode("latin-1")
    return data


def load_json(raw: bytes | str, what: str = "config") -> Any:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptError(f"{what} is not valid UTF-8") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DecryptError(f"{what} is not valid JSON") from exc


LINK_SCHEMES = frozenset(
    {"vless", "vmess", "trojan", "ss", "ssr", "ssh", "socks", "http", "hysteria2", "tuic"}
)


def collect_links(value: Any) -> list[str]:
    """Pull every share URI out of an arbitrary decoded structure."""
    found: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        token = token.strip()
        if "://" in token and token.split("://", 1)[0].lower() in LINK_SCHEMES and token not in seen:
            seen.add(token)
            found.append(token)

    def walk(node: Any) -> None:
        if isinstance(node, str):
            for token in re.split(r"[\r\n,]+", node):
                add(token)
        elif isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)

    walk(value)
    return found

