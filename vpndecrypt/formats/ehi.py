"""HTTP Injector (``.ehi``) exports.

Layers, outermost first:

1. Binary container: two length-prefixed UTF strings, three 32-bit fields, then
   the ciphertext block.
2. AES-256-CBC with a fixed app key over one of six hardcoded IVs. The decrypted
   text is ``<iv>:<filler>:<ciphertext>``.
3. AES-128-CBC with a fixed second key and the IV from step 2.
4. XXTEA with a 16-byte master key. The payload carries its own length in the
   final word.
5. Some builds stop here ("bypass" exports, the side IVs). Others wrap the JSON
   again in a XOR/base64 envelope whose body is Argon2id + XChaCha20-Poly1305.

Individual string fields are then XOR-obfuscated with a per-file salt so the
JSON is not readable in a memory dump.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Any

from argon2.low_level import Type as ArgonType
from argon2.low_level import hash_secret_raw
from Crypto.Cipher import ChaCha20_Poly1305

from ..errors import DecryptError
from .base import aes_cbc_decrypt, b64_decode, collect_links, load_json, pkcs7_unpad

KEY_L1 = bytes.fromhex(
    "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c"
)
KEY_L2 = bytes.fromhex("b2bc617c32d8b9eb1943a5ffa8051eea")
KEY_MASTER = b"null=V5kU5+FFrY\x00"

SIDE_IVS = (
    bytes.fromhex("221d572349555f1d112133236b1f4a3f"),
    bytes.fromhex("5543494c53443e3f4a6a4539384e776a"),
    bytes.fromhex("374c2541575e4d531a3c327b75431e5f"),
)
STANDARD_IVS = (
    bytes.fromhex("2c5d1147bbad422b3b334d4d235f1a53"),
    bytes.fromhex("522b01433a5e8b2fc7549e1ad368e541"),
    bytes.fromhex("337a1035aaedf3458ca167e92d74b839"),
)

CUSTOM_ALPHABET = b"RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_DECODE_TABLE = bytes.maketrans(CUSTOM_ALPHABET, _STD)

MASTER_KEY_FIELDS = (
    "configAesKey",
    "configIdentifier",
    "configSalt",
    "configTimestamp",
    "configExpiryTimestamp",
    "lockModes",
    "lockModesHash",
    "configHwid",
    "configLockMobileOperatorId",
)
_ALWAYS_STRING = {"configTimestamp", "configExpiryTimestamp"}
_VITAL = {"overwriteServerData"}


def decrypt(data: bytes) -> dict[str, Any]:
    payload = _read_container(data)
    if not payload:
        raise DecryptError(".ehi container has no payload")

    for index, iv in enumerate(SIDE_IVS + STANDARD_IVS):
        try:
            layer1 = pkcs7_unpad(aes_cbc_decrypt(KEY_L1, iv, payload))
        except DecryptError:
            continue

        try:
            iv_b64, _, blob_b64 = layer1.decode("latin-1").split(":")[:3]
            inner_iv = base64.b64decode(iv_b64)
            layer2 = pkcs7_unpad(aes_cbc_decrypt(KEY_L2, inner_iv, base64.b64decode(blob_b64)))
        except (ValueError, DecryptError):
            continue

        raw = _xxtea_decrypt(layer2, KEY_MASTER)
        start = raw.find(b"{")
        if start < 0:
            continue
        try:
            config = json.loads(raw[start:].decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        if not isinstance(config, dict):
            continue

        bypass = index < len(SIDE_IVS)
        return _build(config, bypass)

    raise DecryptError(".ehi decryption failed: no IV produced a valid config")


# ------------------------------------------------------------------ container


def _read_container(data: bytes) -> bytes:
    view = memoryview(data)
    offset = 0

    def read_u16() -> int:
        nonlocal offset
        if offset + 2 > len(view):
            raise DecryptError(".ehi container is truncated")
        value = int.from_bytes(view[offset:offset + 2], "big")
        offset += 2
        return value

    def read_u32() -> int:
        nonlocal offset
        if offset + 4 > len(view):
            raise DecryptError(".ehi container is truncated")
        value = int.from_bytes(view[offset:offset + 4], "big")
        offset += 4
        return value

    def read_string() -> str:
        nonlocal offset
        length = read_u16()
        if offset + length > len(view):
            raise DecryptError(".ehi container is truncated")
        value = bytes(view[offset:offset + length]).decode("utf-8", "replace")
        offset += length
        return value

    magic = read_string()
    if magic not in ("ehi", "EHI"):
        raise DecryptError(f"not an .ehi file (tag {magic!r})")
    offset += 8
    read_string()
    offset += 8
    size = read_u32()
    offset += 8
    if offset + size > len(view):
        raise DecryptError(".ehi payload length exceeds the file size")
    return bytes(view[offset:offset + size])


# ---------------------------------------------------------------------- XXTEA


def _xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    if not data:
        return b""
    if len(data) % 4:
        data += b"\x00" * (4 - len(data) % 4)

    words = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    schedule = [
        int.from_bytes((key + b"\x00" * 16)[i * 4:(i + 1) * 4], "little") for i in range(4)
    ]

    n = len(words)
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    total = (rounds * delta) & 0xFFFFFFFF
    y = words[0]

    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = words[p - 1]
            mx = (
                (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                ^ ((total ^ y) + (schedule[(p & 3) ^ e] ^ z))
            ) & 0xFFFFFFFF
            words[p] = (words[p] - mx) & 0xFFFFFFFF
            y = words[p]
        z = words[n - 1]
        mx = (
            (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((total ^ y) + (schedule[e] ^ z))
        ) & 0xFFFFFFFF
        words[0] = (words[0] - mx) & 0xFFFFFFFF
        y = words[0]
        total = (total - delta) & 0xFFFFFFFF

    plain = b"".join(w.to_bytes(4, "little") for w in words)
    declared = words[-1]
    if 0 < declared <= len(plain):
        return plain[:declared]
    return plain.rstrip(b"\x00")


# -------------------------------------------------------------------- config


def _build(config: dict[str, Any], bypass: bool) -> dict[str, Any]:
    salt = str(config.get("configSalt") or "EVZJNI")

    if bypass:
        final = config
    else:
        body = _xor_layer(str(config.get("configData") or ""), salt)
        raw = base64.b64decode(body)
        if len(raw) <= 50:
            raise DecryptError(".ehi secondary payload is malformed")
        final = _open_aead(raw, config)

    cleaned = _clean_fields(final, salt)
    for field in ("v2rRawJson", "overwriteServerData"):
        value = cleaned.get(field)
        if isinstance(value, str):
            nested = _nested_json(value)
            if nested is not None:
                cleaned[field] = nested

    return {
        "format": "ehi",
        "config": cleaned,
        "links": collect_links(cleaned),
        "notes": ["bypass export (no second envelope)"] if bypass else [],
    }


def _open_aead(raw: bytes, config: dict[str, Any]) -> dict[str, Any]:
    time_cost = int.from_bytes(raw[1:5], "little")
    memory_cost = int.from_bytes(raw[5:9], "little")
    parallelism = raw[9]
    salt = raw[0x0A:0x1A]
    nonce = raw[0x1A:0x32]
    aad = raw[:0x1A]
    body = raw[0x32:]

    if time_cost == 0 or memory_cost == 0 or parallelism == 0:
        raise DecryptError(".ehi Argon2 parameters are invalid")

    master = _master_key(config)
    derived = hash_secret_raw(
        secret=master,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=ArgonType.ID,
    )
    try:
        cipher = ChaCha20_Poly1305.new(key=derived, nonce=nonce)
        cipher.update(aad)
        plain = cipher.decrypt_and_verify(body[:-16], body[-16:])
    except ValueError as exc:
        raise DecryptError(".ehi secondary envelope failed to authenticate") from exc
    return load_json(plain, ".ehi config")


def _master_key(config: dict[str, Any]) -> bytes:
    parts: list[str] = []
    for field in MASTER_KEY_FIELDS:
        value = config.get(field)
        if field in _ALWAYS_STRING:
            parts.append(_py_str(0 if value is None else value))
            continue
        if value is None:
            value = ""
        if _truthy(value):
            parts.append(_py_str(value))
    return hashlib.sha256("".join(parts).encode("utf-8")).digest()


def _py_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes, list, dict, tuple)):
        return len(value) > 0
    return bool(value)


def _clean_fields(config: dict[str, Any], salt: str) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in config.items():
        if not isinstance(value, str) or not value.strip():
            cleaned[key] = value
            continue
        if key == "configMessage":
            decoded = _config_message(value)
        else:
            decoded = None
            try:
                decoded = _xor_layer(value, salt)
            except DecryptError:
                decoded = None
        if decoded:
            cleaned[key] = decoded
        elif key in _VITAL:
            cleaned[key] = value
    return cleaned


def _config_message(value: str) -> str:
    try:
        raw = b64_decode(value)
    except DecryptError:
        return ""
    text = raw.decode("utf-8", "replace")
    units = text.encode("utf-16-le")
    key = "EHIMSG"
    out = bytearray()
    for index in range(0, len(units), 2):
        unit = int.from_bytes(units[index:index + 2], "little") ^ ord(key[(index // 2) % len(key)])
        out += unit.to_bytes(2, "little")
    return out.decode("utf-16-le", "replace")


def _xor_layer(value: str, key: str) -> str:
    """Reverse, custom-base64, hex, then XOR — the per-field obfuscation."""
    if not value.strip():
        return value
    reversed_value = value[::-1].replace("?", "")
    reversed_value += "=" * (-len(reversed_value) % 4)
    try:
        decoded = base64.b64decode(reversed_value.translate(_DECODE_TABLE))
    except ValueError as exc:
        raise DecryptError("field is not custom base64") from exc

    hex_text = decoded.decode("latin-1")
    if len(hex_text) % 2:
        hex_text = "0" + hex_text
    try:
        raw = bytes.fromhex(hex_text)
    except ValueError as exc:
        raise DecryptError("field is not hex") from exc

    key_bytes = key.encode("utf-8") or b"\x00"
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return out.replace(b"\x00", b"").decode("utf-8", "replace")


def _nested_json(text: str) -> Any | None:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, str):
        try:
            return json.loads(parsed)
        except json.JSONDecodeError:
            return parsed
    return parsed
