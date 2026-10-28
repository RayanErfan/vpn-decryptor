"""NPVT / NPVT-sub / NPVS exports.

Three shapes share one core:

``NPVT1`` / ``NPVTSUB1`` text
    A list of base64 tokens separated by those markers. Each token is a 16-byte
    counter followed by a white-box AES-CTR stream, so the app can decrypt
    without ever holding a key. The plaintext is JSON with the profiles.

``NPVS`` binary
    Version 1 keeps a JSON header with a wrapped data key and a ChaCha20-Poly1305
    body. Version 5 (Gen-2) adds a per-recipient key block, an encrypted metadata
    record and an ``NPF`` field table whose entries are addressed by sequence
    number. Both wrap the data key with either an app key or a passphrase.

``NPVO1`` / plain JSON
    Already-parsed exports that only carry ``npvs1:`` sentinels to expand.

The white-box AES is a table network: 16 nibble lookups per round, four rounds
per block, and a final byte table. Gen-2 files use a 13-round variant with a
much larger table set. Both are pure functions of the tables shipped in
``vpndecrypt/data``.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import struct
import urllib.parse
import zlib
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..errors import BadPassword, DecryptError, PasswordRequired, UnsupportedFormat
from .base import collect_links

_DATA = Path(__file__).resolve().parent.parent / "data"
_TABLES_FILE = _DATA / "npvt_tables.bin.gz"
_GEN2_FILE = _DATA / "npvt_gen2.bin.z"

SHIFT_ORDER = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
SENTINEL = "npvs1:"
SENTINEL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
)
GEN2_ROUNDS = 13
GEN2_BLOCK = 57344
GEN2_PAGE = 4096

_TABLES: tuple[list[int], list[int], bytes, bytes, bytes] | None = None
_GEN2: bytes | None = None

# configType is numeric in these profiles: 1 VMess, 3 Shadowsocks, 5 VLESS, 6 Trojan.
_V2RAY_KINDS = {1: "vmess", 3: "ss", 5: "vless", 6: "trojan"}
_PROXY_KINDS = ("socksConfig", "socksProfile", "httpConfig", "httpProfile", "proxyConfig")


# ------------------------------------------------------------------- tables


def _words(raw: bytes) -> list[int]:
    return list(struct.unpack(f">{len(raw) // 4}I", raw))


def _tables() -> tuple[list[int], list[int], bytes, bytes, bytes]:
    global _TABLES
    if _TABLES is None:
        try:
            raw = gzip.decompress(_TABLES_FILE.read_bytes())
        except (OSError, gzip.BadGzipFile) as exc:
            raise DecryptError("the NPVT lookup tables are missing") from exc
        if len(raw) != 65536:
            raise DecryptError("the NPVT lookup tables are truncated")
        _TABLES = (
            _words(raw[0:16384]),
            _words(raw[16384:32768]),
            raw[32768:57344],
            raw[57344:61440],
            raw[61440:65536],
        )
    return _TABLES


def _gen2_tables() -> bytes:
    global _GEN2
    if _GEN2 is None:
        try:
            raw = zlib.decompress(_GEN2_FILE.read_bytes())
        except (OSError, zlib.error) as exc:
            raise DecryptError("the NPVT Gen-2 tables are missing") from exc
        if len(raw) != GEN2_ROUNDS * GEN2_BLOCK + GEN2_PAGE:
            raise DecryptError("the NPVT Gen-2 tables are truncated")
        _GEN2 = raw
    return _GEN2


# ------------------------------------------------------------- white-box AES


def _core(block: bytes, tables: tuple[list[int], list[int], bytes, bytes, bytes]) -> bytes:
    ty, mbl, xt, last = tables[0], tables[1], tables[2], tables[3]
    buf = [block[SHIFT_ORDER[i]] for i in range(16)]

    for group in range(4):
        base = group * 4
        b1, b2, b3 = base + 1, base + 2, base + 3

        c1 = ty[base * 256 + buf[base]]
        c2 = ty[b1 * 256 + buf[b1]]
        c3 = ty[b2 * 256 + buf[b2]]
        c4 = ty[b3 * 256 + buf[b3]]

        for slot in range(4):
            row = group * 24 + slot * 6
            high = 28 - slot * 8
            low = 24 - slot * 8

            n1, n2 = (c1 >> high) & 15, (c2 >> high) & 15
            n3, n4 = (c3 >> high) & 15, (c4 >> high) & 15
            top = xt[(row * 16 + n1) * 16 + n2]
            top2 = xt[(row * 16 + n3) * 16 + n4]

            m1, m2 = (c1 >> low) & 15, (c2 >> low) & 15
            m3, m4 = (c3 >> low) & 15, (c4 >> low) & 15
            bottom = xt[
                (row + 5) * 256
                + xt[(row + 2) * 256 + m1 * 16 + m2] * 16
                + xt[(row + 3) * 256 + m3 * 16 + m4]
            ]
            high_nibble = xt[(row + 4) * 256 + top * 16 + top2]

            buf[base + slot] = bottom | (high_nibble << 4)

        d1 = mbl[base * 256 + buf[base]]
        d2 = mbl[b1 * 256 + buf[b1]]
        d3 = mbl[b2 * 256 + buf[b2]]
        d4 = mbl[b3 * 256 + buf[b3]]

        for slot in range(4):
            row = group * 24 + slot * 6
            high = 28 - slot * 8
            low = 24 - slot * 8

            n1, n2 = (d1 >> high) & 15, (d2 >> high) & 15
            n3, n4 = (d3 >> high) & 15, (d4 >> high) & 15
            a1 = xt[(row * 16 + n1) * 16 + n2]
            a2 = xt[(row * 16 + n3) * 16 + n4]
            high_nibble = xt[(row + 4) * 256 + a1 * 16 + a2]

            m1, m2 = (d1 >> low) & 15, (d2 >> low) & 15
            m3, m4 = (d3 >> low) & 15, (d4 >> low) & 15
            b1v = xt[(row + 2) * 256 + m1 * 16 + m2]
            b2v = xt[(row + 3) * 256 + m3 * 16 + m4]
            bottom = xt[(row + 5) * 256 + b1v * 16 + b2v]

            buf[base + slot] = (high_nibble << 4) | bottom

    buf = [buf[SHIFT_ORDER[i]] for i in range(16)]
    return bytes(last[i * 256 + buf[i]] for i in range(16))


def _ctr(nonce: bytes, data: bytes, last: bytes | None = None) -> bytes:
    """Counter mode over the white-box block function."""
    tables = _tables()
    if last is not None:
        tables = (tables[0], tables[1], tables[2], last, tables[4])

    counter = list(nonce)
    out = bytearray(len(data))
    for offset in range(0, len(data), 16):
        stream = _core(bytes(counter), tables)
        for index in range(15, -1, -1):
            counter[index] = (counter[index] + 1) & 0xFF
            if counter[index]:
                break
        chunk = data[offset : offset + 16]
        for index, byte in enumerate(chunk):
            out[offset + index] = byte ^ stream[index]
    return bytes(out)


# ------------------------------------------------------------------ Gen-2 AES


def _be32(block: bytes, offset: int) -> int:
    return (block[offset] << 24) | (block[offset + 1] << 16) | (block[offset + 2] << 8) | block[offset + 3]


def _gen2_a16(salt: bytes) -> bytes:
    tables = _gen2_tables()
    state = list(salt)

    for round_index in range(GEN2_ROUNDS):
        block = tables[round_index * GEN2_BLOCK : (round_index + 1) * GEN2_BLOCK]
        state = [state[SHIFT_ORDER[i]] for i in range(16)]
        for group in range(4):
            _gen2_group(state, block, group)

    page = tables[GEN2_ROUNDS * GEN2_BLOCK :]
    return bytes(page[0x100 * i + state[SHIFT_ORDER[i]]] for i in range(16))


def _gen2_group(state: list[int], block: bytes, group: int) -> None:
    lane = state[4 * group : 4 * group + 4]

    first = 0x6000 + 0x1000 * group
    args = [
        _be32(block, first + 4 * lane[0]),
        _be32(block, first + 0x400 + 4 * lane[1]),
        _be32(block, first + 0x800 + 4 * lane[2]),
        _be32(block, first + 0xC00 + 4 * lane[3]),
    ]
    mid = _gen2_sub7dc0(block, group, *args)
    state[4 * group : 4 * group + 4] = mid

    second = 0xA000 + 0x1000 * group
    args = [
        _be32(block, second + 4 * mid[0]),
        _be32(block, second + 0x400 + 4 * mid[1]),
        _be32(block, second + 0x800 + 4 * mid[2]),
        _be32(block, second + 0xC00 + 4 * mid[3]),
    ]
    state[4 * group : 4 * group + 4] = _gen2_sub7dc0(block, group, *args)


def _gen2_sub7dc0(block: bytes, i: int, x3: int, x4: int, x5: int, x6: int) -> list[int]:
    """One nibble-network sub-block; transcribed from the round layout."""
    m32 = lambda v: v & 0xFFFFFFFF  # noqa: E731
    at = lambda addr: block[addr]  # noqa: E731

    x2 = i
    x3, x4, x5, x6 = m32(x3), m32(x4), m32(x5), m32(x6)

    x8 = m32(x2 + m32(x2 << 1))
    x12 = m32(x3 >> 0x14)
    x11 = m32(x3 >> 0x18)
    x13 = (x4 >> 0x18) & 0xF
    x14 = m32(x5 >> 0x18)
    x10 = x6
    x9 = m32(x8 << 3)
    x8 = x4
    x12 &= 0xF0
    x12 += x13
    x13 = m32(x5 >> 0x14)
    x16 = x8 >> 0x1C
    x9 &= 0xFFFFFFFF
    x11 &= 0xF0
    x14 &= 0xF0
    x15 = m32(x6 >> 0x18) & 0xF
    x13 &= 0xF0
    x17 = m32(x3 >> 0x10)
    x9 <<= 8
    x8 &= 0xF
    x13 += x15
    x17 &= 0xF0
    x11 = x9 + x11
    x14 = x9 + x14
    x12 = x9 + x12
    x16 = at(x11 + x16)
    x14 += x10 >> 28
    x12 = at(x12 + 0x200)
    x13 = x9 + x13
    x0 = m32(x6 >> 0x14) & 0xF
    x14 = at(x14 + 0x100)
    x15 = x9 + (x16 << 4)
    x13 = at(x13 + 0x300)
    x12 = x9 + (x12 << 4)
    x16 = m32(x4 >> 0x14) & 0xF
    x10 &= 0xF
    x14 = x15 + x14
    x15 = m32(x5 >> 0x10)
    x12 += x13
    x13 = m32(x3 >> 0xC)
    x14 = at(x14 + 0x400)
    x12 = at(x12 + 0x500)
    x15 &= 0xF0
    x16 = x17 + x16
    x15 += x0
    x0 = m32(x4 >> 0x10) & 0xF
    x17 = m32(x5 >> 0xC)
    x12 |= x14 << 4
    x13 &= 0xF0
    x14 = m32(x6 >> 0x10) & 0xF
    x13 += x0
    x17 &= 0xF0
    x16 = x9 + x16
    out0 = x12 & 0xFF
    x13 = x9 + x13
    x12 = x17 + x14
    x14 = at(x16 + 0x600)
    x13 = at(x13 + 0x800)
    x15 = x9 + x15
    x12 = x9 + x12
    x15 = at(x15 + 0x700)
    x16 = m32(x5 >> 8)
    x12 = at(x12 + 0x900)
    x14 = x9 + (x14 << 4)
    x13 = x9 + (x13 << 4)
    x0 = m32(x6 >> 0xC) & 0xF
    x17 = m32(x3 >> 8)
    x14 += x15
    x12 = x13 + x12
    x13 = x16 & 0xF0
    x14 = at(x14 + 0xA00)
    x12 = at(x12 + 0xB00)
    x15 = m32(x3 >> 4)
    x13 += x0
    x0 = m32(x4 >> 8) & 0xF
    x16 = m32(x4 >> 0xC) & 0xF
    x12 |= x14 << 4
    x14 = x15 & 0xF0
    x17 &= 0xF0
    x14 += x0
    x15 = x9 + 0xC00
    x0 = m32(x5 >> 4)
    x17 = x15 + x17
    out1 = x12 & 0xFF
    x12 = m32(x6 >> 8) & 0xF
    x16 = at(x17 + x16)
    x14 = x9 + x14
    x17 = x0 & 0xF0
    x14 = at(x14 + 0xE00)
    x12 = x17 + x12
    x13 = x15 + x13
    x12 = x9 + x12
    x13 = at(x13 + 0x100)
    x15 = x9 + (x16 << 4)
    x12 = at(x12 + 0xF00)
    x14 = x9 + (x14 << 4)
    x16 = 0x1000
    x13 = x15 + x13
    x17 = m32(x6 >> 4) & 0xF
    x0 = x5 & 0xF0
    x12 = x14 + x12
    x14 = 0x1100
    x13 = at(x13 + x16)
    x12 = at(x12 + x14)
    x14 = 0x1200
    x15 = m32(x4 >> 4) & 0xF
    x16 = x3 & 0xF0
    x17 = x0 + x17
    x14 = x9 + x14
    x12 |= x13 << 4
    x13 = (x3 & 0xF) << 4
    x16 = x14 + x16
    out2 = x12 & 0xFF
    x8 = x13 + x8
    x12 = x14 + x17
    x14 = (x5 & 0xF) << 4
    x13 = at(x16 + x15)
    x8 = x9 + x8
    x15 = 0x1400
    x12 = at(x12 + 0x100)
    x8 = at(x8 + x15)
    x10 = x14 + x10
    x14 = 0x1500
    x10 = x9 + x10
    x13 = x9 + (x13 << 4)
    x10 = at(x10 + x14)
    x8 = x9 + (x8 << 4)
    x9 = x13 + x12
    x12 = 0x1600
    x8 += x10
    x10 = 0x1700
    x9 = at(x9 + x12)
    x8 = at(x8 + x10)
    x8 |= x9 << 4
    out3 = x8 & 0xFF
    return [out0, out1, out2, out3]


# ------------------------------------------------------------------ sentinels


def _sentinels(value: Any) -> Any:
    if isinstance(value, str):
        return _expand(value)
    if isinstance(value, dict):
        return {key: _sentinels(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sentinels(item) for item in value]
    return value


def _expand(text: str) -> str:
    out: list[str] = []
    while SENTINEL in text:
        before, text = text.split(SENTINEL, 1)
        out.append(before)
        end = 0
        while end < len(text) and text[end] in SENTINEL_ALPHABET:
            end += 1
        token, text = text[:end], text[end:]
        decoded = _sentinel_token(token)
        out.append(decoded if decoded is not None else SENTINEL + token)
    out.append(text)
    return "".join(out)


def _sentinel_token(token: str) -> str | None:
    for padding in ("", "=", "==", "==="):
        for alt in (None, "-_"):
            try:
                raw = base64.b64decode(token + padding, altchars=alt)
                return raw.decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                continue
    return None


# ----------------------------------------------------------------- entrypoint


def looks_like(data: bytes, name: str = "") -> bool:
    lowered = name.lower()
    if lowered.endswith((".npvt", ".npvtsub", ".npvs")):
        return True
    if data[:4] == b"NPVS" or data[:5] == b"NPVO1":
        return True
    if b"NPVT1" in data[:4096] or b"NPVTSUB1" in data[:4096]:
        return True
    head = data[:64].lstrip()
    return head.startswith(b"TlBWUw") or head.startswith(b"{")


def decrypt(data: bytes, password: str | None = None) -> dict[str, Any]:
    blob, text = _normalise(data)

    if text is not None and text.lstrip().startswith("NPVO1"):
        return _open_export(text)

    if blob[:4] == b"NPVS" and len(blob) >= 9:
        version = blob[4]
        if version >= 5:
            return _npvs_v5(blob, password)
        if version <= 1:
            return _npvs_v1(blob, password)
        raise UnsupportedFormat(f"NPVS container version {version} is not supported yet")

    if text is not None and ("NPVT1" in text or "NPVTSUB1" in text):
        return _npvt_text(text)

    if text is not None and text.lstrip()[:1] in "{[":
        return _open_export(text)

    raise DecryptError("not an NPVT/NPVS export: no known marker")


def _normalise(data: bytes) -> tuple[bytes, str | None]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, None

    compact = "".join(text.split())
    if compact.startswith("TlBWUw"):  # base64 of "NPVS"
        try:
            return base64.b64decode(compact), text
        except (binascii.Error, ValueError):
            pass
    return data, text


def _result(payload: dict[str, Any], links: Iterable[str], notes: Iterable[str] = ()) -> dict[str, Any]:
    return {
        "format": "npvt",
        "config": payload,
        "links": list(links),
        "notes": list(notes),
    }


# ------------------------------------------------------------------ NPVT text


def _npvt_text(text: str) -> dict[str, Any]:
    blocks: list[str] = []
    for token in text.replace("NPVTSUB1", "\n").replace("NPVT1", "\n").split("\n"):
        token = "".join(token.split())
        if not token:
            continue
        try:
            blob = base64.b64decode(token + "=" * (-len(token) % 4))
        except (binascii.Error, ValueError):
            continue
        if len(blob) < 32:
            continue
        plain = _ctr(blob[:16], blob[16:])
        if plain:
            blocks.append(plain.decode("utf-8", "replace"))

    if not blocks:
        raise DecryptError("the NPVT tokens did not decode")

    links: list[str] = []
    for block in blocks:
        links.extend(_links_from(block))
    return _result({"blocks": blocks}, links, ["NPVT white-box stream"])


def _links_from(text: str) -> list[str]:
    """Links inside a decoded block: JSON profiles first, then bare URIs."""
    try:
        root = _sentinels(json.loads(text))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return collect_links(text)

    configs = root.get("configs") if isinstance(root, dict) else root
    links: list[str] = []
    if isinstance(configs, list):
        for config in configs:
            link = _config_to_link(config)
            if link:
                links.append(link)
    return links or collect_links(root)


# ------------------------------------------------------------------ NPVS v1


def _npvs_v1(data: bytes, password: str | None) -> dict[str, Any]:
    header_len = struct.unpack(">I", data[5:9])[0]
    if 9 + header_len > len(data):
        raise DecryptError("the NPVS header length is invalid")

    header_raw = data[9 : 9 + header_len]
    try:
        header = json.loads(header_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptError("the NPVS header is not JSON") from exc

    offset = 9 + header_len
    if offset + 16 > len(data):
        raise DecryptError("the NPVS body is truncated")
    nonce = data[offset : offset + 12]
    body_len = struct.unpack(">I", data[offset + 12 : offset + 16])[0]
    offset += 16
    if offset + body_len > len(data):
        raise DecryptError("the NPVS body length is invalid")
    body = data[offset : offset + body_len]

    policy = header.get("policy") or {}
    message = _creator_message(policy)

    key = _unwrap_v1(header, password, message)
    try:
        plain = ChaCha20Poly1305(key).decrypt(nonce, body, header_raw)
    except Exception as exc:
        raise DecryptError("the NPVS body failed authentication") from exc

    text = _expand(plain.decode("utf-8", "replace"))
    return _from_json_text(text, {"configId": header.get("configId"), "policy": policy}, message)


def _unwrap_v1(header: dict[str, Any], password: str | None, message: str) -> bytes:
    app_key = header.get("appKey")
    if isinstance(app_key, dict):
        salt = _b64url(str(app_key.get("salt", "")))
        wrap = _b64url(str(app_key.get("wrap", "")))
        for last in _tables()[3:5]:
            stream = _ctr(salt[:16], bytes(16), last)
            kdk = hashlib.sha256(b"npvtunnel/appkey/v1 " + stream).digest()
            try:
                return ChaCha20Poly1305(kdk).decrypt(wrap[:12], wrap[12:], salt)
            except Exception:
                continue

    passphrase = header.get("passphrase")
    if isinstance(passphrase, dict):
        if not password:
            hint = f"\ncreator message: {message}" if message else ""
            raise PasswordRequired(f"this NPVS export is password protected{hint}")
        salt = _b64url(str(passphrase.get("salt", "")))
        wrap = _b64url(str(passphrase.get("wrap", "")))
        iterations = int(passphrase.get("iters") or 600000)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)
        try:
            return ChaCha20Poly1305(derived).decrypt(wrap[:12], wrap[12:], salt)
        except Exception as exc:
            raise BadPassword("incorrect password for this NPVS export") from exc

    raise DecryptError("the NPVS data key could not be unwrapped")


# ------------------------------------------------------------------ NPVS v5


def _npvs_v5(data: bytes, password: str | None) -> dict[str, Any]:
    header_len = struct.unpack(">I", data[5:9])[0]
    if 9 + header_len > len(data):
        raise DecryptError("the NPVS Gen-2 header length is invalid")

    header = data[9 : 9 + header_len]
    if header[0] != 1:
        raise UnsupportedFormat(f"compressed NPVS Gen-2 headers (v{header[0]}) are not supported yet")

    config_id = header[1:17]
    method = header[50]
    recipients = struct.unpack(">H", header[51:53])[0]
    offset = 53 + recipients * (32 + 0x5D)

    iterations = 0
    if method == 2:
        if offset + 78 > len(header):
            raise DecryptError("the NPVS app-key block is truncated")
        salt = header[offset + 2 : offset + 18]
        wrap = header[offset + 18 : offset + 78]
        offset += 78
    elif method == 1:
        if offset + 80 > len(header):
            raise DecryptError("the NPVS passphrase block is truncated")
        iterations = struct.unpack(">I", header[offset : offset + 4])[0]
        salt = header[offset + 4 : offset + 20]
        wrap = header[offset + 20 : offset + 80]
        offset += 80
    else:
        raise UnsupportedFormat(
            f"NPVS files sealed to a recipient key (method {method}) are not supported yet"
        )

    meta_len = struct.unpack(">I", header[offset : offset + 4])[0]
    meta_blob = header[offset + 4 : offset + 4 + meta_len]
    prefix = header[:offset]

    nonce_offset = 9 + header_len
    nonce = data[nonce_offset : nonce_offset + 12]
    body_len = struct.unpack(">I", data[nonce_offset + 12 : nonce_offset + 16])[0]
    body_offset = nonce_offset + 16
    body = data[body_offset : body_offset + body_len]

    if method == 2:
        kdk = hashlib.sha256(b"npvtunnel/appkey/v2 " + _gen2_a16(salt) + config_id).digest()
    else:
        if not password:
            raise PasswordRequired("this NPVS export is password protected")
        kdk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)

    try:
        key = ChaCha20Poly1305(kdk).decrypt(wrap[:12], wrap[12:], salt)
    except Exception as exc:
        if method == 1:
            raise BadPassword("incorrect password for this NPVS export") from exc
        raise DecryptError("the NPVS app key did not unwrap") from exc

    metadata: dict[str, Any] = {}
    message = ""
    try:
        meta_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=nonce, info=b"NPVS-v5/metadata"
        ).derive(key)
        meta_bytes = ChaCha20Poly1305(meta_key).decrypt(nonce, meta_blob, prefix)
        metadata = json.loads(meta_bytes.decode("utf-8"))
        message = _creator_message(metadata.get("policy") or {})
    except Exception:
        pass

    fields = _npf_fields(body, key)
    links = _configs_from_table(fields)
    payload: dict[str, Any] = {"metadata": metadata}
    if not links:
        payload["fields"] = {
            seq: _field_text(raw) for seq, raw in sorted(fields.items()) if seq != 0xFFFF
        }
    return _result(payload, links, ["NPVS Gen-2 container"])


def _npf_fields(body: bytes, key: bytes) -> dict[int, bytes]:
    if len(body) < 38 or body[:4] != b"NPF\x01":
        raise DecryptError("the NPVS field table is not NPF")

    content_id = body[4:36]
    count = struct.unpack(">H", body[36:38])[0]
    offset = 38
    fields: dict[int, bytes] = {}

    for _ in range(count):
        if offset + 6 > len(body):
            break
        seq, _flags, blob_len = struct.unpack(">HHH", body[offset : offset + 6])
        blob = body[offset + 6 : offset + 6 + blob_len]
        offset += 6 + blob_len

        field_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=content_id,
            info=b"NPV-fields-v1/field/" + struct.pack(">H", seq),
        ).derive(key)

        plain_len = len(blob) - 16
        if plain_len < 0:
            continue
        aad = (
            b"NPV-fields-v1/record/"
            + content_id
            + struct.pack(">H", seq)
            + struct.pack(">I", plain_len)
        )
        try:
            fields[seq] = ChaCha20Poly1305(field_key).decrypt(bytes(12), blob, aad)
        except Exception:
            continue
    return fields


def _configs_from_table(fields: dict[int, bytes]) -> list[str]:
    table = fields.get(0xFFFF)
    if not table:
        return []
    try:
        spec = json.loads(table.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []

    links: list[str] = []
    for config in spec.get("configs") or []:
        link = _config_to_link(_substitute(config, fields))
        if link:
            links.append(link)
    return links


def _substitute(value: Any, fields: dict[int, bytes]) -> Any:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _expand(_field_text(fields.get(int(value), b"")))
    if isinstance(value, dict):
        return {key: _substitute(item, fields) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute(item, fields) for item in value]
    return value


def _field_text(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace").strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text[1:-1]
    return text


# ------------------------------------------------------------------ open text


def _open_export(text: str) -> dict[str, Any]:
    body = text.replace("NPVO1\n", "").replace("NPVO1", "").strip()
    if not body:
        raise DecryptError("the NPVO1 export is empty")
    return _from_json_text(body, {}, "")


def _from_json_text(text: str, metadata: dict[str, Any], message: str) -> dict[str, Any]:
    try:
        root = json.loads(_expand(text))
    except (UnicodeDecodeError, json.JSONDecodeError):
        links = _links_from(text)
        if not links:
            raise DecryptError("the NPVS payload is not JSON")
        return _result({"text": text}, links)

    root = _sentinels(root)
    configs = root.get("configs") if isinstance(root, dict) else root
    links: list[str] = []
    if isinstance(configs, list):
        for config in configs:
            link = _config_to_link(config)
            if link:
                links.append(link)
    if not links:
        links = collect_links(root)

    payload: dict[str, Any] = {"configs": configs} if configs else {"payload": root}
    if metadata:
        payload["metadata"] = metadata
    notes = ["creator message present"] if message else []
    return _result(payload, links, notes)


def _creator_message(policy: dict[str, Any]) -> str:
    parts = [
        str(policy.get(field)).strip().replace("\r\n", "\n")
        for field in ("displayMessage", "customServerMessage")
        if policy.get(field) and str(policy.get(field)).strip()
    ]
    return "\n".join(parts)


# --------------------------------------------------------------------- links


def _config_to_link(config: Any) -> str | None:
    if not isinstance(config, dict):
        return str(config) if config else None

    name = str(config.get("name") or config.get("remarks") or "NPVS")
    address = str(config.get("address") or "")

    profile = config.get("v2rayProfile")
    if isinstance(profile, dict):
        return _v2ray_link(name, address, profile)

    ssh = config.get("sshConfig")
    if isinstance(ssh, dict):
        return _ssh_link(ssh)

    for kind in _PROXY_KINDS:
        block = config.get(kind)
        if isinstance(block, dict):
            return _proxy_link(name, address, kind, block)

    found = collect_links(config)
    return found[0] if found else None


def _text(profile: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = profile.get(key)
        if isinstance(value, bool):
            return "true" if value else "false"
        if value not in (None, ""):
            return str(value)
    return ""


def _number(profile: dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = profile.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return 0


def _v2ray_link(name: str, address: str, profile: dict[str, Any]) -> str | None:
    host = _text(profile, "server") or address
    port = _number(profile, "serverPort", "port")
    if not host or not port:
        return None

    kind = _V2RAY_KINDS.get(_number(profile, "configType"))
    remarks = _text(profile, "remarks") or name
    network = _text(profile, "network") or "tcp"
    security = _text(profile, "security") or "none"

    if kind == "vmess":
        body = {
            "v": "2",
            "ps": remarks,
            "add": host,
            "port": str(port),
            "id": _text(profile, "password", "id"),
            "aid": str(_number(profile, "alterId")),
            "scy": _text(profile, "method") or "auto",
            "net": network,
            "type": _text(profile, "headerType") or "none",
            "host": _text(profile, "host"),
            "path": _text(profile, "path"),
            "tls": "tls" if security in ("tls", "reality") else "",
            "sni": _text(profile, "sni"),
            "fp": _text(profile, "fingerPrint"),
            "alpn": _text(profile, "alpn"),
        }
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return "vmess://" + base64.b64encode(raw).decode("ascii")

    if kind == "ss":
        method = _text(profile, "method") or "aes-256-gcm"
        userinfo = base64.b64encode(f"{method}:{_text(profile, 'password')}".encode()).decode("ascii")
        return f"ss://{userinfo}@{host}:{port}#{urllib.parse.quote(remarks, safe='')}"

    query: list[tuple[str, str]] = [("type", network), ("security", security)]
    if network in ("ws", "xhttp", "httpupgrade"):
        for key in ("path", "host"):
            if _text(profile, key):
                query.append((key, _text(profile, key)))
        if network != "ws" and _text(profile, "xhttpMode", "mode"):
            query.append(("mode", _text(profile, "xhttpMode", "mode")))
    elif network == "grpc":
        if _text(profile, "serviceName"):
            query.append(("serviceName", _text(profile, "serviceName")))
        query.append(("mode", _text(profile, "mode", "xhttpMode") or "gun"))
    elif network in ("tcp", "raw") and _text(profile, "headerType") not in ("", "none"):
        query.append(("headerType", _text(profile, "headerType")))
        for key in ("host", "path"):
            if _text(profile, key):
                query.append((key, _text(profile, key)))

    if security == "tls":
        for key in ("sni", "fingerPrint", "alpn"):
            if _text(profile, key):
                query.append(({"fingerPrint": "fp"}.get(key, key), _text(profile, key)))
        if _text(profile, "tlsAllowInsecure", "insecure").lower() in ("true", "1", "yes"):
            query.append(("allowInsecure", "1"))
    elif security == "reality":
        for key, alias in (("sni", "sni"), ("fingerPrint", "fp"), ("publicKey", "pbk"), ("shortId", "sid")):
            if _text(profile, key):
                query.append((alias, _text(profile, key)))

    if kind == "vless":
        query.append(("encryption", _text(profile, "method") or "none"))
        if _text(profile, "flow"):
            query.append(("flow", _text(profile, "flow")))
        user = _text(profile, "password", "id")
        scheme = "vless"
    else:
        user = urllib.parse.quote(_text(profile, "password"), safe="")
        scheme = "trojan"

    query.sort()
    return (
        f"{scheme}://{user}@{host}:{port}?{urllib.parse.urlencode(query)}"
        f"#{urllib.parse.quote(remarks, safe='')}"
    )


def _ssh_link(ssh: dict[str, Any]) -> str:
    target = str(ssh.get("sshHost") or "")
    port = str(ssh.get("sshPort") or "")
    if port:
        target += f":{port}"

    query = {"remarks": str(ssh.get("remarks") or "NPVS")}
    for key in ("sshConfigType", "httpProxy"):
        if ssh.get(key):
            query[key] = str(ssh[key])

    user = urllib.parse.quote(str(ssh.get("sshUsername") or ""), safe="")
    secret = urllib.parse.quote(str(ssh.get("sshPassword") or ""), safe="")
    payload = str(ssh.get("payload") or "")
    return f"ssh://{user}:{secret}@{target}?{urllib.parse.urlencode(sorted(query.items()))}#{payload}"


def _proxy_link(name: str, address: str, kind: str, block: dict[str, Any]) -> str:
    scheme = kind.replace("Config", "").replace("Profile", "").lower()
    host = str(block.get("server") or block.get("host") or address)
    port = str(block.get("serverPort") or block.get("port") or block.get("localPort") or "")
    target = f"{host}:{port}" if port else host

    query = {"remarks": name}
    for key, value in sorted(block.items()):
        if key not in ("remarks", "server", "host", "port", "serverPort", "localPort") and value:
            query[key] = str(value)

    user = str(block.get("username") or "")
    secret = str(block.get("password") or "")
    auth = ""
    if user and secret:
        auth = f"{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(secret, safe='')}@"
    elif secret:
        auth = f"{urllib.parse.quote(secret, safe='')}@"
    return f"{scheme}://{auth}{target}?{urllib.parse.urlencode(query)}"


def _b64url(value: str) -> bytes:
    text = value.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text)
    except (binascii.Error, ValueError):
        return base64.b64decode(text)
