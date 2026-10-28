"""HTTP Custom (``.hc``) exports.

HTTP Custom has rebuilt its file format several times. Three families are
recognised here, tried newest first:

``stream`` (v2.6 and later)
    The file is masked with a short repeating key, the result is UTF-8 text made
    only of hexadecimal digits, and the bytes behind that hex are a ChaCha20
    stream over a JSON envelope. The envelope holds either a ``cfg.content``
    blob (newest) or an ``xy``/``uv`` pair (older). ``cfg.content`` is itself
    XOR-masked, base64-coded and AES-128-ECB encrypted; the plain result is a
    list of tokens separated by ``[splitConfig]``. Individual tokens may get a
    second ChaCha20 pass, a bespoke XOR ("JKL") pass, braille, or decimal pairs.

``legacy``
    The whole file is XORed per character against a cycle of CJK punctuation,
    which yields base64 of an AES-128-ECB blob keyed by SHA-1 of one of the
    historical ePro passphrases. Same ``[splitConfig]`` layout.

``envelope``
    An ``HCCFG`` container. Detected so the caller gets an honest message
    instead of "corrupt file"; not decrypted.

The token order, the mask, the stream keys and the passphrases are properties
of the file format, not of any particular implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Iterable

from Crypto.Cipher import AES, ChaCha20

from ..errors import (
    BadPassword,
    DecryptError,
    PasswordRequired,
    UnsupportedFormat,
)
from .base import (
    aes_ecb_decrypt,
    b64_decode,
    collect_links,
    hex_chars_only,
    latin1_repair,
    looks_hex,
    pkcs7_unpad,
    xor,
)

# --------------------------------------------------------------------- shared

MASK = bytes.fromhex("e382e4b8adc386f09f9293")

# One per envelope generation; only a couple of them ever appear in a given
# build, so every candidate is tried.
STREAM_KEYS = (
    bytes.fromhex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
    bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
    bytes.fromhex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
    bytes.fromhex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
    bytes.fromhex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
    bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
    bytes.fromhex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
    bytes.fromhex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"),
)

RST_KEYS = (
    b"JN1k3YHc2.6_v235",
    b"JN1k3YHc_2.7_v71",
    b"JN1k3YHc2.7.ps69",
    b"JN1k3YHc2.7.6950",
    b"Jn1K3yHc2.8.ps08",
    b"Jn1K3yHc2.9.ps6c",
    b"Zk:L7>WKaiK*s9>D",
    b"!<f!&WIlM**R.B0X",
    b"b4a5opinx2uloec6",
)

STATIC_NONCE = b"\xdb" * 8
RST_MASK = bytes(range(2, 22))
FIELD_MARKER = "88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d"
SPLIT = "[splitConfig]"

# Legacy generation.
LEGACY_XOR = "。〃〄々〆〇〈〉《》「」『』【】〒〓〔〕"
LEGACY_PASSPHRASES = (
    "hc_reborn___7", "hc_reborn_tester", "hc_reborn_tester_5", "hc_reborn_7",
    "hc_reborn_6", "hc_reborn_5", "hc_reborn_4", "hc_reborn_3", "hc_reborn_2",
    "hc_reborn_1", "hc_reborn10", "hc_reborn9", "hc_reborn8", "hc_reborn7",
    "keY_secReaT_hc", "keY_secReaT_hc1", "keY_secReaT_hc2", "keY_secReaT_hc_reborn",
    "keY_secReaT_hc_reborn1", "keY_secReaT_hc_2", "keY_secReaT_hc_reborn3",
    "keY_secReaT_hc_reborn4", "keY_secReaT_hc_reborn5", "keY_secReaT_hc_reborn6",
    "keY_secReaT_te4Z9", "keY_secReaT_te4Z10", "keY_secReaT_te4Z11", "keY_secReaT_e",
)

# Token order of the [splitConfig] layout. 22 and 24 are reserved.
TOKENS = (
    "payload", "proxy", "lockAllConfig", "blockedByRoot", "expiryTime",
    "noteEnabled", "notes", "sshServer", "mobileDataLock", "unlockUserPass",
    "openvpnConfig", "openvpnCreds", "sni", "unlockUserPass2", "reserved14",
    "blockedByHwid", "cloudConfig", "psiphon", "name", "blockArea",
    "connectionMode", "blockedByPassword", "reserved22", "extraSniffer",
    "reserved24", "v2rayEnabled", "v2rayConfig", "version", "slowdnsEnabled",
    "slowdnsServer", "slowdnsPublicKey", "dnsResolver",
)
_SKIP_TOKENS = frozenset({22, 24})

JKL_KEY_OLD = bytes(
    [0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0, 0xCF, 0xCE, 0xCD, 0xCC,
     0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7, 0xB6, 0xB5, 0xB4]
)
JKL_KEY_NEW = bytes(
    [8, 9, 10, 11, 12, 13, 14, 15, 17, 17,
     5, 4, 3, 2, 1, 0, 255, 254, 253, 252]
)
BRAILLE = (
    "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵"
    "⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚"
)

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_DECIMAL_PAIR = re.compile(r"(-?\d+)\.(-?\d+)")
_CREDENTIALS = re.compile(r"^([^:]+):(.+)$")
_SSH_ENDPOINT = re.compile(r"^([\w.\-]+):([\d\-]+)@(.+):(.+)$")


# ------------------------------------------------------------------ entrypoint


def decrypt(data: bytes, password: str | None = None) -> dict[str, Any]:
    """Decrypt an ``.hc`` file into the common result shape.

    Files that the recognised builds cannot open are reported as password
    protected when no password was supplied, so the caller can ask for one. A
    password that also fails means the file uses a build that is not understood
    yet (several of them exist and are not public).
    """
    for attempt in (_stream, _legacy, _envelope):
        result = attempt(data)
        if result:
            return result

    if password:
        raise BadPassword(
            "this .hc file could not be opened with that password; it may use a "
            "newer HTTP Custom build, or be locked to a device (HWID)"
        )
    raise PasswordRequired(
        "this .hc file needs a password (usually written in the channel post), "
        "or it uses a build that is not supported yet"
    )


def looks_like(data: bytes) -> bool:
    """Whether ``data`` carries any of the markers of an ``.hc`` export.

    Used when the file name gives nothing away: an unknown file that does not
    match any marker is reported as an unknown format instead of sending the
    user after a password that cannot help.
    """
    if b"HCCFG" in data[:512]:
        return True

    for source in _sources(data):
        masked = xor(source, MASK)
        try:
            text = masked.decode("utf-8")
        except UnicodeDecodeError:
            continue
        digits = hex_chars_only(text)
        # The masked tail of a v2.6+ file is hex text and nothing else.
        if len(digits) >= 96 and len(digits) >= 0.9 * len(text):
            return True

    # Locked files from newer builds keep the same UTF-8-of-latin-1 shape: a
    # long, mostly high-byte text with no plain ASCII config inside it.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if len(text) < 128:
        return False
    high = sum(1 for char in text if ord(char) > 127)
    return high / len(text) > 0.3


def _result(text_or_fields: Any, notes: Iterable[str] = ()) -> dict[str, Any]:
    if isinstance(text_or_fields, dict):
        payload = text_or_fields
    else:
        payload = {"text": text_or_fields}
    return {
        "format": "http_custom",
        "config": payload,
        "links": collect_links(text_or_fields),
        "notes": list(notes),
    }


# ------------------------------------------------------------- stream family


def _stream(data: bytes) -> dict[str, Any] | None:
    """v2.6+ : mask -> hex text -> ChaCha20 JSON envelope -> token layers."""
    for source in _sources(data):
        masked = xor(source, MASK)
        try:
            text = masked.decode("utf-8")
        except UnicodeDecodeError:
            continue

        digits = hex_chars_only(text)
        if len(digits) < 96:
            continue
        if len(digits) % 2:
            digits = "0" + digits
        try:
            blob = bytes.fromhex(digits)
        except ValueError:
            continue

        envelope = _open_envelope(blob)
        if envelope is None:
            continue
        return _read_envelope(envelope)
    return None


def _sources(data: bytes) -> list[bytes]:
    """The file itself, plus the UTF-8-of-latin-1 variant some exporters emit."""
    repaired = latin1_repair(data)
    return [repaired, data] if repaired != data else [data]


def _open_envelope(blob: bytes) -> dict[str, Any] | None:
    """Try every stream key and both nonce widths over the hex payload."""
    nonces = (STATIC_NONCE, b"\x00\x00\x00\x00" + STATIC_NONCE)
    for key in STREAM_KEYS:
        for nonce in nonces:
            for body in (blob[:-16], blob):
                if len(body) < 2:
                    continue
                plain = _stream_decrypt(key, nonce, body)
                if not plain.startswith(b"{"):
                    continue
                try:
                    parsed = json.loads(plain)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if isinstance(parsed, dict):
                    return parsed
    return None


def _stream_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 starting 64 bytes into the keystream, as the app does."""
    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
    except ValueError:
        return b""
    cipher.seek(64)
    return cipher.decrypt(data)


def _read_envelope(root: dict[str, Any]) -> dict[str, Any] | None:
    cfg = root.get("cfg") if isinstance(root.get("cfg"), dict) else {}
    alt = root.get("a") if isinstance(root.get("a"), dict) else {}

    if isinstance(cfg.get("content"), str) and cfg["content"]:
        return _read_modern(cfg, root)

    xy = _first_string(cfg.get("xy"), alt.get("xy"), root.get("xy"))
    if xy:
        return _read_classic(root, alt, xy)

    return None


def _first_string(*values: Any) -> str:
    """First value that is a non-empty string."""
    for value in values:
        if isinstance(value, str) and value:
            return value
    return ""


def _read_modern(cfg: dict[str, Any], root: dict[str, Any]) -> dict[str, Any] | None:
    """Newest layout: ``cfg.content`` holds the token list."""
    meta = {
        "hwid": _first_string(cfg.get("b"), root.get("b")),
        "area": _first_string(cfg.get("f"), root.get("f")),
    }
    nonce = _dynamic_nonce(meta)

    if SPLIT in cfg["content"]:
        tokens: str | None = cfg["content"]
    else:
        tokens = _rst_decode(cfg["content"])
        if tokens is None:
            for key in STREAM_KEYS:
                candidate = _hex_stream(cfg["content"], key, STATIC_NONCE)
                if SPLIT in candidate:
                    tokens = candidate
                    break
    if tokens is None:
        return None

    fields = _parse_tokens(tokens, STREAM_KEYS, nonce)
    protections = {name: value for name, value in meta.items() if value}
    return _result(
        {"fields": fields, "protections": protections},
        ["new-style stream layout"],
    )


def _read_classic(
    root: dict[str, Any], alt: dict[str, Any], xy: str
) -> dict[str, Any] | None:
    """Older layout: ``xy`` tokens split on ``uv``, protections beside them."""
    delimiter = _first_string(root.get("uv"), alt.get("uv")) or SPLIT

    protections: dict[str, str] = {}
    for name, key in (("hwid", "bb"), ("password", "e"), ("area", "fe"), ("provider", "ed")):
        raw = root.get(key) if key == "e" else alt.get(key)
        if isinstance(raw, str) and raw:
            decoded = _hex_stream(raw, STREAM_KEYS[7], STATIC_NONCE)
            if decoded:
                protections[name] = decoded

    tokens = _hex_stream(xy, STREAM_KEYS[1], STATIC_NONCE)
    if not tokens:
        return None

    fields = _parse_tokens(tokens, (STREAM_KEYS[7],), _dynamic_nonce(protections))
    return _result(
        {"fields": fields, "protections": protections},
        ["legacy stream layout"],
    )


def _dynamic_nonce(meta: dict[str, str]) -> bytes:
    """Per-file nonce: the protections' hex, folded into the static nonce."""
    hwid = meta.get("hwid") or ""
    password = meta.get("password") or ""
    provider = meta.get("provider") or ""
    area = meta.get("area") or ""

    if hwid and not (password or provider or area):
        seed = (hwid.encode().hex()) * 2
    else:
        seed = password.encode().hex() + hwid.encode().hex() + provider.encode().hex() + area.encode().hex()

    nonce = bytearray(STATIC_NONCE)
    try:
        derived = bytes.fromhex(seed)[:8]
    except ValueError:
        return bytes(nonce)
    for index, byte in enumerate(derived):
        nonce[index] = byte
    return bytes(nonce)


# ------------------------------------------------------------------ token I/O


def _parse_tokens(tokens: str, keys: tuple[bytes, ...], nonce: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    parts = tokens.split(SPLIT)

    for index, token in enumerate(parts):
        if index in _SKIP_TOKENS or index >= len(TOKENS):
            continue

        value: Any = _decode_token(token, keys, nonce)

        if index == 7:
            value = _ssh_endpoint(value)
        elif index == 11:
            value = _pair_credentials(value)

        if not isinstance(value, str) or not value:
            continue
        value = value.replace(FIELD_MARKER, "")
        if not value:
            continue

        if value[:1] in "{[":
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass

        if isinstance(value, str) and looks_hex(value):
            continue
        fields[TOKENS[index]] = value

    return fields


def _decode_token(token: str, keys: tuple[bytes, ...], nonce: bytes) -> str:
    if not token or token.startswith("<") or token in {
        "true", "false", "lifeTime", "[splitPsiphon][splitPsiphon]"
    }:
        return token

    for blob in _token_bytes(token):
        if len(blob) <= 16:
            continue
        for key in keys:
            plain = _stream_decrypt(key, nonce, blob[:-16])
            try:
                text = plain.decode("utf-8")
            except UnicodeDecodeError:
                continue
            unwrapped = _jkl_decode(text)
            if unwrapped != text and _readable(unwrapped):
                return unwrapped
            if _looks_like_config(text):
                return text

    for is_new in (True, False):
        candidate = _jkl_decode(token, is_new)
        if candidate != token and _readable(candidate):
            return candidate

    return token


def _token_bytes(token: str) -> list[bytes]:
    out: list[bytes] = []
    digits = hex_chars_only(token)
    if len(digits) >= 32:
        if len(digits) % 2:
            digits = "0" + digits
        try:
            out.append(bytes.fromhex(digits))
        except ValueError:
            pass
    for encoding in ("latin-1", "utf-8"):
        try:
            out.append(token.encode(encoding))
        except UnicodeEncodeError:
            continue
    return [blob for blob in out if len(blob) > 16]


def _jkl_decode(value: str, modern: bool = False) -> str:
    """The bespoke XOR-and-mask layer some fields carry."""
    key = JKL_KEY_NEW if modern else JKL_KEY_OLD
    padded = value + "=" * (-len(value) % 4)
    try:
        first = base64.b64decode(padded, validate=True)
    except (ValueError, base64.binascii.Error):
        return value

    scramble = bytearray(first)
    for index, byte in enumerate(scramble):
        noise = key[index % len(key)]
        scramble[index] = (
            (((byte ^ 0xFF) & 0xCA) | (byte & 0x35))
            ^ (((noise ^ 0xFF) & 0xCA) | (noise & 0x35))
        )
    try:
        second = base64.b64decode(bytes(scramble).decode("latin-1"), validate=True)
        return second.decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        return value


def _readable(text: str) -> bool:
    if len(text) < 4:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\r\n")
    return printable / len(text) > 0.9


def _looks_like_config(text: str) -> bool:
    if len(text) < 4 or not _readable(text):
        return False
    return any(token in text for token in ("HTTP", "://", "@", "{\""))


def _rst_decode(value: str) -> str | None:
    """XOR with 2..21, base64, then AES-128-ECB with the RST passphrases."""
    try:
        masked = bytes(byte ^ RST_MASK[i % len(RST_MASK)] for i, byte in enumerate(value.encode("utf-8")))
        blob = base64.b64decode(masked)
    except (ValueError, base64.binascii.Error):
        return None

    for passphrase in RST_KEYS:
        key = hashlib.sha1(passphrase).digest()[:16]
        try:
            plain = pkcs7_unpad(aes_ecb_decrypt(key, blob), strict=True)
            text = plain.decode("utf-8")
        except (DecryptError, UnicodeDecodeError):
            continue
        if SPLIT in text:
            return text
    return None


def _hex_stream(value: str, key: bytes, nonce: bytes) -> str:
    """Hex-in, ChaCha20-out, dropping the trailing 16-byte block."""
    digits = hex_chars_only(value)
    if len(digits) < 34:
        return ""
    if len(digits) % 2:
        digits = "0" + digits
    try:
        blob = bytes.fromhex(digits)
    except ValueError:
        return ""
    return _stream_decrypt(key, nonce, blob[:-16]).decode("utf-8", "replace")


# ------------------------------------------------------------- credentials


def _ssh_endpoint(value: str) -> str:
    """``host:port@user:pass`` where the credentials are decimal-coded."""
    if not value:
        return value
    if value[0] in BRAILLE:
        value = _braille(value)

    match = _SSH_ENDPOINT.match(value)
    if not match:
        return value
    host, port, user, password = match.groups()
    return f"{host}:{port}@{_decimal_pair(user) or user}:{_decimal_pair(password) or password}"


def _pair_credentials(value: str) -> str:
    match = _CREDENTIALS.match(value)
    if not match:
        return value
    user, password = match.groups()
    return f"{_decimal_pair(user) or user}:{_decimal_pair(password) or password}"


def _decimal_pair(value: str) -> str:
    """``a.b`` pairs minus an index-derived shift, each byte a power-of-two divisor."""
    pairs = _DECIMAL_PAIR.findall(value)
    if not pairs:
        return ""
    shift = len(pairs)
    out = bytearray()
    for left, right in pairs:
        divisor = 1 << int(right)
        if divisor:
            out.append((int(left) - shift) // divisor % 256)
    return out.decode("utf-8", "ignore")


def _braille(value: str) -> str:
    try:
        raw = bytes(
            (BRAILLE.index(value[i]) * 16 + BRAILLE.index(value[i + 1])) & 0xFF
            for i in range(0, len(value) - 1, 2)
        )
    except ValueError:
        return value
    return raw.decode("utf-8", "ignore")


# ------------------------------------------------------------- legacy family


def _legacy(data: bytes) -> dict[str, Any] | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 16:
        return None

    unmasked = bytes(
        (ord(ch) ^ ord(LEGACY_XOR[i % len(LEGACY_XOR)])) & 0xFF
        for i, ch in enumerate(text)
    )
    try:
        blob = b64_decode(unmasked.decode("latin-1"))
    except DecryptError:
        return None
    if not blob or len(blob) % 16:
        return None

    for passphrase in LEGACY_PASSPHRASES:
        key = hashlib.sha1(passphrase.encode()).digest()[:16]
        try:
            plain = pkcs7_unpad(aes_ecb_decrypt(key, blob), strict=False)
            decoded = plain.decode("utf-8")
        except (DecryptError, UnicodeDecodeError):
            continue
        if SPLIT not in decoded:
            continue
        fields = {}
        for index, part in enumerate(decoded.split(SPLIT)):
            if index in _SKIP_TOKENS or index >= len(TOKENS):
                continue
            value = part.strip()
            if value:
                fields[TOKENS[index]] = value
        return _result({"fields": fields}, ["legacy CJK-XOR layout"])
    return None


# ----------------------------------------------------------- envelope family


def _envelope(data: bytes) -> dict[str, Any] | None:
    if b"HCCFG" in data[:512]:
        raise UnsupportedFormat(
            "this .hc file uses the HCCFG container, which is not supported yet; "
            "re-export it as a plain .hc or share the config as JSON"
        )
    return None
