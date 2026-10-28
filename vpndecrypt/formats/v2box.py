"""V2Box (``.v2box``) profile exports.

The file is a JSON envelope: a 12-byte nonce, a 16-byte GCM tag and the
ciphertext, all base64. The key is an app constant, or ``sha256(password)`` when
``isPasswordProtected`` is set. The plaintext is JSON holding a list of profiles
under ``configs`` (older builds: ``a``).

Each profile carries its own connection parameters rather than a ready-made
share URI, so they are rebuilt here: VLESS/Trojan as query strings, VMess as the
base64 JSON blob, Shadowsocks as base64 userinfo.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import urllib.parse
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import BadPassword, DecryptError, PasswordRequired
from .base import b64_decode

MAGIC = "v2box_export"
STATIC_KEY = b"V2BoxEncryptionKey2026_Secret!#%"
NONCE_SIZE = 12
TAG_SIZE = 16

_VLESS_QUERY = (
    "security", "sni", "alpn", "fp", "fingerprint", "pbk", "publicKey", "sid",
    "shortId", "flow", "type", "network", "host", "path", "serviceName",
    "headerType", "allowInsecure", "insecure",
)
_TLS_QUERY = (
    "security", "sni", "alpn", "fp", "fingerprint", "type", "network", "host",
    "path", "serviceName", "headerType", "allowInsecure", "insecure",
)


def looks_like(data: bytes, name: str = "") -> bool:
    if name.lower().endswith(".v2box"):
        return True
    try:
        text = data.decode("utf-8").lstrip()
    except UnicodeDecodeError:
        return False
    return MAGIC in text and '"ciphertext"' in text


def decrypt(data: bytes, password: str | None = None) -> dict[str, Any]:
    try:
        envelope = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptError("not a V2Box export: it is not JSON") from exc
    if not isinstance(envelope, dict) or envelope.get("magic") != MAGIC:
        raise DecryptError("not a V2Box export: wrong magic value")

    plaintext = _open(envelope, password)
    try:
        payload = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptError("the V2Box payload is not JSON") from exc
    if not isinstance(payload, dict):
        raise DecryptError("the V2Box payload root is not an object")

    profiles = _profiles(payload)
    links: list[str] = []
    unrebuilt: list[dict[str, Any]] = []
    for profile in profiles:
        link = _to_link(profile)
        if link:
            links.append(link)
        else:
            unrebuilt.append(profile)

    if not links:
        links.extend(_loose_links(payload))

    notes = []
    if unrebuilt:
        notes.append(f"{len(unrebuilt)} profile(s) could not be rebuilt into a share link")
    if envelope.get("expirationTimestamp"):
        notes.append(f"expires at {envelope['expirationTimestamp']}")
    if envelope.get("allowedDeviceIDs"):
        notes.append(f"bound to {len(envelope['allowedDeviceIDs'])} device id(s)")

    return {
        "format": "v2box",
        "config": payload,
        "links": links,
        "notes": notes,
    }


def _open(envelope: dict[str, Any], password: str | None) -> bytes:
    protected = bool(envelope.get("isPasswordProtected"))
    if protected and not password:
        raise PasswordRequired("this V2Box export is password protected")

    try:
        nonce = b64_decode(str(envelope.get("nonce", "")))
        tag = b64_decode(str(envelope.get("tag", "")))
        ciphertext = b64_decode(str(envelope.get("ciphertext", "")))
    except DecryptError as exc:
        raise DecryptError("the V2Box envelope is truncated") from exc

    if len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE or not ciphertext:
        raise DecryptError("the V2Box envelope has invalid field lengths")

    key = hashlib.sha256(password.encode("utf-8")).digest() if protected else STATIC_KEY
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:
        if protected:
            raise BadPassword("incorrect password for this V2Box export") from exc
        raise DecryptError("the V2Box payload failed authentication") from exc


def _profiles(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for field in ("configs", "a"):
        value = payload.get(field)
        if isinstance(value, list):
            items = [item for item in value if isinstance(item, dict)]
            if items:
                return items
    return []


def _first(profile: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = profile.get(key)
        if isinstance(value, bool):
            return "true" if value else "false"
        if value not in (None, ""):
            return str(value)
    return ""


def _port(profile: dict[str, Any]) -> int | None:
    value = profile.get("serverPort")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _query(profile: dict[str, Any], keys: tuple[str, ...]) -> list[tuple[str, str]]:
    pairs = []
    for key in keys:
        value = _first(profile, key)
        if value:
            pairs.append((key, value))
    return pairs


def _fragment(profile: dict[str, Any]) -> str:
    name = _first(profile, "remarks", "description")
    return "#" + urllib.parse.quote(name, safe="") if name else ""


def _to_link(profile: dict[str, Any]) -> str | None:
    kind = str(profile.get("configType", "")).upper()
    server = _first(profile, "server")
    port = _port(profile)
    if not server or port is None:
        return None

    if kind == "VLESS":
        query = _query(profile, _VLESS_QUERY)
        encryption = _first(profile, "encryption", "method")
        if encryption:
            query.insert(0, ("encryption", encryption))
        user = _first(profile, "id", "password")
        return f"vless://{user}@{server}:{port}?{urllib.parse.urlencode(query)}{_fragment(profile)}"

    if kind == "TROJAN":
        query = _query(profile, _TLS_QUERY)
        password = _first(profile, "password")
        return f"trojan://{password}@{server}:{port}?{urllib.parse.urlencode(query)}{_fragment(profile)}"

    if kind == "VMESS":
        body = {
            "v": "2",
            "ps": _first(profile, "remarks", "description"),
            "add": server,
            "port": str(port),
            "id": _first(profile, "id"),
            "aid": _first(profile, "alterId", "aid") or "0",
            "scy": _first(profile, "security") or "auto",
            "net": _first(profile, "network") or "tcp",
            "type": _first(profile, "headerType") or "none",
            "host": _first(profile, "host"),
            "path": _first(profile, "path"),
            "tls": _first(profile, "tls") or ("tls" if _first(profile, "security") == "tls" else ""),
            "sni": _first(profile, "sni"),
        }
        blob = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return "vmess://" + base64.b64encode(blob).decode("ascii")

    if kind in ("SHADOWSOCKS", "SS"):
        method = _first(profile, "method", "encryption")
        password = _first(profile, "password")
        userinfo = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
        plugin = _first(profile, "plugin")
        query = "?" + urllib.parse.urlencode({"plugin": plugin}) if plugin else ""
        return f"ss://{userinfo}@{server}:{port}{query}{_fragment(profile)}"

    return None


def _loose_links(payload: dict[str, Any]) -> list[str]:
    """Fall back to any URI already present in the payload (``raws``/``b``)."""
    from .base import collect_links

    return collect_links(payload)
