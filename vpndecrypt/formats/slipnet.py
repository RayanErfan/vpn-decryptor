"""SlipNet (``slipnet-enc://``) profiles.

AES-256-GCM with a fixed app key. Byte 0 of the blob is the format version, the
next 12 bytes are the nonce and the remainder is ciphertext followed by the tag.
The plaintext is a pipe-delimited record; field names depend on the version.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import DecryptError
from .base import b64_decode

KEY = bytes.fromhex("214F052025B2F949605A5429EC3D5FA80C2022C168AD946E68852D447214DBD3")
NONCE_SIZE = 12

_V1 = ["Version", "Tunnel Type/Mode", "Name", "Domain", "Resolvers", "AuthMode",
       "KeepAlive", "CC", "Port", "Host", "GSO"]
_V20 = _V1 + [
    "DNSTT Public Key", "SOCKS Username", "SOCKS Password", "SSH Enabled", "SSH Username",
    "SSH Password", "SSH Port", "Forward DNS thru SSH", "SSH Host", "Use Server DNS",
    "DoH URL", "DNS Transport", "SSH Auth Type", "SSH Private Key (B64)", "SSH Key Passphrase (B64)",
    "Tor Bridge Lines (B64)", "DNSTT Authoritative", "Naive Port", "Naive Username", "Naive Password (B64)",
    "Is Locked", "Lock Password Hash", "Expiration Date", "Allow Sharing", "Bound Device ID",
    "Resolvers Hidden", "Hidden Resolvers", "NoizDNS Stealth", "DNS Payload Size", "SOCKS5 Server Port",
    "VayDNS DNSTT Compat", "VayDNS Record Type", "VayDNS Max Qname Len", "VayDNS RPS", "VayDNS Idle Timeout",
    "VayDNS Keepalive", "VayDNS UDP Timeout", "VayDNS Max Num Labels", "VayDNS Client Id Size",
]
_V21 = _V20 + [
    "SSH TLS Enabled", "SSH TLS SNI", "SSH HTTP Proxy Host", "SSH HTTP Proxy Port", "SSH HTTP Proxy Custom Host",
    "SSH WS Enabled", "SSH WS Path", "SSH WS Use TLS", "SSH WS Custom Host",
]
_V22 = _V21 + ["SSH Payload (B64)"]
_V24 = _V22 + ["Resolver Mode", "RR Spread Count"]
_V25 = _V24 + [
    "VLESS UUID", "VLESS Security", "VLESS Transport", "VLESS WS Path", "CDN IP",
    "CDN Port", "SNI Fragment Enabled", "SNI Fragment Strategy", "SNI Fragment Delay MS", "Legacy SNI (Empty)",
]
_V27 = _V25 + [
    "CH Padding Enabled", "WS Header Obfuscation", "WS Padding Enabled",
    "SNI Spoof TTL", "Fake Decoy Host", "TCP Max Seg",
]
_V28 = _V27 + ["VLESS SNI"]

SCHEMAS: dict[str, list[str]] = {
    "1": _V1,
    "20": _V20, "21": _V21, "22": _V22, "23": _V24, "24": _V24,
    "25": _V25, "26": _V27, "27": _V27, "28": _V28,
}


def decrypt(data: bytes | str) -> dict[str, Any]:
    text = data.decode("ascii", "ignore") if isinstance(data, bytes) else data
    blob = b64_decode(text)
    if len(blob) < 1 + NONCE_SIZE + 16:
        raise DecryptError("slipnet payload is truncated")

    nonce = blob[1 : 1 + NONCE_SIZE]
    sealed = blob[1 + NONCE_SIZE :]
    try:
        plain = AESGCM(KEY).decrypt(nonce, sealed, None)
    except Exception as exc:
        raise DecryptError("slipnet decryption failed") from exc

    fields = plain.decode("utf-8", "replace").rstrip("|").split("|")
    version = fields[0].strip()
    schema = SCHEMAS.get(version)

    profile: dict[str, Any] = {}
    for index, value in enumerate(fields):
        if schema and index < len(schema):
            key = schema[index]
        else:
            key = f"Field{index}"
        profile[key] = value

    return {
        "format": "slipnet",
        "config": {"version": version, "profile": profile},
        "links": _to_link(version, profile),
        "notes": [] if schema else [f"unknown slipnet profile version {version!r}; fields are positional"],
    }


def _to_link(version: str, profile: dict[str, Any]) -> list[str]:
    uuid = profile.get("VLESS UUID", "").strip()
    host = profile.get("Domain", "").strip()
    port = profile.get("Port", "").strip()
    if uuid and host and port:
        transport = profile.get("VLESS Transport", "").strip() or "tcp"
        security = profile.get("VLESS Security", "").strip()
        link = f"vless://{uuid}@{host}:{port}?type={transport}"
        if security:
            link += f"&security={security}"
        name = profile.get("Name", "").strip()
        if name:
            link += "#" + name.replace(" ", "%20")
        return [link]
    return []
