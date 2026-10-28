"""Format recognition and dispatch.

Two entry points:

``identify(data, name)``
    Returns ``(format, hint, confident)`` without decrypting anything.

``decrypt(data, name, password)``
    Dispatches to the right implementation and returns the common result::

        {"format": str, "config": dict, "links": [str], "notes": [str]}

``decrypt_any(data, name, passwords)``
    The same, trying a list of candidate passwords (from a post caption) after
    an attempt without one.

When the format is obvious from the extension, a magic value or a URI scheme,
only that implementation runs and its errors reach the caller unchanged. When
it is not obvious, every plausible implementation is tried in turn and the most
specific error is raised if none succeeds.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .errors import BadPassword, DecryptError, PasswordRequired, UnsupportedFormat
from .formats import ehi, hat, http_custom, netmod, npvt, slipnet, v2box

# Prefixes that a NetMod link can carry: nm-vless://, nm-vmess://, ...
_NETMOD_LINK = re.compile(r"^nm-([a-z0-9]+)://", re.IGNORECASE)
_SLIPNET_LINK = re.compile(r"^slipnet-enc://", re.IGNORECASE)

_BY_EXTENSION = {
    ".ehi": "ehi",
    ".hat": "hat",
    ".hc": "http_custom",
    ".nm": "netmod",
    ".npvt": "npvt",
    ".npvtsub": "npvt",
    ".npvs": "npvt",
    ".v2box": "v2box",
}

# Formats with a working implementation, in the order used when guessing.
_GUESS_ORDER = ("ehi", "v2box", "npvt", "http_custom", "netmod", "hat")

# Formats that can ask for a password, and how to tell they are worth asking
# about when the file name says nothing.
_LOOKS = {"http_custom": http_custom.looks_like, "npvt": npvt.looks_like}

_MAX_GUESS_BYTES = 4 * 1024 * 1024


def _text(data: bytes) -> str:
    """ASCII-ish view used for scheme and JSON sniffing."""
    try:
        return data.decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        return data[:512].decode("latin-1", "ignore").strip()


def identify(data: bytes, name: str = "") -> tuple[str, dict[str, Any], bool]:
    """Return ``(format, hints, confident)`` for a payload."""
    from pathlib import Path

    lowered = (name or "").lower()
    suffix = Path(lowered).suffix
    text = _text(data)

    if _SLIPNET_LINK.match(text):
        return "slipnet", {"payload": text}, True
    match = _NETMOD_LINK.match(text)
    if match:
        return "netmod", {"payload": text, "proto": match.group(1).lower()}, True

    if data[:4] == b"\x00\x03ehi":
        return "ehi", {}, True

    if data[:4] == b"NPVS" or data[:5] == b"NPVO1":
        return "npvt", {}, True
    head = data[:4096]
    if b"NPVT1" in head or b"NPVTSUB1" in head:
        return "npvt", {}, True

    stripped = text.lstrip()
    if stripped.startswith("{") and v2box.looks_like(data, name):
        return "v2box", {}, True

    if suffix in _BY_EXTENSION:
        return _BY_EXTENSION[suffix], {}, True

    # No magic value, scheme or useful extension: the caller has to guess.
    return "unknown", {}, False


def decrypt(data: bytes, name: str = "", password: str | None = None) -> dict[str, Any]:
    """Decrypt one export and return its normalised result."""
    if not isinstance(data, (bytes, bytearray)):
        raise DecryptError("payload must be bytes")
    if len(data) > _MAX_GUESS_BYTES:
        raise DecryptError("file is larger than the 4 MiB limit")

    fmt, hints, confident = identify(bytes(data), name)

    if confident:
        return _run(fmt, bytes(data), hints, password)

    return _guess(bytes(data), name, hints, password)


def decrypt_any(
    data: bytes, name: str = "", passwords: Iterable[str] = ()
) -> dict[str, Any]:
    """Decrypt without a password first, then with each candidate in turn.

    A file that needs a key fails while no password is supplied and succeeds
    once the right one from the post caption is passed, so trying ``None`` first
    keeps unprotected files on the fast path. If nothing works, a password
    failure is preferred over "unknown format" in the raised error.
    """
    attempts: list[str | None] = [None]
    for password in passwords:
        if password and password not in attempts:
            attempts.append(password)

    error: DecryptError | None = None
    for password in attempts:
        try:
            return decrypt(data, name=name, password=password)
        except DecryptError as exc:
            if exc.code in ("password_required", "bad_password"):
                # A password failure says more than "unknown format".
                error = exc
            elif error is None:
                error = exc

    assert error is not None
    raise error


def _guess(
    data: bytes, name: str, hints: dict[str, Any], password: str | None
) -> dict[str, Any]:
    errors: list[DecryptError] = []
    password_error: DecryptError | None = None

    for fmt in _GUESS_ORDER:
        try:
            return _run(fmt, data, {}, password)
        except (PasswordRequired, BadPassword) as exc:
            # Only meaningful when the payload actually looks like that format;
            # otherwise every unknown file would turn into a password prompt.
            if fmt in _LOOKS and _LOOKS[fmt](data):
                password_error = exc
            else:
                errors.append(exc)
        except DecryptError as exc:
            errors.append(exc)

    # A payload that matches a format but needs a key is worth asking about.
    if password_error is not None:
        raise password_error

    # Prefer the most specific explanation when everything failed.
    for exc in errors:
        if isinstance(exc, UnsupportedFormat):
            raise exc
    raise UnsupportedFormat(
        "payload is not a recognised VPN config export; supported: .v2box, .ehi, "
        ".hat, .hc, .nm, slipnet-enc:// and nm-*:// links"
    )


def _strip_scheme(value: bytes | str) -> bytes | str:
    """Drop a ``scheme://`` prefix, keeping the rest untouched."""
    text = value.strip() if isinstance(value, str) else value
    if isinstance(text, str) and "://" in text[:20]:
        return text.split("://", 1)[1]
    return text


def _run(fmt: str, data: bytes, hints: dict[str, Any], password: str | None) -> dict[str, Any]:
    if fmt == "ehi":
        return ehi.decrypt(data)
    if fmt == "hat":
        return hat.decrypt(data)
    if fmt == "netmod":
        return netmod.decrypt(_strip_scheme(hints.get("payload", data)), proto=hints.get("proto"))
    if fmt == "slipnet":
        return slipnet.decrypt(_strip_scheme(hints.get("payload", data)))
    if fmt == "http_custom":
        return http_custom.decrypt(data, password=password)
    if fmt == "v2box":
        return v2box.decrypt(data, password=password)
    if fmt == "npvt":
        return npvt.decrypt(data, password=password)
    raise UnsupportedFormat(f"unrecognised file type ({fmt})")
