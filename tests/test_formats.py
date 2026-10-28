"""Round-trip tests over synthetic exports.

No real user config is checked in: every fixture is built here from the format
facts (keys, layout), encrypted locally, then handed to the decryptor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import os

import pytest
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vpndecrypt import decrypt, identify
from vpndecrypt.errors import DecryptError, PasswordRequired, UnsupportedFormat


# ------------------------------------------------------------------ fixtures


def _pad(raw: bytes, block: int = 16) -> bytes:
    missing = block - len(raw) % block
    return raw + bytes([missing]) * missing


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def make_hat(config: dict) -> bytes:
    key = hashlib.sha1(b"8515D40BD04D8C97").digest()[:16]
    plain = _pad(json.dumps(config).encode("utf-8"))
    return _b64(AES.new(key, AES.MODE_ECB).encrypt(plain)).encode("ascii")


def make_netmod(body: str, key: bytes = b"<n3t5yn4^n3tm0d>") -> bytes:
    plain = _pad(body.encode("utf-8"))
    return _b64(AES.new(key, AES.MODE_ECB).encrypt(plain)).encode("ascii")


def make_v2box(payload: dict, password: str | None = None) -> bytes:
    key = hashlib.sha256(password.encode()).digest() if password else b"V2BoxEncryptionKey2026_Secret!#%"
    nonce = bytes(range(12))
    sealed = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), None)
    envelope = {
        "ciphertext": _b64(sealed[:-16]),
        "isPasswordProtected": password is not None,
        "magic": "v2box_export",
        "nonce": _b64(nonce),
        "tag": _b64(sealed[-16:]),
        "version": 1,
    }
    return json.dumps(envelope).encode("utf-8")


def make_slipnet(fields: str) -> str:
    key = bytes.fromhex("214F052025B2F949605A5429EC3D5FA80C2022C168AD946E68852D447214DBD3")
    nonce = bytes(range(12))
    sealed = AESGCM(key).encrypt(nonce, fields.encode("utf-8"), None)
    return "slipnet-enc://" + _b64(b"\x1c" + nonce + sealed)


def make_hc(content: str, hwid: str = "", area: str = "") -> bytes:
    """A ``.hc`` export in the v2.6+ stream shape."""
    from Crypto.Cipher import ChaCha20

    envelope = json.dumps({"cfg": {"content": content, "b": hwid, "f": area}}).encode("utf-8")
    cipher = ChaCha20.new(key=bytes.fromhex(
        "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"
    ), nonce=b"\xdb" * 8)
    cipher.seek(64)
    sealed = cipher.encrypt(envelope) + bytes(16)
    masked = bytes(
        b ^ bytes.fromhex("e382e4b8adc386f09f9293")[i % 11]
        for i, b in enumerate(sealed.hex().encode("ascii"))
    )
    # Exporters write the masked bytes as latin-1 text, so the file is UTF-8.
    return masked.decode("latin-1").encode("utf-8")


def rst_wrap(tokens: str, passphrase: bytes = b"JN1k3YHc2.6_v235") -> str:
    """The AES-128-ECB layer that ``cfg.content`` normally holds."""
    key = hashlib.sha1(passphrase).digest()[:16]
    blob = AES.new(key, AES.MODE_ECB).encrypt(_pad(tokens.encode("utf-8")))
    text = base64.b64encode(blob)
    masked = bytes(b ^ (i % 20 + 2) for i, b in enumerate(text))
    return masked.decode("ascii")


def make_npvt(payload: dict) -> bytes:
    """An ``NPVT1`` token: 16-byte counter + white-box AES-CTR body."""
    from vpndecrypt.formats import npvt

    plain = json.dumps(payload).encode("utf-8")
    nonce = bytes(range(16))
    token = base64.b64encode(nonce + npvt._ctr(nonce, plain)).decode("ascii")
    return f"NPVT1{token}".encode("ascii")


def make_npvs_v1(payload: dict, password: str | None = None) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    header: dict = {"configId": "test", "policy": {"displayMessage": "hello"}}
    dek = os.urandom(32)
    if password:
        salt = os.urandom(16)
        wrap_nonce = os.urandom(12)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000, 32)
        wrap = wrap_nonce + ChaCha20Poly1305(derived).encrypt(wrap_nonce, dek, salt)
        header["passphrase"] = {
            "salt": base64.urlsafe_b64encode(salt).decode().rstrip("="),
            "wrap": base64.urlsafe_b64encode(wrap).decode().rstrip("="),
            "iters": 1000,
        }
    header_raw = json.dumps(header).encode("utf-8")
    nonce = os.urandom(12)
    body = ChaCha20Poly1305(dek).encrypt(nonce, json.dumps(payload).encode("utf-8"), header_raw)
    return (
        b"NPVS\x01"
        + struct.pack(">I", len(header_raw))
        + header_raw
        + nonce
        + struct.pack(">I", len(body))
        + body
    )


def make_npvs_v5(payload: dict, password: str) -> bytes:
    """A Gen-2 container sealed with a passphrase and an ``NPF`` field table."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = os.urandom(32)
    config_id = os.urandom(16)
    content_id = os.urandom(32)
    nonce = os.urandom(12)
    salt = os.urandom(16)
    iterations = 1000

    fields = {
        1: b'"a.example"',
        2: b"443",
        3: b"6",
        4: b'"secret"',
        5: b'"tls"',
        6: b'"a.example"',
        0xFFFF: json.dumps(payload).encode("utf-8"),
    }
    body = bytearray(b"NPF\x01" + content_id + struct.pack(">H", len(fields)))
    for seq, plain in fields.items():
        field_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=content_id,
            info=b"NPV-fields-v1/field/" + struct.pack(">H", seq),
        ).derive(key)
        aad = (
            b"NPV-fields-v1/record/" + content_id + struct.pack(">H", seq)
            + struct.pack(">I", len(plain))
        )
        blob = ChaCha20Poly1305(field_key).encrypt(bytes(12), plain, aad)
        body += struct.pack(">HHH", seq, 0, len(blob)) + blob

    header = bytearray(53)
    header[0] = 1
    header[1:17] = config_id
    header[50] = 1
    header[51:53] = struct.pack(">H", 0)
    kdk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, 32)
    wrap_nonce = os.urandom(12)
    wrap = wrap_nonce + ChaCha20Poly1305(kdk).encrypt(wrap_nonce, key, salt)
    header += struct.pack(">I", iterations) + salt + wrap

    prefix = bytes(header)
    meta_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=nonce, info=b"NPVS-v5/metadata"
    ).derive(key)
    meta = ChaCha20Poly1305(meta_key).encrypt(nonce, b'{"policy":{}}', prefix)
    header += struct.pack(">I", len(meta)) + meta

    return (
        b"NPVS\x05"
        + struct.pack(">I", len(header))
        + bytes(header)
        + nonce
        + struct.pack(">I", len(body))
        + bytes(body)
    )


# --------------------------------------------------------------------- tests


def test_hat_roundtrip() -> None:
    config = {"profilev5": {"primary_host": "example.com", "server_port": 80}, "enabled": True}
    data = make_hat(config)

    assert identify(data, "x.hat")[0] == "hat"
    result = decrypt(data, "x.hat")
    assert result["format"] == "hat"
    assert result["config"]["profilev5"]["primary_host"] == "example.com"


def test_hat_detected_without_extension() -> None:
    data = make_hat({"a": 1})
    assert identify(data, "blob.bin")[2] is False
    assert decrypt(data, "blob.bin")["format"] == "hat"


def test_netmod_file_roundtrip() -> None:
    config = {"Payload": {"Value": "GET / HTTP/1.1[crlf][crlf]", "Locked": True}}
    data = make_netmod(json.dumps(config))

    assert identify(data, "x.nm")[0] == "netmod"
    result = decrypt(data, "x.nm")
    assert result["config"]["Payload"]["Locked"] is True


def test_netmod_link_carries_scheme() -> None:
    vless = (
        "11111111-2222-3333-4444-555555555555@www.example.com:443"
        "?encryption=none&type=ws&security=tls#Test"
    )
    link = "nm-vless://" + _b64(AES.new(b"<n3t5yn4^n3tm0d>", AES.MODE_ECB).encrypt(_pad(vless.encode())))

    fmt, hints, confident = identify(link.encode(), "pasted.txt")
    assert (fmt, hints["proto"], confident) == ("netmod", "vless", True)

    result = decrypt(link.encode(), "pasted.txt")
    assert result["links"] == ["vless://" + vless]


def test_v2box_vless_profile() -> None:
    payload = {
        "configs": [
            {
                "configType": "VLESS",
                "remarks": "Test node",
                "server": "example.com",
                "serverPort": 2095,
                "id": "11111111-2222-3333-4444-555555555555",
                "security": "tls",
                "sni": "example.com",
                "network": "ws",
                "path": "/ws",
            }
        ],
        "raws": {},
    }
    result = decrypt(make_v2box(payload), "x.v2box")
    assert result["format"] == "v2box"
    assert len(result["links"]) == 1
    link = result["links"][0]
    assert link.startswith("vless://11111111-2222-3333-4444-555555555555@example.com:2095?")
    assert "security=tls" in link and "path=%2Fws" in link


def test_v2box_password_flow() -> None:
    payload = {"configs": [{"configType": "TROJAN", "server": "a.example", "serverPort": 443, "password": "p"}]}
    data = make_v2box(payload, password="hunter2")

    with pytest.raises(PasswordRequired):
        decrypt(data, "x.v2box")
    with pytest.raises(DecryptError) as excinfo:
        decrypt(data, "x.v2box", password="wrong")
    assert excinfo.value.code == "bad_password"

    result = decrypt(data, "x.v2box", password="hunter2")
    assert result["links"][0].startswith("trojan://p@a.example:443")


def test_slipnet_link() -> None:
    fields = "|".join(
        ["28", "dnstt_ssh", "Test", "example.com", "8.8.8.8:53:0", "0", "5000", "bbr", "1080", "127.0.0.1", "0"]
    )
    link = make_slipnet(fields)

    assert identify(link.encode(), "pasted.txt")[0] == "slipnet"
    result = decrypt(link.encode(), "pasted.txt")
    profile = result["config"]["profile"]
    assert profile["Version"] == "28"
    assert profile["Name"] == "Test"
    assert profile["Domain"] == "example.com"


def test_slipnet_rejects_tampered_tag() -> None:
    link = make_slipnet("28|" + "x" * 20)
    body = bytearray(base64.b64decode(link.split("://", 1)[1]))
    body[-1] ^= 0xFF
    with pytest.raises(DecryptError):
        decrypt(b"slipnet-enc://" + base64.b64encode(bytes(body)), "pasted.txt")


def test_hc_stream_with_rst_content() -> None:
    tokens = "[splitConfig]".join(
        [
            "GET / HTTP/1.1[crlf]Host: example.com[crlf][crlf]",  # payload
            "proxy.example:8080",
            "false",
            "false",
            "0",
            "false",
            "",
            "ssh.example:22@root:secret",
            "false",
            "false",
        ]
    )
    result = decrypt(make_hc(rst_wrap(tokens), hwid="ABC"), "x.hc")

    assert result["format"] == "http_custom"
    fields = result["config"]["fields"]
    assert fields["payload"].startswith("GET / HTTP/1.1")
    assert fields["sshServer"] == "ssh.example:22@root:secret"
    assert result["config"]["protections"]["hwid"] == "ABC"


def test_hc_stream_with_plain_content() -> None:
    tokens = "[splitConfig]".join(["keep-alive", "host.example:80"])
    result = decrypt(make_hc(tokens), "x.hc")
    assert result["config"]["fields"]["payload"] == "keep-alive"


def test_npvt_token_roundtrip() -> None:
    payload = {
        "configs": [
            {
                "v2rayProfile": {
                    "configType": 5,
                    "server": "a.example",
                    "serverPort": 443,
                    "password": "11111111-2222-3333-4444-555555555555",
                    "security": "tls",
                    "network": "ws",
                    "path": "/ws",
                }
            }
        ]
    }
    data = make_npvt(payload)

    assert identify(data, "x.npvt")[0] == "npvt"
    result = decrypt(data, "x.npvt")
    assert result["format"] == "npvt"
    assert result["links"][0].startswith("vless://11111111-2222-3333-4444-555555555555@a.example:443?")
    assert "path=%2Fws" in result["links"][0]


def test_npvs_v1_password_flow() -> None:
    payload = {"configs": [{"sshConfig": {"sshHost": "ssh.example", "sshPort": 22, "sshUsername": "root"}}]}
    data = make_npvs_v1(payload, password="hunter2")

    assert identify(data, "x.npvs")[0] == "npvt"
    with pytest.raises(PasswordRequired):
        decrypt(data, "x.npvs")
    with pytest.raises(DecryptError) as excinfo:
        decrypt(data, "x.npvs", password="wrong")
    assert excinfo.value.code == "bad_password"

    result = decrypt(data, "x.npvs", password="hunter2")
    assert result["links"][0].startswith("ssh://root:@ssh.example:22?")


def test_npvs_v5_field_table() -> None:
    # Every value in a Gen-2 table is a sequence number, not a literal.
    payload = {
        "configs": [
            {
                "v2rayProfile": {
                    "configType": 3,
                    "server": 1,
                    "serverPort": 2,
                    "password": 4,
                    "security": 5,
                    "sni": 6,
                }
            }
        ]
    }
    data = make_npvs_v5(payload, password="hunter2")

    with pytest.raises(PasswordRequired):
        decrypt(data, "x.npvs")
    with pytest.raises(DecryptError) as excinfo:
        decrypt(data, "x.npvs", password="nope")
    assert excinfo.value.code == "bad_password"

    result = decrypt(data, "x.npvs", password="hunter2")
    assert result["links"] == [
        "trojan://secret@a.example:443?security=tls&sni=a.example&type=tcp#NPVS"
    ]


def test_npvt_plain_json_export() -> None:
    payload = {"configs": [{"socksConfig": {"server": "p.example", "serverPort": 1080, "username": "u"}}]}
    result = decrypt(json.dumps(payload).encode(), "x.npvs")
    assert result["links"][0].startswith("socks://p.example:1080?")

    with pytest.raises(DecryptError):
        decrypt(b"nothing useful here", "x.npvt")


def test_garbage_hc_asks_for_password() -> None:
    # Without format markers we cannot tell a locked export from a broken one,
    # so the user is asked for the password and told it may be unsupported.
    with pytest.raises(DecryptError) as excinfo:
        decrypt(b"\x00\x11\x22\x33" * 64, "x.hc")
    assert excinfo.value.code == "password_required"
    assert "HTTP Custom" in str(excinfo.value) or ".hc" in str(excinfo.value)

    with pytest.raises(DecryptError) as excinfo:
        decrypt(b"\x00\x11\x22\x33" * 64, "x.hc", password="whatever")
    assert excinfo.value.code == "bad_password"


def test_ehi_bad_container_is_rejected() -> None:
    with pytest.raises(DecryptError):
        decrypt(b"\x00\x03ehi\x00\x00\x00\x01", "x.ehi")


def test_size_limit() -> None:
    with pytest.raises(DecryptError):
        decrypt(b"x" * (5 * 1024 * 1024), "big.bin")


# ---------------------------------------------------------------- passwords


def test_caption_passwords_are_extracted() -> None:
    from vpndecrypt import extract_passwords

    caption = (
        "🔥سری جدید کانفیگ‌های پرسرعت HTTP Custom\n\n"
        "✅ سازگار با همه اپراتورها\n\n"
        "🔓Password: @DigiHubAI\n\n"
        "⚠️برای استفاده از کانفیگ‌ها نسخه آخر را نصب کنید."
    )
    assert extract_passwords(caption)[:2] == ["@DigiHubAI", "DigiHubAI"]

    assert extract_passwords("🔑 کلید/Passphrase این فایل پیدا نشد") == []
    assert extract_passwords("Pass = s3cret, user: bob") == ["s3cret"]
    assert extract_passwords("pwd:hunter2") == ["hunter2"]
    assert extract_passwords("Password: **topsecret**") == ["topsecret"]
    assert extract_passwords("no label here") == []
    assert extract_passwords(None) == []


def test_decrypt_any_uses_caption_password() -> None:
    from vpndecrypt import decrypt_any

    payload = {"configs": [{"configType": "TROJAN", "server": "a.example", "serverPort": 443, "password": "p"}]}
    data = make_v2box(payload, password="hunter2")

    # Wrong candidate first, right one second: the right one still wins.
    result = decrypt_any(data, "x.v2box", ["nope", "hunter2"])
    assert result["links"][0].startswith("trojan://p@a.example:443")

    with pytest.raises(PasswordRequired):
        decrypt_any(data, "x.v2box", [])


def test_hc_password_required_then_bad_password() -> None:
    # A locked/newer build: nothing opens it, with or without a password.
    locked = bytes(x ^ bytes.fromhex("e382e4b8adc386f09f9293")[i % 11] for i, x in enumerate(os.urandom(400)))

    with pytest.raises(PasswordRequired):
        decrypt(locked, "x.hc")
    with pytest.raises(DecryptError) as excinfo:
        decrypt(locked, "x.hc", password="@DigiHubAI")
    assert excinfo.value.code == "bad_password"


def test_unknown_file_without_hc_markers_is_unsupported() -> None:
    # A masked .hc is offered the password prompt even when renamed; random
    # binary is not, so it is reported as an unknown format instead.
    with pytest.raises(UnsupportedFormat):
        decrypt(b"just some random bytes, not a config" * 4, "blob.bin")
