"""HTTP API for the VPN config decryptor.

Run with::

    uvicorn api.main:app --host 0.0.0.0 --port 8000

``POST /decrypt`` accepts three body shapes so that curl, a file picker and a
JSON client all work without separate routes:

* ``multipart/form-data`` with a ``file`` field (optional ``password`` /
  ``caption`` fields)
* ``application/json`` with ``{"text": "...", "name": "...", "password": "..."}``
* a raw body, with ``?name=`` / ``?password=`` query parameters

``caption`` is the text of the channel post the file came from. A password
written in it (``🔓Password: @DigiHubAI``) is read automatically, so a caller
that forwards the post does not have to parse it.

Every failure returns ``{"error": {"code": ..., "message": ...}}`` with a stable
``code``, so clients never have to parse prose.
"""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vpndecrypt import __version__, decrypt_any, extract_passwords, identify
from vpndecrypt.errors import DecryptError

MAX_BYTES = 2 * 1024 * 1024

STATUS_BY_CODE = {
    "unsupported_format": 415,
    "not_encrypted": 400,
    "password_required": 401,
    "bad_password": 403,
    "hardware_locked": 403,
    "decrypt_failed": 422,
}

SUPPORTED = [
    {"id": "v2box", "extensions": [".v2box"], "name": "V2Box"},
    {"id": "ehi", "extensions": [".ehi"], "name": "HTTP Injector"},
    {"id": "hat", "extensions": [".hat"], "name": "HA Tunnel Plus"},
    {"id": "http_custom", "extensions": [".hc"], "name": "HTTP Custom"},
    {"id": "netmod", "extensions": [".nm", "nm-*://"], "name": "NetMod"},
    {"id": "npvt", "extensions": [".npvt", ".npvtsub", ".npvs"], "name": "NPVTunnel"},
    {"id": "slipnet", "extensions": ["slipnet-enc://"], "name": "SlipNet"},
]

app = FastAPI(
    title="VPN Decryptor",
    description="Decrypts the export formats used by V2Box, HTTP Injector, "
                "HA Tunnel Plus, HTTP Custom, NetMod, NPVTunnel and SlipNet.",
    version=__version__,
)


def _error(code: str, message: str, status: int | None = None) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message}},
        status_code=status or STATUS_BY_CODE.get(code, 400),
    )


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


@app.get("/formats")
async def formats() -> dict[str, Any]:
    return {"supported": SUPPORTED, "pending": []}


@app.get("/")
async def index() -> dict[str, Any]:
    return {
        "service": "vpn-decryptor",
        "version": __version__,
        "endpoints": ["POST /decrypt", "GET /formats", "GET /health"],
    }


@app.post("/decrypt")
async def decrypt_route(request: Request) -> Any:
    try:
        payload, name, passwords = await _read_body(request)
    except ValueError as exc:
        return _error("decrypt_failed", str(exc), 400)

    if not payload:
        return _error("decrypt_failed", "no payload received", 400)
    if len(payload) > MAX_BYTES:
        return _error(
            "decrypt_failed",
            f"file is larger than the {MAX_BYTES // 1024 // 1024} MiB limit",
            413,
        )

    try:
        result = decrypt_any(payload, name=name, passwords=passwords)
    except DecryptError as exc:
        return _error(exc.code, str(exc))

    result["detected"] = identify(payload, name)[0]
    return JSONResponse(result)


async def _read_body(request: Request) -> tuple[bytes, str, list[str]]:
    """Return ``(payload, name, password candidates)`` from any accepted shape."""
    content_type = request.headers.get("content-type", "")

    if content_type.startswith("multipart/form-data") or content_type.startswith(
        "application/x-www-form-urlencoded"
    ):
        form = await request.form()
        passwords = _passwords(form.get("password"), form.get("caption"))
        if "text" in form:
            text = _clean(form.get("text")) or ""
            return text.encode("utf-8"), _clean(form.get("name")) or "config", passwords
        upload = form.get("file")
        if upload is None or not hasattr(upload, "read"):
            raise ValueError("expected a 'file' or 'text' field")
        name = _clean(form.get("name")) or getattr(upload, "filename", "") or "config"
        return await upload.read(), name, passwords

    if content_type.startswith("application/json"):
        try:
            body = await request.json()
        except json.JSONDecodeError as exc:
            raise ValueError("body is not valid JSON") from exc
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        passwords = _passwords(
            body.get("password"),
            body.get("caption"),
            body.get("post"),
        )
        name = _clean(body.get("name")) or "config"
        if isinstance(body.get("text"), str):
            return body["text"].encode("utf-8"), name, passwords
        if isinstance(body.get("base64"), str):
            import base64

            try:
                raw = base64.b64decode(body["base64"])
            except ValueError as exc:
                raise ValueError("'base64' is not valid base64") from exc
            return raw, name, passwords
        raise ValueError("JSON body needs a 'text' or 'base64' field")

    raw = await request.body()
    return (
        raw,
        request.query_params.get("name") or "config",
        _passwords(
            request.query_params.get("password"),
            request.query_params.get("caption"),
            request.query_params.get("post"),
        ),
    )


def _passwords(*values: Any) -> list[str]:
    """Explicit passwords first, then anything labelled inside a caption."""
    found: list[str] = []
    for value in values:
        text = _clean(value)
        if not text:
            continue
        for candidate in extract_passwords(text) or [text]:
            if candidate not in found:
                found.append(candidate)
    return found


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


if os.environ.get("VPN_ALLOW_ORIGINS"):
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            origin.strip()
            for origin in os.environ["VPN_ALLOW_ORIGINS"].split(",")
            if origin.strip()
        ],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
