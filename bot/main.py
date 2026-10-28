"""Telegram bot for the VPN config decryptor.

Run with::

    BOT_TOKEN=123:abc python -m bot.main

Send a file, or paste a ``slipnet-enc://`` / ``nm-*://`` link or a ``.v2box``
JSON body. The password written in a post is picked up from the caption (or from
the pasted text) automatically; if it is missing or wrong the bot asks for it and
retries with the same document.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import re
from typing import Any

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import Message

from vpndecrypt import __version__, decrypt_any, extract_passwords, identify
from vpndecrypt.errors import DecryptError

MAX_TEXT_BYTES = 64 * 1024
CHUNK = 3800

BRAND = "⚡ <b>VPN Decryptor</b>\nhttps://github.com/RayanErfan"

_LINK = re.compile(r"(?:slipnet-enc|nm-[a-z0-9]+)://[^\s<>\"']+", re.IGNORECASE)


FORMAT_LIST = """<b>Supported files</b>
• <code>.v2box</code> — V2Box
• <code>.ehi</code> — HTTP Injector
• <code>.hat</code> — HA Tunnel Plus
• <code>.hc</code> — HTTP Custom
• <code>.nm</code> — NetMod
• <code>.npvt</code>, <code>.npvtsub</code>, <code>.npvs</code> — NPVTunnel
• <code>nm-vless://</code>, <code>nm-vmess://</code>, … — NetMod links
• <code>slipnet-enc://</code> — SlipNet

<b>Locked files</b>
• Password-protected exports are opened with the password written in the post
  (<code>🔓Password: …</code>); if it is missing I ask for it once."""

START_TEXT = f"""{BRAND}

Send me an encrypted config file and I will return the profile inside it, plus
any share links it contains. A password in the caption is read automatically.

{FORMAT_LIST}"""

HELP_TEXT = """How to use:

1. Attach a config file (as a <i>file</i>, not a photo).
2. Or paste a <code>slipnet-enc://</code> / <code>nm-*://</code> link.
3. Or paste the whole channel post: I will find the link and the
   <code>Password: …</code> line inside it.

If the file is password protected I read the password from the caption first
(for example <code>🔓Password: @DigiHubAI</code>). If it is missing or wrong I
ask for it once, then retry the same file.

Nothing is stored on the server: the file is decrypted in memory and sent back
to you."""

logger = logging.getLogger(__name__)
router = Router()


class Flow(StatesGroup):
    waiting_for_password = State()


# --------------------------------------------------------------------- helpers


async def _send(message: Message, text: str) -> None:
    """Send text in Telegram-sized chunks, splitting on line boundaries."""
    for chunk in _split(text):
        await message.answer(chunk)


def _split(text: str, size: int = CHUNK) -> list[str]:
    if len(text) <= size:
        return [text]

    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        while len(line) > size:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:size])
            line = line[size:]
        if len(current) + len(line) > size:
            chunks.append(current)
            current = ""
        current += line
    if current:
        chunks.append(current)
    return chunks


def _label(fmt: str) -> str:
    return {
        "v2box": "V2Box",
        "ehi": "HTTP Injector",
        "hat": "HA Tunnel Plus",
        "http_custom": "HTTP Custom",
        "netmod": "NetMod",
        "npvt": "NPVTunnel",
        "slipnet": "SlipNet",
    }.get(fmt, fmt)


def _render(result: dict[str, Any]) -> str:
    lines = [f"✅ <b>{_label(result.get('format', '?'))}</b> config decrypted", ""]

    links = result.get("links") or []
    if links:
        lines.append(f"<b>{len(links)} share link(s)</b>")
        for index, link in enumerate(links, start=1):
            lines.append(f"{index}. <code>{html.escape(link)}</code>")
        lines.append("")

    config = result.get("config")
    if config not in (None, "", {}, []):
        lines.append("<b>Config</b>")
        lines.append(f"<pre>{html.escape(_pretty(config))}</pre>")

    for note in result.get("notes") or []:
        lines.append(f"ℹ️ {html.escape(str(note))}")

    lines.append("")
    lines.append(BRAND)
    return "\n".join(lines)


def _pretty(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2)


def _payload_from_text(text: str) -> tuple[bytes, str] | None:
    """Find a config link or a ``.v2box`` JSON body inside a pasted message."""
    match = _LINK.search(text)
    if match:
        return match.group(0).encode("utf-8"), "pasted.txt"

    stripped = text.strip()
    if stripped.startswith("{") and "v2box_export" in stripped[:400]:
        return stripped.encode("utf-8"), "pasted.json"
    return None


def _open(
    payload: bytes, name: str, candidates: list[str] | None = None
) -> tuple[dict[str, Any] | None, DecryptError | None]:
    """Decrypt with no password first, then with each candidate in turn."""
    try:
        return decrypt_any(payload, name=name, passwords=candidates or ()), None
    except DecryptError as exc:
        return None, exc


async def _deliver(
    message: Message, payload: bytes, name: str, candidates: list[str] | None = None
) -> None:
    result, error = _open(payload, name, candidates)
    if result is None:
        assert error is not None
        await message.answer(f"❌ {html.escape(str(error))}\n\n<i>code: {error.code}</i>")
        return
    result["detected"] = identify(payload, name)[0]
    await _send(message, _render(result))


# ---------------------------------------------------------------------- routes


@router.message(CommandStart())
async def on_start(message: Message) -> None:
    await message.answer(START_TEXT)


@router.message(Command("help"))
async def on_help(message: Message) -> None:
    await message.answer(HELP_TEXT)


@router.message(Command("formats"))
async def on_formats(message: Message) -> None:
    await message.answer(FORMAT_LIST)


@router.message(Command("version"))
async def on_version(message: Message) -> None:
    await message.answer(f"vpn-decryptor {__version__}")


@router.message(F.document)
async def on_document(message: Message, bot: Bot, state: FSMContext) -> None:
    document = message.document
    if document is None:
        return
    if document.file_size and document.file_size > MAX_TEXT_BYTES * 64:
        await message.answer("❌ That file is too large for a config export.")
        return

    name = document.file_name or "config"
    buffer = await bot.download(document)
    payload = buffer.read() if hasattr(buffer, "read") else bytes(buffer)

    # The password is usually written in the post right next to the file.
    candidates = extract_passwords(message.caption)
    result, error = _open(payload, name, candidates)

    if result is not None:
        result["detected"] = identify(payload, name)[0]
        await _send(message, _render(result))
        return

    assert error is not None
    if error.code in {"password_required", "bad_password"}:
        await state.set_state(Flow.waiting_for_password)
        await state.update_data(file_id=document.file_id, file_name=name)
        if candidates:
            await message.answer(
                "🔒 The password in the caption did not unlock this file.\n"
                "Send the right password, or /cancel."
            )
        else:
            await message.answer(
                "🔒 This export is password protected.\n"
                "Send the password, or /cancel.\n\n"
                "<i>Tip: keep <code>Password: …</code> in the caption next time and "
                "I will read it automatically.</i>"
            )
        return

    await message.answer(f"❌ {html.escape(str(error))}\n\n<i>code: {error.code}</i>")


@router.message(StateFilter(Flow.waiting_for_password), F.text, ~F.text.startswith("/"))
async def on_password(message: Message, bot: Bot, state: FSMContext) -> None:
    data = await state.get_data()
    file_id = data.get("file_id")
    if not file_id:
        await state.clear()
        await message.answer("Session expired, please send the file again.")
        return

    raw = (message.text or "").strip()
    # Accept both a bare password and a full "Password: …" line.
    candidates = extract_passwords(raw)
    if raw and raw not in candidates:
        candidates.append(raw)

    buffer = await bot.download(file_id)
    payload = buffer.read() if hasattr(buffer, "read") else bytes(buffer)

    result, error = _open(payload, data.get("file_name", "config"), candidates)
    if result is not None:
        await state.clear()
        result["detected"] = identify(payload, data.get("file_name", "config"))[0]
        await _send(message, _render(result))
        return

    assert error is not None
    if error.code == "bad_password":
        # Keep the pending document so the user can simply retry.
        await message.answer("❌ Wrong password. Send it again, or /cancel.")
        return

    await state.clear()
    await message.answer(f"❌ {html.escape(str(error))}\n\n<i>code: {error.code}</i>")



@router.message(Command("cancel"))
async def on_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer("Cancelled.")


@router.message(F.text)
async def on_text(message: Message) -> None:
    text = (message.text or "").strip()
    if not text or text.startswith("/"):
        return

    found = _payload_from_text(text)
    if found is None:
        # A bare password has no meaning outside the password prompt.
        await message.answer(
            "Send me a config file, or paste a "
            "<code>slipnet-enc://</code> / <code>nm-*://</code> link.\n\n"
            "Use /help for details."
        )
        return
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        await message.answer("❌ That message is too long.")
        return

    payload, name = found
    # A pasted post can carry the password in the same message.
    await _deliver(message, payload, name, extract_passwords(text))


@router.message()
async def on_other(message: Message) -> None:
    await message.answer("Send a config file or use /help.")


# ------------------------------------------------------------------------ main


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    token = os.environ.get("BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("set BOT_TOKEN (or TELEGRAM_BOT_TOKEN) first")

    bot = Bot(token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dispatcher = Dispatcher(storage=MemoryStorage())
    dispatcher.include_router(router)
    await dispatcher.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
