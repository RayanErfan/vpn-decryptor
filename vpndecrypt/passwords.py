"""Pull a password out of a post caption or a forwarded message.

Channel posts usually carry the password in the caption, next to the file::

    🔓Password: @DigiHubAI
    🔑 کلید/Passphrase: hunter2
    Pass = s3cret

Reading it here means the user does not have to retype it. The extractor is
deliberately conservative: a label must be followed by ``:`` or ``=`` and a
value, so prose such as "کلید پیدا نشد" is ignored.
"""

from __future__ import annotations

import re

_LABELS = (
    "password", "passphrase", "pass word", "pass", "pwd", "pw",
    "key", "secret", "رمز", "پسورد", "پسوورد", "پاسورد", "کلید", "کلمه عبور",
)

_PATTERN = re.compile(
    r"(?:" + "|".join(re.escape(label) for label in _LABELS) + r")"
    r"\s*(?::|：|=|->|=>|➜)\s*"
    r"([^\s,;|<>\"'`]+)",
    re.IGNORECASE,
)

_TRAILING = ".,;:!?)]}»…،؛"


def candidates(text: str | None) -> list[str]:
    """Every plausible password in ``text``, most likely first, deduplicated."""
    if not text:
        return []

    found: list[str] = []
    for match in _PATTERN.finditer(text):
        raw = match.group(1).strip()
        raw = raw.rstrip(_TRAILING)
        # Markdown/HTML wrappers people paste along with the value.
        raw = raw.strip("*_`~")
        if len(raw) < 2 or raw.lower() in {"this", "the", "none", "null", "n/a"}:
            continue
        for variant in (raw, raw.lstrip("@")):
            if variant and variant not in found:
                found.append(variant)
    return found


def first(text: str | None) -> str | None:
    values = candidates(text)
    return values[0] if values else None
