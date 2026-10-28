"""VPN config decryptor.

Opens the encrypted export formats used by V2Box, HTTP Injector, HA Tunnel Plus,
HTTP Custom, NetMod, NPVTunnel and SlipNet and returns the resulting
configuration plus any share links found inside it.

    >>> from vpndecrypt import decrypt
    >>> result = decrypt(open("config.ehi", "rb").read(), "config.ehi")
    >>> result["links"]
    []

Locked exports raise :class:`~vpndecrypt.errors.PasswordRequired`; pass the
password to :func:`decrypt`, or hand a whole post caption to
:func:`decrypt_any` / :func:`extract_passwords` and let the password be read
from it.

Only the formats that could be verified against real exports are implemented;
anything else raises :class:`~vpndecrypt.errors.UnsupportedFormat` with a
message that can be shown to the user as-is.
"""

from __future__ import annotations

from .detect import decrypt, decrypt_any, identify
from .errors import (
    BadPassword,
    DecryptError,
    HardwareLocked,
    NotEncrypted,
    PasswordRequired,
    UnsupportedFormat,
)
from .passwords import candidates as extract_passwords
from .passwords import first as first_password

__version__ = "1.1.0"

__all__ = [
    "decrypt",
    "decrypt_any",
    "identify",
    "extract_passwords",
    "first_password",
    "DecryptError",
    "UnsupportedFormat",
    "NotEncrypted",
    "PasswordRequired",
    "BadPassword",
    "HardwareLocked",
    "__version__",
]
