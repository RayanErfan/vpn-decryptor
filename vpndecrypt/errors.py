class DecryptError(Exception):
    """A config could not be opened.

    ``code`` is stable and safe to show to end users, so the API and the bot can
    both branch on it without parsing free text.
    """

    code = "decrypt_failed"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        if code:
            self.code = code


class UnsupportedFormat(DecryptError):
    code = "unsupported_format"


class NotEncrypted(DecryptError):
    code = "not_encrypted"


class PasswordRequired(DecryptError):
    code = "password_required"


class BadPassword(DecryptError):
    code = "bad_password"


class HardwareLocked(DecryptError):
    code = "hardware_locked"
