class WgauError(Exception):
    """Base for all wgau errors. cli.py catches this and prints `error: ...`."""


class ConfigError(WgauError):
    """wgau.conf is missing, unreadable or has bad values."""


class Wg0Error(WgauError):
    """wg0.conf is missing, unreadable or lacks required fields."""


class WgError(WgauError):
    """`wg` binary is missing or returned an error."""


class PeerExistsError(WgauError):
    """A peer with this name is already in wg0.conf."""


class NoFreeIPError(WgauError):
    """No free IP left in ADDRESS_BASE range."""


class ClientNotFoundError(WgauError):
    """Client folder / peer not found."""


class KeyMismatchError(WgauError):
    """sec.key does not match pub.key."""


class QRCodeError(WgauError):
    """QR code generation failed."""


class PermissionDeniedError(WgauError):
    """Not enough privileges for the requested operation (e.g. needs root)."""


class DbError(WgauError):
    """SQLite database cannot be opened, initialized or updated."""
