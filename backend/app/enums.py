"""Vocabulary shared by the parsers, the database and the API."""

from enum import StrEnum


class Action(StrEnum):
    """What a log line says happened."""

    AUTH_FAIL = "auth_fail"  # a login attempt was rejected
    AUTH_OK = "auth_ok"  # a login succeeded
    INVALID_USER = "invalid_user"  # someone tried a user name that does not exist
    DISCONNECT = "disconnect"  # an SSH connection ended
    SUDO_EXEC = "sudo_exec"  # a command was run through sudo
    SUDO_DENIED = "sudo_denied"  # sudo refused to run a command


class Level(StrEnum):
    """How noteworthy a single line is on its own (rules judge patterns of lines)."""

    INFO = "info"
    WARNING = "warning"
