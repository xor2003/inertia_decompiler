# cython: language_level=3, infer_types=True
"""Layer: Frontend/runtime.

Responsibility: provide debug printing helpers for the frontend emulator/lifter code.
Forbidden: recovery diagnostics, validation verdicts, or decompiler output changes.
Fatal ERROR/ASSERT diagnostics deliberately raise SystemExit(1), including for
unsupported instructions. Do not replace this user-required termination policy
with a recoverable LiftingException or silently continue decoding.
"""

from __future__ import annotations
import typing
import cython

import sys
import traceback
from typing import TextIO

# Constants for debug message types
F_ASSERT: cython.longlong = 0
F_ERROR: cython.longlong = 1
F_WARN: cython.longlong = 2
F_INFO: cython.longlong = 3
F_MSG: cython.longlong = 4

# Global debug level
debug_level: cython.longlong = 0

__all__ = [
    "ASSERT",
    "DEBUG_MSG",
    "ERROR",
    "F_ASSERT",
    "F_ERROR",
    "F_INFO",
    "F_MSG",
    "F_WARN",
    "INFO",
    "MSG",
    "WARN",
    "debug_print",
    "set_debuglv",
]

_DebugCaller = tuple[str, str, int]


@cython.ccall
def _debug_caller() -> _DebugCaller:
    frame = traceback.extract_stack()[-3]
    return frame.filename, frame.name, frame.lineno or 0


def debug_print(
    message_type: cython.longlong,
    file: object,
    function: object,
    line: cython.longlong,
    level: cython.longlong,
    fmt: object,
    *args: object,
) -> None:
    """Prints debug messages based on the message type and debug level."""
    typeset: dict[cython.longlong, tuple[str | None, TextIO, cython.bint]] = {
        F_ASSERT: ("ASSERT", sys.stderr, True),
        F_ERROR: ("ERROR", sys.stderr, True),
        F_WARN: ("WARN", sys.stderr, False),
        F_INFO: ("INFO", sys.stdout, False),
        F_MSG: (None, sys.stdout, False),
    }

    name, fp, fatal = typeset[message_type]

    if fatal or (level > 0 and (1 << (level - 1)) & debug_level):
        if name:
            print(f"[{name}{f'_{level}' if level else ''}] ", end="", file=fp)
            print(f"{function} ({file}:{line}) ", end="", file=fp)
        rendered = fmt % args
        print(rendered, file=fp)
        if fatal:
            raise SystemExit(1)


@cython.ccall
def ASSERT(cond: object) -> None:
    """Assert a condition; a failure prints the location and exits with status 1."""
    if not cond:
        debug_print(F_ASSERT, *_debug_caller(), 0, "assertion failed: %s", cond)


def ERROR(fmt: object, *args: object) -> None:
    """Print a fatal frontend error and exit with status 1."""
    debug_print(F_ERROR, *_debug_caller(), 0, fmt, *args)


def WARN(fmt: object, *args: object) -> None:
    """Prints a warning message."""
    debug_print(F_WARN, *_debug_caller(), 0, fmt, *args)


def INFO(level: cython.longlong, fmt: object, *args: object) -> None:
    """Prints an informational message based on the debug level."""
    debug_print(F_INFO, *_debug_caller(), level, fmt, *args)


def DEBUG_MSG(level: cython.longlong, fmt: object, *args: object) -> None:
    """Prints a debug message based on the debug level."""
    debug_print(F_MSG, *_debug_caller(), level, fmt, *args)


def MSG(fmt: object, *args: object) -> None:
    """Prints a regular message to stdout."""
    print(fmt % args, file=sys.stdout)


@cython.ccall
def set_debuglv(verbose: object) -> None:
    """Sets the global debug level."""
    global debug_level
    debug_level = int(verbose)
