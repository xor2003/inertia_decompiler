"""Versioned terminal-status transport for external CLI consumers.

Layer: CLI/fallback/reporting.
Responsibility: preserve legacy CLI helper surface while delegating semantic
proof to X86_16 layers; this module carries authoritative terminal reasons
independently of prose and legacy exit codes.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess
semantic repair.
"""

from __future__ import annotations

import json
import sys
from enum import StrEnum

TERMINAL_RECORD_PREFIX: str = "[inertia-terminal] "
TERMINAL_RECORD_SCHEMA: int = 1


class CliTerminalStatus(StrEnum):
    """Terminal reasons supported by this version of the CLI transport."""

    TIMEOUT = "timeout"


def emit_terminal_status(status: CliTerminalStatus) -> None:
    """Flush one typed record before the CLI returns or performs a hard exit."""
    record = {"schema": TERMINAL_RECORD_SCHEMA, "status": status.value}
    print(TERMINAL_RECORD_PREFIX + json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)


def read_terminal_status(diagnostics: str) -> CliTerminalStatus | None:
    """Decode explicit records; reject malformed transport instead of guessing.

    Unrelated diagnostic lines are not evidence. Repeated identical records are
    allowed when a wrapper forwards output from a terminal child.
    """
    status: CliTerminalStatus | None = None
    for line in diagnostics.splitlines():
        if not line.startswith(TERMINAL_RECORD_PREFIX):
            continue
        record = json.loads(line[len(TERMINAL_RECORD_PREFIX):])
        if not isinstance(record, dict) or set(record) != {"schema", "status"}:
            raise ValueError("Invalid CLI terminal record fields")
        if type(record["schema"]) is not int or record["schema"] != TERMINAL_RECORD_SCHEMA:
            raise ValueError("Unsupported CLI terminal record schema")
        decoded = CliTerminalStatus(record["status"])
        if status is not None and status is not decoded:
            raise ValueError("Conflicting CLI terminal records")
        status = decoded
    return status
