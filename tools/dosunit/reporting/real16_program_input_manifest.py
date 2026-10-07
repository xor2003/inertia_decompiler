"""Bounded declarations and identity projection for DOS input files.

Layer: dosunit CLI/environment contracts.
Responsibility: parse exact supplied regular-file bytes before guest execution
and bind identities to input policy, handles, contents and initial cursors.
"""

from __future__ import annotations

import hashlib

from tools.dosunit.runtime.real16_program_input import MAX_INPUT_BYTES, MAX_INPUT_FILES, InputFile, InputPolicy


def _integer(value: object, name: str) -> int:
    """Accept explicit JSON integers/hex strings, never bool or float aliases."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"{name}: invalid integer") from error
    raise ValueError(f"{name}: expected integer")


def _object(value: object, keys: set[str], name: str) -> dict[str, object]:
    """Require exactly the declared JSON members, without ignored fields."""
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name}: expected exactly {sorted(keys)}")
    return value


def parse_input_policy(value: object) -> InputPolicy | None:
    """Bound file count and hexadecimal work before decoding supplied bytes."""
    if value is None:
        return None
    declared = _object(value, {"files", "max_call_bytes", "max_total_bytes"}, "input_files")
    raw_files = declared["files"]
    if not isinstance(raw_files, list) or len(raw_files) > MAX_INPUT_FILES:
        raise ValueError("input_files requires a bounded file list")
    files: list[InputFile] = []
    remaining = MAX_INPUT_BYTES
    for raw in raw_files:
        item = _object(raw, {"handle", "bytes", "cursor"}, "input file")
        hexadecimal = item["bytes"]
        if not isinstance(hexadecimal, str) or len(hexadecimal) > remaining * 2:
            raise ValueError("input file hexadecimal exceeds supplied-byte budget")
        # Exact compact hex avoids unbounded whitespace scans in bytes.fromhex.
        if len(hexadecimal) % 2 or any(character not in "0123456789abcdefABCDEF" for character in hexadecimal):
            raise ValueError("input file bytes must be compact hexadecimal")
        data = bytes.fromhex(hexadecimal)
        remaining -= len(data)
        files.append(InputFile(_integer(item["handle"], "input handle"), data,
                               _integer(item["cursor"], "input cursor")))
    return InputPolicy(tuple(files), _integer(declared["max_call_bytes"], "input per-call cap"),
                       _integer(declared["max_total_bytes"], "input total cap"))


def input_policy_document(policy: InputPolicy | None) -> dict[str, object] | None:
    """Bind exact byte fingerprints without duplicating file data in reports."""
    if policy is None:
        return None
    return {"files": [{"handle": item.handle, "size": len(item.data),
                       "sha256": hashlib.sha256(item.data).hexdigest(), "cursor": item.cursor}
                      for item in sorted(policy.files, key=lambda item: item.handle)],
            "max_call_bytes": policy.per_call_bytes, "max_total_bytes": policy.total_bytes,
            "scope": "declared preopened immutable regular files; successful read/seek only"}
