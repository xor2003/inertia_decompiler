"""Layer: Test support.

Responsibility: parse existing JSON diagnostic records and validate integer
fields before regression assertions consume them. Never coerce malformed
counts or invent missing telemetry values.
"""

import json
from collections.abc import Mapping


def diagnostic_payloads(output: str, prefix: str) -> tuple[dict[str, object], ...]:
    """Read matching JSON objects in order, refusing malformed matched records."""
    payloads: list[dict[str, object]] = []
    for line in output.splitlines():
        if line.startswith(prefix):
            payload = json.loads(line[len(prefix):])
            assert isinstance(payload, dict), f"Expected a JSON object for {prefix}"
            payloads.append(payload)
    return tuple(payloads)


def telemetry_integer(payload: Mapping[str, object], field: str) -> int:
    """Require an actual integer field, not a boolean, coercion or default."""
    value = payload[field]
    assert type(value) is int, f"Expected integer telemetry field {field}: {value!r}"
    return value
