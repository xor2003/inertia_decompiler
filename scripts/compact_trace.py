"""Convert telemetry traces into compact text summaries for agent handoff.

Layer: Tooling/gates.
Responsibility: summarize telemetry for diagnostics without owning decompiler semantics.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ATTR_ALIASES = {
    "base_addr": "base",
    "c_target": "target",
    "entry_point": "entry",
    "function_label": "label",
    "low_memory_path": "lowmem",
}


def _format_attr_value(value: object) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return "-"
    text = str(value)
    if not text:
        return "-"
    if any(ch.isspace() for ch in text):
        text = "_".join(text.split())
    return text.replace("|", "/")


def _format_attrs(attrs: dict[str, object]) -> str:
    if not attrs:
        return ""
    parts = []
    for key in sorted(str(key) for key in attrs):
        value = attrs.get(key)
        parts.append(f"{_ATTR_ALIASES.get(key, key)}={_format_attr_value(value)}")
    return " ".join(parts)


def _name_dictionary(rows: list[dict[str, object]]) -> dict[str, int] | None:
    if len(rows) < 16:
        return None
    names: dict[str, int] = {}
    for row in rows:
        name = str(row.get("name", "unknown"))
        if name not in names:
            names[name] = len(names)
    if len(names) >= len(rows):
        return None
    raw_name_chars = sum(len(str(row.get("name", "unknown"))) for row in rows)
    dict_name_chars = sum(len(str(name_id)) + 1 + len(name) for name, name_id in names.items())
    row_name_chars = sum(len(str(names[str(row.get("name", "unknown"))])) for row in rows)
    if dict_name_chars + row_name_chars + len("names:\n") + 32 >= raw_name_chars:
        return None
    return names


def _collect_otlp_rows_8616(text: str) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    """Split JSONL lines into the summary object and span rows."""
    summary: dict[str, object] | None = None
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            continue
        if "span_count" in obj and "id" not in obj:
            summary = obj
            continue
        if "id" in obj and "name" in obj:
            rows.append(obj)
    return summary, rows


def _render_otlp_row_8616(row: dict[str, object], name_ids: dict[str, int]) -> str:
    """Render one span row in compact ``id|parent|ms|n|attrs`` form."""
    parent = row.get("parent")
    parent_text = "-" if parent is None else str(parent)
    name = str(row.get("name", "unknown"))
    name_text = str(name_ids[name]) if name_ids else name
    attrs = row.get("attrs", {})
    if not isinstance(attrs, dict):
        attrs = {}
    return f"{row.get('id')}|{parent_text}|{row.get('duration_ms')}|{name_text}|{_format_attrs(attrs)}"


def convert_otlp_jsonl_text(text: str) -> str:
    """Convert Inertia OTEL JSONL trace text into compact line-oriented text."""
    summary, rows = _collect_otlp_rows_8616(text)

    total = summary.get("total_ms", "?") if summary else "?"
    otel = summary.get("otel_export", "?") if summary else "?"
    if otel == "disabled":
        otel = "off"
    raw_errors = summary.get("errors", []) if summary else []
    errors = raw_errors if isinstance(raw_errors, list) else []

    lines = [f"summary total_ms={total} spans={len(rows)} otel={otel} errors={len(errors)}"]
    name_ids = _name_dictionary(rows)
    lines.append("schema: id|parent|ms|n|attrs" if name_ids else "schema: id|parent|ms|name|attrs")
    if name_ids:
        lines.append("names:")
        for name, name_id in sorted(name_ids.items(), key=lambda item: item[1]):
            lines.append(f"{name_id}={name}")

    for row in rows:
        lines.append(_render_otlp_row_8616(row, name_ids))

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert Inertia OTEL JSONL traces to compact agent text.")
    parser.add_argument("trace", nargs="?", help="JSONL trace path. Reads stdin when omitted or '-'.")
    parser.add_argument("-o", "--output", help="Output path. Writes stdout when omitted.")
    args = parser.parse_args(argv)

    text = Path(args.trace).read_text(encoding="utf-8") if args.trace and args.trace != "-" else sys.stdin.read()
    output = convert_otlp_jsonl_text(text)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
