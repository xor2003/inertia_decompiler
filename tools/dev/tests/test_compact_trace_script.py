from __future__ import annotations

import json

from tools.dev.compact_trace import convert_otlp_jsonl_text


def _jsonl(*objects):
    return "\n".join(json.dumps(obj, separators=(",", ":")) for obj in objects) + "\n"


def test_compact_trace_converts_full_jsonl_to_agent_text():
    text = _jsonl(
        {
            "span_count": 2,
            "total_ms": 8.5,
            "errors": [],
            "otel_export": "disabled",
        },
        {
            "id": 1,
            "parent": None,
            "duration_ms": 8.0,
            "name": "direct.decompile_job",
            "status": "ok",
            "attrs": {
                "addr": "0x1000",
                "function_label": "cmp_i16",
                "low_memory_path": False,
            },
        },
        {
            "id": 2,
            "parent": 1,
            "duration_ms": 1.25,
            "name": "validation.acceptance",
            "status": "ok",
            "attrs": {"c_target": "portable-flat"},
        },
    )

    converted = convert_otlp_jsonl_text(text)

    assert converted.startswith("summary total_ms=8.5 spans=2 otel=off errors=0")
    assert "schema: id|parent|ms|name|attrs" in converted
    assert "1|-|8.0|direct.decompile_job|addr=0x1000 label=cmp_i16 lowmem=0" in converted
    assert "2|1|1.25|validation.acceptance|target=portable-flat" in converted
    assert "{" not in converted


def test_compact_trace_uses_name_dictionary_when_it_saves_space():
    rows = [
        {
            "id": index + 1,
            "parent": None,
            "duration_ms": 1.0,
            "name": "decompiler.very_repetitive_slow_stage",
            "attrs": {"addr": hex(0x1000 + index)},
        }
        for index in range(20)
    ]
    text = _jsonl({"span_count": 20, "total_ms": 20.0, "errors": []}, *rows)

    converted = convert_otlp_jsonl_text(text)

    assert "names:\n0=decompiler.very_repetitive_slow_stage" in converted
    assert "schema: id|parent|ms|n|attrs" in converted
    assert "1|-|1.0|0|addr=0x1000" in converted
