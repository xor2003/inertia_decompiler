# Decompiler Telemetry

Purpose: quickly find slow decompilation stages without dumping huge logs.

Default agent context is compact text, not OTLP JSON. JSON/JSONL is available
only for tools that parse it; it repeats keys/punctuation and wastes LLM tokens.

Enable compact spans:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FILE=.cache/frontend/otel.trace.txt \
./.venv/bin/python ./decompile.py ./SORTDEMO.EXE
```

Useful knobs:

- `INERTIA_OTEL_SPANS=1` enables tracing. Default is off.
- `INERTIA_OTEL_SPAN_FILE=path` writes compact agent text by default, even for `.json` suffixes.
- `INERTIA_OTEL_SPAN_FORMAT=text|slow|json|jsonl` overrides file format. Use `json`/`jsonl` only for parsers; stderr summaries stay compact agent text.
- `INERTIA_OTEL_TEXT_MAX_SPANS=200` caps rows in agent-text output.
- `INERTIA_OTEL_TOP_N=16` controls how many slow spans/aggregates are kept.
- `INERTIA_OTEL_MIN_MS=1` hides tiny spans from the `top` list.
- `INERTIA_OTEL_STDERR=0` suppresses the `[otel-trace]` stderr line when writing a file.
- `INERTIA_OTEL_FULL_JSONL=1` writes summary plus every span as JSONL.
- `INERTIA_OTEL_EXPORT_OTLP=1` exports spans through OTLP HTTP/protobuf.
- `INERTIA_OTEL_SERVICE_NAME=inertia-decompiler` overrides the OpenTelemetry service name.
- `INERTIA_OTEL_FORCE_FLUSH_MS=3000` controls exporter flush timeout at process exit.
- `INERTIA_OTEL_PROFILE_IN_PROCESS=1` disables direct-address fork isolation for profiling so nested child spans flush into the same compact trace. Use only for profiling, not default runs.

CLI equivalents on `decompile.py`:

- `--otel-spans` / `--otel-no-spans`
- `--otel-span-file PATH`

Use text for agent handoff. It intentionally avoids duplicated `top`/`agg`
JSON sections and repeats only a short schema:

```text
summary total_ms=8562.5 spans=6 otel=off errors=0
schema: id|parent|ms|name|attrs
5|2|7372.118|direct.decompile_job|addr=0x1000 blocks=11 bytes=65 name=cmp_i16 status=ok timeout=73
```

Use slow mode when only the longest spans matter:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FORMAT=slow \
INERTIA_OTEL_SPAN_FILE=.cache/frontend/otel.slow.txt \
./.venv/bin/python ./decompile.py examples/build_msc6/CMP16.EXE
```

Example:

```text
trace total=8562.5ms spans=6 otel=off errors=0
7372.118 direct.decompile_job addr=0x1000 blocks=11 bytes=65 name=cmp_i16 status=ok timeout=73
126.63 validation.acceptance status=ok target=portable-flat
```

Use `.json`/`.jsonl` only when a parser requires it. Agent handoff should use `text` or `slow`; stderr is always compact text even when the trace file is JSON/JSONL.

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_EXPORT_OTLP=1 \
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
./.venv/bin/python ./decompile.py examples/build_msc6/CMP16.EXE
```

OTLP export is only enabled when `INERTIA_OTEL_EXPORT_OTLP=1` (or equivalent CLI flag) is set. Collector endpoint variables alone do not turn export on. Exporter configuration or collector failures must not fail decompilation; check `otel_export` in the compact summary for status.

JSON output remains available for tools:

```json
{"span_count":8,"total_ms":1907.4,"top":[["direct.decompile_job",909.7,{"addr":"0x1000","name":"_start"}]],"agg":[["direct.decompile_job",1,909.7,909.7]],"errors":[]}
```

Convert existing full JSONL traces before giving them to an agent:

```bash
./.venv/bin/python tools/dev/compact_trace.py otlp.jsonl > trace.agent.txt
```

Implementation:

- Use `@trace_function(name="...")` on normal functions. It auto-extracts common attributes from arguments: `binary`, `addr`, `function`, `project`, `timeout`, `status`, `window`, and related fields.
- Use `with span("operation.name", ...)` only for local closures, timeout wrappers, and operations that are not functions.
- Use `with span_here(...)` when the calling function name is a good span name.
- Use `annotate_current_span(...)` only for values known after work completes, such as `status`, `elapsed_ms`, `blocks`, and `bytes`.

Keep spans high-level first: project build, sidecar load, discovery, per-function work, decompile, tail validation, recompilation/acceptance. Avoid adding spans inside tight loops unless a specific profiler run proves the loop is the problem.
