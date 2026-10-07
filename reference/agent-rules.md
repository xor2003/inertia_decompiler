# Agent Rules And Internal Glossary

This file holds internal guidance that should not live in the user-facing README.

## Canonical Architecture Contract

AGENTS.md contains the mandatory agent rules and canonical architecture
contract. Keep mission, priority, pipeline order, layer ownership, hard rules,
execution discipline, and function-fix acceptance criteria there so agents have
one source of truth without making this supplemental reference compete with it.

This file intentionally does not restate those rules. It adds internal glossary,
diagnostic, and long-running-agent guidance that would make `AGENTS.md` too
large. If a rule here seems to conflict with `AGENTS.md`, fix this file instead
of creating a second contract.

## Development Execution Rules

Read and follow [agent-execution.md](agent-execution.md) for mandatory regression,
performance, selective-delegation, output, and progress-reporting rules. Keep
that policy in one place; this file retains the glossary and diagnostic guide.

## Glossary

Execution semantics: low-level instruction meaning during execution. `DS << 4` may exist internally for real-mode execution but must not leak into normal emitted C.

Semantic recovery: reconstruction of stack variables, loops, conditions, pointer types, function calls, structs, and arrays from machine code before cosmetic rewrites.

Materialization: the point where a recovered semantic concept becomes emitted C, such as a stack slot becoming `local_2`, a recurrence becoming `i++`, or segmented access becoming `SEG_U16(ds, off)`.

Canonicalization: normalization of equivalent expressions into a stable form without inventing semantics.

Tail validation: semantic comparison between recovered/pre-postprocess representation and final emitted representation. Semantic drift is failure.

Semantic honesty: the decompiler fails explicitly instead of emitting misleading C.

Segmented memory model: 16-bit real-mode DOS memory with CS, DS, SS, and ES segment registers plus offsets. Physical address is `(segment << 4) + offset`, but normal output uses segmented helpers.

Laundered segment linearization: hidden linearization such as `tmp = ss; ptr = tmp << 4;`. Validation should reject it like direct `ss << 4`.

Runtime helper: a portable abstraction such as `SEG_U8`, `SEG_U16`, `SEG_PTR`, and `MK_FP`.

Stable stack slot: a proven persistent stack location such as `SS:BP-0x2:size2`.

Stack carrier: a low-level temporary stack representation before materialization, such as `s_0`, `s_4`, or `s_fffd`.

Byte carrier: a temporary representing one byte of a wider stack/local value. It should usually disappear after widening and materialization.

Widening: combining proven low-level pieces into a larger semantic value, such as low/high bytes or split pointer pieces.

Stack alias: proof that multiple expressions refer to the same stack location.

Stack canonicalization bridge: validation metadata proving two stack expressions represent the same stable slot.

ConditionIR: intermediate representation for equality, ordering, signed/unsigned comparisons, and zero checks.

Typed condition materialization: conversion of flag logic into typed C conditions.

Linear recurrence: a loop-update pattern such as `i = i + 1`, `i += 1`, or `i++`.

Recurrence rebinding: replacing low-level recurrence carriers with the materialized semantic local.

Callsite materialization: recovery of actual function arguments from pushes and call setup patterns.

Stale pushed arguments: previous stack state incorrectly surviving into a recovered call.

Prototype stabilization: recovery and enforcement of consistent function signatures from call usage, helpers, sidecars, annotations, and ABI facts.

Honest fallback prototype: safe fallback signature when exact prototype recovery is impossible.

PipelineHardError: fatal semantic pipeline error used when semantics are corrupted, validation fails, forbidden constructs remain, or materialization invariants fail.

Rewrite lane: late cosmetic transformation phase. It may format and simplify, but must not infer semantics.

Semantic consumer: a pass that converts proven semantic facts into higher-level representations.

Acceptance gate: final correctness gate requiring generated C, validation where enabled, recompilation where requested, and no unresolved semantic blockers.

Compile-readiness: syntactically valid generated C, typically checked with `gcc -std=c99 -Wall -Werror -fsyntax-only`.

Dead setup artifact: a low-level temporary emitted after semantic materialization already consumed it.

Semantic ownership: the rule defining which layer is responsible for each transformation.

## Diagnostics And Profiling

Focused SORTDEMO regression:

```bash
INERTIA_ENABLE_TAIL_VALIDATION=1 ./decompile.py --alternate-source-c ./SORTDEMO.EXE
```

Compact telemetry for slow decompilation:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FILE=.cache/frontend/otel.trace.txt \
./decompile.py ./SORTDEMO.EXE
```

Use JSON/JSONL traces only for parsers. Human and agent handoff should use compact text or slow-span summaries. Details are in `reference/telemetry.md`.

## Resume Loop

For long autonomous repair sessions:

```bash
./.venv/bin/python tools/dev/codex_resume_loop.py \
  --prompt "go on. fix function by function. Finish only when all functions are fixed." \
  --goal-cmd 'jq -e ".stop_reason==\"goals_met\"" .cache/frontend/auto_decomp_loop/DONE.marker.json >/dev/null 2>&1' \
  --status-cmd 'test -f .cache/frontend/auto_decomp_loop/DONE.marker.json' \
  --max-iterations 200 \
  --stagnation-limit 30
```

Prefer the default resume behavior, use `--goal-marker-file` or `--goal-cmd` as the hard stop, and keep a manual stop file such as `/tmp/STOP_CODEX_LOOP` available.
