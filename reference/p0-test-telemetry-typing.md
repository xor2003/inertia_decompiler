# SORTDEMO Test Telemetry Typing

## Reason And Scope

The strict-C checkpoint exposed 11 Pyright diagnostics in the legacy SORTDEMO
regression module: three unresolved sibling test-helper imports and eight
operations on JSON telemetry values typed as `object`.

The project Pyright search path now includes pytest's sibling-helper directory.
Three duplicate log parsers delegate to `x86_16_telemetry_support.py`, which
preserves JSON record order and refuses malformed selected records. Integer
arithmetic uses a checked accessor that rejects booleans, strings, floats,
missing fields and other non-integers without coercion. Container assertions
narrow the two telemetry lists before their existing contents are checked.
The large regression module is 18 lines shorter. Decompiler code is unchanged.

## Acceptance

DoD: the 11 diagnostics disappear without ignores or `Any` substitutions;
parser/count regressions exercise valid, malformed and missing data; existing
semantic assertions remain; focused runtime results do not regress; the fast
quality gate passes. Definition of failure: coerce unknown values to zero,
accept boolean counters, weaken assertions, or report typing success as
RunMenu semantic acceptance.

Pyright before: 11 errors. After, on the regression module, helper and new tests:
zero errors and warnings. Scoped Ruff and helper/script MyPy pass. Seventeen
new cases are admitted to routine tests and ownership selection.

Before editing the existing regression, RunMenu already failed because
`replacement_payload["attempted_count"]` was 0 rather than the required 1
(39.92 seconds, including 32.02 seconds in the function). Afterward, the same
assertion fails; the helper cases and InitBars pass: 18 passed, one failed,
seven warnings, 9.57 seconds. This shorter rerun may use caches and is not a
performance claim. Do not accept zero or remove this test without investigating
the current materialization owner and proving the required behavior elsewhere.

`make quality-fast` exited zero: 3,290 tests passed, seven warnings, 112.92
seconds pytest; all three executable quality guards passed. This is a
test/config-only change; the full repository suite and default external
pipeline have not been rerun here. The preceding production checkpoint's
default pipeline and seven MS C tiny roundtrips remain the last such evidence.

The fast gate started at 03:32:43 CEST on 2026-09-10; terminal exit zero was
verified by 03:36:00, a 3m17s observation window including polling. This is not
total active coding time or an estimate for the remaining goal.

Logs: `/tmp/inertia-telemetry-types-{before,after}.log`,
`/tmp/inertia-telemetry-runmenu-before.log`, `/tmp/inertia-telemetry-focused.log`,
and `/tmp/inertia-telemetry-quality-fast.log`.
