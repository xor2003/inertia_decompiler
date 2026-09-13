# Step 9 Failure Retry

## Scope

Reran the 21 exact `failed_nodeids` from the retained full-suite machine report
using the project venv, `PYTHON_JIT=1`, `PYTHONHASHSEED=0`, pytest `-n 7`, short
tracebacks and duration reporting. This retry followed the return-address
Semantics repair and its passing routine/MS C pipeline. No production edits
were made during the retry.

Result: **21 failed, 0 passed**, seven dependency warnings, **166.13s**.
Log: `/tmp/inertia-step9-failure-retry.log`.

This is not a full-suite audit and cannot exclude new failures elsewhere.
The preceding 11,750/21/170 full-suite result remains the last full inventory.
Recent safety fixes and the 3,978-test routine pass have not closed any of
these 21 exact failing nodes.

## Observations And Next Action

- LIFE timed out after 8s during Clinic peephole optimization under this
  parallel retry. The prior isolated run reached unresolved-stack rejection.
  Neither outcome is success; retain both observations rather than attributing
  the timeout to a semantic change without an isolated comparison.
- DrawRadarAlt and SetGear retain timeout-related failures. Do not repair only
  their expected timeout text and claim decompilation works.
- The mset_pos test first rejects casted modulo spelling, but its emitted C
  also shows conflicting argument declarations. Do not classify this as solely
  cosmetic or relax the text assertion without strict compilation/behavior.
- Several SORTD failures still reject temporary names, casts, anonymous callees
  or loop spelling. They require equivalent executable checks, not blanket
  regex relaxation. RunMenu and other semantic acceptance failures remain open.

Next work must close a reproduced failure or its necessary shared contract.
Preserve the current early-layer guards and investigate failed C/validation
before adding more unrelated hardening. Existing FPU tests remain intact;
new LIFE 80387/x87 recovery remains out of scope.

## RunMenu Fresh Diagnostic Check

On 2026-09-11, an isolated request-cache key reproduced the RunMenu diagnostic
failure without production changes. The command used `PYTHON_JIT=1`,
`PYTHONHASHSEED=0`, `INERTIA_ENABLE_TAIL_VALIDATION=1`,
`INERTIA_DISABLE_TIMING=1`, `INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS=1`, and
`INERTIA_DIAGNOSTIC_CACHE_NAMESPACE=runmenu-step9-20260911-current`:

```sh
.venv/bin/python decompile.py SORTDEMO.EXE --addr 0x102e0 --timeout 300 \
  --alternate-source-c --c-target portable-flat
```

The namespace variable is an otherwise unused input to the existing
`INERTIA_*` cache-environment fingerprint, not a new runtime option or a
separate cache directory. Shared caches were not deleted. The log confirms
actual project construction and analysis, from 12:06:48 to 12:07:25; these
timestamps are observations, not a controlled performance measurement.

- Exit status 0, `validation=passed`, whole-tail validation clean.
- Segment helper candidates/materialized/refused: 128/128/0.
- Switch diagnostic still reports four unresolved `SimMemoryVariable`
  carriers named `inertia_ds`; no unresolved linear segment carriers.
- Fresh and previously cached C have the same SHA-256:
  `570c004779222e94842efb1b7e132e8291834ba5db881fd1e258e6148cb948b3`.
- Temporary artifacts: `/tmp/inertia-runmenu-step9-fresh.c` and
  `/tmp/inertia-runmenu-step9-fresh.log`.

Current-source inspection identifies inconsistent classification:
`cli_decompilation._typed_switch_seqnode_case_segment_quality_8616` recognizes
only `SimRegisterVariable` segment operands. Lowering's
`materialize_runtime_helper_segment_carriers_8616` also consumes
`segment_register_state.runtime_segment_name_for_variable_8616` for already
lowered runtime-state variables. The latter currently recognizes memory
variables by reserved symbol name; its producer also records a dedicated
category, address and width. A fix must preserve that owned identity rather
than teach the CLI to guess segments from arbitrary names.

Next: cover physical, proven lowered, unknown, and misleadingly named carriers
with focused diagnostic regressions, consume the authoritative Lowering
contract, and rerun the exact RunMenu regression and relevant gates. This
investigation does not close the failing test, establish strict recompilation,
or change the recorded full-suite totals.

## RunMenu Diagnostic Repair

The CLI diagnostic now consumes the existing Lowering-owned runtime segment
identity query as well as physical registers. That query requires the owned
`inertia_segment_state` category, so an unrelated memory variable named
`inertia_ds` is not accepted as architectural state. The architecture allowlist
documents this diagnostic-only dependency; no semantic recovery was added to
the CLI and no test assertion was relaxed.

New focused tests cover physical, lowered, unknown and misleadingly named
carriers. Before repair: one failed (lowered), three passed in 10.22s. After
repair: the four tests, original RunMenu regression and segment-effect tests
all pass: **17 passed in 74.54s**. RunMenu took 44.97s. An intermediate run
aborted because a docstring edit overlapped startup validation; the recorded
passing rerun used stable source and the aborted run is not acceptance evidence.

Verification:

- Full architecture check passed; scoped MyPy and Pyright passed for the
  Lowering owner. New test file is Ruff-clean.
- `ruff check --fix` and `quality-fast` remain red on existing legacy findings,
  including two complexity findings in `segment_register_state.py`.
- `test-pipeline`: **3,982 passed in 207.87s**, seven dependency warnings;
  all seven MS C compile/decompile/recompile/run examples passed. Three lanes
  passed, zero failed/skipped/timed out. New tests are in routine Make/pipeline
  lists and the segment ownership mapping.
- Logs: `/tmp/inertia-switch-diag-{before,after,architecture,mypy,pyright}.log`,
  `/tmp/inertia-switch-diag-quality-fast.log`,
  `/tmp/inertia-switch-diag-pipeline.log`.

This closes the reproduced RunMenu diagnostic regression, not Step 9 or the
full-suite audit. No fresh full-suite pass/fail total is claimed.
