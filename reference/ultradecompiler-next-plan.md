# UltraDecompiler QuickC Completion And Next Plan

## Context

The UltraDecompiler borrowing pass is complete for the current QuickC scope.
UltraDecompiler remains useful as a fixture and edge-case source, but the
runner, object/library evidence, function matching, and compiler flag detection
remain Inertia-owned.

Keep these boundaries:

- UltraDecompiler remains a fixture and edge-case source only.
- DOS execution remains based on `/home/xor/kvikdos/kvikdos`; do not add
  DOSBox-X.
- Inertia keeps its existing OMF/PAT reader, function matcher, compiler/flag
  detector, and neural flag detector.
- Semantic fixes still belong in the earliest correct layer. Do not add
  rendered-C or CLI text repair.
- Runtime traces can refine evidence but must not become the only semantics
  source.

## Completed Work

### 1. QuickC Fixture Report Normalization

Status: implemented and verified.

DoD evidence:

- The QuickC importer emits deterministic machine-readable fixture reports.
- Per-fixture report entries include compile, link, run, decompile, validation,
  and compiler evidence status.
- Aggregate counts cover selected fixtures, passed fixtures, validation status,
  decompile status, generated-C gaps, and compiler evidence gaps.
- Excluded fixtures remain visible with explicit reasons.
- Tests assert structured fields rather than prose formatting.

### 2. `args.c` Fixture Promotion

Status: implemented and verified.

DoD evidence:

- `args.c` is promoted into explicit default fixture metadata.
- Runtime args and expected stdout are structured:
  `-v alpha beta` and `total: 2`.
- The fixture is required, not silently skipped.
- Compile, link, run, decompile, validation, and compiler evidence pass.
- `reference/ultradecompiler-args-triage.md` records the source-backed triage.

### 3. Structured Decompile Target Selection

Status: implemented and verified.

DoD evidence:

- QuickC fixtures no longer depend on `sub_10010` as a universal target.
- OMF PUBDEF evidence selects user `_main` for the default fixtures.
- Target selection records mode, evidence source, symbol, address, object path,
  and reason.
- Fixture overrides remain available but are reported when used.
- Tests cover automatic selection and fallback behavior.

### 4. Pipeline Aggregate Visibility

Status: implemented and verified.

DoD evidence:

- `tools/dev/test_pipeline.py --lane ultra-quickc-fixtures` records compact lane
  details from the nested QuickC report.
- Lane details include selected/passed/decompiled/validated/evidence-gap
  counts and the nested report path.
- The top-level pipeline summary remains compact.
- `--require-external` behavior is unchanged.

### 5. `switch_fold` Tail-Validation Normalization

Status: implemented and verified.

Result:

- `switch_fold` generated source-equivalent C, but tail validation previously
  reported precision deltas around switch-helper artifacts and BP-relative
  stack argument fingerprints.
- Tail validation now accepts only the proven switch-helper precision delta:
  raw helper/CITE/AX scratch artifacts are classified as a validation precision
  improvement, not as a semantic rewrite.
- DS/global and stack-slot canonicalization remain conservative; arbitrary
  segmented memory is not flattened.

DoD evidence:

- Focused switch-helper tests pass.
- Tail-validation fingerprint tests for stack-slot equivalence pass.
- Direct `switch_fold` decompile reports `validation=passed`.
- The fix lives in validation fingerprinting/comparison, not rendered-C
  postprocess.

### 6. `select_and_apply` Function Pointer Semantics

Status: implemented and verified.

Result:

- Generated `select_and_apply` no longer emits the semantic error
  `fn = which;`.
- Generated C preserves the conditional assignments:
  `fn = inc_one;` / `fn = dec_one;`.
- The call remains `return apply_twice(fn, value);`.
- The unsupported function-pointer stack overwrite is pruned from direct stack
  move evidence without accepting call-argument loss.

DoD evidence:

- Focused MSC6 regression for `select_and_apply` passes.
- Focused `function_pointers` fixture builder passes with fallback rebuild and
  decompiled run success.
- Generated `FPTR1.C` contains no `fn = which` and contains
  `return apply_twice(fn, value);`.
- Validation refuses the broader bad delta where call arguments disappear.

## Verification Snapshot

Last verified gate set:

- Direct `switch_fold` decompile:
  `validation=passed`.
- Focused `function_pointers` builder:
  build/run/decompile/recompile/decompiled-run all pass.
- Changed-file gate:
  `rtk make check-files PYTHON=./.venv/bin/python FILES="..."`
  passed with 384 tests.
- Architecture gate:
  `rtk make architecture-check PYTHON=./.venv/bin/python`
  passed.
- QuickC lane:
  `rtk ./.venv/bin/python tools/dev/test_pipeline.py --lane ultra-quickc-fixtures ...`
  passed with 1 selected, 1 passed.
- Default external tier:
  `rtk ./.venv/bin/python tools/dev/test_pipeline.py --tier default --require-external`
  passed with 3 selected, 3 passed, 0 failed, 0 timed out.

## Current State

The QuickC borrowing work and the MSC6 tiny default-tier blockers are no longer
the active plan. Treat them as regression expectations.

Next work should move back to real-program pressure testing, especially the
current `SORTDEMO.EXE` handoff.

Before restarting SORTDEMO work, read:

- `SORTD_GHIDRA_PLAN.md`
- `reference/project-map.md`
- `reference/decompiler-map.md`
- `reference/dosunit-execution-spec.md`

## Next Execution Plan

### A. Re-Establish SORTDEMO Baseline

Requirements:

- Read `SORTD_GHIDRA_PLAN.md`.
- Check for and avoid stale concurrent `SORTDEMO` decompile processes.
- Run the focused decompile command from the handoff for the active function.
- Capture tail-validation status, generated C shape, required calls, and any
  semantic deltas.

DoD:

- Baseline command, function address/name, status, and failure mode are recorded.
- Any failure is classified as validation, recompilation, runtime, call loss,
  stack/local recovery, condition recovery, or structuring.
- No fix is attempted without a focused before/after regression target.

### B. Continue ReInitBars / SwapBars / HeapSort

Requirements:

- Work one function at a time.
- For every function being fixed, run a focused function regression before and
  after changes.
- If original C/COD source exists, compare output shape and call semantics
  against source.
- Required calls must survive with correct value-vs-pointer argument classes.

DoD:

- The function reports `validation=passed`.
- No semantic call loss is introduced.
- Output is closer to original C than the previous baseline.
- Any DCE candidate without full evidence remains `UNKNOWN_REFUSE` and is kept.

### C. Gate The SORTDEMO Slice

Requirements:

- Run focused tests for each changed behavior.
- Run changed-file checks for all touched files.
- Run architecture check.
- Run the relevant external/pipeline gate if the change affects fixture or
  runtime behavior.

DoD:

- Focused regression passes.
- `make check-files PYTHON=./.venv/bin/python FILES="..."` passes for touched
  files.
- `make architecture-check PYTHON=./.venv/bin/python` passes.
- Any remaining blocker is recorded with command, function, stage, evidence, and
  typed failure classification.

## Regression Expectations

- QuickC fixture reports remain deterministic and machine-readable.
- `args.c` remains a required default fixture with structured run args and
  expected output.
- QuickC target selection remains evidence-based and records OMF/PUBDEF details
  where available.
- Top-level QuickC pipeline lane details continue to expose compact aggregate
  counts.
- `switch_fold` direct decompile remains validation-clean.
- `select_and_apply` does not reintroduce `fn = which;`.
- The default external tier remains green unless a new typed blocker is recorded.
