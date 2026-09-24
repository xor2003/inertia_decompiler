# Progress

Current objective: implement `reference/compiler-coverage-plan.md` —
correctness-first compiler coverage with evidence-driven semantic recovery.
Tagged start: `far-pointer-candidates-93c6b401`.

## Completed milestones

- Large-model far-frame argument base proven from terminal `retf` evidence
  (`argument_frame_base.py`, `SimCC8616MSClarge`); far `inc_one`
  `validation=passed` with its argument at machine `BP+6` (commit d3dc07573).
- AGENTS.md hard rule 16 (loud exceptions) added; both silent far-proof
  catch-alls removed; incomplete test mocks completed instead (d3dc07573).
- Far function pointers proven by call-operand width
  (`FunctionPointerParameterFact8616.pointer_width`,
  `SimTypeFarPointer16_8616`); materialization widens the proven slot and
  re-sites later arguments; far-CC survives clinic via
  `PrototypeSource.CCA_DECOMPILER` (commit 2a446ba04).
- Near-model regressions hold: `apply_twice`, `inc_one` `validation=passed`.
- Far-pointer reflow now reports declaration refreshes and updates angr's
  separate rebuild argument storage; focused before/after regression added.
  Pointer/layout/codegen neighborhood: 16 passed; Ruff and focused MyPy clean.
- Traced the subsequent layout reset to COD labels being consumed as layout
  facts. Typed NAME_ONLY purpose now excludes optional labels from prototype
  geometry while preserving naming use; first focused neighborhood 87 passed.
- Positive-BP replay now consumes closed per-slot function-pointer evidence.
  The failing regression shrank `(4,4)/(8,2)` to `(4,2)` before the fix;
  the initial pointer neighborhood passes 12 tests after it. No signature
  authority promotion or complete-argument-census claim is introduced.

- Promoted-linter-debt cleanup (ruff C901/PLR0916/PERF102 only, no
  suppressions): stale Makefile mypy paths removed (`make mypy` green),
  PERF102 x2 fixed, and ~60 complexity findings refactored into typed
  helpers across ~49 X86_16 files. Owning pytest batches verified
  green per change (126/225/256/145/285+1 pre-existing/81/92 pass runs).
  X86_16 findings: 1507 → 1452. Baseline suite remains 47
  pre-existing failures (far-pointer work), unchanged. Focused pytest
  needs `PYTHONHASHSEED=0` (make exports it); without it 8
  cache-surface tests fail on `allows_semantic_cache` refusal.
  Focused mypy needs sibling promoted modules on the command line —
  `follow_imports=skip` makes off-run imports Any and reports false
  no-any-return errors otherwise.

## Open work (far obligations, all still unadmitted)

- Native machine-frame correction is implemented: the tracker had popped two
  bytes for both near and far CALLs. Semantics now supplies exact encoded
  frame width; the adapter records typed counters and refuses unknown frames.
  Baseline 2 failed / 1 passed, initial neighborhood 69 passed. Final width
  and refusal rerun: `.cache/native-call-frame-final-widths.log`.
  Linked `.cache/coverage-apply-twice-machine-frame.{c,err}` exits 4 with
  matching SI/DI save/restore slots and final whole-tail clean. New active
  blocker: typed function-pointer calls retain `arg_6 & 0xffff`, rejected
  by gcc. Fix pointer target materialization at its owning lowering boundary;
  do not repair rendered C or assert unknown target preservation.
  Scoped Ruff/MyPy pass; quality-dev exits 2 on repository debt.
  Final focused result: 73 passed in 32.19 seconds (seven workers, JIT),
  including near/far 16/32-bit machine frames and refusal controls.
  Existing default pipeline is in its QuickC external lane (child PID
  3129058); do not restart it or count it as acceptance of this later fix.
- Fresh frame-boundary probe finished exit 4 at 10:30 local on September 24.
  `.cache/coverage-apply-twice-frame-boundary.err` proves the rebased native
  boundary accepts both indirect calls (0x1010, 0x101c), consuming all 12
  classified machine-frame effects with zero failures. Thus the observed
  four-byte save/restore coordinate drift is not explained by rejected
  indirect CALL-frame consumption. Next inspect surviving pre-SSA argument
  pushes/cleanup and native SP tracking. The direct-address fallback has an
  unmatched return edge and is a distinct path; no function acceptance claimed.
- Default gate pytest lane has now finished: 6,468 passed, 23 failed,
  10 warnings in 1,888.10 seconds. Pipeline PID 3110637 remains live at
  10:30 local; external-lane completion is not yet established. Preserve
  `.cache/pointer-slot-replay-pipeline.log`; do not launch a duplicate gate.
- `apply_twice` far now retains both pointer/value arguments in linked replay
  `.cache/coverage-apply-twice-pointer-slots.{c,err}`, but still exits 4 with
  `validation_failed` / `unassigned-stack-local`. It is not accepted.
- SI/DI save provenance is lost at calls with incomplete typed stack effects;
  final restore reads at `SS:BP-8..-5` remain uninitialized.
- Diagnostic replay `.cache/coverage-apply-twice-call-proof-seeded.err`
  finished, exit 4. First far call refuses `STACK_ALLOCATION_UNPROVEN`;
  both indirect calls refuse `TARGET_UNRESOLVED`. Set `PYTHONHASHSEED=0`
  before launching in-process probes:
  otherwise `decompile.py` exec-restarts and drops installed Python hooks.
  The first unseeded probe timed out and produced no hook evidence; do not
  interpret its empty observations as absence of call effects.
- Far allocation proof now requires the binary helper's exact return-frame
  kind and retains conflicting proofs for refusal. Baseline 3 failures / 12
  passes; initial neighborhood 42 passed; MyPy/Ruff clean. Final test run hit
  a transient concurrent IndentationError in `calling_convention_compat.py`;
  that file now compiles. Final rerun: 44 passed in 53.60 seconds, log
  `.cache/far-allocation-final-stable.log`.
  Linked replay `.cache/coverage-apply-twice-far-allocation.err` finished
  exit 4: allocation call now PROVEN/BP-preserved, leaving exactly the two
  indirect TARGET_UNRESOLVED refusals. SI/DI validation remains failed.
- Further diagnostic `.cache/coverage-apply-twice-spill-prune.err` finished
  exit 4: the spill-prune owner recognized SI/DI pairs but made no deletions.
  Do not change that owner on the assumption it removed these saves.
  Native codegen snapshots are now being captured in session `84619`, log
  `.cache/coverage-apply-twice-native-saves.err`, to locate their actual loss.
- Direct-caller census completeness only covers discovered direct callers;
  it does not close unknown incoming edges. Do not use it alone to assume
  the indirect targets or their preserved-register effects. The fixture has
  multiple pointer targets and branch-selected pointer arguments.
- Prior default pipeline process/session are gone; its log records only
  prerequisite 292 passed. Structured summary is stale (September 20), so
  no full-pipeline success is established. A fresh gate remains required.
- Expanded pointer neighborhood: 38 passed in 48.42 seconds after completing
  old mocks with the missing empty callee decoder surface. No production
  catch added. New default gate log: `.cache/pointer-slot-replay-pipeline.log`.
  Gate session `68055`, PID `3110637`, remains live; prerequisite 292 passed.
- Failed quality-dev (exit 2) log `.cache/pointer-slot-replay-quality-dev.log`
  reports repository Ruff debt and a mypyc type error in
  `validation_control_flow.py`; focused MyPy passes on both replay owners.
- `quality-dev` has typing failures outside this slice in
  `validation_condition_storage_views.py` and `semantics/call_stack_effects.py`;
  full log: `.cache/far-pointer-rebuild-quality-dev.log`.
- `fill_bytes`/`swap_ptrs`/`offset_copy` far-frame argument reads.
- Candidate manifest reruns for `large-far-pointer-001` and
  `large-far-function-001` once the above validate.

## Verification commands

- Focused regressions: `pytest angr_platforms/tests/...` (277 passing
  across the stack-prototype/GP-restore/CC/fn-pointer suites).
- Single function: `./.venv/bin/python decompile.py --no-alternate-source-c
  --timeout 60 --proc NAME --proc-kind {NEAR,FAR} <EXE>` in the retained
  `.cache/compiler-coverage/large-far-function-001/case-000` artifacts.
