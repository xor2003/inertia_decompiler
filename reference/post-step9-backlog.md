# Open Work Outside Bounded Step 9

These tasks are not complete. The user moved them outside Step 9 on September
19, 2026. Do not start them merely to prolong SORTD acceptance.

## TID And Other COD Repairs

Reason: unrelated programs still expose real semantic and initialization gaps.
DoD: each fixed function has clean validation, preserved call/memory/control-flow
effects, strict compilation, and its source-backed behavioral regression passing.
Failure: cosmetic assertion changes, source-dependent recovery or hidden failure.

TIDShowRange still exits 4 for unassigned stack locals. Return-reuse diagnostics
now distinguish typed refusal causes. The captured producer exists once, but
the legacy block walker supplies only its sibling's six-statement prefix.
Lowering now extends an exact unchanged prefix through transparent sequences;
branches, clobbers and stale prefixes still refuse. Focused tests: 51 passed
in 12.49s; scoped Ruff/MyPy/type/doc checks pass. The live proof advances to an
intervening assignment to `ir_15` (synthetic register 4132), not function success.
Next: prove read-helper effects and destination storage disjointness at the
owning layer; do not infer purity from a function name or relax the clobber guard.
Evidence: `.cache/step9-return-{refusal,sibling}-*.log` and
`.cache/step9-tid-return-{ownership,sibling,barrier}.{c,log}`.

## Whole-Repository Quality

Reason: curated acceptance is not a green complete pytest collection or lint run.
DoD: source-stable full pytest, global lint/types and hard quality gates pass;
retain behavior coverage when replacing outdated assertions; measure slow tests.
Failure: skips, weaker checks, inflated timeouts or unsupported failure-count claims.

See [the failure inventory](step9-failure-refresh-20260919.md). Two stack-probe
tests also reproduce without the latest return-dispatch wiring. Global Ruff
remains red. The last completed default pipeline passed 5,791 routine tests and
both external lanes, but predates the latest refusal/prefix changes.

Newer bounded checkpoint: the default pipeline passes 5,819 routine tests and
both external lanes. A separate 317-test validation surface has one failure:
`test_x86_16_tail_validation.py::test_tail_validation_compare_classifies_switch_decision_tree_without_helper_delta`.
It persists after removing the rejected captured-call fingerprint experiment
and restoring the accepted production digest. Track this separately; do not
report the curated pipeline as a green full collection.

Final bounded Step 9 checkpoint: 5,861 routine tests pass in 352.04s, plus
268 prerequisite tests and both external lanes (four QuickC fixtures and seven
MS C tiny round trips). Project-wide MyPy passes. Global quality-fast and
quality-hard remain Ruff-blocked. The routine lane's configured 30-second
budget is exceeded; this is recorded, not a performance target achieved.
See [the closure ledger](step9-closure.md). No full-collection rerun is claimed.

## Generated-C Readability Exception

The user explicitly deferred the four previously reported SORTD generated-C
`variable set but not used` warnings from bounded Step 9. Preserve their raw
compiler evidence. The subsequent clarification makes compiler errors blocking
and warnings subject to review, with justified narrow suppression permitted.
All semantic and behavioral checks remain blocking; warnings indicating actual
correctness defects cannot be waived as cosmetic. This does not authorize
deleting live assignments or blanket warning suppression.

Current status: `step9-sortd-compilation.json` records all 20 functions with
zero errors and zero warnings. The exception is unused, not four outstanding
warnings in the current artifact. No additional cleanup is required for closure.

## General Contracts And Migrations

Reason: Tasks 3 and 8 contain broader work than one fixed executable can prove.
DoD: preserve their individual typed contracts, negative cases, closed evidence
counters and owning-layer acceptance in `SORTD_GHIDRA_PLAN.md`.
Failure: declaring general completion from the 20 SORTD functions alone.

## Measured Performance

Reason: speed work must target current measured bottlenecks rather than old profiles.
DoD: follow Step 10 and `DECOMPILER_PERFORMANCE_PLAN.md`, including stable repeats,
semantic acceptance and the existing gain threshold for substantial changes.
Failure: repeating rejected experiments without new evidence or trading correctness
for throughput. This task does not block Step 9 unless a required gate cannot finish.
