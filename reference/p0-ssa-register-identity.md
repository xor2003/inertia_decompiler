# SSA Register Identity Follow-Up

## Root Cause

While tracing BIOS private-stack candidates, the live IR showed the second
SP update, `SP - 4`, reading version zero instead of the SP version established
by the preceding PUSH. The block-local SSA key included `IRValue.offset`.
For a named REG value that offset is arithmetic displacement, not a distinct
storage location. Consequently `SP`, `SP-4` and `SP+2` acquired unrelated
version histories. This prevented trustworthy frame-coordinate reasoning.

The six SP-relative Alias refusals in the fixture are separately recorded.
`StackMemorySSAAliasArtifact.complete` means the evidence census closes; it
does not mean zero refusals. The observed census was raw=10, materialized=4,
failure=6, with complete=True. No lifetime/deletion permission follows from it.

## Implementation

IR owns the fix. Named-register version identity now ignores the expression's
offset while preserving that offset, operation, width and VEX temporary
provenance in the value itself. Memory offsets and unnamed register identities
remain distinct. Function join keys consume the same block-local key owner.
No Alias, Rewrite, CLI, instruction execution or frame-deletion behavior was
added. Existing temporary-capture semantics continue to select an older
register version when a VEX temporary captured it before a later overwrite.

## Evidence And Acceptance

Fifteen new tests exercise SP/BP/BX, positive/negative displacement, current
versus captured definitions, and offset-distinct memory/unnamed registers.
Before: 12 failed, three passed (8.45s). After: 40 SSA/Alias tests passed
(13.33s), then 124 SSA/wiring tests passed (10.39s). Scoped Ruff, MyPy and
Pyright pass. The live BIOS trace now uses SP version 1 for `SP-4`.

Reason: frame ownership cannot rely on displaced register expressions attached
to the wrong reaching definition.
DoD: preserve exact source versions and displacement, keep snapshots and
storage distinctions intact, maintain shared block/function identity, and
verify broad regression/compilation behavior. Definition of failure: rewriting
all reads to the latest version despite temporary provenance, merging memory
slots by dropping offsets, or treating corrected SSA as proof of private
stack lifetime. The BIOS strict-C regression remains an independent blocker.

## Full Audit

Started at approximately 17:52 CEST on 2026-09-10:
`PYTHON_JIT=1 PYTHONHASHSEED=0 make pytest-all PYTHON=./.venv/bin/python PARALLEL_JOBS=7`.
Production is held stable during the audit. Exact active-work start before
this checkpoint was not captured; no synthetic elapsed estimate is reported.

Evidence: `/tmp/inertia-ssa-displacement-before.log`,
`/tmp/inertia-ssa-displacement-after.log`, `/tmp/inertia-ssa-identity-wiring.log`,
`/tmp/inertia-bios-frame-fixed.log`, `/tmp/inertia-full-suite-ssa-identity.log`.
The prior machine report was retained at
`/tmp/inertia-full-suite-before-ssa-identity.json` for failure comparison.

Completed: 11,478 passed, 23 failed, 170 skipped, all 11,671 tests accounted
for, in 1,370.09s (22m 50s runner time). Peak aggregate RSS was 1,839,548 KiB;
no memory-limit breach, missing tests, duplicate tests or unexpected outcomes.
Source remained stable, SHA256
`aab1a872b1296774d2b71c88c292f13bb350cfa6b64e8c8500acec8837e31ea1`.
Compared with the saved baseline, 13 prior failures pass; the only newly
failing node is the deliberately admitted BIOS strict-compilation regression.
This comparison spans the preceding segment/store/call repairs as well as SSA;
it is not an isolated performance or causality measurement of the SSA change.
Runtime remains well above the accepted 335-398s range.

The architecture test remained red but its findings changed: two new modules
needed canonical ownership markers and explicit typed-promotion registration.
Those omissions were subsequently corrected without weakening the checker.
The complete architecture module plus SSA/segment/store-width regressions then
passed: 402 tests in 46.21s. Scoped MyPy passed. Ruff reports 70 pre-existing
findings in the large architecture checker; the four semantic modules and new
tests are clean. Do not recalculate a full-suite total from this focused repair.

Slowest measured tests: TidShowRange CLI 124.08s, OpenFileWrapper COD 85.49s,
InitBars 72.48s, QuickSort 45.24s, and SetGear 41.89s. Both failed and passing
corpus tests contribute to the slow tail; no tests were removed or skipped.
The fresh machine evidence is `.cache/pytest/partitioned-summary.json`.
Routine post-repair quality and default executable gates are recorded in
`/tmp/inertia-ssa-final-gates.log` (started approximately 18:20 CEST).

## Routine Gate Closeout

Completed before 18:29 CEST on 2026-09-10. Fast pytest: 3,610 passed, one
failed in 196.44s. Default pytest: 3,610 passed, one failed in 156.44s.
Both failures are the admitted BIOS strict-C regression, not SSA tests.
All three executable quality guards passed; the default pipeline reports
two passing lanes (including MS C compile/decompile/recompile/execute checks)
and one failing pytest lane. Both Make goals therefore correctly remain red.
Scoped MyPy and Pyright pass; global Ruff remains red. No diagnostics were
suppressed, no tests removed, and no BIOS frame stores deleted to satisfy gcc.

This is a bounded SSA prerequisite checkpoint, not BIOS/P0/full-suite closure.
Next semantic work must prove stack allocation/lifetime, escape and read
closure in IR/Alias before allowing any exact frame-store elimination.
