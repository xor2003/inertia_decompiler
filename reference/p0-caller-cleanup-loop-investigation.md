# Caller-Cleanup Loop: Remaining Failure

## Carry Duplication Follow-Up

The FLAGS reaching-definition slice contains expression nodes, not the low
result assignment. Reusing a result from that slice is therefore not justified.
The fallback predicate now uses the exact unsigned-word identity
`WORD_MAX - rhs < lhs`, with required unsigned operand conversions. The
subtraction cannot underflow for word operands and the predicate does not
repeat the low addition. The existing assigned-result path remains unchanged.
This is Types/Lowering consuming the proven ADD_WITH_CARRY fact, not a text
rewrite or an invented assignment crossing control-flow boundaries.

All **37 focused tests pass** in **10.48s**, seven dependency warnings. The
compiled predicate checks 458,752 operand pairs with cosmetic casts disabled;
its AST contains no Add. The original full-decompiler addition and subtraction
regressions pass unchanged. Scoped Ruff, MyPy and Pyright are clean.
The native addition probe reports stable postprocess whole-tail live-out
validation and emits the low sum once. Its raw native output still has unresolved
declaration/memory rendering details, so this is not a claim that the complete
native translation unit is recompilable.
Logs: `/tmp/inertia-carry-threshold.log`, `/tmp/inertia-add-carry-final.log`.

Final checkpoint verification: both routine lanes pass **3,537 tests**, in
**164.15s** and **143.99s**; all three executable quality guards and all seven
MS C full round trips pass. `make -k quality-fast test-pipeline` still exits
**2** because repository-wide Ruff reports legacy debt. The focused production
Ruff/MyPy/Pyright checks pass; no global clean-lint or complete-suite claim is
made. Log: `/tmp/inertia-carry-threshold-gates.log`.

Timing: first diagnostic log created **12:42:31 CEST**, broad gates started
**12:45:48**, results collected **12:54:25**, on 2026-09-10. Approximately
**12 minutes elapsed**, including about **8.5 minutes of broad verification**;
this is wall time, not an estimate of uninterrupted engineering effort.
The caller argument contract remains the next unresolved issue in this report.

## Latest Follow-Up: Native Clinic and Required Casts

The subtraction failure below was traced past Lowering to native Clinic.
The existing straight-line X86_16 ITE policy was applied only by the CLI;
direct angr decompilation bypassed it. Clinic introduced blocks inside an
instruction and the high subtraction consumed its output FLAGS instead of
the incoming borrow. Raw VEX retained the correct pre-write operands.
Bootstrap now installs the same policy at Clinic's decompilation entry.
Three native-path regressions failed before this change and pass afterward;
the original subtraction integration regression also passes. Branching and
unknown CFG policy remains unchanged.

Review of the new FLAGS pruner additionally found opaque AIL reads and shared
variable identities that needed conservative handling. Eight new regressions
failed before those corrections; its focused module now has **20 passing**
tests. Unknown dirty payloads refuse deletion, and exact vvar and unified
storage identities both participate in the read census.

Addition then exposed an independent rendered-C defect: an ordinary cast
around the low sum disappeared when cosmetic casts were hidden. C integer
promotion therefore made the carry comparison wrong. Lowering now uses the
existing `CSemanticCast8616` for required unsigned-word conversions. A gcc
execution regression checks every low operand against seven boundary operands
and reproduces wrong execution before the fix, passing afterward. It is in
both Make selections and the routine pipeline runner, with ownership mapping.

Focused verification: **65 passed, one failed**, seven dependency warnings,
**11.48s**. The remaining addition assertion still detects a repeated low sum;
it was not relaxed. The complete original caller-argument failure also remains
open. These are partial repairs, not a completed function-fix certificate.
Logs: `/tmp/inertia-native-clinic-before.log`,
`/tmp/inertia-native-clinic-after.log`, `/tmp/inertia-carry-c-before.log`,
`/tmp/inertia-carry-semantic-after.log`.

Broad follow-up: `make -k quality-fast test-pipeline` exits **2**. The routine
lanes each report **3,535 passed, two failed**, taking **174.57s** and
**154.89s**. The failures are addition duplication and the bootstrap inventory
missing the newly installed policy. After the broad pytest runs, the inventory
assertion was updated and its focused test passes in **18.44s**, with Ruff
clean. The broad counts are not retroactively adjusted.

All three executable quality guards and all seven MS C tiny full round trips
pass, including generated-C recompilation and execution. Scoped production
Ruff, MyPy and Pyright pass; global lint debt remains. The slowest first-lane
tests are InitMenu (**69.22s**), RunMenu (**64.93s**) and InitBars (**60.66s**).
Log: `/tmp/inertia-carry-required-casts-gates.log`. The working tree remains
uncommitted because the addition regression is unresolved. Next: preserve
the proven low-result carrier without repeating its arithmetic; do not remove
the required truncation or weaken the regression to obtain a green result.

## Flag-Pruning Repair

The next investigation (approximately 11:50-12:00 CEST) captured the first
DCE input and output. The input already read undefined `v5`; DCE was not the
pass that first lost that definition. The legacy flag pruner considered only
the remainder of each local statement block and treated physical-register
writes as killing distinct captured SSA values.

Three new tests failed before repair: while/do-while enclosing-guard reads
and an older SSA value consumed after a distinct FLAGS definition. The new
`postprocess/flag_dead_definitions.py` consumes existing register/SSA identities
and requires absence of reads across the whole structured function before
removing a pure assignment. Dead acyclic chains reach a fixed point; unknown
identities, cycles, calls, opaque expressions and memory reads are retained.
This is cleanup proof, not new flag semantics or condition recovery.

The legacy entry now delegates to this focused owner, reducing the large file
by approximately 50 lines. The new owner and its regression module are enrolled
in Make typing/Ruff/test scopes, architecture promotion and ownership mapping.

Verification:

- All **37 focused cleanup tests pass**, seven warnings, **11.76s**.
- The broader caller/cleanup selection has **38 passed, one failed**. The
  unchanged caller signature assertion remains the failure; the prior FLAGS
  validation-rejection messages no longer occur. Absence of a warning is not
  by itself a function-level equivalence certificate.
- Both production modules pass MyPy and Pyright. The new module and regression
  file pass Ruff; the legacy cleanup module retains **31 Ruff findings**.
- Broad `quality-fast test-pipeline` verification exits **2**: both routine
  lanes report **3,503 passed and one failed**, in **164.92s** and **147.46s**.
  The three executable guards and all seven MS C round trips pass. Global
  Ruff debt also remains. Log: `/tmp/inertia-flags-liveness-gates.log`.

The new broad failure is
`test_full_decompiler_preserves_one_low_subtraction_and_one_high_borrow`.
Widening succeeds, but bit Lowering returns `CARRY_USE_AMBIGUOUS`, with zero
materialized and one failed fact. The preserved definitions expose a dependency
on the old deletion: `carry_borrow_bit_placement.py`'s orphaned-use fallback
refuses when those definitions survive. Do not restore unsafe deletion or
weaken the ambiguity check. Next, trace exact high-instruction carry-use roles
and reaching SSA definitions in Lowering; distinguish input carry from output
FLAGS and prove which occurrences represent the same semantic use.

After this gate, both FLAGS test modules were explicitly added to the runner's
`FOCUSED_PYTEST_TARGETS`, which is separate from Make's own pytest inventory.
The counts above predate that selection-only addition. This is an uncommitted
repair checkpoint, not a stable completed step or a green whole-suite result.
The pipeline-selection and both FLAGS modules then pass **69 tests** in
**8.85s**, seven dependency warnings. Scope scripts retain 71 Ruff findings;
`git diff --check` passes. Log: `/tmp/inertia-flag-scope-tests.log`.

Remaining DoD: verify and repair the recovered caller argument contract,
explicit whole-tail acceptance and generated-C compilation. No integration
assertion or validation rule was weakened. Logs:
`/tmp/inertia-caller-dce-capture.log`, `/tmp/inertia-flags-liveness-before.log`,
`/tmp/inertia-flags-liveness-after.log`, `/tmp/inertia-flags-liveness-focused.log`.

## Current Evidence

Investigated on `11500a82b`, 2026-09-10, approximately 11:41-11:49 CEST.
The five-test caller-cleanup module reports **one failed, four passed** in
18.90s. Its sidecar-free PercolateUp acceptance passes. This does not close
the original full-suite failure.

For the synthetic loop at `0x1000`, all three affine stack-tracker assertions
pass. CFG reports a call block at `0x1003` targeting `0x1020`. Generated C
retains that target but passes two expressions, the high byte of AX and AX,
instead of the test's literal no-argument call. No assertion was relaxed:
call presence alone does not establish correct argument recovery.

The input contains two word PUSHes, a near CALL, `add sp,4`, `dec cx` and a
backedge. Callee code is a bare RET. The physical pushed-word inventory and
the callee's actual consumed-argument contract must be inspected separately.
The output cannot justify recovering AX's high byte as a separate word by
itself.

## FLAGS Diagnosis

The existing frontend artifact is active and covers two packed-preservation
sites. The initial structured body contains three runtime-FLAGS entry copies.
Although these copies have empty instruction tags, def-use recognizes their
definitions; missing tags alone are not the demonstrated cause.

During cleanup, def-use reports a read of `reg+0x24:size2`, SSA `ir_2`, at
`root.stmt1.do.condition` with an empty defined set. Validation rejects and
restores attempted cleanups; the final function still falls back to its earlier
representation. This is not successful whole-tail validation.

The focused FLAGS test now covers if, while and do-while guards. All preserve
the live entry/update chain and allow removal after its consumer disappears.
All **nine module tests pass** in **8.03s**, seven dependency warnings;
all ten reported durations are below one second. Ruff `check --fix` and Pyright
pass. Six pre-existing magic-comparison findings in this touched file were
resolved using a named preservation site and the source SSA identity.

Thus ordinary loop-guard traversal alone does not reproduce the integration
failure. Next: capture the exact first rejected cleanup input and output,
reduce its FLAGS chain into a failing unit regression, and trace the dropping
decision before changing production. Also verify the physical call inventory.

Reason: prevent live branch-state or argument loss without weakening validation.
DoD: original caller-cleanup regression, correct argument classes, clean tail
validation, focused refusal tests, scoped quality and routine executable gates.
Failure: accepting any call text, marking missing definitions architectural
live-ins without proof, or removing validation checks to accept the output.

Logs: `/tmp/inertia-affine-cleanup-before.log`,
`/tmp/inertia-affine-cleanup-output.log`, `/tmp/inertia-affine-def-use.log`,
`/tmp/inertia-flags-loop-guards-final.log`. No production code changed; broad
gates were not repeated for this test-only extension.
