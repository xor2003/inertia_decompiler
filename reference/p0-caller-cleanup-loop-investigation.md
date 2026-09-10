# Caller-Cleanup and PUSH Widths

## Saved-BP Byte Pair Repair

QuickC `hello` reproduced the final-C failure on the width-safety revision
(exit **4**). Frame decoding was complete, but all seven observed frame-pruning
attempts refused the structured entry carrier. The low byte was an aliased
one-byte stack variable at entry-SP minus two, sourced from the BP SSA value;
the high byte remained a segmented store at entry-SP minus one, sourced from
the same value shifted by eight. Existing whole-word matching intentionally
rejected the one-byte carrier.

Lowering now recognizes this pair only with decoded canonical-frame proof,
exact instruction ownership, the native entry-SP anchor, both saved-word slots,
an exact shared SSA identity and matching physical BP views. Isolated bytes,
different SSA values, wrong slots/shifts/instructions, and duplicate/conflicting
projections refuse. The existing whole-function frame-use check still runs
before the instruction group is consumed. No lifter behavior, validation rule,
or Rewrite recovery was changed. The production owner remains below 350 lines.

The first focused candidate exposed two proof holes: general expression
equality ignored distinct register SSA IDs, and a conflicting high-byte store
was initially ignored. New refusal tests reproduced both; the final proof uses
the existing frame scalar-identity owner and rejects conflicts. All **64 focused
frame tests pass** in **9.64s**, seven dependency warnings. The original
isolated-byte refusal tests remain unchanged.

The live `hello` command now exits **0**, reports `validation=passed` and clean
whole-tail validation, retains the call argument, and emits no raw saved-BP
store. Its generated C passes `gcc -std=c99 -Wall -Wextra -Werror -fsyntax-only`.
Scoped Ruff, MyPy and Pyright pass. Final fast/default test lanes each pass
3,562 tests (159.34s/146.68s); executable guards and all three default pipeline
lanes pass. The combined Make command still exits 2 on global Ruff debt.
The subsequent complete audit remains red; see
[full-suite follow-up](p0-full-suite-followup-20260910.md).
Logs: `/tmp/inertia-hello-before.log`, `/tmp/inertia-hello-frame.log`,
`/tmp/inertia-frame-byte-final.log`, `/tmp/inertia-hello-after.log`.

## Width Safety Repair

Removing the last-N-stores fallback alone did not fix the bug: a second
backtracking path selected the same byte stores. The shared store-value reader
was returning lvalues typed as 8-bit `char` as complete pushed arguments.
The existing `lowering/call_argument_stack_sources.py` now owns a typed width
verdict: 16/32-bit stores have complete architectural PUSH width; subword,
oversized and unknown-width stores refuse. Width is only a necessary condition,
not proof of PUSH identity or argument ownership. No byte coalescing or new
semantic recovery was introduced in Rewrite.

The legacy reader consumes this verdict and leaves refused stores intact.
The redundant last-N-stores materialization/deletion branch was removed,
shrinking the large compatibility file by 85 lines before the width check.
No architecture exception was added: the check resides in the existing admitted
stack-source owner. The original no-argument assertion and the added value
regression both pass; the physical unknown sources are not promoted to invented
byte arguments. Complete word reconstruction for unknown sources remains a
separate typed recovery obligation, not something proven by this guard.

Verification: **83 related integration tests pass** in **20.61s**, including
the sidecar-free PercolateUp acceptance; **26 owner/caller tests pass** in
**22.10s** after adding width/refusal coverage. Scoped production MyPy and
Pyright pass. Ruff is clean for the touched Lowering owner and test module;
the legacy calls module retains **367 findings**. Its two related Lowering lint
findings were fixed by separating native inventory traversal from deduplication
and naming the return-frame offset bound. Routine runner and ownership scopes
now include the caller-cleanup module, matching Make's existing selection.
Broad gates: both routine lanes pass **3,552 tests**, in **176.33s** and
**147.81s**. All three executable quality guards and the complete seven-case
MS C round-trip lane pass. The aggregate still exits **2**: global Ruff debt
remains, and the Ultra/QuickC fixture lane has **three passed, one failed**.
No whole-suite closure is claimed.

The newly exposed fixture is QuickC `hello`. Its call argument survives, and
whole-tail validation reports passed, but the final-C contract correctly rejects
a surviving saved-BP high-byte store rendered using raw `ss << 4` arithmetic.
The output includes a write of `(inertia_ebp & 0xffff) >> 8` through that stack
address. This is frame-bookkeeping preservation/materialization debt, not a
reason to restore byte-as-word argument guessing or suppress the final-C guard.
The next repair must establish the exact saved-register spill ownership and
handle all byte projections coherently at the owning layer. The broad run is
not green; this safety checkpoint remains uncommitted.

The structured pipeline result is authoritative: the failed lane is
`ultra-quickc-fixtures`, not `msc6-tiny-full-pipeline`. Some MS C profiles record
failed earlier attempts even when the accepted round trip passes; these fields
alone do not identify the failing lane.
Log: `/tmp/inertia-caller-width-gates.log`; structured evidence:
`angr_platforms/.cache/test_pipeline/summary.json` and
`examples/build_ultra_quickc_pipeline/ultra_quickc_fixtures.json`.
Logs: `/tmp/inertia-caller-no-guess.log`, `/tmp/inertia-caller-store-width.log`,
`/tmp/inertia-caller-width-final.log`, `/tmp/inertia-caller-owner-tests.log`.

## Reproduced Word-PUSH Argument Corruption

Revalidated on committed `2bc106e48`: the original caller-cleanup regression
still fails. Binary summary at callsite `0x1005` reports two physical pushes at
`0x1003` and `0x1004`, widths `(2, 2)`, and cleanup of four bytes. Both push
sources remain unclassified; the callee argument-count evidence is UNKNOWN.
The native Clinic call has no arguments. During the legacy calls adapter,
`_rewrite_block_body` selects the last `expected_arg_count` stack-store
statements and passes their RHSs to `_set_materialized_call_args`.

The stores are independently resolved bytes of word PUSHes. Therefore the last
two statements are the high and low byte stores of the final PUSH, not two
logical arguments. The resulting call is `sub_1020(AX >> 8, AX)` even though
both machine pushes capture AX. This is a concrete width/identity failure;
changing call text or counting stores cannot repair it.

A new AST regression reproduces the value mismatch without claiming that the
bare RET establishes zero formal arguments: if the physical words become
arguments, their captured values must be identical. The original no-argument
assertion is unchanged. The focused module excluding its external PercolateUp
case now reports **two failed, six passed**, seven warnings, **11.87s**. Ruff
is clean after parameterizing the existing immediate-boundary cases and naming
the declaration-plus-call count. No production behavior has changed in this
investigation; the new failing regression is uncommitted.

Next repair belongs in typed stack-argument lowering: consume exact PUSH
instruction identities, widths and storage facts, account for every byte
projection, and materialize a word only when all pieces agree. Replace the
legacy last-N-statements shortcut with that proof or explicit refusal. Do not
change the byte-safe frontend access helpers, infer zero arity from a bare RET,
or add another Rewrite argument heuristic. Preserve memory effects until the
typed materialization and consumption proof closes.

DoD: the value regression passes; the arity expectation is resolved using
binary/callee evidence; whole-tail validation and generated-C execution pass;
unrelated stores, incomplete byte sets and conflicting identities refuse; the
routine gates and MS C round trips remain green.
Failure: accepting one byte as a word, suppressing the original assertion,
discarding stores without consumption proof, or hiding UNKNOWN as success.
Evidence: `/tmp/inertia-caller-current.log`,
`/tmp/inertia-caller-args-evidence.log`, `/tmp/inertia-caller-word-regression.log`.

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
