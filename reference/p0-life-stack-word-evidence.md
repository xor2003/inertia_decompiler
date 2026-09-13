# LIFE Stack-Word Evidence Investigation

## Status

`pause_screen` remains unresolved. The final-emission guard correctly rejects
an unresolved SP-relative local; it has not been relaxed. The focused original
test reproduces the failure in 23.02s with seven workers. The source-independent
success requirement remains open.

## Evidence

The rejected C declares byte-sized `key` and `local_1`, plus
`stack_sp_m3_2`, although the machine operand is `WORD PTR [bp-2]`.
Its input-loop predicate is also inconsistent with the source's key-selection
loop. The source/COD was used for diagnosis, not recovery.

The native frame artifact has a proven BP-to-entry-SP delta of -2, but reports
only one-byte BP slots at -2 and -1. Alias reports 62 raw access candidates,
zero materialized, with 18 unknown-call-stack-effect and 44 unproven-range
refusals. Complete call effects exist; the get_key call carries an escaped
range. Therefore missing stack-coordinate proof is not the only issue, and
Alias refusals must not be interpreted as private or disjoint storage.

Read-only probes retain the rejected C and structured evidence in
`/tmp/inertia-life-pause-rejected3.c` and
`/tmp/inertia-life-pause-evidence3.log`.

## Isolated Frame-Width Defect

Before the change, a binary containing only a frame setup and
`mov ax,[bp-2]` produced two byte frame slots. The regression expected the
machine operand's word width and failed before the fix.

`ir/frame_memory_accesses.py` now consumes closed, function-owned logical
memory records with exact current raw-instruction bindings. Covered execution
bytes contribute one logical operand; uncovered raw accesses remain intact.
Independent byte instructions remain independent. Missing, incomplete, foreign
or stale bindings retain byte evidence instead of inventing a word access.

This is lossless IR operand evidence consumed by Analysis and Semantics, not
alias identity, object widening, semantic cleanup or a change to byte-safe
frontend execution. The frame owner
now consumes it and shrinks rather than accumulating recovery code. Seven
focused width/refusal tests pass. The original LIFE regression still fails;
no whole-function fix is claimed.

Verification: routine pytest passed 3,905 tests (seven dependency warnings,
253.88s), and all seven MS C tiny compile/decompile/recompile/execute round
trips passed. No pipeline lanes failed or timed out. Scoped Ruff (`--fix`),
MyPy, Pyright, full architecture and diff checks pass. Logs:
`/tmp/inertia-logical-frame-{before,life,pipeline,mypy3,pyright2,architecture2}.log`.
The last full-suite audit still reports 21 failures; it has not been rerun
after this isolated frame-evidence improvement.
`quality-fast` remains red at the global Ruff gate; its mypyc import smoke
passed for 39 compiled modules. Global lint is not treated as waived.

## Call-Effect Width Follow-Up

A second native-operand regression demonstrated an unsafe preservation claim:
passing the low address of a logical word escaped its low execution byte but
left the high byte preserved. The regression failed on `effect.preserves(high)`
before the change. The same exact operand view now lives in IR so Semantics
and frame Analysis can consume it without reversing layer dependencies.

Call-effect range collection retains both raw cells and validated logical
operands. Escaped operands include their overlapping tracked cells; a scalar
argument control still preserves both bytes. This does not establish bounds
for arbitrary pointer arithmetic or prove that an escaped value is unchanged.
It is not permission to invent a local or ignore an unknown call write.

Twenty-three call/frame tests pass, but the LIFE regression still raises the
unresolved-stack hard error. Scoped MyPy/Pyright and architecture checks pass.
Before/after evidence: `/tmp/inertia-call-word-{before2,after,life}.log`.
The completed routine gate passed 3,907 tests in 231.84s, all seven MS C tiny
round trips, and all three pipeline lanes without failures or timeouts
(`/tmp/inertia-call-word-pipeline.log`). `quality-fast` still fails its global
Ruff gate; compiled import smoke passed for 39 modules.

The subsequent behavior-preserving provenance extraction removed the five
Ruff findings from the touched call-effect owner. Physical PUSH expression
interpretation now belongs to `semantics/call_stack_provenance.py`, with named
tuple arities and separate expression validation and operation interpretation.
The call-effect owner is below 350 lines. Both modules pass Ruff `--fix`, MyPy,
and Pyright; the full architecture checker and diff checks also pass.
Forty-eight focused call/frame/provenance tests pass in 10.16s,
including malformed sources and conservative pointer-arithmetic refusals.
The new cases are registered in the routine pipeline and test ownership map.
These focused results follow the extraction; the routine gate above precedes
it, and neither replaces the recorded full-suite audit.
Logs: `/tmp/inertia-call-provenance-{tests,mypy,pyright,architecture}.log`.

## Wrapped Call-Argument Follow-Up

Three additional native-operand cases failed because linear offset containment
treated `BP+FFFEh`, `BP+FFFFh`, and an accumulated 64 KiB displacement as
disjoint from the tracked word at `BP-2`. Semantics now uses the existing IR
circular-range comparison for the pointed byte, retaining the logical-word
escape expansion. The disjoint wrapped-address and scalar controls still pass.
All 52 focused tests pass (9.30s); scoped Ruff, MyPy and Pyright pass.
Before/after logs: `/tmp/inertia-call-wrap-{before,after}.log`.
The final routine pipeline passes 3,936 tests (201.17s), all seven MS C tiny
compile/decompile/recompile/run cases, and all three lanes with no failures,
skips or timeouts. The full architecture checker passes. Evidence:
`/tmp/inertia-call-wrap-{pipeline,architecture}.log`.
The final `quality-fast` run still fails global Ruff; compiled import smoke
passes for 39 modules (`/tmp/inertia-call-wrap-quality.log`). Scoped green
checks do not clear that global debt or the 21 failures in the last full audit.
This closes an unsafe preservation claim, not the LIFE function failure.

## Existing Identity Evidence

The retained LIFE artifact already publishes nine logical storage identities
for the same `SS:BP-2`, size-two range, despite refusing memory value versions.
The separate identity owner is `alias/logical_stack_storage_identity.py`;
`lowering/instruction_bp_stack_access.py` already indexes that evidence.
Do not add a duplicate identity mechanism or relax unknown-write refusals.
Trace current Lowering consumption and coordinate selection first. In
`resolve_logical_stack_word_owner_8616`, the instructionless path requires
exactly one matching read; repeated reads of the same storage may therefore
refuse it. This is a candidate limitation, not a proven cause of LIFE's output:
the path also requires the same canonical CVariable for both byte views.

## Confirmed Operand-Provenance Loss

Fresh LIFE probes isolate the active lookup failure: seven recompositions carry
JCC instruction addresses, but the logical Alias inventory is indexed by the
memory CMP addresses. For example, branch `0x10840` consumes the word comparison
at `0x1083c`; Lowering searches for a word load at `0x10840` and refuses it.
The retained typed conditions initially had `SS:BP-2`, size two, but no
`memory_access_insn` on any of the eight key comparison operands.

The frontend `_condition_stack_value_8616` constructor omitted access evidence.
Three native memory-CMP regressions failed before the change. Direct-memory
CMP forms now pass their own instruction address to that constructor, which
retains access size and address. Other callers keep absent evidence absent;
previously loaded register operands are not rebound to the current CMP.
No byte-safe execution helper, Alias refusal, or final-emission guard changed.

Sixty-six focused frontend/transfer/cache tests pass (10.19s), including the
three native CMP forms and an unknown-provenance control. A fresh LIFE probe
confirms `0x1083c` now reaches the typed operand for branch `0x10840`, but the
seven C-AST recompositions still lack that provenance. LIFE remains rejected.
Next: transport operand-owned load evidence through stack condition lowering,
then verify the canonical coordinate and word owner. Do not attach a producer
address merely because it is a nearby CMP: a register comparison may consume
a value loaded elsewhere. The instructionless-owner hypothesis above did not
explain these seven tagged refusals and is not the immediate repair target.

Before/after evidence: `/tmp/inertia-stack-condition-{before,after3}.log` and
`/tmp/inertia-life-pause-evidence{7,8}.log`. Scoped MyPy/Pyright pass. The new test
module passes Ruff; existing lifter and transfer-test lint debt remains.
The first routine run exposed two additional INC/CMP exact-value expectations
that omitted the newly retained access fields. Both were updated to require
the exact CMP load address without changing the incremented register operand.
All 59 tests in that module pass (15.43s); all seven external MS C round trips
also passed in that first run. Its pytest lane was red and is not reported as
a passing routine gate (`/tmp/inertia-stack-condition-pipeline.log`).
The complete rerun passes 3,940 pytest tests in 167.11s, all seven MS C
round trips, and all three lanes without failures or timeouts
(`/tmp/inertia-stack-condition-pipeline2.log`). Architecture and scoped typing
checks pass. These are routine-gate results, not a refreshed full-suite audit.
The final `quality-fast` run remains red at global Ruff; compiled import smoke
passes for 39 modules (`/tmp/inertia-stack-condition-quality.log`).

## C-Operand Transport And Rollback

The next failing-before test showed the typed stack operand builder dropped a
supplied load address. Its implementation now lives in
`lowering/condition_stack_value.py`, with only an import delegate left in the
legacy typed-condition postprocess module. The direct Structuring value path
uses the same tag helper. The architecture guard initially rejected the new
edge; the extracted compatibility delegate is explicitly documented/admitted.
No condition discovery or semantic recovery was added to postprocess.

Thirty-eight related tests pass, including supplied/absent access provenance
for both expression paths. Scoped MyPy/Pyright and architecture pass; the new
Lowering module and touched condition/LIFE tests pass Ruff. Legacy owner lint
debt remains. Logs: `/tmp/inertia-condition-tags-{before,focused,mypy,pyright,architecture2}.log`.

An observed LIFE run confirms each of the eight exact load addresses reaches
the returned CVariable tags. The final rejected C nevertheless remains
byte-identical: whole-tail validation rejects the transformed body with
uninitialized stack reads and restores its older snapshot. The restored word
recompositions therefore still show seven `alias_load_missing` refusals.
Read-only evidence is `/tmp/inertia-life-pause-evidence12.log`; the focused
LIFE test still fails (25.22s, `/tmp/inertia-condition-tags-life-test.log`).

The old source-sidecar-independence test ignored decompilation status and could
pass on timeout. It now requires `status == "ok"`; an extended 60s diagnostic
run still reaches the unresolved-stack guard, so no function fix is claimed.
Investigate the callee's binary-proven pointer-output effects and their
conditional availability at the input-loop exit. Do not assume every call
initializes the key: the false return path may leave it untouched.

The routine pipeline passes 3,944 pytest tests in 197.70s, all seven MS C tiny
compile/decompile/recompile/run cases, and all three lanes without failures or
timeouts (`/tmp/inertia-condition-tags-pipeline.log`). The explicitly failing
LIFE regression is outside this curated lane; the full-suite debt stays open.
Final `quality-fast` remains red at global Ruff, with all 39 compiled import
smoke checks passing (`/tmp/inertia-condition-tags-quality.log`).

## Conditional Output Oracle Checkpoint

The native input routine at `0x10AC5`, called at `0x10822`, writes a word
through DS:BX only on the input-available path, returning AX=1. The other
path returns AX=0 without writing. Both paths join at the same RET. The
pointer argument is loaded from SS:BP+4; that alone does not prove DS=SS.

`test_x86_16_conditional_pointer_output_native.py` pins the actual LIFE bytes
and executes both paths with equal and distinct DS/SS values. It checks the
entire output word, neighboring bytes, return value and BIOS service sequence.
Controlled corruptions prove the oracle rejects a byte-only store and a write
without available input, specifically on the memory assertion. BIOS input is
hooked; this is native execution evidence, not generated-C equivalence.

A separate Semantics regression verifies that a one-path word store remains
CONDITIONAL when both paths share a return block. It is deliberately not a
MUST_WRITE fact. These tests are registered in the routine Make/Python
pipelines and pointer-output test ownership. Focused verification: 17 passed,
7 dependency warnings in 10.48s; scoped Ruff passes. Full pipeline and whole
suite were not rerun for this test-only checkpoint.

The remaining implementation must associate the write with a proven return
condition, preserve that qualification through Alias/Lowering, and consume it
only where the caller establishes the condition. It must separately prove
the segment relation before treating DS output as an SS local definition.
No LIFE fix or new repository-wide passing count is claimed.

Native SSA follow-up: lifting the actual routine through the public IR and
function-SSA builders produces two conditional DS:BX byte-output facts at
relative offsets 0 and 1, with one shared terminal. Logical-memory evidence
retains the single two-byte operand and its two execution slices. The new
regression also changes the instruction to a byte store and requires both
views to narrow to one byte; it does not merge cells by adjacency. The focused
native/Semantics gate now passes 19 tests in 10.86s with seven dependency
warnings; Ruff passes. Logs: `/tmp/inertia-conditional-output-native-ssa.log`.

Consequently, return qualification alone is not enough: the implementation must
consume the existing logical-operand binding when projecting a word definition.
The inspected terminal-register-return owner tracks AX lanes and storage roles;
the pointer-output contract currently retains disposition and terminal sets,
not a return-value predicate. Keep the qualified effect in Semantics and
preserve its proof through the existing Alias and Widening contracts.

## Conditional Widening Safety Fix

Inspection exposed a separate correctness defect: Widening grouped conditional
byte outputs solely by disposition and terminal sets. Complementary branches
with a shared epilogue therefore appeared to write one combined word, although
neither branch necessarily wrote both bytes.

Semantics now exposes conservative conditional store-block evidence derived
from retained STORE sites. Widening requires that evidence to agree before
combining conditional lanes, and the view contract independently rejects a
forged combined view. Unconditional must-writes remain unaffected. Matching
store blocks are sufficient, not necessary: broader equivalence requires an
additional path proof, never a terminal-set guess.

Regression evidence: the complementary-branch case failed before the change
(1 failed, 6 passed in 8.43s). After the change, 26 focused native, Semantics
and Widening tests pass in 9.11s. Same-block conditional byte stores still
widen, while different-block stores remain separate. Scoped Ruff, MyPy and
Pyright pass. Global `quality-fast` remains red at Ruff; all 39 compiled-import
smoke checks pass. Full architecture validation passes. Routine pipeline:
3,956 pytest tests passed in 222.01s, all seven MS C round trips passed, and
all three lanes passed without skips, failures or timeouts. The slowest
pytest case was the InitMenu pause guard at 88.53s. Log:
`/tmp/inertia-pointer-cooccur-pipeline.log`. The whole suite was not rerun.
This is not the return-qualified initialization fix.

## Zero-Return Classification Follow-Up

The existing branch-target return classifier understood `xor ax, ax` and
`sub ax, ax`, but the terminal-return classifier reported no constant result
for either. It also recognized `sub ah, ah` but not `xor ah, ah`. LIFE's
input routine uses both AX and AH self-clears, so its success/failure effects
cannot safely be inferred from the old terminal classification alone.

Both classifiers now consume one shared decoded-register self-clear helper.
Terminal AX/DX self-clears produce an exact zero-register result; AH clears
retain the existing partial-lane effect. This is a register-result projection,
not permission to delete instructions or discard flags. Different registers,
carry-dependent SBB, and unsupported 32-bit forms are not guessed as 16-bit
zero-return effects.

Native regressions failed in four cases before the correction (4 failed,
13 passed in 8.47s). Afterward, the combined native and return-classifier gate
passes 51 tests in 10.39s. Scoped MyPy/Pyright and full architecture checks
pass; the production decoder still has legacy Ruff complexity/magic-value
debt. Native tests and ownership metadata pass Ruff. Routine pipeline passes
3,964 tests in 238.99s and all seven MS C round trips; all 39 compiled-import
smoke checks pass, while global quality remains red at Ruff. The separate LIFE
test still fails with unresolved stack locals (23.48s), not a timeout.
Logs: `/tmp/inertia-selfclear-pipeline.log`, `/tmp/inertia-selfclear-life.log`.
This closes the inconsistent zero-return classification, not LIFE acceptance.

## Native Alias Handoff Verification

The native word/byte regression now also constructs the decoded function CFG
and invokes the real register-provenance and pointer-output Alias collectors.
No parameter-source result is mocked. Both word-store execution bytes bind to
the exact SS:BP+4 two-byte pointer parameter; Widening yields one conditional
word view. Changing the native store to a byte instruction yields a conditional
byte view, not an invented word. Output remains in DS; binding the pointer
parameter in SS does not prove the caller's DS/SS equivalence.

Verification: 17 native tests passed in 13.23s, seven dependency warnings,
Ruff and diff checks pass (`/tmp/inertia-native-pointer-alias.log`). This
extends existing routine tests without increasing their count. No production
change was needed for this handoff. The previously recorded broad gate predates
these stronger assertions; it was not rerun for this test-only extension.

## Remaining Work

Return-decoder quality checkpoint: numeric Capstone operand tags now use the
library constants, compound register conditions have names, and the two large
classifiers delegate coherent move/arithmetic decoding. Shared typed effects
and operand interpretation live in `semantics/return_effect_operands.py`;
the old public import path remains available. Both modules are below 350 lines
and pass Ruff, MyPy and Pyright. Full architecture validation passes after
restoring its required ownership-header markers. This is code-quality work,
not a claim of improved LIFE behavior.

After extraction, 51 focused tests pass in 8.79s. The routine gate passes
3,964 tests in 238.95s and all seven MS C round trips, with three lanes passed
and no failed/skipped/timed-out lanes. Global `quality-fast` still fails Ruff;
the complete repository suite was not rerun. Log:
`/tmp/inertia-return-decoder-split-pipeline.log`.

Scope: LIFE's 80387/x87 recovery is excluded by the user's 2026-09-11
instruction. This investigation concerns integer instructions, BIOS INT 16h,
and segmented pointer writes, not FPU semantics. Do not expand it into FPU
support or suppress existing FPU regressions to close the goal.

1. Prove the input call's memory definitions and consume them in validation.
   Reason: direct operand tags survive, but uninitialized-read validation
   rejects the transformed function and rolls it back.
   DoD: binary-derived conditional output effects, preserved call writes,
   correct key width, and valid initialization on each loop exit.
   Failure: assume preservation across an unknown call or merge byte cells by
   name/proximity without authoritative identity.
2. Verify branch polarity and complete input-loop behavior.
   Reason: generated C must wait for a valid key, not merely compile.
   DoD: retain get_key calls, accept the correct character set, and preserve
   branch-specific calls, globals and returns in an executable oracle.
   Failure: repair rendered conditions or bypass failed tail validation.
3. Close acceptance with focused and broad gates.
   Reason: this shared frame-evidence change can affect other functions.
   DoD: strict generated-C compilation, validation passed, no lost calls or
   argument-class changes, routine pytest and all seven MS C round trips.
   Failure: call seven focused tests a complete LIFE or repository fix.
