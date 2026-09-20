# COD Stack-Restore Refusal

## Frozen Failure Cohort

`DOSFUNC.COD`: `_dos_envSize`, `_dos_lastFreeBlock`, `_dos_mcbInfo`.
All three were rejected by the classified-but-not-materialized GP restore
contract in the 32-function survey. The cohort remains open; no gate is weakened.

Latest status (September 20, 10:44): `_dos_envSize` passes validation,
recompilation and the guarded controlled-memory behavioral test. Broad repair
acceptance remains open: routine tests reported three timeouts, two of which
persisted in a targeted recheck, and global lint debt remains. The other two
cohort functions retain their original restore-proof refusals. Historical
failure descriptions below are chronological.

## Smallest Reproducer

`_dos_envSize` stores AX at BP-4 and subsequently restores BX with LES.
Alias proves entry-SP bytes (-6, -5), saved at synthetic address 0x101d and
restored at 0x1023. The current C projection contains two constant byte stores
into one local followed by a recomposed word reload. The restore consumer
does not recognize this representation. Alias's register-identity proof alone
does not authorize replacing the stores with a runtime AX snapshot: the
constant-propagated value must remain coherent with any published register
state. Do not solve this with matching rendered C or source substitution.

Worker-local read-only instrumentation confirmed the failed materialization
path. Diagnostic artifacts are `.cache/envsize-restore-owner.{c,log}` and
`.cache/envsize-restore-owner-layers/`. These are local evidence, not fixtures
that the test pipeline depends on.

## Refusal-State Repair

An independent safety defect was demonstrated in the same path: constructing
the candidate snapshot replaced `unified_local_vars` and `variables_in_use`
before checking whether a restore expression could be matched. Refusal could
therefore alter a local's declaration despite materializing no snapshot.

The Lowering owner now publishes the declaration only after inserting a
successfully materialized snapshot. The negative regression verifies that a
valid insertion point plus an unmatched restore still raises the contract
error, preserving the existing declaration, variable-use map and statement.
Before repair: one failure, three passes. After repair: 48 focused GP-restore
and local-reload tests pass. The test module is already in the routine pipeline.
Scoped mypy and the types/docs ratchet pass. Ruff retains two complexity
findings in the existing insertion-point and materialization functions.

The required routine pipeline then passed: 268 contract tests, followed by
6,141 focused tests in 305.76 seconds and passing QuickC/MS C6 external lanes.
Final summary: three lanes passed, zero failed/skipped/timed out. Full log:
`.cache/gp-restore-publication-pipeline.log`. This is not a full-repository
pytest result. `quality-fast` remains blocked by lint debt; its compiled import
smoke passed for 39 modules. No diagnostics were suppressed.

This is a refusal-state fix, not completion of the three-function cohort.
The next semantic repair needs typed evidence connecting the original saved
value, its lowered byte stores, the exact stack object and the restored word.
Acceptance still requires validation, compilation, source/assembly comparison
and no lost calls or changed memory/register effects for the frozen cohort.

## Verified Value-Provenance Gap

A fresh worker trace after the refusal-state fix still exits 4. Its exact IR
contains two AX reads (temporaries 108/109) and `Iop_Sub16` at 0x101b, followed
by byte stores at 0x101d into SS:BP-4 and SS:BP-3. The low byte refers to AX
through temporary 192 and `Iop_16to8`; the high byte refers to temporary 194
through the same conversion, after `Iop_Shr16`. Evidence is in
`.cache/envsize-restore-ir.{c,log}`. An initial diagnostic hook used the wrong
IRBlock field; that failed probe was corrected to `instrs` and rerun. Do not
count the hook failure as a production defect.

`alias/segment_stack_fragments.py` preserves register and stack-byte origin,
but its register case does not consume the prior value definition.
Consequently the proven restore fact has `constant_value=None`. A syntax-only
extension recognizing the C word reload would then snapshot runtime AX, which
still holds the earlier memory load in this C projection, rather than zero.
That is not an acceptable fix.

The existing far-pointer constant flow correctly recognizes self-subtraction,
but its load evidence exposes a stack offset/constant without the exact GP
save/restore identity required here. Do not join proofs using offsets alone
or add a second decoded-instruction evaluator in the restore consumer.

Implementation order for this same cohort:

1. Preserve exact constant-value provenance through typed IR definitions,
   register snapshots and byte projections. Refuse unknown operations,
   intervening overlapping register writes and unproved call effects.
2. Carry that value alongside Alias's existing exact byte/save/restore proof.
   Storage identity and value evidence must refer to the same saved definition.
3. Let Lowering consume the combined proof when recognizing an existing word
   reload or materializing a snapshot. Never substitute the current register
   value for a constant-folded earlier definition.
4. Test corrupted byte order, mismatched storage, stale register reads, missing
   definitions and partial stores; rerun all three frozen functions and the
   ordinary semantic/compilation gates before accepting the cohort.

Graph lookup/index/coverage calls failed with `Transport closed`; these are
bounded direct-source findings, not an exhaustive architecture audit.

## Constant-Proof Implementation Checkpoint

Implemented at the original owners, without source/name/address special cases:

- `ir/constant_flow.py`: block-local constants and immutable temporary value
  identities, using authoritative register families. Missing definitions,
  unsupported operations, partial writes and calls cannot reuse stale values.
- Alias carries the proven byte values alongside its existing save/restore
  identity. Any function with IR refusals disables this additional constant
  evidence. Native-word constants require low-address/low-byte agreement.
- Lowering recognizes the exact word-local byte views and snapshots the proven
  saved constant, never a stale current register. Unproved views still fail.
- DCE consumes the live save identity as well as side metadata. A cloned or
  rebound local must not lose its existing protection. This is evidence
  preservation, not semantic recovery in Rewrite.

Before/after failures were demonstrated for constant save recovery (three
cases), word-view materialization (three), stale DCE metadata (one), incomplete
IR (one), and reversed byte order/register-name aliases (two). The final focused
restore/loop selection passes 46 tests. Both new test modules are in Make's
regular test/lint lists, the ownership manifest and the routine pipeline.
New-module Ruff and scoped mypy/types/docs pass. The scoped mypy invocation
includes the typed declaration owner because `follow_imports=skip` otherwise
makes its imported return type appear as Any; no types were suppressed.

The first broad run passed 6,158 tests in 359.29 seconds and all three pipeline
lanes. Additional refusal hardening followed that run. A final unchanged-code
pipeline was observed running at 09:31:58+02:00 on September 20; results are
recorded below. Concurrent diagnostic/focused checks make the first timing
unsuitable as a controlled performance comparison.

The production probe at 09:32:07+02:00 still returns CLI exit 4, now solely
reporting two GCC errors on the first memory-load expression in `_dos_envSize`.
Its whole-tail check is clean. Compare `.cache/envsize-constant-guarded.{c,log}`
against source/assembly at `DOSFUNC.COD:1350`: the saved pointer offset remains
zero and the return reads the MCB size at offset 3. The PSP-environment load
still contains raw integer dereferences, so no recompilation or original DOS
behavior equivalence is claimed. Next repair: the segmented-load projection
owner, not a cast inserted into rendered C. Other current artifacts:
`.cache/lastfree-constant-proof.{c,log}` and
`.cache/mcbinfo-constant-proof.{c,log}` retain the other two failures.

Final verification completed before the 09:40:21+02:00 checkpoint:
6,161 routine tests passed in 331.92 seconds; all three pipeline lanes passed,
with zero failed/skipped/timed-out lanes. Log:
`.cache/restore-constants-pipeline-final.log`. The 268 pipeline contract checks
also passed; their count is not added to the routine total because scopes can
overlap. This is not a full-repository pytest claim.

`quality-fast` remains blocked by existing lint findings; its 39-module compiled
import smoke passes. A separate full architecture audit initially reported
23 findings, including the new module's missing exact header markers. Those
markers were corrected and the new owner passes the scoped header check;
unrelated architecture debt remains. See
`.cache/restore-constants-architecture.log` and
`.cache/restore-constants-quality-fast.log`. The new IR module is included
automatically in the indexed-Alias cache source manifest; that membership was
checked directly. No cache validity or quality checks were bypassed.

## Segmented-Load Investigation, September 20

The 09:46:38+02:00 fresh production probe reproduces the two integer-dereference
compiler errors with clean whole-tail validation. Exact IR load facts exist:
instruction 0x1012, ES:BX, byte offsets 0 and 1, temporary IDs 72 and 74.
Carrier replay reports 20 raw/normalized facts and zero classified/materialized
facts. This is a materialization gap, not absent decoded load instructions.
Logs: `.cache/envsize-load-probe.{c,log}`.

Worker-local AST inspection confirms both dereferences have empty tags; their
address roots retain instruction 0x1012, VEX block 0x1000, and statement indices
84/90. The selector expression is a word GP variable (register offset 8,
SSA identity `ir_2`), not a named ES node. The selector-scale statements retain
indices 83/89. `_segment_base_name_8616_impl` recognizes segment-register nodes
but does not establish this GP copy as a selector. Carrier replay additionally
requires exact retained load-temporary identity or a constant segment; neither
applies to these leaves. Evidence: `.cache/envsize-selector-probe.log`.

Next: carry/consume exact load and selector-value provenance at the IR/codegen
boundary. Do not treat an arbitrary `value << 4` as a segment, or substitute
current ES/BX for an earlier inlined value. Preserve bytewise offset wrapping.
This is still unresolved; no new production fix or function acceptance claimed.

A new small linked [selector/offset probe](segcopy-stability-probe.md) exposes
a separate lost-load failure, also without sidecars. It is a recorded backlog
blocker, not an expansion of this repair's frozen three-function acceptance.

## Exact IR Statement Provenance

The next implementation checkpoint adds `IRInstructionOrigin8616` to imported
instructions: original block address, VEX statement index, and an explicit
LOAD/STORE address temporary when the VEX address is `RdTmp`. Synthetic terminal
instructions retain `origin=None`. A literal address is not reinterpreted as a
temporary ID. This is an IR-owned source contract, not permission to replay a
register's current value or infer segmented semantics from C shape.

Register SSA, memory SSA and call-effect enrichment preserve this contract with
dataclass replacement. Origin participates in instruction equality, so the SSA
cache cannot reuse an equal-looking instruction from another source statement.
Serialization and pickle persistence retain it. Both function IR/SSA and
indexed-Alias source manifests include the new module; membership was checked.

Before implementation, all three initial regressions failed on missing origin.
The initial importer/carrier/constant selection then passed 27 tests. Additional
store, cache and call-enrichment checks bring the new module to six tests;
the final origin/call-effect selection passes 20 tests. The module is enrolled
in routine tests, Make typing/Ruff lists and the ownership manifest.

Scoped mypy passes with the consumed typed helper owners included (the project
uses `follow_imports=skip`). New-module/test Ruff passes. `quality-fast` still
fails broad lint debt; its compiled-import smoke passes 39 modules. Do not
interpret this metadata transport as a completed memory-load repair: the
Lowering consumer remains to be implemented and validated.

An `_dos_envSize` probe concurrent with broad gates timed out at 30 seconds;
its validation was uncollected, not passed. It is not a controlled performance
measurement. Repeat after the gate processes terminate before interpreting
the production result. Routine pipeline results will be recorded below.

Verification checkpoint, September 20 at 10:08:31+02:00: the routine pipeline
completed successfully, with 6,167 pytest cases passing in 374.80 seconds and
all three lanes passed (zero failed/skipped/timed-out lanes). The separate
268 pipeline contract tests also passed; counts are not summed. The external
lanes include QuickC and all eight MS C tiny round trips. Full log:
`.cache/ir-origin-pipeline.log`. This is not a full-repository pytest result.

The isolated post-gate `_dos_envSize` rerun exits 4, with clean whole-tail
validation and the same two GCC integer-dereference errors. Generated C is
byte-identical to the pre-change `.cache/envsize-load-probe.c` (`cmp -s` exit 0).
Artifacts: `.cache/envsize-origin-isolated.{c,log}`. Thus origin transport is
verified without claiming that the function is repaired. Next checkpoint:
consume the exact LOAD/address-definition provenance in typed Lowering while
retaining the original AST selector/offset values, then repeat this function's
validation, recompilation and source comparison.

## Exact Segmented-Load Lowering Repair

Implemented in `lowering/segmented_load_origins.py`, not Rewrite or CLI.
The registered IR LOAD must have a proven stable DS/ES byte address and an
explicit address temporary. Its address definition and segment-scale definition
must have matching source block/instruction coordinates in the correct order.
The retained AST must match those exact statement origins and operations.
The emitted helper uses the existing AST selector and offset values, never the
current contents of ES/BX. Missing, duplicate or conflicting evidence refuses
the replacement. Existing carrier counters include these materializations.

The production probe materializes both missing ES loads (raw/normalized 20,
classified/materialized 2, failures 0). It exits 0, reports validation passed
and clean whole-tail validation. No assembly fallback or source-body replacement
is involved. Final artifact: `.cache/envsize-origin-byte-safe.{c,log}`.

Boundary review exposed two related Widening problems: an IR address with a
register base could be mistaken for an absolute scalar identity, and its two
byte reads could be merged without proving that the offset cannot wrap.
Both regressions failed before the Widening changes. Indexed typed addresses
now refuse absolute identity and contiguous-word widening without a bound.
The byte helpers retain independent 16-bit offset wrapping. This is a scoped
ratchet for accesses carrying typed addresses, not a claim that all older
untagged widening or runtime-memory behavior has been audited.

Source comparison at `DOSFUNC.COD:1350`:

- PSP environment word: the previously uncompilable integer dereferences now
  read the retained PSP selector at offset 0x2c using segmented byte helpers.
- MCB selector: subtracting one remains a 16-bit operation, including 0 -> FFFFh.
- MCB size: the return still reads offset 3 from that selector. No calls existed
  in the original function, and none were introduced apart from memory macros.
- Stack save/restore evidence remains materialized; unused snapshots are not
  removed to make compilation succeed.

`test_x86_16_envsize_behavior.py` decompiles the real COD procedure, compiles
the resulting C and checks four controlled memory layouts, including selector
underflow and zero/FFFFh sizes. It explicitly binds the unresolved `_psp` slot
at DS:0. This is not original linked-DOS environment equivalence. A deliberately
lost-load implementation fails the same oracle. A separate compiled expression
test checks FFFFh byte wrapping and rejects a contiguous word-read control.
GCC `-Wall -Wextra` compilation of the generated function emits no diagnostics.

New coverage: 15 origin/refusal/wrap tests plus one production behavior test,
enrolled in routine tests, Make and ownership selection. The related focused
selection passes 34 tests. Scoped mypy passes for all four production owners;
new-module/test Ruff and the touched identity owner pass. Existing carrier and
widening complexity findings remain, and global `quality-fast` still fails
lint debt while its 39-module compiled import smoke passes.

At 10:25:44 and 10:26:02, the other cohort members were rechecked and still
fail classified-but-not-materialized GP stack restoration. Artifacts:
`.cache/lastfree-origin-lowered.{c,log}` and
`.cache/mcbinfo-origin-lowered.{c,log}`. The routine pipeline started before the
10:27:02 checkpoint; no full repair acceptance is claimed until it completes.
Graph coverage remained unavailable (`Transport closed`); source and live
worker evidence were used instead.

### Read-Position And Width Guards

A negative probe showed that address provenance alone also matched an assignment
target or an address-taking expression. Both regression cases failed before the
guard. Lowering now protects those subtrees, including shared AST nodes, and
requires a retained byte type. Wider reads are refused rather than truncated.
A fresh, cache-separated production probe confirmed that the two real loads
retain their byte types; no type is guessed to admit this function.

The guarded implementation passes 19 origin/refusal/wrap and production-behavior
tests in 49.14 seconds. Focused Ruff and mypy pass. The production behavior test
still validates, recompiles and executes the unchanged generated function.
Logs: `.cache/load-guards-after.log`, `.cache/load-guards-mypy.log`.

The preceding broad run finished with 6,180 routine tests passed and three
timeouts (InBoxLng, loadprog, SetGear) in 465.22 seconds. Its contract and MS C
tiny-example lanes passed, but overall pipeline status is failed. That run
overlapped diagnostic activity and does not establish the cause of the timeouts;
it also predates the final guards. Keep its failure visible and recheck on the
frozen source. The two remaining cohort failures are not waived.

At 10:44, the corrected targeted recheck finished: InBoxLng passed; loadprog
and SetGear still timed out (2 failed, 1 passed in 103.08 seconds). The first
selection used an incorrect test-module path and collected no tests; it is not
passing evidence. The corrected run overlapped the end of quality-fast, so
these results do not isolate the performance cause. Do not classify the two
remaining timeouts as harmless flakes. Log:
`.cache/segmented-origin-timeout-rechecks-corrected.log`.

Final quality-fast returned 2 on global Ruff debt; its 39-module compiled import
smoke passed. Focused changed-module Ruff and mypy and `git diff --check` pass.
This is an explicitly partial checkpoint, not completed cohort acceptance or
a green whole-project test claim. No deadlines, semantic checks or test
expectations were relaxed.
