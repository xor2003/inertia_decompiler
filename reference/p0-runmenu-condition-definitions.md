# RunMenu Condition Definition Binding

## Status: Partial, Step 9 Open

### Follow-Up: 2026-09-12 23:22 +02:00

New loop guards are classified only after binary CFG exit and AST placement
proof. Missing/internal exits and unanchored candidates retain their code and
are not counted as classified or materialized guards. The unanchored regression
now checks raw/normalized evidence and the retained failure/refusal diagnostics
as well. The focused topology and JCC surface passes **125 tests in 16.01s**;
scoped MyPy passes. Ruff `check --fix` reports six existing complexity/magic-value
findings across the legacy owner and test file; none were suppressed.

Logs: `/home/xor/.cache/loop-refusal-final{,-mypy,-ruff}.log`.
Complete-collection, expanded and required quality acceptance remain open.

### Follow-Up: 2026-09-12 23:13 +02:00

**RunMenu's original sidecar-free regression now passes without weakening
validation or its switch/call assertions.** The fresh source-frozen mandatory
pipeline also passes: **4,828 curated tests**, 310.01 seconds; **268 preliminary
tests**, 19.43 seconds; QuickC, 50.58 seconds; all **seven MS C tiny round trips**,
135.43 seconds. These are separate lanes, not a complete-repository test count.

The upstream switch defect was not merely a validator representation mismatch.
The runtime bridge reported `case_path_value_count_mismatch` because the grouped
decision tree was incomplete. Structuring's `_single_eq_edge_guard_8616` accepted
`eq` but rejected equivalent unary `zero` ConditionIR guards emitted for DEC/JCC
cases. The existing subtraction-ladder regression reproduced the loss with a
real zero-test representation: that parameter failed while its equality control
passed. The consumer now projects an explicit unary zero test as equality to a
width-matched zero constant, preserving its producer and storage evidence. The
existing typed switch machinery then recovers the complete dispatch, including
Escape. No forced replacement, CLI semantic recovery, source hints, or relaxed
tail-validation obligation was introduced. The two parameter cases are in both
routine lists. Grouped/switch tests plus RunMenu pass 31 tests in 56.83 seconds.

The first broad run caught two integration issues: a legacy wrapper fixture
lacked CFG evidence, and the new topology owner imported `loop_recovery`, which
is registered as a test-only prototype. The fixture now supplies an explicit
topology; production uses NetworkX's dominator tree and the existing production
natural-loop classifier. NetworkX 3.6.1 omits the root from its dominator map;
the local traversal explicitly terminates at the entry and tests self-loops,
backward numeric addresses, and irreducible cycles. The affected wrapper,
topology, and layer-boundary surface passes **122 tests**, 31.52 seconds.

MyPy passes; new topology code/tests pass Ruff. `quality-fast` remains red on
**6,240 existing style/complexity findings**: 4,174 magic-number comparisons,
1,865 complexity findings, 199 Boolean-expression complexity findings and two
dictionary-iteration findings. Its 39-module compiled-import smoke passes.
No lint rules, type requirements, or documentation requirements were weakened.

Next acceptance work: refresh the exact complete pytest collection on frozen
source, run expanded acceptance, resolve remaining required quality gates, and
audit refusal accounting so an unproven loop exit is not reported as a
classified/materialized break. Do not equate the passing curated pipeline with
Step 9 completion. The observed work interval since the previous checkpoint is
22:39-23:13, including diagnostic and test waits; active coding time was not
separately measured.

Evidence: `switch-zero-{before,after,pipeline}.log`,
`switch-integration-{after,ruff,mypy}.log`, and
`switch-final-{pipeline,quality}.log` under `/home/xor/.cache/`.

### Follow-Up: 2026-09-12 22:39 +02:00

The fresh in-process trace after both tag fixes confirmed the internal-edge
guard defect remained: `0x1044b` introduced a top-level break although its
source and both destinations belonged to the `0x102eb` natural loop; refresh
then reversed its predicate. A new Structuring owner,
`structuring/loop_break_topology.py`, consumes the immutable CFG inventory and
the existing natural-loop classifier. New break insertion now requires a
unique loop owner, an actual taken edge into its body, and a proven fallthrough
exit edge. Incomplete, unsupported, or ambiguous topology refuses insertion.
It does not infer topology from missing AST tags or repair expressions.

The internal-edge and missing-CFG regressions fail before this gate, while the
genuine-exit control passes. The final focused loop surface is **28 passed**,
15.32 seconds; new owner/tests pass Ruff, scoped MyPy passes, and architecture
passes. Six topology tests and the new typed owner are enrolled in routine
test/type/lint gates. Existing owner lint debt remains. The first integration
attempt misplaced a local initialization; focused tests caught the NameError
and the placement was corrected before these passing results.

RunMenu's erroneous early guard is absent from the regenerated body. Its
original regression still fails (42.46-second call; combined run 21 passed /
1 failed, 53.23 seconds). The output now visibly retains
`if (v14 == 27) break;`, followed outside the loop by SI/DI restoration and
return. This is NOT sufficient evidence of complete function correctness.

The next investigation is more precise than simply "restore Escape":
`validation_control_flow_obligations.py` accepts only a `CSwitchCase` body with
an unconditional return, and the corpus regression also mandates switch text.
The new stage trace observed no switch at its watched boundaries, including
the initial priming surface; it did not observe a switch being removed.
Trace why canonical switch recovery is absent and reconcile the exit obligation
with the actual semantic representation. Do not delete the obligation or weaken
the test merely to accept this output. Any equivalent if-chain acceptance needs
independent execution coverage and corrupted controls; any switch/return repair
must preserve register-restoration effects instead of bypassing the epilogue.

Logs: `runmenu-current-topology.log`, `runmenu-switch-lifetime.log`, and
`loop-topology-{before,after,focused,ruff,mypy,architecture}.log` under
`/home/xor/.cache/`. Broad/full/expanded acceptance is not refreshed after this
gate; Step 9 remains open.

### Follow-Up: 2026-09-12 22:26 +02:00

The source-frozen mandatory pipeline after runtime-condition projection reached
**4,812 passed / 1 failed**, 257.38 seconds, plus **268 preliminary passes**.
RunMenu was the only curated failure. QuickC passed in 44.13 seconds and all
seven MS C tiny round trips passed in 109.23 seconds.

The subsequent loop-break tag audit reproduced the same boundary defect for
Python `Mapping` checks: Rust-backed `Tags` is neither `dict` nor `Mapping`.
Both direct and cached instruction membership tests failed before the fix;
dictionary controls passed. Loop-break membership, condition keys, and initial
surface collection now accept both supported representations. Four new cases
are enrolled in both routine test lists. The loop-specific run passes 22 tests,
but RunMenu still fails missing Escape case 27 (combined run 57.68 seconds).
CFG exit proof and placement/polarity remain necessary; tag compatibility alone
does not close RunMenu. Re-profile the actual current stage output before
assuming every earlier intermediate AST observation remains unchanged.

Scoped MyPy passes for both loop-break and condition materialization owners.
`quality-fast` was rerun and remains red on lint findings; its compiled import
smoke passes for 39 modules. The latest broad pipeline predates the loop-tag
change, and no full/expanded success is claimed. Logs:
`runtime-condition-pipeline.log`, `loop-tags-{before,after,ruff,mypy,quality}.log`
under `/home/xor/.cache/`.

### Follow-Up: 2026-09-12 22:14 +02:00

The caller-cleanup failures are repaired in Structuring's condition projection
index. Real angr instructions carry Rust-backed `Tags`, not Python `dict`;
the dictionary-only check silently discarded their instruction provenance.
The index now consumes the supported tag access API and recognizes runtime GP
destinations through the Types/Lowering owner's category-checked contract.
Mutable runtime destinations project the stored value, never their RHS again.
This preserves one decrement and the low-word view of the 32-bit ECX lane.

Both previously failing caller-cleanup tests pass, including the compiled
countdown behavior oracle. The five-file focused surface is **92 passed** in
19.64 seconds. Eight new positive/refusal cases exercise dictionary/Rust tags,
ordinary memory, wrong-block provenance and later assignments; both routine
test lists include them. Scoped MyPy and architecture checks pass. New tests
pass Ruff; four legacy condition-lowering findings remain.

RunMenu was rerun separately: **1 failed**, 45.33 seconds, still missing Escape
case 27. No whole-function success is claimed. The prior broad result below
predates this fix. Logs: `runtime-condition-{focused,mypy,ruff,architecture,runmenu}.log`
under `/home/xor/.cache/`.

### Follow-Up: 2026-09-12 22:07 +02:00

The live-call-result pruning defect is repaired: void-return normalization no
longer deletes a call-result assignment based on uses in only its immediate
statement container. Anchored condition lowering now refuses missing register
definition evidence instead of inventing an anonymous physical register.
RunMenu's emitted-C def-use failures decreased from 25 to zero; its control-flow
validation still fails for missing Escape case 27. This is not function acceptance.

The last broad checkpoint was 4,801 passed / 4 failed in 291.62 seconds, with
268 preliminary passes. QuickC and the seven MS C tiny constructs passed.
Subsequent same-block projection ordering work repairs the high-byte regression:
the latest four-file focused run is **82 passed / 2 failed**, 24.87 seconds.
The two failures are caller-cleanup tests, not two additional RunMenu failures.
Full and expanded acceptance remain unrefreshed. Ruff `check --fix` was rerun
on both touched condition modules; outstanding lint findings remain.

Current root causes and next actions:

- Caller-cleanup: the `DEC CX` assignment at `0x100b` is present with exact
  instruction/block tags, but its destination has already become a typed
  `inertia_gp_register_state` memory variable for ECX. The condition expression
  map contains only FLAGS; the register-only same-block index also misses this
  runtime-storage projection. Consume the authoritative contract in
  `lowering/gp_register_state.py`, including width and update timing. Do not
  restore raw-register fallback, guess from names, or evaluate the decrement
  twice. The existing compiled countdown oracle checks initial counts 0..3,
  16-bit wrap, call counts, and preserved upper ECX / EAX bits.
- RunMenu: loop-break recovery inserts a guard for an internal CFG edge at
  `0x1044b`; source and both destinations are inside the natural loop headed at
  `0x102eb`. Missing AST tags are not loop-exit proof. A later condition refresh
  also reverses the inserted guard. Require CFG exit ownership, preserve
  control-dependent placement, and carry guard polarity through refresh.

Diagnostic evidence: `/home/xor/.cache/caller-condition-probe.log`,
`caller-condition-debug.log`, `runmenu-exit-topology.log`, and
`runmenu-projection-order.log`. Diagnostic probes did not bypass the failing
materialization guard. Earlier checkpoints below are historical, not current
test totals or unresolved def-use claims.

Checkpoint: 2026-09-12 20:51 +02:00. The register-definition lookup defect
is repaired and covered by focused regressions. RunMenu itself is **not fixed**:
the original sidecar-free regression still rejects its generated C.

The diagnostic baseline completed at 20:25; the production corpus check ran
at 20:41, and the broader gate completed by 20:51. These are observed checkpoints,
not a claim of precisely measured active development time.

## Root Cause And Change

The first wrong operand appeared in typed-condition materialization, before
call-argument replay. At condition boundary `0x10433`, the legacy register map
selected `v43 * -1` from another switch arm solely because its instruction
address was the largest address below the boundary. Addresses were correctly
rebased; numeric order was not reaching-definition evidence.

The decoded CFG instead proves the call-result definition at `0x10328` reaches
that boundary. New Alias owner `alias/condition_register_definition.py` reuses
the existing register-source join solver. Structuring projects its exact address
onto an existing expression; the legacy typed-condition module delegates and
its nearest-address lookup is removed. The compatibility import is documented
in the architecture guard, not admitted as new Rewrite-owned inference.

The proof refuses conflicting paths, incomplete inventories, unknown calls and
unrepresented or partial writes. Query prefixes are independent sinks: full
block effects remain available for loop backedges, including writes after the
queried instruction. Explicit represented call-result definitions are supported.

Five initial regression cases fail against the old implementation. Eight cases
now cover unrelated arms, backward address edges, conflicting joins, partial
writes, misleading partial-write tags, unknown calls, explicit call results,
and later writes on loop backedges. They are enrolled in both routine test lists.
Four existing projection fixtures now supply decoded instruction/CFG evidence
instead of relying on an address-only expression map with no function CFG.

## Verified Gates

- Focused surface: **49 passed**, 10.25 seconds, pytest `-n 7`.
- New production owners: Ruff `check --fix` and MyPy pass.
- Full architecture gate passes; new owners are in typed/Ruff promotion gates.
- Preliminary pipeline checks: **268 passed**, 12.58 seconds.
- Curated lane: **4,735 passed / 1 failed**, 246.50 seconds. RunMenu is the failure.
- QuickC fixtures pass, 35.57 seconds.
- MS C tiny compile/decompile/recompile/execute lane: **7/7 pass**, 90.56 seconds.
- Global `quality-fast` remains red on lint debt. Touched legacy files still
  report lint findings; no exclusions or thresholds were relaxed.
- Full collection and expanded acceptance have not been refreshed.

Logs: `/home/xor/.cache/runmenu-definition-{before,after,corpus,pipeline}.log`;
gate summary: `angr_platforms/.cache/test_pipeline/summary.json`.

## Remaining Acceptance

| Work | Reason | Definition Of Done | Definition Of Failure |
| --- | --- | --- | --- |
| Preserve call-result definition/use coherence | RunMenu still reads `ir_8` without its emitted definition | Trace the first destructive owner; preserve the call result and every live use, including snapshot lifetime; def-use validation passes | Rename only the destination, substitute rendered text, or suppress uninitialized-read evidence |
| Preserve Escape and switch control flow | Validation still reports missing case 27 | Original RunMenu regression passes with all required cases, calls, argument classes, binary-proven Escape return, semantic validation and strict recompilation | Merely remove the diagnostic or make C compile by deleting live control flow |
| Finish Step 9 acceptance | Curated success alone is not full acceptance | Required full/expanded tests and quality gates pass on a stable tree under the existing Step 9 contract | Declare completion using only these focused/curated results |

The first CFG-based diagnostic removed the invalid loop-branch report and the
unrelated `ir_37` operand. The production run still reports `ir_8` reads and a
missing Escape case. Existing selector materialization can replace a destination
with physical AX, but the first loss of the old assignment still needs exact
stage evidence; do not assume that helper alone is the root cause.
