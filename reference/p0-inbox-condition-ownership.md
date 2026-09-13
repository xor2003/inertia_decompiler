# InBoxLng Folded Guard Ownership

## Status

InBoxLng's function acceptance is closed, Step 9 remains open. The original
uncached worker exited 4 and its C failed the independent behavior oracle.
The repairs below now produce compact whole-width comparisons, exit 0 with
whole-tail validation passed, and pass strict compilation and compiled behavior.

### Closure: Machine-Coordinate Wide Pair Proof

A fresh isolated-cache observer proved the remaining refusal: for example,
both word projections shared one four-byte C owner at rendered offset 10,
whose authoritative machine BP offset was 12. The existing projected-pair
proof compared raw 10 with IR 12 and refused the valid owner. It could also
accept the opposite wrong-coordinate case. This was not missing adjacency or
an absent wide declaration.

`lowering/wide_stack_pair_evidence.py` now checks both projected sources in
machine BP coordinates, retaining the shared four-byte BP-owner requirement.
Two new regression cases failed before the fix: a valid projected pair was
refused and an invalid raw-offset match was accepted. Four coordinate/context
controls now pass. The existing body builder recovers the four comparisons
without new semantic recovery or cleanup in Rewrite.

Output is now `x < xl || x > xh || z < zl || z > zh`, with explicit `int32_t`
casts on every operand. Those casts preserve DOS width on hosts with 64-bit
`long`; the live test now requires them instead of demanding their absence.
It still requires the complete compact condition, both returns, exit 0,
validation passed, and the unchanged strict compiled behavior oracle.
The live InBoxLng node and coordinate tests are enrolled in the routine pipeline.

Focused acceptance: 20 passed in 17.76s, including InBoxLng in 7.50s. The first
pipeline passed 5,034 tests but SetGear hit its 17-second analysis deadline;
both external compiler stages passed. An unchanged lighter repeat passed both
SetGear (13.72s) and InBoxLng (4.36s). SetGear's behavior test now requests a
bounded 20-second base analysis budget (34 seconds after seven-worker scaling),
without changing its semantic assertions, subprocess deadline or global policy.
This is deadline headroom, not a claimed performance improvement.

Final warm pipeline rerun: 268 preliminary checks; 5,035 curated tests in
182.57s; QuickC 2.108s; seven MS C tiny roundtrip constructs 36.024s. All three
stages pass with no skips or timeouts. Caches were retained between runs, so
these times must not be interpreted as a controlled cold speedup. The proof
module and new tests are Ruff-clean; quality-fast still fails on global lint
debt, with no MyPy errors and 39 compiled imports passing.

Observed timestamps (+02:00, 2026-09-13): isolated proof observation
04:47:31-04:47:38; focused acceptance 04:50:52-04:51:10; final pipeline
04:59:31-05:03:21 (3m50s elapsed). The earlier failed pipeline and investigation
are additional work, not included in that final pipeline duration. Logs use
`/home/xor/.cache/step9-inbox-wide-pair.*`, `step9-wide-pair-coordinates-*`,
`step9-inbox-setgear-repeat.log`, and `step9-inbox-closure-*`.

Baseline accounting is now 15 of 47 original failures individually resolved,
32 unresolved. This is not a fresh full-suite result or Step 9 completion.

### Validation-Coordinate Follow-Up (2026-09-13)

Source argument labels and sizes were keyed by rendered offsets while their
consumers used machine BP offsets. Correct the coordinate maps and preserve
the exact typed word range instead of expanding it to a named dword argument.
Tail validation now recognizes a high-word projection only when its typed
fact, actual mask and shift, BP storage owner, and source type width agree.
It does not trust projection tags alone or modify emitted C.

Fail-before: the coordinate-map, exact-word-range, and high-word identity
regressions each failed before their respective correction. Afterward nine
coordinate/projection tests pass, including seven corrupted-evidence controls.
The live InBoxLng test passes return-code, validation, strict compilation and
the unchanged behavior oracle, then fails its compact-condition text check.
Do not remove that remaining shape requirement to claim completion.

Related validation checks: 396 passed, one indexed-field condition test failed
in 8.85s. That failure also reproduces with HEAD's fingerprint module loaded
against the current dependencies; this is a module-level control, not a full
HEAD checkout. Its expected condition contains a signed-short semantic cast
around an indexed dereference, unlike the final typed field expression.
Scoped MyPy, the new helper/test Ruff checks and startup architecture pass.
Routine pipeline passes: 268 preliminary checks, 5,009 curated tests in
222.27s, QuickC in 35.622s, and all seven MS C tiny roundtrip constructs in
78.806s. No stages failed, skipped or timed out. The curated lane still exceeds
its configured 30-second budget; passing behavior is not performance acceptance.
Global quality-fast exits 2 on lint debt, with no MyPy errors reported and all
39 compiled-import smokes passing. Logs are under `/home/xor/.cache/`:
`step9-projection-proof-live.log`, `step9-projection-proof-related.log`, and
`step9-indexed-head-control.log`; broad gates are in
`step9-projection-proof-pipeline.log` and `step9-projection-proof-quality.log`.

### Indexed-Field Validation Follow-Up

The separate indexed-field failure above is now repaired. A signed word read
can appear as an explicit signed cast over a segmented helper or as a signed
struct field. Comparing those representations requires checking physical
storage, access width, current signedness and comparison polarity together.
`validation_condition_storage_views.py` owns that proof. Control-flow validation
uses it only when ordinary identity fails and the existing CFG-region check
has already succeeded. No generated expression, branch body or cast is removed.

Before: the indexed-field acceptance failed while its two wrong-storage controls
passed. After: all ten existing tests pass, plus eleven new positive/refusal
controls covering unsigned/wider fields, pivot width/signedness, inverse branches,
pointer fields, missing helper evidence, contradictory helper width and non-BP
storage. Both test modules now run in the routine pipeline. No test was deleted
or its existing acceptance weakened.

Verification: 367 related tests passed before the final three refusal controls;
the completed focused family passes 21 tests. All 53 control-flow tests pass
after the quality gate rebuilt mypyc. Routine pipeline passes 268 preliminary
checks, 5,030 curated tests in 226.50s, QuickC in 33.830s and seven MS C tiny
roundtrip constructs in 84.305s. All three stages pass without skips/timeouts;
the curated lane still exceeds its configured 30-second budget. `make mypy`,
new helper/test Ruff and startup architecture pass. `quality-fast` remains
red on lint debt; no MyPy errors were reported and 39 compiled imports pass.

Observed timing: first retained experiment artifact at 2026-09-13 04:34:36
+02:00; pipeline ran 04:38:56-04:44:49 +02:00 (5m54s elapsed). Earlier diagnosis
time is not captured by these timestamps. Logs use the prefix
`/home/xor/.cache/step9-indexed-storage-` (`after`, `controls`, `related`,
`pipeline`, `quality`, `mypy-all`, `architecture`, `final`).

InBoxLng's compact wide-comparison acceptance is still open. Next inspect the
existing `wide_stack_pair_evidence.py` proof with a fresh live observation:
it compares some raw C-variable offsets with machine-IR offsets. Source inspection
alone does not establish whether that is the current refusal cause. Do not
replace those checks with permissive adjacency or weaken Alias proof.

### Production Local-Region Checkpoint

### Storage-Width Follow-Up

Two additional Lowering defects are repaired, without closing InBoxLng:

- The legacy sign-only declaration consumer now requires complete, non-conflicting
  storage-owner coverage through the existing `condition_stack_value` boundary.
  Partial word evidence cannot resize a dword owner, and dword evidence cannot
  widen a word owner. A fresh observer proved the former mutation changed five
  four-byte argument types to short; afterward all six argument types retain
  their four-byte widths. The artificial uninitialized-read failures disappear.
- A high-word projection now retains its wide source type through the shift.
  Previously `prefer_word_view=True` mislabeled that source as short before a
  16-bit shift. Narrow interpretation happens after the high-word extraction.

Before: two width-direction tests failed and two same-width controls passed;
the separate high-word source-type test also failed. After: all eleven new
tests pass. They cover partial/overlapping/missing owners and are enrolled in
the routine pipeline and Make lint/test scopes. The storage proof is in
Types/Lowering, not new semantic recovery in postprocess. The startup guard
rejected an initial direct import from a different Lowering owner; that import
was removed, and no architecture allowlist was expanded.

Fresh production C still passes the unchanged compiled behavior oracle.
Live InBoxLng remains exit 4 with predicate mismatches at 0x1018 and 0x101a:
expected BP+0x16:size4 versus high16 of BP+0x14:size4. Next inspect the exact
registry result and selected CVariable during `condition_ir_semantic_fingerprint_8616`;
the expected expression uses the regular typed condition materializer. Do not
assume the registry or fingerprint normalizer is guilty without a live trace.

Routine pipeline: 268 preliminary checks, **5,000 curated tests in 228.06s**,
QuickC 33.836s, MS C tiny roundtrips 82.593s; all three stages pass with no
skips or timeouts. Scoped MyPy and architecture pass. New proof/test Ruff passes;
legacy owners retain findings. Global quality-fast still exits 2 with 6,278
Ruff findings, no reported MyPy errors, and 39 compiled import smokes passing.
Artifacts: `/home/xor/.cache/step9-inbox-width-after.log`,
`/home/xor/.cache/step9-high-word-live.log`,
`/home/xor/.cache/step9-storage-width-pipeline.log`, and
`/home/xor/.cache/step9-storage-width-quality.log`.

### Earlier Local-Region Evidence

`structuring/local_condition_regions.py` now supplies immediate-sibling
continuation ownership and a bounded SSA/CFG region proof. Reused statement
nodes and missing direct entry evidence refuse. Accepted regions have matching
SSA/CFG edges, no cycles, no block/memory refusals or phi nodes, and only
explicit total temporary operations, stable proven SS:BP reads, and conditional
branches. Calls, stores, architectural-register writes, division, unknown
operations, DS reads, and unproven memory addresses refuse. Body and
continuation blocks are boundaries, so their effects are not bypassed.

The existing Structuring materializer consumes this proof, preserves bodies,
and rebuilds only the bounded predicate. The unchanged generated-C behavior
oracle passes through the production CLI, not merely the monkeypatch. Logs:
`/home/xor/.cache/step9-inbox-production-behavior.log` and
`/home/xor/.cache/step9-local-regions-live.log`. CLI remains exit 4; diagnostics
include argument-width/subview inconsistencies and predicate-replay mismatch.

Acceptance evidence: 20 new controls passed; 69 related tests passed in 9.55s;
scoped MyPy, new module/test Ruff, and architecture checks passed. New files
are enrolled in Make's typing/lint/test scopes, the architecture inventory,
and the routine pipeline. Routine pipeline passed all three stages:
4,989 curated tests in 238.77s, QuickC in 34.902s, and MS C tiny roundtrips in
82.471s (268 preliminary tests also passed). Global quality-fast still exits
2 with 6,278 Ruff findings, no reported MyPy errors, and 39 compiled import
smokes passing. Full suite, expanded pipeline, and quality-hard remain open.
Logs: `/home/xor/.cache/step9-local-regions-pipeline.log` and
`/home/xor/.cache/step9-local-regions-quality.log`.

Next inspect storage-width preservation and replay of compound predicates.
Source inspection found that the legacy signedness application chooses a
replacement argument type from the comparison operand's byte width. Verify
the live mutation before repairing it in the owning Types contract; word
signedness evidence must not narrow a proven dword storage owner. Do not
suppress validation or assume this is the only remaining discrepancy.

The oracle's first reported case varies z with value=low=high=INT32_MIN while
x=0, xl=-1, xh=1. The reported axis identifies the test inputs, not the first
incorrect branch: the emitted x lower-bound guard already uses an unsigned
high-word comparison where the binary uses signed JL. Do not conclude that
the z upper-bound equality arm alone causes the failure.

## Fresh Evidence

Probe: `/home/xor/.cache/probe-inbox-conditions.py`, using a temporary cache
directory, PYTHON_JIT=1, PYTHONHASHSEED=0, and both diagnostic in-process worker
settings. It observes the existing wide-chain recovery callback without
changing its decisions. The callback executed; this was not a cache-only run.

Artifacts:

- `/home/xor/.cache/step9-inbox-uncached.c`
- `/home/xor/.cache/step9-inbox-conditions.log`

The rebased first lower-bound decision chain is:

| Block | Branch | Meaning | Taken | Fallthrough |
| --- | --- | --- | --- | --- |
| 0x1000 | 0x100c | signed xl.high > x.high | 0x1045 | 0x100e |
| 0x100e | 0x100e | signed xl.high < x.high | 0x1015 | 0x1010 |
| 0x1010 | 0x1013 | unsigned xl.low > x.low | 0x1045 | 0x1015 |

These are observed ConditionIR/CFG facts, consistent with CARR.COD's machine
instructions. COD source is only the independent reference, not recovery input.

`condition_materialization._materialize_cfg_single_branch_expr_8616` sees the
folded no-else return guard rooted at 0x100e. Its return-orientation classifier
reports UNKNOWN_REFUSE: shared return block 0x1045 is reachable through both
root successors. Wide-single-body recovery produces no proof. The original
compound CITE predicate survives, including its incorrect unsigned comparison.

The outer condition's attempted whole-chain rebuild also refuses: it chooses
an interior statement origin as a target and then reaches return block 0x104c
outside that target pair. This is separate from the correct presence of the
typed signed conditions, which the worker explicitly materializes elsewhere.

## Next Fix And Acceptance

### Diagnostic Local-Continuation Experiment

An uncached observer confirms immediate structured siblings for the three
folded no-else return guards. Unwrapping only the first statement of a following
CStatements yields these candidate body/continuation boundaries:

| Root branch | Body block | Next statement block |
| --- | --- | --- |
| 0x100e | 0x1045 | 0x1015 |
| 0x101a | 0x1045 | 0x1021 |
| 0x102c | 0x1045 | 0x1033 |

For a following CIfElse, the experiment resolves its direct instruction tag
through the unique typed condition fact to obtain the block entry. It does
not use a descendant operand tag or minimum numeric instruction address.

The external probe then calls the existing target-directed condition builder
with these local boundaries. All three replacements are produced. Generated
C passes the unchanged independent inclusive signed-dword behavior oracle
(strict GCC compilation and undefined-behavior sanitizer included). The
production baseline fails that same oracle. This establishes a useful
reconstruction direction, not production acceptance: CLI still exits 4 with
the separate storage-view validation discrepancy.

Artifacts: `/home/xor/.cache/step9-inbox-local-prototype.c` and
`/home/xor/.cache/step9-inbox-local-prototype.log`. This is a diagnostic-only
monkeypatch in `/home/xor/.cache/probe-inbox-conditions.py`, not shipped code.
Earlier unmodified observations remain in the original log. The prototype
does not yet provide a general effect-preservation proof and must not be
copied directly into production.

The six observed predicate SSA blocks have no block refusals and contain
MOV/LOAD/integer comparison-address arithmetic/CJMP operations. Integration
must consume an explicit effect proof, not infer purity merely because a
block has a ConditionIR or happens to match these examples. Required negative
controls include intervening stores/calls, unknown operations, cycles,
ambiguous/reused AST ownership, and missing continuation evidence.

### Original Design And Remaining Acceptance

The implemented direction uses an exact structured continuation boundary.
For the first guard, the local continuation is the next comparison block
0x1015, not every eventual exit reachable from it. Prove that boundary from
the structured statement position and typed CFG before rebuilding a predicate
to the body/continuation pair. Do not infer polarity from return addresses,
numeric address ordering, names, or rendered C. Unknown ownership must refuse.

Add generic regression controls for shared eventual returns, signed high-word
boundaries, missing continuation ownership, intervening effects, and loops.
Keep the original bodies and evaluation order. A width collapse additionally
requires the existing Alias-backed pair proof; local ownership alone is not
wide-value evidence.

Then investigate the independently reported validation binding discrepancy:
BP+0x16 represented as size4 versus high16 of the size4 owner at BP+0x14.
Do not suppress this discrepancy to accept the function.

DoD: the existing live InBoxLng regression passes with validation=passed,
unchanged independent behavior oracle, strict compilation, related refusal
controls, scoped types/docs/lint, and routine pipeline acceptance. Failure:
removing live guards, changing inclusive bounds, widening without Alias proof,
or accepting a semantic delta because only the output shape looks better.
