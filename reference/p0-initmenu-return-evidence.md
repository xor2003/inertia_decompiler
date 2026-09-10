# InitMenu Return Evidence Gap (2026-09-10)

## Implementation Checkpoint

Semantics now supplies binary return evidence for bodyless native callees.
The immutable contract moved to `semantics/terminal_return_contract.py` and
retains decoded operand widths, including explicit unknown width. The existing
collector re-exports its public contracts and shrank from 375 to 338 lines.
Complete cleanup alone does not prove a compatible return width.

The first implementation proved mapped bodyless examples but did not improve
InitMenu: all four real callees are outside its slice's loaded objects. The
consumer now uses the loader-published original project and exact linear delta
only for an out-of-slice target. It does not try alternate addresses or prefer
original bytes over mapped current bytes. Recovery remains in Semantics; no
CLI or rewrite behavior changed.

Seventeen new routine regression cases cover bodyless straight/branched far
returns, near/mixed returns, word/dword widths, missing width, explicit cleanup,
unresolved exits, rebased source mapping and conflicting mapped bytes. The
initial bodyless run failed seven cases (18 passed, 8.35 seconds); the initial
rebased run failed its positive case (three passed, 9.01 seconds). Final focused
verification passes 62 tests, including numeric-SP compiled-C comparisons and
upper-ESP preservation. The additional unchanged InitMenu acceptance test
still fails its final SP-bookkeeping assertion: 62 passed, one failed, seven
dependency warnings, 54.26 seconds. Its call/argument and validation checks
before that assertion pass; the behavioral harness after it is not reached.
Scoped Ruff `check --fix`, MyPy and Pyright pass.

The final observation-only probe accepts all 12 candidate return-segment
sequences, each with three exact PUSH projections, across the four callees.
This is classification evidence, not a claim that all 36 projections were
deleted. Generated C improves and retains validation=passed and clean whole-tail
validation, but SP/BP execution bookkeeping remains. Strict GCC still fails:
20 errors versus the earlier recorded 22. Output SHA-256:
`93baff153b118893f541e17ab51148cbb7c7115a53493eb57265227914da8686`.
Artifacts: `/tmp/inertia-rebased-initmenu.{c,log}` and
`/tmp/inertia-rebased-initmenu-gcc.log`. All 20 GCC errors are parenthesization
warnings promoted by -Werror, not undeclared-name errors. Do not claim full
function acceptance.

Final `make quality-fast test-pipeline PYTHON=./.venv/bin/python` exits 0.
Fast: 3,195 tests pass in 140.90 seconds, eight warnings; all three executable
quality guards pass. Default: 3,195 tests pass in 124.43 seconds pytest /
124.903 seconds lane, seven warnings; QuickC passes in 45.258 seconds and the
MS C tiny full pipeline passes in 62.450 seconds. The default unit lane is
still over budget. Static, compiled-import and architecture checks pass.
Log: `/tmp/inertia-rebased-return-gates.log`. This is routine gate evidence,
not a fresh full-repository audit; InitMenu's focused acceptance remains red.

Observed timing anchors: baseline log creation 01:38:51 CEST, rebased-regression
baseline log creation 01:44:21, final focused run log creation 01:45:50 with
54.26 seconds pytest time. These describe recorded command windows, not total
active coding time or a remaining-plan ETA.
The final combined gate log was created at 01:48:08 and its terminal exit 0
was verified by 01:56:16 CEST: an 8m08s observation window including polling.
From baseline log creation to that terminal observation is 17m25s; it includes
experiments, implementation, verification and waits, not just coding time.

## Verified Finding

Read-only probes of the current InitMenu analysis separate three issues:

- The late CALL-frame consumer sees 18 callsites but no candidate assignment
  at their tags. Its NOT_APPLICABLE verdict is not the blocking refusal.
- Ten surviving SP assignment tags decode to four PUSH instructions and six
  ADD SP cleanup instructions. Two ordinary PUSH candidates (0x1019, 0x10cf)
  reach the consumed-argument classifier and return OBSERVED. Their downstream
  numeric SP dependencies must not be deleted independently.
- Two surviving PUSH CS instructions (0x10f2, 0x116e) are not argument pushes.
  The pre-SSA return-segment collector reports UNKNOWN_CALLEE for these and
  the other candidate PUSH CS/near-CALL sequences. All four affected callee
  objects have zero return sites and zero endpoints. They are neither PLT nor
  SimProcedure functions and have no recorded unresolved jumps/calls or
  jumpout/callout sites. Empty endpoint inventories are not complete proofs.

Addresses above are diagnostic coordinates in this analysis project only.
They must never become recovery rules or address-specific exceptions.

## Owners And Remaining Work

Before this repair, `semantics/call_return_segment.py::_callee_refusal_8616`
required a closed native Function endpoint census. It correctly refused missing
evidence but left separately pushed return segments in the native SP chain.
`inertia_decompiler/cli_decompilation.py::_create_or_update_direct_call_stub_8616`
creates callee objects and seeds names/prototypes/returning status; those fields
do not establish a machine return frame.

At the investigation checkpoint, the Semantics owner `terminal_stack_cleanup.py` supported
bounded binary reachability when a callee body is missing. Its immutable
`TerminalStackCleanupEvidence8616` carried cleanup and near/far kind, but not
operand width. Reusing kind alone would confuse word and dword far returns.
Do not replace the current width check with a FAR-only test.

1. Implemented: establish a complete, width-aware binary return-frame contract for
   bodyless callees, using existing reachability and typed refusal machinery.
   Keep compatibility projections coherent; do not add semantic recovery to CLI.
2. Integrated: consume that proof in return-segment classification before native SSA folds
   PUSH CS into subsequent SP values. Preserve exact instruction/projection
   ownership and whole-group refusal.
3. Open: inspect the remaining caller cleanup chain and close InitMenu acceptance.
   Removing return-frame uncertainty is not proof that all argument pushes,
   numeric stack observations or frame setup are disposable.

Reason: complete caller stack reasoning cannot depend on whether a callee
happens to have a populated native Function object in a sliced project.

DoD: regressions cover a bodyless callee with a closed binary word-far-return
census, divergent/unknown exits, near and mixed returns, operand-size-32
returns, and explicit cleanup. Numeric SP/upper-ESP behavior remains correct.
InitMenu must retain calls and argument classes, pass tail validation and
strict compilation, and improve its unchanged acceptance test. Run focused
tests, scoped Ruff/MyPy/Pyright, quality-fast and test-pipeline after repair.

Definition of failure: accept adjacency/name/prototype as return-frame proof;
accept incomplete reachability or wrong width; erase observed SP/CS effects;
move recovery into cleanup or CLI; or call the function fixed before its
acceptance and compilation gates pass.

## Evidence And Limits

Probes ran serially with PYTHON_JIT=1, PYTHONHASHSEED=0, isolated decompilation
caches, and in-process threaded analysis. Each completed with exit 0,
validation=passed, clean whole-tail validation, and unchanged generated C:
SHA-256 `08e8bc643d98e18c39a3f91da4e2c8e6569114e0e8d3ec44caf65664d155bea8`.
Artifacts: `/tmp/inertia-initmenu-{push,segment,callee}-verdicts.{c,log}`.
These are observations of SORTDEMO.EXE InitMenu, not a new sidecar-free SORTD
acceptance result. The hooks remain temporary and are not installed in source.

The original investigation changed no production implementation. The later
implementation and its scoped verification are recorded above. Neither is
proof that the full repository suite is green.
