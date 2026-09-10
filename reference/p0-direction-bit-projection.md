# Direction-Bit Projection And InitMenu

## Root Cause And Owner

After the callee-cleanup correction, InitMenu still emitted frame setup, an
identity SP update and `SP - 4` before its final output call. Native post-SSA
evidence showed the final SP value feeding packed status calculations for
`ADD SP, 4`. Those calculations fed a synthetic direction-flag branch even
though ADD preserves DF. Both branch arms reached the same epilogue.

`Processor._sync_lifted_direction_step` legitimately synchronizes derived native
direction state after FLAGS writes, including when that state was stale. The
problem was rebuilding the selected DF bit through the entire packed status
expression. Skipping direction synchronization would violate that contract.

The earliest fix is now split between two focused owners:

- `ir/vex_bit_source.py` proves that one selected bit has an equivalent captured
  source through neutral AND/OR operands. Other source bits are unspecified.
- `direction_step.py` consumes only FLAGS bit ten and emits the same +1/-1
  direction synchronization as before. Processor delegates to it; the large
  Processor module shrinks instead of receiving another substantial pass.

The actual FLAGS writes are unchanged. Captured `RdTmp` reads stay captured;
the projection never moves a fresh register/memory read after a FLAGS write.
Unsupported operations, incompatible widths, conflicting definitions, cycles
and exhausted traversal bounds retain the original input where proof fails.
Every projection carries closed raw/normalized/classified/materialized/failure
counts, retained on the lifter facade for that instruction. An unchanged source
is an unmaterialized projection, not permission to delete its computation.

## Acceptance Contract

Reason: remove false status-bit dependencies before SSA liveness and structuring,
without deleting stack effects by shape or weakening architectural FLAGS state.

DoD: prove selected-bit equality for all values in the tested 8/16/32-bit cases;
preserve captured reads and unknown cases; keep DF synchronization correct even
with stale native direction state; preserve STD/CLD; pass InitMenu's unchanged
acceptance and behavior harness, strict generated-C compilation, whole-tail
validation, unchanged call inventories, scoped types/linters and routine gates.
Check the separate no-sidecar InitMenu fixture before claiming both modes.

Definition of failure: treating projected bits as an equivalent whole FLAGS
value, rereading FLAGS across a write, trusting stale native direction state,
dropping unknown effects, recovering semantics in Rewrite/CLI, changing calls
or argument classes, or weakening the original InitMenu assertion/harness.

## Verified Focused Result

The temporary probe removed every remaining SP/BP assignment and passed strict
C compilation and validation. Its counter used Python object identity across
wrapper reads and is not an authoritative count of accepted projections.

Production uses explicit bounded proof and retained source identity. Eighteen
parameterized bit-vector cases prove selected-bit equality; six cases cover
unknown operators, live bits, mixed widths, cycles, duplicate definitions and
invalid selection. Sixteen execution cases cover status updates, STD/CLD and
deliberately stale derived direction state. The first run caught a missing
cycle refusal; the bounded traversal was corrected. No instruction test failed.

The unchanged InitMenu acceptance and behavior harness now pass: 49 focused
tests passed with seven dependency warnings in 47.48 seconds, including
39.19 seconds for InitMenu. The acceptance test was promoted into the routine
pipeline and frontend test-ownership selection.

Final production live output has no SP/BP assignments (`STACK_ORIGINS=[]`).
All 18 call inventories are identical to the prior cleanup checkpoint. CLI exit
is zero; strict portable C compilation and whole-tail validation pass.
Output SHA-256:
`802a992c49145cabbf1bcd751220a575482666bbddab43cc75304d3bf67a0d4b`.
The code is closer to the source without inserting source-derived semantics.

Scoped Ruff `check --fix`, MyPy and Pyright pass. The helper explicitly models
the dynamic lifter facade/customizer boundary; it does not pretend the facade
is a plain pyvex Instruction or suppress the resulting typing diagnostics.
Both `make quality-fast` and `make test-pipeline` exit zero. Fast passes 3,443
tests with eight warnings in 146.21 seconds; default passes 3,443 with seven
warnings in 117.25 seconds. All three executable quality guards pass. QuickC
passes in 41.970 seconds; all seven MS C tiny full roundtrips pass with return
code zero in a 61.383-second lane. The default unit lane remains over its
configured budget at 117.683 seconds including overhead. This is not a
full-repository pytest audit.

The separate no-sidecar InitMenu regression also passes: one test, seven
warnings, 30.52 seconds total (22.86 seconds for the test). It strips the image's
debug overlay, uses an isolated executable without local sidecars, checks
numeric calls and argument shapes, and requires strict compilation plus clean
whole-tail validation. InitMenu's bookkeeping checkpoint is now closed in both
tested modes. The wider plan remains open.

## Timing And Artifacts

Investigation began after the 06:27 CEST cleanup checkpoint on 2026-09-10.
The successful temporary output was produced at 06:33; final production live
validation was observed at 06:42. These are work checkpoints, not a full-plan ETA.
Final gate/no-sidecar evidence and `git diff --check` were verified by 06:53:59
CEST. No controlled performance improvement is claimed.

Logs: `/tmp/inertia-direction-{focused,acceptance,live,ruff-final,mypy-final,pyright-final,gates}.log`.
No-sidecar log: `/tmp/inertia-direction-sidecar-free.log`.
Native evidence: `/tmp/inertia-final-frame-observe.log`. The experiments are
temporary diagnostics, not production dependencies.

Follow-up: the complete suite reports 11,326 passed, 40 failed and 170 skipped;
see [the full audit](p0-full-suite-audit-20260910.md). InitMenu remains green,
but this is not whole-decompiler closure. The direction helper was subsequently
added to the positive persistent IR/SSA source manifest, with a failing-before
test and eight passing cache regressions, to cover future helper edits.
