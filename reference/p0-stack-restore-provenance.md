# Stack Restore Provenance Checkpoint

## Scope And Acceptance

Step 9 remains open. Alias owns captured SP and saved-byte provenance;
Types/Lowering consumes exact storage and instruction ownership. No semantic
repair belongs in Rewrite. This combined patch is not yet corpus-accepted.

DoD: correct distinct nested saves through loops, conservative refusal after
clobbers, exact restore-byte binding, idempotent replay including cross-register
restores, passing final validation and strict compiled-C behavior, followed by
quality-fast, test-pipeline and the full Step 9 acceptance audit.

Failure: fabricated save provenance, a sibling expression rewritten under an
aggregated instruction tag, duplicate snapshots on replay, lost memory effects,
uninitialized C reads, or failing generated-C compilation/execution.

## Proven Causes And Changes

- Alias previously initialized unvisited back-edges as analyzed unknown states.
  The must-analysis now waits for visited predecessors, while analyzed unknown
  and clobbered states still refuse proof. Seven initial loop controls included
  three failures before the change.
- Negative stack offsets were treated as entry-SP-relative regardless of their
  captured base. Actual VEX for nested PUSH DI/SI/ES captures different SP values;
  two real-instruction controls proved the old code incorrectly restored SI into
  DI. A block-local typed SP capture owner now resolves the recorded base.
- GP Lowering previously accepted byte-join syntax without exact storage identity
  and used compound statement tags as leaf ownership. Two failing controls now
  enforce the Alias-proven byte pair and leaf statement boundary.
- Snapshot save tags used the source register while replay looked for the
  destination register. The valid PUSH AX / POP BX case repeatedly inserted
  snapshots. Save tags and their consumers now consistently use the restore
  register; the RHS still consumes the saved register's value.

## Replay Verification

Replay follow-up: approximately 05:29-05:34 +02:00 on 2026-09-12; about five
minutes, not an estimate of remaining Step 9 effort.

- New cross-register test: failed before repair, passed afterward.
- Four focused stack-restore modules: 24 passed in 6.52s, pytest -n 7.
- GP Lowering MyPy: passed. Ruff check --fix: test module clean, production
  module still has two complexity findings and one numeric-constant finding.
- Full architecture check: passed, including the new SP capture owner.
- Fresh corpus probes: two failures in 49.30s. InitMenu took 42.74s and
  __fimemset took 11.08s; xdist overlaps these durations.
- InitMenu still fails final validation on uninitialized BP-0x24/BP-0x23 reads.
  The capture change does not establish the root cause of that failure.
- __fimemset now retains distinct SI and DI restores, but four original save-byte
  locals become unused after wide snapshot materialization. Strict GCC rejects
  them. Do not suppress the warning or delete stores without liveness evidence.

Logs: `/home/xor/.cache/gp-replay-{before,after,ruff,mypy,corpus}.log`.
Earlier loop/capture evidence: `/home/xor/.cache/stack-sp-captures-*.log` and
`/home/xor/.cache/nested-stack-ir.log`.

## Existing Byte Representation

Follow-up started approximately 05:35 +02:00 on 2026-09-12. Lowering now recognizes
an already materialized byte pair before introducing a separate wide snapshot.
It requires Alias-proven offsets, matching existing C variable identities,
unique non-escaped byte writers, exact saved-register byte values, and the
correct upper-word-preserving destination write. Every restore copy must pass.
Adjacent saves must dominate the restore in one unconditional statement
sequence; transparent CStatements may nest, but branches and loops are not
flattened. Gotos refuse this recognition path.

The normal-worker observation disproved a suspected lowering-order problem:
the bytes and runtime GP values already existed at the boundary. Separate
unconditional statement lists caused the initial narrow recognition to refuse.
No orchestration reorder was needed.

The positive control failed before the change. Final focused verification:
46 passed in 15.58s, including real __fimemset decompilation, strict GCC compilation
and execution in both DF directions for counts 0..3. The existing oracle checks
memory, return value and ES/ESI/EDI preservation and rejects corrupted controls.
Wrong value, definition order, overwrite, goto, conditional save and conflicting
restore-copy cases refuse byte-representation acceptance. Tests are enrolled in
the routine lane through the existing GP binding module.

No C stores or declarations are deleted and no warning is suppressed. Scoped
Ruff and MyPy pass for the expanded identity helper and tests. quality-fast
remains red on global Ruff debt; the 39-module mypyc import smoke passes.
Full architecture passes. Routine pipeline: 268 early contracts pass; 4,469
pytest tests pass and the same three SORTD tests fail in 197.70s. Compared with
the prior 202.27s routine checkpoint, no broad slowdown is observed; these are
single runs, not a controlled performance claim.

External acceptance is red: four of seven MS C tiny examples pass complete
round trips (loops_jumps, storage_classes, function_pointers, pointer_memory).
compare16, simple_control and scalar_types_io fail. The QuickC lane also failed;
the aggregate summary's three failures counted pipeline lanes, not fixtures.
This supersedes the older seven-of-seven MS C result. The broader
stack-restore patch remains unaccepted despite the repaired __fimemset corpus.
Logs: `/home/xor/.cache/gp-byte-reuse-{before,final,ruff,mypy,quality,pipeline}.log`.
Worker observations: `/home/xor/.cache/gp-byte-boundary.jsonl`.

## Next Action

The normal-worker cmp_i16 probe passes the byte-representation check initially,
then loses all assignments before the second Lowering replay. A scoped transition
probe identifies `_materialize_structuring_selector_return_branches_8616`:
13 assignments before, zero afterward, reproduced across four attempts. The
separate return-chain pass observes zero assignments on entry, so it is not the
first loss. The replay gate correctly refuses missing materialization.

Repair the selector-return replacement at its Structuring owner. Preserve
required effects or consume explicit valid elimination evidence before replacing
the body; do not silence the Lowering gate or carry forward stale completion
counts. Add a focused regression for saved-register effects through selector
return materialization, then rerun all seven MS C examples. InitMenu's first
provenance loss remains a separate unresolved investigation.

Diagnostic evidence: `/home/xor/.cache/gp-cmp-{boundary,callers,return-chains,transitions}.jsonl`.
Follow-up ended approximately 05:53 +02:00 (about 18 minutes including gates and
diagnostics). No speculative source change was made to the selector-return pass.

No current full-suite pass or whole-Step-9 completion is claimed.

Subsequent checkpoint: the shared selector/return-chain storage guard restores
compare16 and scalar_types_io round trips. See
[effect-preservation gate and latest results](p0-selector-storage-effects.md)
for the six-of-seven MS C result, remaining switch_fold case-2 error and corrected
QuickC accounting (three fixtures passed, args failed).
