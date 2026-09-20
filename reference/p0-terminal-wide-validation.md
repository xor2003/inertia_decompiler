# Terminal Wide Predicate Acceptance

## Scope And Ownership

This is a Step 9 correctness slice, not full Step 9 closure. The sidecar-free
Sleep regression now passes validation, strict generated-C compilation, and
50 deterministic clock deadline cases. The oracle also checks preservation of
SI/DI state. The refreshed whole-file SORTD gate accepts 16/20 functions, up
from 15/20. Named/sidecar-assisted Sleep still fails separately; this slice
does not establish every Sleep execution path as fixed.

Reason: terminal composite comparisons consume scalar AX/DX carriers. Final
validation tried to reconstruct those obsolete scalar expressions instead of
checking the complete accepted comparison. Independently, the renderer dropped
temporary declarations and the legacy CLI declaration fallback guessed a word
type, truncating a correctly captured 32-bit clock result.

Ownership:

- Lowering publishes an immutable wide-call binding: exact condition keys,
  callsite, resolved target identity, stack BP offset, and captured temporary.
- Structuring publishes the complete wide decision and natural-loop header
  only after its existing full-graph, polarity, dominance, and effect checks.
- Validation consumes both proofs. It checks current typed facts, signed
  comparison, operand widths, rendered declarations, stack binding, unique
  call definition, and immediate-before-terminal-guard placement. It does not
  reconstruct missing semantics or accept branch provenance alone.
- Frontend/angr rendering compatibility retains typed temporary declarations
  in deterministic local-variable sorting. No semantic recovery was added to
  Rewrite or CLI, and the CLI's guessed type is no longer needed for this case.

The placement check deliberately refuses intervening statements. Supporting
more general placement requires an earlier-layer proof, not a validation
heuristic. Existing narrow register-copy capture forms remain valid Lowering
operations but do not automatically satisfy this terminal validation contract.

## Acceptance Contract

Definition of done for this slice: complete comparison and original dynamic
clock-call count survive; final declarations retain the captured width;
sidecar-free generated C passes strict compilation and deadline/ABI execution;
all proof corruption controls refuse; focused typing, lint, architecture and
ownership checks pass; the normal test pipeline includes the new coverage.

Definition of failure: treating an address tag or mutable AST reference as
semantic proof; accepting missing or changed branch facts, predicate polarity,
call identity/arguments, storage, declaration type, or capture placement;
replacing runtime checks with a textual formatting allowance; hiding a final
validation failure or claiming a curated run is a complete-suite pass.

## Evidence

- Before: existing Sleep test failed with `invalid-fingerprint` in 11.77s.
- New proof control failed before validation integration; 12 initial corruption
  controls rejected changes afterward (35 focused tests, 6.21s).
- The executable oracle then caught a genuine truncated clock temporary despite
  passing structural validation. Generated C declared `unsigned short tmp_0`.
- A read-only worker probe showed the variable manager, CVariable, and unified
  declaration all retained `long (32 bits)`, but the renderer omitted that entry.
- The temporary-sorting regression failed before the compatibility fix.
- Added missing/narrowed declaration controls and an oracle corruption case
  for a short clock capture; no validation check was disabled.
- Final live/oracle/proof set: 27 passed, 14.24s.
- Branch/coverage/structuring/capture/render integration: 204 passed, 10.32s.
- Scoped Ruff `check --fix` and MyPy pass for the focused owners/tests; MyPy
  also passes for `validation_branch_conditions.py`.
- Startup architecture and ownership checks pass. The larger integration-tool
  Ruff run retains 74 findings. This is not global quality closure.

The former exact `if (clock() > goal)` assertion was replaced by execution of
the unchanged generated C, allowing the proven in-place captured temporary.
The old `local_6` name ban was replaced by saved-register behavior checks:
that name now denotes a legitimate byte of saved DI, not a stale clock word.

Evidence logs are `/tmp/step9-wide-*.log`, `/tmp/step9-render-before.log`, and
`/tmp/step9-resume-sleep-before.log`. Temporary diagnostic scripts and generated
artifacts are outside the repository. Observed work began around 22:30 +02:00
on 2026-09-18; active engineering time was not separately measured. Individual
test durations above are measured wall time, not a total implementation time.

The default pipeline passed before the final projection-coherence checks:
5,461 routine tests in 282.93s, QuickC in 42.039s, and MS C tiny in 101.666s.
Three additional corruption cases then demonstrated that mismatched display
identities or branch provenance could pass. The validator now requires those
projections to agree; all 19 projection/live tests passed in 14.18s. A subsequent
fact-check helper extraction passes focused Ruff and MyPy but awaits the broad
audit. No full-suite or final post-extraction pipeline pass is claimed.

The refreshed `quality-hard` gate exits at Ruff: 6,243 findings across 786
files (4,182 magic comparisons, 1,865 complexity findings, 194 Boolean-complexity
findings, and two dictionary-iteration findings). Later quality-hard stages did
not execute. This is a substantial independent Step 9 acceptance obligation,
not evidence of thousands of semantic defects or a completed typing audit.
An hours-level completion forecast for the entire unchanged Step 9 contract is
not supportable. Complete collection and whole-file acceptance remain pending.

## Refreshed Audit

- Whole-file gate: 16/20 accepted; validation failures at `0x10808`, `0x108d0`,
  `0x10a88`, and `0x10c18`. No timeout, empty function, or traceback was reported.
  Evidence: `/tmp/step9-wide-whole.json` and `/tmp/step9-wide-whole.txt`.
- Inventory initially refused 23 cases across four helper-only test modules.
  Explicit reviewed ownership metadata now admits them without changing test
  selection. Four admission regressions failed before the metadata correction;
  all ten profile tests pass afterward. Inventory admits 13,339 records.
- The full audit process and session disappeared without publishing a final
  controller summary. Saved shard reports in
  `.cache/pytest/pytest-partition-3505o_mc/` contain 6,315 passed, 39 failed, and
  124 skipped. Two reports have exit status 3. The cause of interruption is
  not established; no full-suite completion or source-stability attestation
  is claimed. The older `partitioned-summary.json` is not evidence for this run.
- Two observed failures were stale ownership-test expectations missing the
  already-enrolled DrawTime and RunMenu gates. Correcting those expectations
  preserves enrollment: all 60 ownership tests pass in 1.22s, Ruff clean.
  Evidence: `/tmp/step9-manifest-repair.log`.
- Remaining observed families include indexed memory width/identity,
  CFG/condition validation, call-argument source precedence, COD object/stack
  recovery, and obsolete name-only assertions. Each needs semantic review;
  passing compilation alone does not justify weakening an assertion.
