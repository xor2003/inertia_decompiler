# Bounded Steps 10-12 Acceptance

User approved bounded scope September 19, then clarified September 20 that
Ghidra/Reko parity features and new mechanisms remain required. This corrected
contract bounds the inventory, not the requested feature set. Execution Steps
10-12 map to Tasks 6, 5 and 7 respectively in SORTD_GHIDRA_PLAN.md. Task 5 and
Tasks 7.1-7.4 feature acceptance cases remain authoritative within the selected
SORTD inventory; the earlier audit-only reduction is superseded. Step 9 remains
historically closed. Passing existing tests is not feature completion.

## Scope And Order

Latest execution priority: [stability, correctness, then remaining features](stability-first-execution.md).
That finite work queue supersedes the order below, not these completion requirements.

Use the same frozen 20-function sidecar-free SORTD inventory as Step 9.
Audit existing implementations first, implement missing Step 11/12 features,
then run Step 10 measurements and final acceptance.
Existing semantics, refusal behavior, layer ownership, types and docs remain
mandatory. Source and peer output are comparison oracles, never recovery inputs.
Numeric names and explicit unresolved facts remain acceptable.

User clarification September 20: bounded scope does not prohibit new
mechanisms. Add them when they deliver a demonstrated improvement in this
SORTD inventory. Each mechanism needs a concrete baseline defect, earliest
correct owner, focused positive/refusal tests, observable improvement, and
validation/compilation/behavior acceptance. Keep its implementation bounded;
defer speculative generalization, not the architecture needed to fix the defect.

## Step 11: Readability

User-required feature (September 20): proven 16-bit-only binaries must not
expose 32-bit GP upper-half preservation plumbing such as
`inertia_esi = (inertia_esi & 0xffff0000) | ...`. Emit coherent 16-bit register
state and direct word assignments. This is a semantic projection contract,
not rendered-text cleanup and not permission to change the machine lifter.
Mixed-width programs retain full coherent lanes where upper halves are observed.
Operand-size defaults alone do not prove a binary is word-only.

Reason: upper-half plumbing obscures application logic in word-only DOS code.
DoD: authoritative typed register-view evidence feeds Types/Lowering,
declarations, runtime ABI, validation and worker transport consistently; word
writes become word assignments, byte writes retain the other byte, SP still
wraps at 16 bits, and mixed-width/unknown cases retain the full model. Include
positive word-only and negative wide-read/call-boundary regression controls,
then pass the same function and whole-file acceptance gates. Coherent word views
may retain upper bits internally; whole-program observability proof is required
only if storage is physically narrowed or upper-bit effects are deleted.
Prioritize this
mechanism before optional saved-register-local presentation work.
Failure: deleting upper halves based on code-segment bitness, missing observed
ESI/EDI/ESP state, inconsistent function declarations, losing byte preservation,
or weakening validation to accept the changed output.

Reason: retain the verified readability gain without turning aesthetic cleanup
into an unbounded stack-analysis project.

DoD:
- retain the accepted signed-conversion projection and its negative tests;
- compare all 20 function exports against the recorded Step 9 baseline;
- verify no regression in validation, recompilation, calls or behavior;
- explicitly inventory remaining readability defects, including saved-register
  byte locals and unknown segmented identities.
- project proven stack slots, aggregates and signed conditions as required by
  Task 5; implement missing proof/projection mechanisms for the selected cases.

Failure: guessed semantics, hidden unknowns, widened loads, lost evaluation or
ABI effects, or a regression in the required acceptance gates.

Candidate new mechanism: exact saved-register SP-coordinate proof and its
Alias/Widening projection. Admit a bounded implementation if the live evidence
supports word locals with preserved memory and ABI effects; do not join bytes
by appearance. General stack normalization and unrelated cosmetic cleanup stay
deferred. Record an explicit evidence-backed disposition for this candidate.

## Step 12: Required Parity Features

Reason: deliver the requested useful Ghidra/Reko features, reusing existing
owners but adding missing mechanisms instead of only auditing current output.

DoD:
- audit Beep, Sleep, InitBars, ReInitBars, Swaps, SwapBars and QuickSort;
- verify required calls, argument values/classes, memory effects, returns and
  conditions with executable checks and semantic validation;
- fix demonstrated correctness failures in those functions at the earliest
  correct layer, with focused positive and refusal/corruption regressions;
- map current contracts, consumers and known limitations to these obligations;
- implement new mechanisms where the audit demonstrates a bounded quality or
  correctness improvement; audit-only work is not a substitute for an admitted
  implementation, and existing mechanisms must not be duplicated;
- record unsupported mechanisms separately, without reporting them complete.
- satisfy Task 7.1: proven split-word arithmetic, comparisons, slices and stores
  for Sleep, ReInitBars and Beep, plus deterministic affected-candidate recovery
  and mismatched-provenance/segment/CFG refusal cases;
- satisfy Task 7.2 for the selected inventory: one accepted storage contract
  shared by definitions and callsites, exact reaching arguments, recursive
  QuickSort edges, closed caller census, typed conflicts and worker transport;
- satisfy Task 7.3: InitBars' 43-word local array, independent two-byte global
  arrays, Swaps' temporary and whole-object copies, ReInitBars' element copies,
  and cross-segment/stride/overlap/unbounded-index refusal cases;
- satisfy Task 7.4 closed evidence, layer ownership and executable gates.

For each case record: existing-and-verified, missing-and-to-implement, or
explicitly refused with evidence. A refusal of a required positive case is
remaining work, not completion. Peer mistakes need not be reproduced; document
binary evidence for any rejected peer behavior.

Failure: missing calls/arguments/effects, incorrect value/pointer classes,
validation disagreement, guessed signatures, or semantic repair in Rewrite/CLI.

Deferred: arbitrary-binary generalization, new independent solvers where existing
ones suffice, and aggregate inference outside this inventory's acceptance cases.
SCC/worker transport, affected-candidate widening and aggregate mechanisms are
not deferred when needed for the required positive cases above.
Existing solvers and proof contracts must not be duplicated or weakened.
Any implementation remains independent of incompatible licensed source.

## Step 10: Bounded Measurement

Reason: establish reproducibility and resource use without another open-ended
optimization campaign.

DoD:
- one warmup and at least three stable repeats of the documented sidecar-free
  primary command, with PYTHON_JIT=1 and PYTHONHASHSEED=0;
- record source revision/worktree identity, cache state, worker cap, wall/CPU
  time, aggregate PSS/RSS, output hashes, validation and available stage timings;
- verify deterministic output and the documented 2 GiB aggregate worker budget;
- identify any blocking performance/resource regression and address it, or
  record the baseline and defer further optimization. No mandatory speedup.

Failure: nondeterminism, lost worker failures, memory-limit violation, invalid
output, or claiming speed gains from incomparable cache/load conditions.
Unstable host measurements are inconclusive, not a successful measurement.

Deferred: speculative parallelism, another fork-server design, dependency
worklists and mypyc experiments without a demonstrated blocking bottleneck.
Previously rejected experiments remain rejected absent new evidence.

## Final Acceptance And Stop Rule

One final checkpoint on the accepted source state must pass:
- all 20 sidecar-free functions, with clean whole-tail validation;
- generated-C compilation: errors block; examine and record all warnings;
- all 19 generated behavior harnesses;
- all seven MS C tiny compile/decompile/recompile/behavior round trips;
- the default test pipeline, including its QuickC lane;
- architecture and relevant lint/type/doc checks for changed code.

Pre-existing unrelated global lint/test debt stays separately documented; do
not suppress failures or silently waive a required lane. Record exact gate
scope, artifacts and source identity. Focused tests alone cannot close a step.

Stop after these bounded obligations and any admitted mechanisms pass. New
binaries and improvements outside this inventory go to a separate backlog.
Do not reopen the milestone automatically because another improvement is possible.
