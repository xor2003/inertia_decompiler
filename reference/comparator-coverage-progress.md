# Comparator plan: loop invariants and indirect calls

Date: 2026-10-06. Status: **planned; implementation not started**.
Acceptance: **0/6 milestones completed**. Update the ledger only from reviewed
evidence; drafting this plan is not an implementation milestone.

This replaces the completed bounded coverage plan.

## Goal and scope

Increase sound per-function equivalence coverage for **16-bit real-mode MZ**
and **PE32-to-PE32** originals/rebuilds by discharging bounded loop-invariant
and indirect-call obligations. Preserve existing unconditional proofs, full
observations, declared premises, provenance and resource limits.

Use BCC/MSC PE32 and retained actual-MZ cases. Do not develop the ELF path;
preserve its compatibility. Do not edit reconstructed compiler/application C,
change compiler flags to hide differences, reopen decompiler M0–M7, or expand
this into compiler/decompiler coverage work. Static lifting, Z3 and Unicorn
require no KVM. Mandatory Cython real16 lifting remains active.

First delivery is deliberately limited to:

- Single-loop regions with one backedge, fixed-step bit-vector counters or
  pointers, complete entry/exit effects and bounded relation proposals.
- Finite indirect calls selected through registers/ITE terms, or small
  initialized tables whose contents and relevant writes can be proved.
- Combining those two capabilities through complete, nonrecursive callee
  summaries once each track is accepted independently.

General invariant synthesis, arbitrary pointer analysis, differing recursive
layouts, irreducible/nested loops, unrestricted unrolling, and mutable vtables
without a proved target relation are deferred. Indirect jumps are outside the
first indirect-call milestone; if they prevent loop closure, record the blocker
rather than starting a switch-recovery workstream.

## Starting evidence and existing owners

The quoted BCC distribution (580 loop refusals; 160 indirect-call refusals)
motivates this work; it is user-reported historical evidence, not a fresh census.
Do not merge it with earlier MSC totals or infer conversions from bucket size.
The completed delivery has no new unconditional real-corpus proof; its final
gate passed 305 contracts and 1,366 comparator tests. Refresh semantic hashes
and the selected baseline before implementation.

Extend existing machinery rather than introducing another proof engine:

| Responsibility | Existing owners / controls to inspect |
| --- | --- |
| CFG partition and cutpoint proposals | `tools/dosunit/compare/paired_region_graph.py`, `region_pairing.py`, `cutpoint_state_relations.py`, `register_affine_relations.py` |
| Architectural real16 invariants and call-loop proof | `tools/dosunit/compare/real16_loop_invariants.py`, `real16_loop_calls.py`; physical successors, CS domain and SS/DS/ES remain distinct |
| PE32 call-loop transitions and retry | `tools/dosunit/compare/flat32_loop_calls.py`, `flat32_region_attempts.py`, `flat32_proof_retry.py` |
| Real16 finite indirect calls | `tools/dosunit/compare/real16_call_indirect.py`, `real16_call_contracts.py`; target closure, per-arm return and CS restoration already exist |
| PE32 indirect callbacks and complete callees | `tools/dosunit/compare/flat32_call_composition.py`, `flat32_call_execution.py`, `flat32_call_contracts.py`; trace the exact target resolver before editing |
| Public regressions | `test_flat32_loop_controls.py`, `test_flat32_loop_calls_public.py`, `test_relational_rotation_public32.py`, `test_real16_loop_calls.py`, `test_real16_far_loop_controls.py`, `test_flat32_indirect_callbacks.py`, `test_flat32_indirect_callback_effects.py`, `test_real16_indirect_call_multiarm.py`, `test_real16_indirect_call_budgets.py` under `tests/` |

Inspection found matched-loop induction and finite indirect-call controls
already present. Determine the missing admission, relation, target discovery or
public-driver connection for each selected root before extending semantics.
Names, CFG similarity and runtime traces may propose candidates; none prove them.

## Milestones and acceptance ledger

| ID | Deliverable | Acceptance | Status |
| --- | --- | --- | --- |
| LI0 | Frozen baseline and exact blockers | Retained binaries/SSA, contracts, identities, selected roots and resource receipt; distinguish unsupported structure from unwired existing support | Not started |
| LI1 | Bounded loop relation proposals | Typed relation/evidence, deterministic proposal limits; full-state initiation/preservation/exit/progress checks and negative controls | Not started |
| LI2 | Loop proof through both public comparators | Actual-MZ and actual-PE positive/corrupted controls; reviewed real-corpus loop conversion under the frozen contract | Not started |
| LI3 | Closed finite indirect calls | Complete guarded target coverage, callee effects and returns through both public comparators; actual-image controls and reviewed corpus conversion | Not started |
| LI4 | Loops containing finite indirect calls | Compose the accepted targets/summaries in loop transitions; prove closure, return, state and progress together without new premises | Not started |
| LI5 | Integration and measured delivery | Relevant gate green, protected proofs preserved, resource contract met, exact per-root gains and remaining refusals published | Not started |

### LI0 — freeze a small, representative baseline

Select **up to 16 real-corpus roots**, four per architecture/feature bucket:
real16 loops, PE32 loops, real16 indirect calls, PE32 indirect calls. Prefer small
complete regions and reused callees. Start from saved SSA/reports; relift only
when bytes, source identities or required evidence changed. No full-corpus sweep
on the development path.

Record exact names, paths, hashes, architecture, loaded ranges, current verdict
and retry lanes, full input/observation contract, premises and limits in an
ignored `.cache/comparator-loops-indirect/` manifest. Record smaller available
denominators honestly; do not invent real16 corpus coverage. Add a protected
sample of previously proved functions from both architectures.

For each refusal, identify its actual obligation: graph pairing, missing
cutpoint relation, unknown target term, unproved table memory, unmapped callee,
return-frame failure, or budget. Keep dependency/callsite evidence structured.
Fix an existing-path wiring defect before building another mechanism. Freeze
cohort membership before evaluating improvements.

### LI1–LI2 — prove bounded loop invariants

Start with synchronized single-backedge transitions. Propose existing identity,
register-renaming or affine bit-vector relations from typed SSA; retain full
memory equality or an existing proved memory relation. Use **at most four
candidate relations and two refinement rounds per root**, all charged to its
existing absolute deadline. These are proposal caps, not larger solver budgets.

A relation is accepted only when Z3 discharges:

1. A nonempty admitted entry domain and invariant initiation.
2. Preservation across every continuing transition, including guarded calls,
   flag/register updates, memory stores and machine-width wraparound.
3. Complete taken/fallthrough and exit coverage, including early returns and
   in-scope faults; all required final observations agree.
4. Control correspondence, architectural-domain preservation and progress.
   Synchronized steps must account for divergence. A later bounded 1:2/2:1
   proposal requires proved finite progress on the stuttering side; unrolling
   alone or equal iteration counts cannot establish equivalence.

Keep entry/final ABI observations unchanged. Real16 proofs include full loaded
destinations, CS aliases, SP/return frames and segmented memory; PE32 keeps
32-bit EIP/ESP and near-call frames. Loop invariants must not silently strengthen
the caller input domain. Any genuinely external premise stays named conditional.

Use actual MZ/PE controls for changed stride, bound/signedness, wraparound,
stored byte, live flags, early exit and divergence. A SAT induction obligation
is not automatically a reachable program counterexample: retain refusal unless
the existing counterexample contract establishes reachability, and use
byte-verified replay when claiming a concrete divergence. Do not dismiss the
previous 119 BCC failures or change their domains in this milestone.

### LI3 — close and compose indirect calls

Begin with cases already close to the finite-target controls. Propose targets
from SSA definitions and loaded-byte evidence. Prove, under every reachable
callsite state, that the actual control target belongs to the admitted set.
Require executable target entries, complete bodies and paired callee mapping;
name equality is only a pairing proposal. Unknown or omitted feasible targets
remain refused. Never truncate a candidate set to fit a cap.

For a loaded table, bind its bytes and relocations to the initialized-image
contract and prove relevant caller/callee writes cannot invalidate the read,
or derive the target from the modeled evolving memory. Runtime-observed targets,
read-only section labels or symbol names alone do not establish this property.

Compose every feasible guarded callee through existing summaries, preserving
registers, flags, memory, stack, returns and modeled outcomes. Prove guard/target
correspondence across binaries even when target addresses differ. Real16 far
targets additionally need complete selector/offset and return-CS obligations;
support them only through existing proved frame/domain contracts. Unproved
recursive targets or unsupported environments remain refused.

Preserve current caps: real16 four live targets / sixteen discovery candidates;
PE32 eight selector leaves (proof paths, not just distinct callees). Reuse
source/contract/dependency-bound summaries. Paired-call congruence may remain an
explicit conditional lane but cannot satisfy a new proved-callee obligation.

Required controls: equal two-target callbacks, changed callee effect, changed
selector arm, omitted feasible target, unconstrained pointer, mutable table,
corrupt return frame, unmapped/recursive target, budget exhaustion and stale
image/summary. Exercise both public drivers and real16 intake, not only helpers.

### LI4 — combine the accepted tracks

Use one small actual-image loop/callback case per architecture. Compose each
proved target arm into a cutpoint transition, retaining loop-carried target
selection and memory changes. Recheck initiation, every transition and exit,
return destination and progress. Changed callback stores or target selection
must still fail or honestly refuse. If a combined proof exceeds its original
budget, retain that result; do not raise depth, target or expression limits.

## Resource, validation and stop rules

- Keep existing per-root absolute deadlines; PE32 corpus timeout remains at
  most 60,000 ms. Every discovery, refinement and retry consumes that same
  deadline. No larger default block, term, edge/depth, store, target or inline
  budgets. Preserve shared DAG accounting and completed-summary reuse.
- Freeze proof-relevant sources before measurement. Use private regular-file
  snapshots, never stash/reset or overwrite shared production files for a
  baseline. Record cache state and workers; separate cold and warm samples when
  measuring cache behavior. Record CPU/wall, peak RSS, lift/composition/solver
  times and relation/target/term counts; unavailable metrics stay unavailable.
- For the protected already-proved cohort, median CPU/wall and peak-RSS ratios
  must be <=1.20 over three matched runs. Reaching a solver on a previously
  refused root can cost more; report that cost separately, within the unchanged
  deadline, and require peak-RSS ratio <=1.20. A breach requires optimization
  or keeping the feature opt-in, not hiding the measurement.
- Run Python/pytest through RTK at nice 10 with `PYTHON_JIT=1`,
  `PYTHONHASHSEED=0`, `CI=1`. Share at most six test slots and two heavy proof
  jobs. Static comparator checks require no KVM; actual KVM runners keep marks.
- Per coherent code edit: scoped `lint-iteration` and focused regression. At
  completed interfaces: scoped typing and applicable architecture checks.
  Rebuild Cython/mypyc only for affected compiled sources. Follow
  [linter cadence](agent-execution.md#linter-cadence); no repeated broad scans.
- Enroll new controls in the existing comparator gate and test ownership.
  Integration gate: `rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 CI=1
  make comparator-check-fast PYTHON=./.venv/bin/python
  COMPARATOR_PYTEST_WORKERS=2`. No broad decompiler gate as the development loop.
- Keep `passed`, named `conditional`, modeled `failed`, and `refused` distinct;
  preserve every selected result and retry. Report candidate/admitted/proved
  relation/target counts, rejected obligations and exhausted limits. A changed
  refusal reason is diagnostic progress, not a proof gain.
- Stop a root after its bounded proposals/refinements. At two coherent failed
  experiments for a class, publish the exact missing obligation and leave that
  milestone open; do not expand scope or chase the entire corpus indefinitely.

## Finish line and delegation

Acceptance needs at least one newly proved actual-image control in each of the
four architecture/feature buckets, corrupted controls that reject, and at least
one reviewed real-corpus conversion for **each feature** under unchanged input
contracts. Count unconditional gains separately from gains retaining existing
relocation/environment premises. Introducing a new assumed callee is not a
proof gain. No-gain experiments may be closed as diagnoses, but cannot mark a
coverage milestone accepted or this plan complete.

Complete only after LI0–LI5 evidence is reviewed, the integration gate passes,
protected results/resources meet the contract, and the final ledger states exact
per-root transitions, premises and unresolved blockers. This does not require
proving all 580 historical loop refusals or every dynamic function pointer.

When Devin delegation is used under the user's standing authorization, start
with disjoint loop and indirect-call owners plus a bounded corpus/resource
reviewer; up to four Devins, shared files coordinated by the parent. Each runs
its focused tests/lint and returns exact deltas and receipts. Follow
[Devin handoff](devin-handoff.md), including sandbox/baseline rules and parent
review. Do not launch this plan as one unbounded task. This documentation update
does not claim a Devin implementation or a new test run.
