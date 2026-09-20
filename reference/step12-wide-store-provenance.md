# Step 12 Wide Store Provenance

Status: investigation plus bounded call-placement repair; full Task 7.1 remains open.
Evidence observed September 20, 2026, through 05:11:39 +02:00.
This refines Task 7.1; it does not replace the remaining parity obligations.

## Live Positive Controls

Fresh isolated result caches and the in-process/thread diagnostic settings
confirmed execution of the inspected producers and consumers. No production
source was changed for these probes.

- Sleep `0x10f38`: one carry candidate survives Semantics, Alias, value
  Widening, destination Alias and storage Widening. Stack assignment Lowering
  reports one classified/materialized assignment, zero failures. The next
  invocation reports the assignment already materialized. Two pipeline applies
  reuse one build with identical SSA and stack-Alias inputs.
- ReInitBars `0x10678`: zero carry candidates is expected, not missing evidence.
  Its separate global-store collector reports the call at `0x10683`, target
  `0x1137e`, stores at `0x10686` and `0x10689`, DS offset `0x0ba6`, width four.
  The tagged fold reports one classified, already-materialized store and zero
  failures. It also reuses one carry build across two applies.
- Both fresh v3 direct-function runs finish with `validation=passed` and clean
  whole-tail validation. These are focused runs, not a new full-suite result.

Artifacts: `.cache/widening_live_probe.py`,
`.cache/widening-{sleep,reinitbars}-v3.{c,log}`. These ignored diagnostics are
not durable regression tests. Earlier Beep observations found no carry
candidates; its division/slice evidence still requires separate inspection.

No unchanged-input rebuild defect was demonstrated. A changed-input experiment
and affected-candidate scheduling remain open. Do not introduce a new scheduler
on the basis of repeated apply calls alone.

## Confirmed Boundary Defect

A real binary fixture uses entry `0x1000`, caller end `0x100f`, and these bytes:

```text
control: 85 c0 90 90 e8 08 00 a3 00 02 89 16 02 02 c3 c3
bypass:  85 c0 75 03 e8 08 00 a3 00 02 89 16 02 02 c3 c3
```

The bypass JNE reaches the AX store at `0x1007` without executing CALL
`0x1004`. The following DX store is at `0x100a`. Closed Frontend boundaries
give control edge `1000 -> 1007`, versus bypass edges `1000 -> 1004`,
`1000 -> 1007`, `1004 -> 1007`.

With an owned zero-argument summary and no return-store summary, both inputs
produce the same four-byte candidate from
`_collect_direct_global_call_return_store_evidence_8616`. Passing the candidate
and actual AX/DX register AST reads to
`_make_direct_global_call_return_store_rhs_8616` produces a new `sub_100f()`
call in both cases. The latter helper checks carrier register identity, not
reaching call provenance. Its only production caller may retain that new call
even without a matching preceding standalone call.

Artifacts: `.cache/probe_wide_store_cfg.py` and
`.cache/wide-store-cfg-consumer.{jsonl,log}`; probe exits zero. The fixture's
RET-only callee is not proof of a wide-return ABI. This proves an unsafe
collector/consumer boundary, not a reproduced whole-CLI miscompilation, and
does not imply that current ReInitBars output is wrong.

## Next Correctness Change

Reason: instruction adjacency must not introduce calls on bypass paths or
substitute a different reaching AX/DX value. This precedes scheduling work.

Owner: existing `semantics/call_outputs.py` already refuses a return block
with another predecessor using `RETURN_BLOCK_HAS_OTHER_PREDECESSOR`. Reuse
that authoritative provenance and its SSA consumers; do not independently
recover call semantics from register names in Lowering or postprocess.

Required work: make wide-store recovery consume proven call-output identities,
retain unproven scalar stores, and prohibit fresh call synthesis without a
proven original call/effect placement. Cover collector and materializer paths,
including summary and fallback inputs. Preserve call arguments and evaluation
count; a name match is not proof.

DoD: durable before/after regressions cover bypass, clobber, conflicting joins,
unknown provenance and a real positive wide return. ReInitBars and Sleep retain
their accepted wide operations, original calls and validation. Closed evidence
counters, generated-C compilation, behavior, scoped lint/types/docs,
quality-fast and test-pipeline are checked before claiming the fix complete.

Definition of failure: a fresh or duplicated call on a bypass path; widening
unproven carriers; loss of accepted wide recovery; hidden refusal/failure;
or moving semantic recovery into a later layer. Passing only helper tests
does not close Task 7.1.

Graph indexing and coverage requests returned `Transport closed`. Evidence is
bounded direct source inspection and executable probes, not a complete graph
audit. No production fix or new broad gate result is claimed here.

## Call Placement Repair

Implementation checkpoint observed at 05:34:48 +02:00 on September 20.
This section supersedes the investigation-only status above for the bounded
call-placement defect, not the full provenance or scheduling obligations.

Before the change, four new materializer cases failed: absent original call,
conditional call, wrong call address and wrong target. The exact-call control
passed. Merely stopping fresh call synthesis then exposed a second defect:
the nested-group path could move an existing call out of a conditional branch.

Types/Lowering now reuses the exact original call node and arguments, or keeps
the register-valued store. It no longer creates a zero-argument call from
physical AX/DX reads. A focused `straight_line_placement.py` owner checks
unique adjacency through transparent CStatements only; control-flow nodes,
intervening statements, reversed order, shared groups and cycles refuse.
The large segmented-global owner became smaller overall.

The first whole-binary attempt correctly failed validation for DrawTime and
ReInitBars. This was not accepted or waived. Probes established that Semantics
already proves their DX:AX outputs, but the C call node uses a near-address
CConstant while the evidence uses a linear address. The legacy name matcher
missed the original call; synthetic-call replacement had concealed this
projection mismatch. The consumer now reuses the existing authoritative
binary-target matcher, including its relocation and conflict checks. No new
Semantics solver, name-based exception or postprocess recovery was added.

Four legacy test expectations were corrected: they had required constructing
calls where no original call was present, or moving a nonadjacent carrier
without proof. Their replacements check retained values, original calls and
zero call materializations. New controls preserve original argument-node
identity and reject wrong near targets. The scoped gate also exposed two old
format assertions: saved pre-fix exports already used `(signed char)` and
an explicit unsigned-short index cast. Those assertions now require the
established forms; validation and compilation checks were not weakened.

Verification so far:
- New producer/consumer and placement tests: 14 cases, enrolled in routine
  pytest, Make and ownership manifests. Combined global-store suite: 194 pass.
- Scoped check-files: 223 pass in 48.21s, plus Ruff, MyPy, type/doc,
  startup architecture, agent-context and ownership checks.
- Separate MyPy/type-doc checks pass on the touched legacy production owner.
- New helper and regression Ruff checks pass. Whole legacy-owner Ruff retains
  69 findings; global quality-fast remains blocked by existing Ruff debt.
  Neither gate was suppressed or declared green.
- Final whole-binary gate: all 20 functions validate; zero timeouts, tracebacks
  or violations. Eighteen exports are byte-identical to the prior checkpoint;
  the other two only remove a redundant `sub_137e` prototype. Bodies and calls
  are unchanged. Coherent word-register views remain enabled.
- Explicit generated-C compilation: zero errors and warnings. All 19 compiled
  behavior cases pass. Routine test-pipeline finished with two passing lanes
  and one failing lane: 6,036 pytest passes and a SetGear recovery timeout.
  The isolated SetGear regression subsequently passed, as did a second run
  alongside SetDLC, without changing code or timeouts. These reruns do not
  replace full-pipeline acceptance; see the stability-first execution report.

Artifacts use `.cache/wide-store-` prefixes: `preservation-before.log`,
`check-files-final.log`, `quality-fast.log`, `final.json`,
`final-compilation.json`, `behavior.log` and `test-pipeline.log`.
The rejected whole-binary attempt remains in `sortd.json`; do not confuse it
with the accepted `final.json`. Diagnostic v4/v5/v6 failures remain historical
evidence, not current successful results.

Frozen production hashes:
- segmented_global_loads.py:
  `3069294f5cffb9455141a13e29cb6a5d96a99d9219c97f991802782b790de38c`
- straight_line_placement.py:
  `3a6b703b90946e1ca0bb95de3f583276bf802227bab3bb6eaa27d66bee256e72`

Observed milestones: rejected direct probe finished at 05:23:30; repaired
direct probe at 05:28:01; whole-file compilation/behavior verified by 05:34:48.
The implementation start was not separately timestamped; no precise total
active-work duration is claimed. Gate durations above come from their logs.

Remaining: replace instruction-adjacency candidates with authoritative typed
call-output/store provenance and explicit refusals, including the collector's
bypass case. This repair prevents the demonstrated call synthesis/movement;
it does not certify every candidate, all legacy DCE, all wide-value recovery,
or affected-candidate scheduling. Tasks 7.1-7.4 and Steps 10-12 remain active.
