# Binary behavior preservation: real16 and PE32 Z3 comparators

Status: complete for the declared comparator contracts, accepted 2026-10-06.
This is capability/implementation acceptance, not proof of all corpus functions.
This file is the current plan; dated progress history is archived separately.

## Scope and completion boundary

Improve and finish the 16-bit real-mode and 32-bit PE32-to-PE32 Z3 comparators.
Reduce unsupported/refused cases soundly with bounded CPU and memory. Preserve
ELF compatibility without expanding it. Use Devin for implementation and tests;
the parent reviews changes and evidence. At most four Devins, six aggregate test
workers and two heavy jobs; run Python/pytest with nice10 and PYTHON_JIT=1.

Fix a shared lifter/IR dependency only when it blocks an actual comparator
requirement. Unrelated decompiler/generated-C/recompilation failures do not
block this goal. Earlier SetGear/InitBars/Loadprog/SORTD decompiler investigations
were scope drift: their private patches and failure records remain preserved,
but those assignments are stopped. Historical broad gates are not relabeled
passed. Repository-wide release/PR checks remain separate obligations for those
checkpoints, not a requirement to repair the whole decompiler for this task.

The original M0–M7 semantic requirements and acceptance matrix below are retained.
Later proposed experiments and delivery estimates do not enlarge completion.
Unknowns, unsupported effects and conditional assumptions remain explicit; this
plan does not promise equivalence proofs for arbitrary binaries.

## Current acceptance ledger and next actions

| Milestone | Current evidence/status |
| --- | --- |
| M0–M4 | Previously accepted; preserve their controls and invalidate only evidence whose relevant dependencies changed. |
| M5 | Accepted2026-10-06 for bounded recursive-component, indirect-target and environment contracts; current identities, public bridge and comparator checkpoint reviewed. Recursive premises remain conditional. See attachment ACCEPTANCE.md. |
| M6 | Previously accepted bounded independent replay and initialized program controls; execution agreement is not symbolic proof. |
| M7.1 | Accepted: current30public bridges and dependency review; corrected both flat32 help/report descriptions and MSC8 README; both actual CLI helps and scoped lint pass. |
| M7.2 | Final corrected-profiler measurement reviewed:14 recorded runs,55 obligations per phase, exact cold/warm rows/contracts/dependencies,3046 stable source/input identities.300.392s total child elapsed,439408KiB peak child RSS. Named boundaries only; no controlled speedup claim.16 dependency controls and7-run cache-disabled evidence retained. See comparator-profile-final-validation/PARENT_REVIEW.md. |
| M7.3 | Accepted:1363admission +305shared contracts +228dosunit/MSC8 +26BC5 pass;5native KVM skips remain separate. Final reconciliation covers source deltas, public contracts, cache evidence and diagnostic typing/parent controls. |

Final requirement-by-requirement reconciliation:
`.cache/comparator-implementation/comparator-profile-final-validation/COMPLETION_AUDIT.md`.
All original M0–M7 comparator obligations are accepted within their published
contracts. The fixed manifest still contains49unknown and2conditional results
per phase; these are not promoted. Its other results are3proved and1counterexample.
The later diagnostic-only typing guard has an exact one-line diff, clean scoped
MyPy/Ruff,11focused tests and2independent parent controls. The measured source
hash is retained separately; no byte-identical post-edit measurement is claimed.
No unrelated decompiler failure or optional experiment remains on this goal's
completion path. Repository-wide release/PR acceptance remains separate.

Evidence under `.cache/comparator-implementation/` (not new pass claims):

- `m5-current-acceptance-attachment/{REPORT.md,attachment.json,PARENT_REVIEW.md}`
  maps recursive, indirect-target and environment obligations to exact controls.
  Its `ACCEPTANCE.md` records M5 acceptance and explicit scope limitations.
- `m7-recursive-admission-fix/PARENT_FINAL_REVIEW.md` binds the latest recursive
  repair; `m7-unicorn-memory-policy/PARENT_INTEGRATION_REVIEW.md` binds replay
  resource controls.
- `public-contract-refresh-20261006/PARENT_FINAL_REVIEW.md` records the public
  adapter/schema/CLI checkpoint.
- `m7-current-phase-run/PARENT_REVIEW.md` records seven lanes,55obligations per
  cold/warm phase, detailed verdict/dependency parity and named-owner timings.
  Counts remain3proved/2conditional/1counterexample/49unknown per phase;
  baseline288.216s and profile259.841s are not a speedup claim.
- `three-mode-parity/run-2026-10-06/PARENT_REVIEW.md` retains earlier cold/warm/
  cache-disabled evidence; its relevant source identities must still agree.
- `comparator-current-gates/` owns the current bounded test run and receipts.
- `comparator-public-bridge-final/PARENT_REVIEW.md` accepts the current30
  recursive/terminal controls. Only `pyproject.toml` changed during the run
  (default discovery adds `test_components.py`); explicit test selection and
  comparator sources were unchanged. This is qualified test evidence, not a
  claim that the whole-tree snapshots match.
- `comparator-final-corpus/profiled-run.log` records a rejected refresh:
  source drift stopped the runner, and the warm real16-changed lane also
  failed inside profiling. Preserve the failed receipt; resolve instrumentation
  and freeze sources before the necessary retry. Do not replace unknown rows,
  increase proof budgets, or count this partial run as acceptance.
- `comparator-final-corpus/PARENT_REVIEW.md` accepts the stable `profiled-r2`
  refresh:14runs,55obligations per phase, unchanged verdict counts, exact
  cold/warm rows/contracts/dependency bindings. Historical Sleep refusal detail
  changed to deadline exhaustion and remains explicit. Peak438868KiB and
  total388.569s child elapsed are not a speedup comparison.
- `comparator-help-review-fix/PARENT_REVIEW.md` records integrated public
  description corrections, independent AST review, scoped lint and both CLI
  help checks. Only descriptive text changed after the corpus snapshot.
- `comparator-disabled-final/PARENT_REVIEW.md` accepts optional-cache bypass
  on all7lanes with3041stable/live identities and the same55verdicts. Exact
  dependency edges remain equal; flat32 freshness keys changed for the reviewed
  descriptive-only patch. This is qualified cross-snapshot evidence, not
  byte-identical three-mode contracts.
- `comparator-profile-parent-review/ACCEPTANCE.md` accepts the diagnostic
  interruption repair after2deterministic parent regressions and43focused
  active-harness tests plus18subtests. Interrupted timing is explicitly partial;
  target exceptions and proof budgets stay unchanged. Final measurement and
  completion audit use `comparator-profile-final-validation/`; typing follow-up
  is in `comparator-profile-parent-review/type-finish/`.

Run serial groups with fixed existing budgets; do not repeat unchanged passing
checks merely to produce another report:

To reproduce the fixed-manifest cold/warm measurement, choose a fresh output
directory (the runner retains the seven executable command arrays and inputs):

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 CI=1 TMPDIR=.cache \
  .venv/bin/python .cache/comparator-implementation/m7-profiled-corpus/run.py \
  --execute --profile --watchdog-seconds 120 --out .cache/comparator-recheck
```

Comparator regression commands:

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 CI=1 PYRIGHT_WATCH=0 \
  make comparator-check-fast PYTHON=./.venv/bin/python \
  PYTEST_WORKERS=2 COMPARATOR_PYTEST_WORKERS=2
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 CI=1 PYRIGHT_WATCH=0 \
  ./.venv/bin/python -m pytest -q -n 2 \
  angr_platforms/tests/test_dosunit_tool.py
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 CI=1 PYRIGHT_WATCH=0 \
  ./.venv/bin/python -m pytest -q -n 2 \
  artifacts/msc8-z3cmp32/test_z3cmp32.py
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 CI=1 PYRIGHT_WATCH=0 \
  ./.venv/bin/python -m pytest -q -n 2 \
  artifacts/bc5-z3cmp32/test_z3cmp32.py
```

Run the adapter files separately: both are named `test_z3cmp32.py`, so pytest's
default import mode collides if both are collected in one process. This is a
test-invocation constraint, not a comparator proof failure.

The admission target's shared-contract prerequisite is a bounded dependency
check, not a mandate to run or fix the whole decompiler. Add exact changed-owner
and missing-original-obligation controls when these groups do not cover them.
Retain full logs, commands, exits/counts, source/binary identities, elapsed time,
RSS, budgets and refusal/assumption details. No all-green claim from partial runs.

## History and completion notification

[Full pre-correction history](binary-behavior-equivalence-history-20261006.md)
retains all previous receipts, failure records, proposed experiments and estimates.
Its obsolete gate lists and work queues are historical, not active instructions.
Use the [current checklist](binary-behavior-acceptance-checklist.md) for acceptance.

When every original comparator requirement is accepted, explicitly notify the
user with supported scope, evidence, remaining typed limitations and reproducible
usage commands. Do not postpone that notification for optional experiments.

## Objective and acceptance boundary

Compare an immutable original executable with each rebuilt executable after
modifications. Establish equal observable behavior for every admitted initial
state under an explicit machine, ABI, memory and environment contract. Keep
SSA/Z3 as the proof engine; decompose loops and calls into reusable obligations.

The primary comparison is binary-to-binary. Internal decompiler tail validation
remains required for decompiler changes but is not end-to-end binary acceptance.
Source, symbols, MAP/COD/listings and traces may propose correspondences or test
inputs; they do not establish semantics. New proof recovery uses decoded binary
IR and typed effects, never regex over assembly or emitted C.

Deliver two independently accepted tracks: segmented x86 real mode, including
in-scope 386 operand/address overrides; and flat i386 PE32-to-PE32 through the MSC8 and BC5 adapters. Existing ELF
compatibility is retained without expansion. Bit width is not an executable-format contract. Unsupported
extenders, loaders, instructions and environment effects remain explicit.

## Inspected starting points

These are source observations, not fresh corpus-test results. The worktree is
shared and already contains changes; preserve them and save the actual pre-edit
baseline before implementation.

| Surface | Existing mechanism | Work to establish or extend |
| --- | --- | --- |
| `tools/dosunit/straightline_ssa.py` | `_run_callee_proof_fixpoint`, matched-delta `_compare_region_transition_system`, bounded region comparison and connectivity gates | Audit complete-function proof promotion, internal-state coverage, call dependencies and normalization assumptions; extend beyond matching deltas. |
| 16-bit execution specification | Acyclic region comparison; symbolic paths exhausting loop bounds refuse | Preserve this rule; separate fully discharged finite bounds from incomplete exploration. |
| `artifacts/msc8-z3cmp32/flat32_cfg.py` | Closed matched-CFG block induction, with call boundaries refused | Reuse the induction strategy through architecture-specific state contracts. |
| MSC8/BC5 `z3cmp32.py` drivers | Auto loop retry limited to eight blocks and 250 ms per block | Make resource refusal explicit; budget increases are not new proof capabilities. |
| BC5 paired-call mode | Assumed equal post-call state yields conditional evidence | Replace assumptions with proved callee relations, without promoting old conditional results. |
| Existing dosunit execution plans | Original-side vector generation, concrete oracle and candidate replay | Reuse and verify available backends; add corresponding flat32 execution coverage. |

Related contracts: [execution specification](dosunit-execution-spec.md),
[reconstruction workflow](dos-c-reconstruction-toolchain.md),
[execution gap plan](dosunit-gap-closure-plan.md),
[original-side edge solver](dosunit-edge-solver-plan.md), and
[real-mode scope](real-mode-edge-policy.md). This plan extends those efforts;
it does not replace their execution-backend work or relax their gates.

## Shared proof contract and ownership

Introduce small typed owners under `tools/dosunit/` for proof obligations,
architecture state adapters, state relations, callee summaries, loop checking,
dependency scheduling and evidence reports. Exact filenames are decided after
the baseline audit. Avoid adding another large subsystem to `straightline_ssa.py`.
Extract only what a milestone needs, with parity checks before changing defaults.
Keep the MSC8 and BC5 drivers as adapters; consolidate duplicated proof logic
incrementally. Decompiler semantic recovery remains in X86_16, not these drivers.

Every proof artifact must include:

- Original/candidate image and loaded-image hashes, function ranges, mode,
  loader/lifter/model versions, ABI, input domain and memory relation.
- Entry relation, cutpoint relations, exit observations, call dependencies,
  normal/fault/nonreturning outcomes, and environment assumptions.
- Typed verdict, reason, proof method, obligation IDs and dependency identities.
  Existing JSON strings are serialization boundaries, not internal status logic.
- Required/attempted/discharged/failed/unknown obligations, plus
  `raw_fact_count`, `normalized_fact_count`, `classified_fact_count`,
  `materialized_count`, `failure_count`. Classified but unmaterialized semantic
  evidence fails the pipeline; it cannot vanish from the report.

Keep proof status and execution-test status independent. Suggested proof states:
`PROVED`, `CONDITIONAL`, `COUNTEREXAMPLE`, `UNKNOWN`, `UNSUPPORTED`, `UNMAPPED`.
Execution records distinguish agreement, mismatch, fault, timeout and unavailable
backend. Preserve typed reasons for resource limits and incomplete coverage.
Solver SAT is a modeled counterexample; record concrete replay separately.
An abstraction-induced SAT result is not automatically a real binary mismatch.

Only fully discharged obligations under the declared supported model can map
to `validation=passed`. Unproved relational assumptions stay conditional.
Missing, duplicate, contradictory or aborted evidence cannot produce success.
All requested functions remain in the denominator, including mapping failures;
candidate-only code and reachable unmapped dependencies are accounted for too.

### State and memory relations

Distinguish strict machine-state equivalence from explicitly declared ABI-level
equivalence. Do not silently drop registers, flags, writes or stack effects.
Internal cutpoints must retain every component needed by later execution;
an EAX-only return contract does not justify EAX-only loop or call boundaries.

Default to full modeled memory comparison. Different stack/global layouts need
a proved relation covering object identity, offsets, sizes, initialization,
pointer translation and alias preservation. Excluding private scratch storage
requires nonescape/nonobservation evidence and frame conditions. Address-like
integers and matching labels alone do not justify relocation normalization.

For real mode, preserve `Address(space, offset)` and segment registers. SS/DS/ES
remain distinct logical spaces, while the execution relation must also model
physical aliasing where their concrete segment values overlap. Do not assert
that distinct segment names imply disjoint memory. Linearize only at the
execution boundary with the declared wrap/A20 model.

## Milestones and dependencies

### M0 — Freeze baselines and audit proof promotion (both tracks)

1. Record binary/build hashes, current dirty-source snapshot, tool versions,
   command lines, actual scope and budgets. Never reset shared sources.
2. Inventory current verdict paths, call lemmas, loop/transition paths, quick
   equality shortcuts, output projections and relocation assumptions.
3. Trace whether a proved block or call-target match can become a whole-function
   pass without complete connectivity, live state or callee effects. Findings
   become focused red regressions; do not presume these paths are unsound.
4. Capture a fixed manifest of tiny positive/negative binaries and a bounded
   representative sample from available SORTDEMO/MSC16 and MSC8/BC5 inputs.
   Include loops, direct calls and current refusals. Freeze selection before
   measuring improvements; publish every manifest entry's result.

Exit: reproducible per-function baseline and a current capability matrix for
each track. No existing historical result counts as a fresh run.

### M1 — Typed obligations, complete accounting and adapter contracts

Implement the shared contract above and a compatibility layer for current
reports/CLIs. Explicitly identify architecture, widths, calling convention,
return kind, observable domain and environment model. Cache proof dependencies
by binary content and all semantic contract versions, not function name.

Exit: tests reject missing evidence, stale summaries, narrower reused contracts,
unmapped successors and conditional-to-proved promotion. Current accepted
fixtures retain their results unless M0 establishes a concrete soundness defect.

### M2 — Direct-call composition

Prove complete leaf functions first; schedule callers in dependency order.
Represent a callee by a relation over pre/post registers, memory, observable
events and outcomes, with an explicit footprint/frame contract. A paired call
must satisfy its precondition on both sides and reestablish the continuation
relation. The caller must be valid for all outcomes admitted by the summary.
Cache successful obligations and invalidate callers when dependencies change.

| 16-bit implementation | 32-bit implementation |
| --- | --- |
| Audit and reuse existing proof-cache/fixpoint mechanisms. Verify that evidence covers the whole callee, not merely its entry block. | Supply the missing flat32 callee relation and integrate it into region and CFG paths. |
| Prove near/far CALL/RET/RETF, saved CS:IP, SS:SP effects, immediate cleanup, segment preservation, register/stack arguments, and value versus near/far pointer inputs. Include operand-size variants within the supported model. | Prove full EIP/ESP/return-address effects, stack/register arguments, caller/callee cleanup, preserved registers and memory. Support only declared, checked ABIs. |
| Preserve alias effects when stack arguments or pointers overlap other memory. | Replace BC5 paired-call assumptions only when every required summary is proved. Keep assumption mode explicitly conditional. |

Initial scope: direct, nonrecursive calls. Small-callee inlining may be a bounded
fallback, but incomplete inlining never produces a pass. Treat external calls
through explicit environment contracts with provenance and visible assumptions.

Exit: leaf -> caller -> caller chains prove in both modes; changed argument,
callee store, return value, cleanup or return target is rejected. Corrupting a
callee invalidates its callers. Names alone and unresolved calls never pass.

### M3 — Closed matched-loop induction

Extend the existing transition/CFG paths rather than blanket-unrolling loops.
Check entry establishment, preservation across every reachable edge, branch
agreement, all exits and complete machine-state/memory relations. Include calls
inside loops only through M2 summaries.

For 16-bit code, verify segment state, modular arithmetic, high register halves
when live, flags, stack state and near/far control at cutpoints. For flat32,
retain full-width control, partial-register semantics and lazy-flag effects.
Unknown flag semantics must remain explicit; do not treat abstraction-induced
counterexamples as concrete failures.

Exit: zero/one/many iterations, nested loops, early exits and call-in-loop cases
prove for admitted matching graphs. Mutations of guards, strides, stores, flags,
segments and successors fail. A million-iteration loop needs no million-step
unroll. Synchronized induction must preserve infinite behavior as well as exits;
an execution timeout is not proof of divergence.

### M4 — Relational loops and differing CFGs

Build a paired transition system with cutpoints derived from binary CFGs.
Propose relations for register renaming, stack-slot correspondence, affine
recurrences and equivalent conditions using typed IR/alias evidence. Proposals
are candidates only: Z3 must prove initiation, preservation and exit behavior.
Use exact bitvector widths; mathematical integer invariants need overflow proof.

Start with renamed registers and split/merged blocks, then loop rotation and
different induction variables. Permit unequal numbers of internal steps only
with a progress obligation preventing one side from stuttering forever. Prove
relative termination/divergence, not merely equal outputs when both return.
Irreducible CFGs and unsupported relations refuse with their missing obligation.

Exit: equivalent different-shape loops pass in each architecture; nontermination,
off-by-one, signedness, wraparound and hidden-memory mutations are rejected.
Invariant synthesis exhaustion is unknown, never equality.

### M5 — Recursive and indirect calls; environment effects

After direct calls and induction stabilize, group recursive dependencies into
strongly connected components. Check joint relational summaries and relative
termination/progress; never bootstrap a cycle by marking its callees proved.
Indirect calls require a proved target relation with complete admitted target
coverage. Unknown targets retain a refusal, even if runtime traces saw one.

Model external effects as related event traces and state transitions. Extend
DOS/BIOS interrupts and device I/O for 16-bit; imports/services and supported
exception behavior for flat32. Match faults and nonreturning exits. Unsupported
floating point or asynchronous effects remain visible scope limitations.

Exit: recursive base/progress mutations, changed callback targets and changed
external effects are rejected. Environment assumptions propagate to callers.

### M6 — Concrete differential execution (begin after M1; grow throughout)

Use existing dosunit oracle/replay infrastructure for real mode; verify actual
backend availability and snapshot isolation. For flat32, select and validate a
backend supporting the real loaded image and service model. A fixture backend
only tests the harness. No host/backend installation is implied by this plan.

Reset related initial states per vector. Generate boundary, alias, branch and
loop inputs; add deterministic fuzzing and runtime-derived realizable states.
Replay realizable solver counterexamples, collecting return/control outcomes,
registers, memory writes and external observations. Diagnose inadmissible
counterexamples explicitly rather than changing the domain to hide mismatches.

Exit: original/original passes, intentionally corrupted candidates fail, replay
is deterministic, and unavailable execution remains visible. Coverage includes
tested edges, loop cases, call targets and declared memory observations; it is
not an all-input proof. Whole-program scenarios compare initialized data,
startup, files/output and applicable DOS/device behavior in addition to functions.

### M7 — Integration, performance and release gates

Expose shared proof/evidence semantics through `z3func.py`/dosunit and both
flat32 drivers. Update schemas, CLI help, execution specification, reconstruction
workflow and tests together. Preserve independent symbolic and execution status.

Measure cold/warm load, lift, normalization and solver time, peak RSS, proof
counts and refusal reasons on the fixed manifest. Optimize measured costs with
summary reuse, dependency-aware invalidation, expression sharing and incremental
solver contexts where useful. Cache hits must reproduce cold verdicts and
dependencies. Use explicit per-obligation and total budgets and bounded workers;
do not run overlapping broad gates or add unbounded inlining/unrolling.

Exit: no baseline capability loss without a documented corrected false proof;
each new capability proves its positive controls and rejects its negative ones.
Budget exhaustion remains visible. There is no promise to decide equivalence
for arbitrary binaries; publish supported scope and remaining obligations.

## Acceptance matrix

Each relevant row requires original/original, equivalent changed-code, deliberate
corruption and unsupported/incomplete controls. Use real compiled/assembled bytes
and real SSA/Z3, not only mocked results.

| Behavior | Real-mode cases | Flat32 cases |
| --- | --- | --- |
| Calls | Near/far, segment preservation, cleanup, pointer aliasing | Full-width return, stack/register ABI, preserved registers |
| Loops | Wraparound, live flags/segments, nested loops, REP semantics when supported | Partial writes, lazy flags, nested loops, different register allocation |
| Memory | DS/SS/ES distinction plus physical aliasing, far pointers | Relocated globals, overlapping pointers, changed stack layout |
| Control | Missing edges, indirect near/far targets, division faults | Missing edges, full-width indirect targets, division faults |
| Dependencies | Changed callee invalidates transitive callers | Same, including conditional paired-call downgrade prevention |
| Outcomes | Equal return, matching faults/nonreturning paths, termination differences | Same, under explicit service/exception model |
| Evidence | Missing/unmapped parts, timeout, stale cache, nonvacuous input domain | Same, plus duplicated driver/report obligations |

For each semantic milestone, require focused positive, corruption and incomplete
controls, scoped lint/types, the comparator admission gate, both PE32 adapter
suites and affected shared-owner regressions. Broader repository release/PR
checks remain separate. An unrelated generated-C or recompilation failure is
not a comparator acceptance blocker. Static SSA/Z3 tests need no KVM; concrete
native execution controls retain explicit backend requirements and markers.

Milestone dependency order: M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M7, with M6 starting
after M1 and expanding at every milestone. Ship each milestone for both modes
with separate acceptance evidence; success in one mode does not close the other.
Within these dependencies, use the optional coverage/resource experiments
in the archived history when useful; their order does not postpone mandatory correctness or model closure.
The first implementation slice is M0 plus M1, followed by one proved direct-call
chain in each architecture. No agents or external workers are launched by this plan.
