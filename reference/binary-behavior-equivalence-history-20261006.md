# Binary behavior preservation: 16-bit and 32-bit comparator plan

Status: implementation in progress, 2026-10-06. Milestone acceptance remains
subject to the evidence recorded below; focused tests are not whole-binary acceptance.

### User scope correction — 2026-10-06 (supersedes gate blockers below)

The goal is improving the real16 and PE32 Z3 comparators. The user explicitly
clarified that unrelated decompiler gates are not acceptance criteria for this
goal. Previous attempts to close SetGear, InitBars, Loadprog and SORTD generated-C
regressions expanded the task incorrectly. Those investigations are stopped;
private patches and failure evidence are preserved, not integrated or erased.
Their failures do not by themselves keep comparator milestones M5/M7 open.

Remaining acceptance must follow comparator dependencies: shared SSA/Z3 and
binary-proof tests, both PE32 adapters, public comparator/schema contracts,
fixed-manifest verdict/assumption/dependency parity, resource measurements and
lint/types for changed owners. Start with `make comparator-check-fast`, the
dosunit and both adapter suites, then only missing original comparator controls.
For shared lifter/IR changes, include directly affected regression tests; repair
demonstrated regressions caused by comparator work. Do not require unrelated
generated-C recovery or DOS recompilation to pass. Static Z3 comparison does not
require KVM; explicitly native execution controls remain separate and marked.

Historical broad-gate failures stay recorded as failures, not retroactive passes.
Repository-wide release/PR gates remain repository checks, not a mandate to fix
the whole decompiler before accepting this comparator task. M5/M7 completion is
still unproven until their actual comparator requirements and current evidence
are reconciled; this correction does not silently mark either complete.

### Current acceptance status — 2026-10-06 (review and integration follow-up)

M0–M4/M6 remain accepted; M5/M7 and final full gates remain open.
Current InitBars original-node rerun fails in70.44s; its retained probe pins
the first missing preservation proof to0x10566→0x11222, with six call-budget
refusals and ten pending jumps (`m7-initbars-current-repair/`). This supersedes
the older CS_WRITE_INTERFERENCE diagnosis for this invocation. SetGear's
explicit-CS extension remains private:15small controls pass, but real pending
caller authentication and accessor-corruption review are still open. Current
read-only release-linter equivalent passes Ruff/MyPy/mypyc39/Basta/Lizard and
fails Vulture on the quoted-only DataclassInstance import in generation atoms;
the minimal annotation repair is now reviewed and integrated:8focused tests,
scoped lint/MyPy and full Vulture pass, with the final file hash verified
(`m7-generation-vulture-fix/PARENT_REVIEW.md`). Source snapshot4879paths stayed
unchanged during that linter run; literal linters-hard and final gates remain
pending. Receipts:`m7-release-linters-current/REPORT.md` and
`m7-setgear-domain-refusal/PARENT_V4_INTERIM_REVIEW.md`.
KVM access was restored using the verified inherited-descriptor transport:
char10:232/API12, host read-only/repository writable, unchanged4GiB sandbox.
The original serial native recheck completed1passed/1failed in44.83s:
InBoxLng passed validation and compiled behavior; SetGear failed semantic
validation before recompilation, not device access. Its declared synthetic
callee was routed through real-body binding. The staged target-dispatch
repair was rejected: independent probe shows an undeclared placeholder RET
closure claiming all6segment registers preserved. Target classification
cannot authorize effects; correction is private and original refusal remains.
Receipt: `m7-setgear-domain-refusal/PARENT_V2_REJECTION.md` plus the probe in
`m7-stub-effect-audit/`. Native receipts: `m7-kvm-descriptor-review/` and
`m7-small-timeout-recheck/native/` under `.cache/comparator-implementation/`.

The recursive repair now preserves raw machine-state identity and re-proves
dispatch destinations at consumption. The initial49-test-green projection
was rejected for trusting claimed metadata; its coherent forged-target
mutation now refuses. Final52tests passed56.74s, scoped checks clean and8file
hashes parent-verified. This accepts bounded dispatch repair, not unrestricted
term equality or executable authenticity from metadata. Independent image
binding remains required; joint proof remains conditional. Receipt:
`m7-recursive-admission-fix/PARENT_FINAL_REVIEW.md`. Current-source named-phase
measurement is accepted:28/28baseline/profile child runs completed on identical
3043-path source snapshots,16dependency controls passed in each invocation,
and every detailed verdict/assumption/contract/dependency row agrees. All four
named phase categories observed; budgets unchanged. Per phase counts remain
3proved/2conditional/1counterexample/49unknown. Child totals288.216s baseline
and259.841s profiled, peak404940/439040KiB; no speedup claim. Named-owner
measurement is not exhaustive attribution; cache-disabled was not rerun.
Receipt:`m7-current-phase-run/PARENT_REVIEW.md`. SetGear stays private.

The reviewed Unicorn16MiB translation-arena policy is integrated and accepted
as a bounded resource change:64shared-tree tests passed14.49s and7seeded
replay controls passed40.81s, scoped lint/types/enrollment clean, all10final
file hashes parent-verified. Child-enforced address-space pressure retains
correct16/32-bit observables.
This demonstrates reduced virtual reservation, not historical crash
attribution or measured end-to-end speedup. Final gates remain owed.
Receipt: `m7-unicorn-memory-policy/PARENT_INTEGRATION_REVIEW.md`.
Execution caps remain4Devins,6aggregate test workers and2heavy jobs;
workers own scoped tests/lint, parent owns review and acceptance.

M5 evidence consolidation is parent-reviewed at
`m5-current-acceptance-attachment/PARENT_REVIEW.md`: original requirements
map to existing receipts and the accepted recursive/resource deltas. The
unverified historical84-test DOS-version count is retired; current50tests
pass8.46s with6live hashes verified. M5 remains open pending required
checkpoint gates; focused test counts are not unconditional proof counts.

### Earlier checkpoint — 2026-10-06 (interrupted default gate + fixture repairs)

The required default `test-pipeline` ran once on the frozen tree and was
intentionally interrupted (parent-confirmed terminal exit130, already a
failing diagnostic checkpoint): contracts305passed, binary-budgeted3passed,
unit-focused11270passed/26failed, pytest-serial/linux-process-controls/
makefile-gnu-oracle/gp-word-native passed (gp-word ran against verified KVM
at run time); binary-relational partial with live failures and two xdist
worker crashes; ultra-quickc-fixtures and msc6-tiny-full-pipeline never
executed; no summary.json produced. The live-enumerated source seal binds
3195paths unchanged before/after the run, captured before the four fixture
edits below. Receipts:`m7-pipeline-current/REPORT.md`, `pipeline.log`,
`source-delta.json` under `.cache/comparator-implementation/`.

Dispositions since: the10ASan tidshowrange nodes re-verified10passed6.80s
with adequate address space (`m7-asan-recheck/pytest.log`) — environment
constraint, not a gate. The two relational Unicorn crash nodes re-ran serial
2passed; the historical crash cause is unverified and a bounded16MiB
resource-policy experiment is underway. The four reviewed test-fixture
repairs are integrated and accepted (156passed/lint0;
`m7-gate-fixture-repair/PARENT_INTEGRATION_REVIEW.md`). The recursive
fixture-only patch was rejected for ownership; production repair plus
fixture-forwarding is staged.13residual unit failures remain under read-only
triage (`m7-gate-triage-next/REPORT.md`) — the LoadProgram wrapper green does
not prove callee loadprog green and the historical wrapper receipt stands.
Native recheck is currently blocked: the shell lists char10:232 but sandboxed
Python cannot see /dev/kvm and a new `--with-kvm` launch failed
(`.cache/devin-prompts/m7-small-timeout-kvm-launch-failed.log`); the earlier
gate gp-word KVM pass remains real historical evidence and the native gate is
not waived. M0–M4/M6 accepted; M5/M7 and the final full gates stay open.

### Current acceptance status — 2026-10-06 (supersedes top-checkpoint wording)

Latest reviewed public checkpoint:253passed (180public/30bridges/17MSC8/
26BC5), all5CLIhelps exit0. Fresh live inventory binds3195source paths before
and after with no additions/removals/changes; parent verified current hashes.
The private driver now re-enumerates after execution and compares both
memberships. Receipt:public-contract-refresh-20261006/PARENT_FINAL_REVIEW.md.
Required default test-pipeline is delegated on frozen sources,4pytest workers;
two other Devins own private invocation-admission and phase-measurement work,
one test worker each. No final pipeline/M5/M7 acceptance yet.

The exact0x123a6->0x1247b diagnosis is resolved: encoded target and callee
closure agree. Symbolic CALL binding refuses selector_window_unproved;
TARGET_MISMATCH is the downstream classification. Inventory hits its boundary
budget at0x1239e and leaves the global source uninstalled. The new bounded
probe finds a scoped source, but no complete caller premise; its retained
event prefix includes declared_service_unproven boot-path refusals. This is
not evidence that raising the inventory cap will repair the premise. Next
repair must establish authenticated invocation evidence, not relax equality
or guess CS.
Receipt:sortd-call-target-mismatch/PARENT_CHECKPOINT.md. The new worker stages
only a bounded admission repair; repeated whole-closure diagnosis is excluded.

Current execution checkpoint: KVM access is restored and independently verified
through `scripts/workspace_sandbox.py --with-kvm` (character10:232/API12).
The earlier missing-device skip remains historical, not native acceptance.
The one-bit EQ/NE effect repair is integrated:5red controls become green,
153focused tests pass after the final type repair, and the earlier292test
owner cohort is green. The real root0x11728 region admits its pending transfer;
this is not whole-function SWAPS acceptance. Source writing is now frozen.
Three Devin jobs own disjoint read-only validation: the unchanged public
LoadProgram native regression, the original seven corpus lanes across
cold/warm/cache-disabled modes, and SWAPS after the native execution slot frees.
The unchanged public LoadProgram COD regression now passes1test36.72s,
including its declared assumption, call/output behavior and recompilation
assertions. Its retained generated C and8vector oracle were parent-reviewed.
The corrected private parity harness passes21controls; its final-source
dependency gate passes16controls33.23s. All21corpus attempts now complete with
all7lanes matching verdict/assumption/contract/dependency parity across the
three modes, observed reuse controls satisfied and unchanged source/input
snapshots. Each phase retains55obligations:3proved/2conditional/1counterexample/
49unknown. Child elapsed totals are176.34s cold/163.10s warm/177.08s disabled;
maximum child peak RSS404392KiB. This accepts three-mode correctness parity
for this snapshot, not full phase profiling, a speedup or proof conversion.
Whole SWAPS still fails caller SSA intake (1failed114.32s); InitBars still
reports call-preservation budget refusals. No milestone closes from these
focused checks. The final one-shot scoped Pyright
retry exits0 with0errors, superseding the terminated watcher.
Current next work: refresh the established public/schema/CLI selections on
this frozen tree, and privately isolate the observed0x123a6->0x1247b target
mismatch in the shared SORTD dependency region. InitBars capture is terminal,
with10pending selector refusals and6call-preservation budget refusals; no
budget increase or broad closure profiling is the next repair.
Worker limits: at most4Devin,6aggregate pytest workers and2heavy proof/native
tasks; Python runs at nice10 with JIT/hash-seed configured. Receipts:
`repne-scas-effects/PARENT_REVIEW.md`,
`repne-scas-effects/PARENT_INTEGRATION_REVIEW.md`,
`loadprogram-native-recheck/PARENT_REVIEW.md`,
`three-mode-parity/run-2026-10-06/PARENT_REVIEW.md`,
`three-mode-parity/PARENT_REVIEW_R2.md` under `.cache/comparator-implementation/`.

Bounded implementation repairs are accepted; none is full function or proof
acceptance. M0–M4/M6 accepted, M5/M7 open; scope unchanged. The corrected
generation atoms (unsafe per-type field/name caches removed; builtin
dispatch now uses identity) pass their green cohort: 88 controls in 11.38s,
private baseline parity 0 defects — a bounded correctness repair, not an
end-to-end speedup claim. The SWAPS epoch-lifecycle fix is accepted as a
bounded component repair; original SWAPS still refuses. The LoadProgram
native test now carries the `requires_kvm` marker: 6 passed / 1 skipped in
17.11s on missing `/dev/kvm` — the skip is not a pass and native evidence
is still owed. The current SWAPS capture maps caller 0x108D0 / callsite
0x10929 to five `terminal_jump_selector_window_unproved` IRRefusals; one
recovered loader window alone is not selector authority, so call-premise /
call-preservation repair is next. The architecture gate reached
ARCH_EXIT=0 at a scoped checkpoint (prior run: 9 diagnostics); final
integrated gates remain owed. Original D4/experiment 5 requires cold, warm
AND cache-disabled verdicts plus dependency parity — no narrowing.

Next: call-premise repair, native acceptance with accessible KVM,
stable-source public/corpus parity and final gates. Receipts:
[generation-correction-integrate](../.cache/comparator-implementation/generation-correction-integrate/PARENT_REVIEW.md),
[swaps-epoch-integrate-reviewed](../.cache/comparator-implementation/swaps-epoch-integrate-reviewed/PARENT_REVIEW.md),
[loadprogram-kvm-mark](../.cache/comparator-implementation/loadprogram-kvm-mark/PARENT_REVIEW.md),
[swaps-ir-refusal-capture](../.cache/comparator-implementation/swaps-ir-refusal-capture/PARENT_REVIEW.md),
[m7-architecture-integrate-safe](../.cache/comparator-implementation/m7-architecture-integrate-safe/PARENT_REVIEW.md),
[acceptance-docs-review-finish parity](../.cache/comparator-implementation/acceptance-docs-review-finish/PARENT_PARITY_REVIEW.md).

### Latest integration checkpoint — 2026-10-06

SWAPS now has bounded demand counters, rather than only sampled stack depth:
225 inventory-refused installs/24.09s inclusive in 100s of diagnostic
process time; 42 IR imports/30 completed, only 2 repeated full recorded
identity/context snapshots. These snapshots omit mutable proof inputs and
are not sound cache keys. Diagnostic timed out externally (124); required
SWAPS regression remains open. Evidence:
swaps-request-counts/{summary.json,events.jsonl,run.log}. Original
LoadProgram regression also remains red (timeout, 1 failed 64.51s), while
the declared-call invocation completes under the internal
`native_compare.py` runner, not the public `decompile.py` entrypoint. Devin
checks unchanged generated C against an explicit binary-ABI behavior
harness (superseded — integrated and green on all 8 vectors; see status
above); source-shape assumptions in the existing test do not establish
behavioral acceptance.

Latest parent native pair completed under the internal `native_compare.py`
runner on unchanged production sources, not the public `decompile.py`
entrypoint: LoadProgram exit 0, validation=passed, declared assumption
consumed, 20.30s total wall and 273248KiB RSS under unchanged 20s analysis
budget. Private Python dispatch also completed but took
33.56s/273288KiB; generated C is identical. No end-to-end speedup
demonstrated, so no optimization promoted. Separate fresh caches,
sequential ordinary fork runs, nice 10, JIT/hash-seed configured. Four
relevant owner hashes unchanged; host load varied. Evidence:
perf-retained-native-review/. This supersedes the preceding timeout as the
latest invocation result, not as final M5/M7 acceptance or unconditional
callee proof. Review output/call shape and applicable round trip before
marking the function fixed. Broad gates still predate recent integration
changes. Both delegated tasks are terminal: audit 0, measurement 143 during
setup; parent performed the actual measurements.

Receipt stage-order repair is integrated: function-summary publication used to
replace the segment-state summary and lose already-consumed declarations. The
publisher now reauthenticates and republishes consumed receipts for the same
function, preserving absent-consumption and revocation refusal. Focused native
consumer/projection controls: 67 passed 21.07s; scoped lint/MyPy and
frozen-source startup architecture pass. Evidence: receipt-stage-order/.
The ordinary fresh-cache LoadProgram run still times out at 20s
(wall 39.30s, RSS 272144KiB); timeout does not
establish a remaining receipt defect. No native acceptance follows.

Private retained-IR experiments show Python dispatch 153ms→91ms and Cython
351ms→214ms median traversal time under separate timing conditions. Neither
demonstrates end-to-end improvement; neither is promoted. Two bounded Devin
tasks now check the native dispatch candidate and independently reconcile the
completion critical path from saved evidence, respectively. (Superseded: both
are terminal; delegated check ownership as of this snapshot is described in
the status above.) They own separate
private directories; no broad gates or proof-budget increases are authorized.

Devin admission audit34445 is terminal0 and parent-reviewed. Parent reproduced
four schema defects (bool/float at document and receipt boundaries), required
exact integer schema versions, removed expected-failure markers, and split the
reviewed tests into three enrolled modules plus shared fixture. Combined final
admission/consumption/projection/transport cohort139passed18.76s; lint, ownership
and admission-owner MyPy pass. Logs:declaration-admission-parent/. No source
assumptions or proof budgets broadened.

Fresh bounded production diagnostics isolate repeated generation fingerprinting:
30segment-state roots consumed6.78s inclusive; image hashing under1ms. A deeper
instrumented run identifies retained source IR as the dominant nested field
(4completed source-artifact traversals2.74s versus~0.24s for state maps).
Instrumentation changes timing; these are hotspot evidence, not paired gains.
The native20s LoadProgram attempt remains timeout. Exact mutation/provenance
detection must survive any reuse; rejected cyclic memo proposals stay private.
Evidence:m7-declaration-integration/{field-profile-summary,segment-field-summary}.json.
No worker or test process from this checkpoint remains running. M5/M7 stay open.

Declaration transport is now promoted to production (16 additional implementation
files), preserving the previously integrated CALL_OUTPUT repair. Three native
consumer/transport/projection modules and their fixture are enrolled in Make,
the curated pipeline and ownership manifest. Parent retained exact pre-promotion
sources and hashes under m7-declaration-integration/promotion-baseline/.
Combined production check:125passed/4failed24.17s; all four were ordinary cache
tests run without the required PYTHONHASHSEED=0. Deterministic cache-module rerun:
7passed9.18s. Lint-iteration, startup architecture and ownership pass. Package
MyPy has six diagnostics in the existing projection owner, reproduced exactly
against the saved pre-promotion sources (line offsets differ); no clean typing
claim. Production LoadProgram still exits3/timeout under its unchanged20s budget.
Missing receipts in that timed-out result do not establish a consumption defect.
Comparator gate completed:305prechecks13.81s +1267admission tests233.31s, exit0.
This source set predates the follow-up CLI status guard: a new real-method
regression reproduced four cases where absent receipts overwrote a timeout,
error, unknown or prior validation failure. Receipt authentication now gates
only success; unsuccessful attempts retain their original cause. Five controls
are added to the enrolled transport module. The expanded cache check exposed
an incomplete test CliArguments fixture, now explicitly supplying the optional
declaration tuple. Final focused check:59passed31.77s; scoped lint passes.
That checkpoint's Devin admission-control audit is now reviewed above.
Native behavior, corpus/performance/release evidence and
M5/M7 remain open.

Promoted the reviewed native CALL replay-context repair from the declaration
overlay. Exact native terminal/temporary provenance now checks the active lift
first and retries once with architectural flag emission when an optimized
task-local session is active. The session is restored on every exit; forged
coordinates remain refused. Production baseline: 1 failed / 3 passed in11.25s.
Final CALL-binding/segment-output cohort49passed9.08s; existing flag-context
cohort21passed12.75s. The CALL regression module is already enrolled in Make,
the curated pipeline and ownership manifest. Lint-iteration and startup
architecture pass. Scoped context/codec MyPy passes; explicit binder checking
reports three Any-return diagnostics in unchanged portions (578,1000,1006),
so no clean whole-owner typing claim. Evidence: m7-declaration-integration/
replay-*.log. Declaration-overlay promotion, whole-function acceptance and
M5/M7 remain open. Current host KVM API12 and VM creation both verified.

## Current work (2026-10-05)

M0–M4/M6 remain accepted; original M5/M7 remain open. Dated entries below are
historical evidence, not a list of live processes or current blockers.

Latest parent checkpoint (2026-10-06): the private declaration overlay now
authenticates enriched CALL IR through the retained semantic projection rather
than requiring it to be the raw registry object. Shared block-overlay checks
were moved from Lowering to a Semantics owner used by both consumers; raw CALL
bytes, whole-image identity and declaration authority remain mandatory. Native
red regression reproduced the original refusal. Projection/CALL-binding cohort
55passed53.26s; actual CALL-byte and Devin transport cohort50passed25.52s;
full-IR minimal/application corruption cohort18passed26.06s (overlapping cohorts,
not additive). A separate actual LoadProgram summary-construction, semantic
publication and segment-state application control passes in15.84s total/1.50s
body and publishes the consumption receipt. Ruff, type/doc/access ratchet and
scoped MyPy on the four touched owners pass. All changes remain private until integration
gates, test enrollment and full native acceptance close.

Devin99345 is terminal0: three durable test files replace AST-extracted transport
checks with actual imports. Parent reviewed and independently ran its32controls
in the50-test cohort. Its claim that pytest discovery alone supplies enrollment
is insufficient: promotion still needs the curated native lane and ownership
manifest entries. No additional Devin process was started.

The whole CLI still times out at20s. A diagnostic observed projection resolution
complete but later consumption refused; other attempts reached no consumption
hook before timeout. Do not equate either with the component's green result.
Verified thread samples also reach repeated postprocess validation and indexed
logical-memory receipt checking. Next: capture the failed consumption's exact
projected block/native binding, compare it to the green component fixture, then
close full-function behavior without raising budgets. Avoid more blind CLI
retries or atom-cache experiments. Evidence: `m7-declaration-integration/`
(`projection-*.log`, `test_projected_consumption.py`) and `m7-declaration-tests/`
under `.cache/comparator-implementation/`. M5/M7 remain open.

### Critical path and delay audit (2026-10-05)

Live SWAPS sampling now identifies deep caller/callee proof construction as
the immediate CPU bottleneck (299 samples; 10–12 nested IR imports).
See [measured delay audit](comparator-delay-audit.md) for evidence and ordered
reuse experiments. This is a sampled phase, not a whole-suite profile or a
measured optimization; preserve source freeze until the collector terminates.

Current next actions, in order:
1. Resolve the real SWAPS collector's retained IR_BUILD_REFUSED: its fresh
   post-REP/refinement regression is terminal1 (334.11s,317.17s body). The
   earlier native CALL CX is proven unreachable, but whole-caller intake still
   refuses. Private Devin intake review stopped at15minutes without a patch or
   counter experiment (`intake-reuse/PARENT_CHECKPOINT.md`); do not repeat that
   broad investigation. No production optimization or conversion claimed.
2. Finish private declaration integration, then original LoadProgram behavior
   acceptance. The combined14-module overlay imports and admits the declaration,
   but its native20s CLI times out. Worker stack samples localize that timeout
   to recursive tail-validation generation atom building. The second private
   Devin experiment (`atom-cycle-reuse/`) is stopped after parent review: its
   native counters observe no cycles in their recorded prefix, and neither the
   SCC proposal nor a simpler full-context memo closes native20s acceptance.
   Parent also repaired same-builder cyclic mutation staleness in its private
   SCC copy;1000random graphs match, but that is not native performance proof.
   Both atom proposals remain unintegrated. Keep the
   timeout unchanged. Target binding itself is integrated; the declaration
   patch remains private until consumer/transport/native acceptance closes.
   Parent native apply regression exposed and repaired a missing function_addr
   access plus stale receipts after revocation; combined32controls pass14.18s.
   Optional cache-input defaults and explicit new receipt/CLI test contracts
   preserve ordinary reuse (13cache controls pass23.02s);14staged owners Ruff
   clean. Full types/architecture/enrollment and native acceptance remain open.
   Final bounded stack probe (terminal3) records36fingerprint calls totaling
   15.54s across attempts versus35collection calls/1.25s. These inclusive stage
   timings overlap other rows and are not an end-to-end speedup. Next: use
   existing internal boundary spans to separate AST fingerprint, descriptor and
   generation costs before selecting another optimization. OTel probe is now
   terminal4 (diagnostic in-process/thread mode, not acceptance):45AST-root
   fingerprint spans total196.64ms;44descriptor spans3.30ms. No native atom
   speedup demonstrated. More importantly it exposes a real final semantic
   refusal: bp+0xa and bp+0xc require pointer parameters but emit value classes,
   alongside missing/stale declared-call consumption receipt. Next blocking
   action: inspect native declaration consumption/publication on the real
   LoadProgram IR and preserve its provenance through the actual pipeline;
   do not optimize the synthetic cycle example or raise the timeout. Evidence:
   `m7-declaration-integration/loadprogram-{otel.log,spans.jsonl,span-summary.json}`.
3. Resolve the retained SWAPS/InitBars/SORTD acceptance failures, then refresh
   final M5/M7 corpus, cold/warm performance and release gates.

Declared-target prerequisite integrated: shared native E8 binding now exposes
an explicit registered-synthetic-target API while retaining the ordinary
real-body exclusion. It proves target identity only, not declared effects.
Nine permanent controls are enrolled in the native routine lane. Parent
reviewed both exact source deltas against saved baselines; final production
cohort58passed18.03s, scoped lint, startup architecture and ownership pass.
Shadow-file MyPy has one identical before/after diagnostic, not a clean scoped
typing claim. The consumer still needs registry/artifact/current whole-image
authentication. Sandboxed Devin88383 produced the two-file private repair with
rootRO/repoRW/4GiB verified; it was stopped at the15minute checkpoint (terminal1).
Parent reproduced a missing-origin far-call admission defect and removed that
unsupported shortcut; repaired private near-consumer cohort10passed16.07s.
Far declarations stay refused without a shared native/provenance theorem.
CLI/cache exact-receipt replay and assumption-only reporting remain in review.
Evidence: `.cache/comparator-implementation/m7-declared-target-binding/`.

REP transfer integrated after native/source review: both feasibility and the
census consume the same complete bounded STOS footprint; partial DF is carried
through must joins and invalidated at unproved calls. Existing work/deadline
caps remain unchanged. Native second-iteration code overwrite now refuses;
forward/reverse/zero-count/unknown-value/source-mutation controls are permanent.
Parent added a real STOSW witness. Final production cohort46passed37.11s;
scoped lint, startup architecture, ownership and full mypy-dev pass. Narrow
four-file MyPy reports context-dependent diagnostics and is not called clean.
Final comparator gate passes305prechecks11.06s +1211tests204.16s (terminal0).
Native SORTD still refuses CALL_BOUNDARY_UNPROVEN at0x212f after the repaired
transfer; its three earlier pruned edges are unchanged. This is not native
function acceptance. Observational followup is checking feasibility inputs
at REP and declared-service crossings before further edits. Receipts:
`.cache/comparator-implementation/m5-rep-transfer/`.

Native followup proved the remaining REP input loss came from the first
feasibility pass retaining a subsequently disproved failure path. Bounded
monotone edge refinement is now integrated: each round starts from the same
seed, excludes only previously proved dead edges from predecessor meets, and
shares the original deadline/work budget. Provisional rounds publish nothing;
an earlier fully completed round may be retained. Final production47tests
pass36.23s; lint/full mypy-dev/ownership pass. The unchanged native probe now
proves2127->212f dead and advances to directCALL2131, target27aa; its diagnostic
phase takes5.74s under the unchanged15s cap. Native whole-function and M5/M7
acceptance remain open. Evidence:
`.cache/comparator-implementation/m5-feasibility-refinement/`.

Read-only direct-call followup: the manual probe supplied boot/services but
left both interior-call proof arguments at their empty defaults. No callee27aa
proof was attempted or registered. Its2131 refusal therefore marks the probe's
scope boundary, not a demonstrated missing callee theorem. The next acceptance
action is the actual SWAPS collector regression, which exercises production
intake instead of inventing another semantic fix from this probe limitation.
Evidence: `.cache/comparator-implementation/m5-next-direct-call/`.

Measured delay: the last comparator gate passed 305 prechecks in 16.65s and
1211 tests in 178.18s. The retained SWAPS failure alone took 334.73s (326.19s
in its test body). Repeating that pipeline before prerequisite fixes is
expensive; use its bounded reproducer first. These are existing receipts,
not a new paired performance benchmark. KVM API12 was rechecked successfully;
static SSA/Z3 and native lifting do not require KVM.

The critical path is successive semantic gaps plus review/rework, not just
solver throughput. An external-call Devin attempt ran 54 minutes without
completed candidate tests. That attempt and its investigation followup are
stopped; two current private slices are REP transfer and declared-target
binding. Require reviewable code at the existing 15–20 minute checkpoint,
take over bounded harness/report cleanup, and avoid delegating another broad
investigation of the same blocker. Batch focused tests on frozen sources;
run full gates at integration checkpoints, not for every prerequisite edit.
Use at most two wall-budgeted proof workers and six aggregate test workers.

Fresh guard check: corrected the test's nonexistent STORE_CODE_OVERLAP enum
name to CODE_WRITE_VIOLATION; scoped lint and the regression pass (1 test,
15.91s total, all reported test phases below 1s). This reinforces batching:
startup/collection overhead dominates this tiny check. No production semantic
change or measured end-to-end speedup is claimed for the test correction.

Consult this checklist and the completion ledger first. The dated entries
below preserve evidence; do not repeatedly load the entire historical log.
No current full-suite, whole-function or M5/M7 acceptance follows from this audit.

- 2026-10-05 authenticated LOAD integration: shared initialized-memory projection
  and path-overlay reader are integrated in census and feasibility. Native
  LOAD operands bind before pruning; stale boot bytes, unknown writes, taint,
  differing branch writes and undeclared memory retain refusal. Final production
  cohort37passed44.76s; lint, architecture, ownership and full mypy-dev pass.
  Narrow four-file MyPy still reports import-context diagnostics; no narrow-clean
  claim. Native SORTD now resolves the prior LOAD, but still refuses AH4A because
  the census join includes a proven-impossible edge between otherwise live
  blocks. The root-only explicit-edge-filter repair is now integrated: final
  55controls pass23.24s, lint/full mypy-dev/architecture/ownership pass. Nested
  callee scopes retain unfiltered joins. Native trace now preserves SI and BX
  until Iop_MullS16 at0x210d, whose unsupported widening multiply loses the
  value. Shared typed widening arithmetic is now integrated in both scalar
  consumers (native opcode is NEG BX, F7DB). Final86controls pass30.58s; lint,
  full mypy-dev, architecture and ownership pass. Native SORTD now supplies
  BX5610 and AH4A returns carryFalse through the canonical response owner;
  the next refusal is CALL_BOUNDARY_UNPROVEN at0x212f. Its incomplete whole
  premise still returns no admitted consumption record. A separate IMUL/Mul32
  classification gap remains documented, not weakened. Comparator gate67949
  passed on frozen sources:305prechecks16.65s +1211admission tests178.18s,
  terminal0. No native function or M5/M7 acceptance claimed.
  Evidence:
  `m5-path-load/` including native-recheck receipts. No M5/M7 acceptance follows.
  Devin17860 was intentionally stopped after54minutes (terminal1), preserving
  its external-call draft. New Devin38382 owns only the exact CALL-binding
  repair and focused tests; no new CLI overlay/harness project. KVM API12 was
  reverified; static comparator work does not depend on it.

- 2026-10-05 resize integration and aggregate premise accounting: parent
  integrated the corrected shared AH4A response and path-associated memory
  lattice into both census and feasibility, preserving encoded-CALL changes.
  Permanent native controls retain differing/equal branch writes, reachable
  code-write error paths and authenticated parent-to-child memory transport.
  Combined production cohort96passed50.33s; final adapter follow-up52passed
  16.53s. Scoped lint, startup architecture and ownership checks pass. Identical
  scoped MyPy selection reports39before/39after diagnostics,0added/removed;
  no clean broad typing claim. Receipts:m5-resize-bridge/parent-review/.
  Parent also integrated collector-wide premise accounting: sibling CALLs no
  longer each reset64attempts; replay scopes/caches/budgets remain unchanged.
  Its staged red4failed/4passed becomes23passed30.04s with existing guards,
  then passes the combined production cohort. The unbounded-by-collection
  SWAPS run was deliberately interrupted at760.27s(exit2), with live stack
  evidence identifying recursive premise/reimport work. The changed-source
  rerun terminates334.73s with the existing IR_BUILD_REFUSED assertion failure;
  this is bounded work, not function acceptance or a paired speedup benchmark.
  Source trace also observes repeated static inventory installation in that
  path. Final23guard/intake controls pass18.93s; full mypy-dev passes after
  fixing the optional-boundary local annotation (reproduced on saved baseline).
  Native SORTD with the original image and explicit native PSP/MCB profile
  accepts both service declarations, but AH4A still refuses:BX is unknown,
  AX0x4a01/ES0x100/SS0x6ea/SP0x13aa are proven, MCB overlay untainted. Its
  first input guard rejects before resize response evaluation. Native tracing
  locates the earlier unknown SI at byte LOADs from DS:2/3; MOV/unary/SUB
  propagate that unknown correctly. Authenticated declared-memory readback is
  the next owner, without invented loader PSP fields. Receipts:m5-resize-native/.
  Final comparator-check-fast passes305prechecks16.47s and1211admission tests
  182.16s on the integrated sources. External-call Devin17860 is implementing
  its private declaration transport; resize Devin52137 was stopped and parent
  integration supersedes its private proposal. Original M5/M7 remain open.

- 2026-10-05 remaining-boundary work: one bounded SWAPS diagnostic identifies
  caller0x102e0 as NOT_REGISTERED before0x108d6→0x11222. The callee's CX return
  is already recognized; its mixed selector obligations require a transported
  caller domain. Native caller-intake repair is now integrated: exact ordinary
  import runs inside the existing cycle/budget guard; refused/pending bodies
  cannot publish, and raw registration precedes required ownership coverage.
  Parent final-source cohort18passed31.40s with mandatory Cython; scoped lint,
  architecture and ownership pass. Scoped MyPy reproduces59baseline diagnostics,
  0added/removed. Native9control regression enrolled in serial native lane.
  Receipts: `m7-swaps-next/parent-*.log`. SWAPS itself awaits the bounded rerun;
  no budget enlargement or conditional-to-universal promotion occurred.
  Independent sandboxed Devin17860 owns the explicit external-call segment
  contract described in `m7-loadprogram-final-review/REPAIR_PROPOSAL.md`, staged
  under `m7-external-call-segment/`. Its rootRO/repoRW/4GiB/KVM-API12 boundary
  was verified. Resize correction remains private in Devin52137. Parent added
  matching-branch resize positives:2passed9.94s against the rejected snapshot;
  these must survive repair alongside the two false-proof negatives. No new
  original milestone acceptance follows from these active tasks.

- 2026-10-05 encoded-entry integration: parent authenticated retained E8 bytes
  against the caller's native census and selected the executed destination,
  preserving prefixes hidden by normalized lookup identities. Two permanent
  native/Unicorn controls cover prefix effects and counterfeit indexes; enrolled
  in the serial native lane and ownership mapping. Final-source focused cohort
  44passed218.80s with mandatory Cython; scoped lint, startup architecture and
  ownership checks pass. SWAPS and InitBars still fail their original focused
  assertions (IR_BUILD_REFUSED and selector-window refusal respectively),
  2failed215.43s. This is soundness progress, not closure of those functions.
  Receipts: `m7-encoded-entry-transport/integrated-*.log`.
  Identical scoped MyPy runs with saved-baseline shadow files and current sources
  each report59diagnostics,0added/removed (`types-{baseline,current}.log`);
  this is an unchanged-debt result, not a clean typing gate.
  Resize Devin17355 was deliberately stopped at its reviewable checkpoint,
  terminal1. Parent review executed two native counterexamples: mutually
  exclusive MCB writes collapse into a global last-writer ledger; stale initial
  MCB facts in feasibility prune a reachable code-write branch. Both falsely
  produced complete premises, so the bridge remains unintegrated. Reproduction
  and review: `m5-resize-bridge/parent-review/`. Sandboxed Devin52137 owns only
  the private correction, with compiled-lifter controls and a bounded handoff.
  Original M5/M7 and all final corpus/gate obligations remain open.

- 2026-10-05 comparator gate reconciliation: two E8CBFF negative controls
  expected solver refusal after the producer had correctly begun refusing
  selector-dependent targets earlier. Both now verify the native refusal,
  absent admitted target and nonproof; the boundary retains failed accounting.
  Independent retained-SSA evaluation preserves physical destination0x11000
  atCS0x103, versus0x1000 atCS0/0x100. No production gate or budget changed.
  Combined controls35passed21.53s; scoped lint passes. The intervening gate
  stopped at987passed/1failed152.25s on the companion boundary expectation;
  final rerun is recorded separately in
  `m7-control-refusal-review/comparator-gate-final.log`. InitBars callsite0x10576
  target-mismatch diagnosis is delegated to a read-only sandboxed Devin task
  under `m7-initbars-target-review/`; no full-plan acceptance is claimed.
  Final comparator-check-fast exits0:305precheck passes13.76s and1211admission
  passes183.59s. Both stages passed; broader repository/native gates remain open.
  Integration MyPy exposed optional instruction-address and redundant-cast
  errors. Explicit missing-address refusal and cast removal pass mypy-dev,
  scoped lint and34service/joint controls46.20s. Mypyc smoke needed writable
  TMPDIR=.cache in this sandbox and then passed. The current quality-dev
  run uses that environment (`quality-dev-tmpdir.log`); earlier failed gate
  logs remain intact and are not relabeled green.

- 2026-10-05 unary integration follow-up: eight reviewed owners and eight
  permanent regression modules are now in production. Initial new controls
  58passed25.24s; broader production cohort195passed/1failed32.93s. The failure
  was an incomplete synthetic VEX fixture declaring no 32-bit conversion
  result width; supplying its actual width preserves all original assertions,
  with importer/address cohort39passed12.15s. Parent fixed six new feasibility
  typing errors and one optional-register-value annotation; scoped MyPy now
  reproduces exactly43saved-before diagnostics,0added/removed. Scoped lint and
  startup architecture pass. Native SORTD prefix reaches past NEG BX and now
  refuses call_boundary_unproven at0x11011 (747classified/746materialized/1failure).
  This is bounded prefix progress, not whole-function acceptance. Logs/receipts:
  `m7-unary-integration/`. Enrollment checks and final gates remain pending.
  Sandboxed Devin22994 owns only `m7-typehoon-review/` for the existing
  ancestor-cone candidate and permanent-quality controls; no production patch
  or native speedup accepted. Original M5/M7 remain open.
  Follow-up: enrollment166passed6.96s; actual ownership/context checks pass;
  production native-scoped cohort10passed266.55s. Exact next native refusal is
  INT21/AH4A resize: canonical DOS model exists, but the version-only declared
  IR service bridge lacks this relation (next-service-review.md).
  Devin22994 then completed. Parent found and fixed a one-shot-target iterator
  defect and strengthened copied-graph work accounting:18private/185production
  controls pass; scoped lint/MyPy/architecture pass. Component timing improves
  dead-cone enumeration1.46–6.60x, with12–14percent small full-cone overhead.
  Unchanged SetGear still fails its30s subprocess watchdog under verifiedKVM
  with3132unchanged source paths. No end-to-end gain established; production
  Typehoon hook/owner/test withdrawn, exact reviewed candidate retained under
  `m7-typehoon-review/parent-final/`. No proof budgets or gates were weakened.
  Do not repeat this experiment: earlier `m7-typehoon-parent-review.md` already
  measured706actual-worker pairs with negligible benefit. The current resize
  diagnostic also uses PSP0xff0/noresize_policy, while the native tail profile
  requiresPSP0x100; a bridge alone cannot invent that missing declaration.

- 2026-10-05 development-latency intervention: consumer Devin35525 was
  deliberately stopped at its reviewable checkpoint after verified process
  identity; terminal exit1, exact sources preserved. Parent merged its final
  complexity refactor with the reviewed captured-constant address repair.
  Independent merged results:126passed26.58s plus33/33diagnostic controls;
  scoped Ruff clean. Source snapshots, merged owners and evidence:
  `m7-unary-integration/`. Measured coordination/fixture overhead and execution
  rule corrections are in `DEVELOPMENT_COST.md`; these measurements are not
  solver speedup claims. Next is coherent production integration and required
  final-source checks, not another worker report cycle. M5/M7 remain open.

- 2026-10-05 unary consumer integration review finds two additional concrete
  omissions: constant_flow rereads a changed register (1 instead of0xffff8000),
  and vex_addressing independently drops an active NOT in Add16. Reproducers:
  `m7-invocation-edge-feasibility/parent-review/unary-joint-review/other-consumers-review.md`.
  Sandboxed Devin35525 owns private repairs under `m7-unary-consumers/`, using
  frozen unary owners and saved production baselines. Parent independently
  confirmed rootRO/repoRW/4GiB before launch; noKVM for this static work.
  Separate private review worker owns `m7-unary-call-binding/`: adapt exact
  near-call conversion traversal to the new operand evidence without weakening
  native or selector-domain checks. Original Devin87005 still owns the four
  staged unary owners and focused regression classification. No overlapping
  source ownership or production promotion; final integration must cover all
  affected consumers together.
  Parent subsequently stopped87005 deliberately after verifying its hostPID/
  namespace identity: terminal exit1. It began an operand-pin compatibility
  experiment that overloads source_tmp instead of adapting the old binder.
  Saved rejected copies and restored only the two private changed owners to
  the coherent frozen contract, including the parent fold repair. Receipt:
  `parent-review/rejected-operand-pin-compat/README.md` in the feasibility task.
  Parent permanent-style fold regressions now4failed before/4passed after
  (11.94s/11.33s); logs in `parent-review/parent-fold-repair/`.
  Call-binding worker released its private candidate:12failed48passed before,
  67passed26.59s after (60existing plus7corruption/leaf controls), scoped Ruff
  and two-file shadow MyPy clean. Parent read every binder delta and starts
  independent affected invocation/native-scoped/fold replay as66813;
  report/log:`m7-unary-call-binding/REPORT.md` and `parent-review/affected.log`.
  Worker positive counts do not close the broader original123regressions;
  parent additionally prepared the explicit active_unary:null serialization
  expectation in a private core-test copy for eventual integrated validation.
  Parent66813 then completed exit0:36passed282.57s, including affected native
  scoped import/resolution/closure, invocation/unused-premise, binder corruption
  and folding controls. Slowest scoped-domain separation70.79s; proof budgets
  unchanged. Call binding is independently verified for this private cohort;
  production and full-plan acceptance still await coherent consumer integration.
  Parent81167 subsequently completed exit0:30passed25.13s for the private core
  serialization update, scalar active-operation storage guards and all23staged
  unary/feasibility controls, with reviewed binder and fold repair loaded.
  Receipt:`m7-unary-integration/core-controls.log`; isolated runner lists exact
  owner substitutions. No production source was changed by this replay.
  Bounded abstract-arithmetic membership controls additionally4passed12.94s
  after scoped Ruff: two81-state byte domains cover every represented concrete
  member for arithmetic/bitwise/equality, shifts and signed/unsigned extension.
  Fully known inputs must remain known; test bodies total under1s. This is
  transformer validation, not a whole-function proof. Final log and coherent
  promotion checklist: `m7-unary-integration/{known-bits-final.log,README.md}`.
  Pre-integration address review then reproduces a remaining captured-constant
  projection defect in Devin's evolving candidate: t7=Not16(Const0) computes
  0xffff but _decompose_rdtmp uses retained const0 instead. Add16 and widened
  Add32 consumers therefore use the wrong displacement. Frozen candidate and
  strict failing control: `m7-unary-integration/address-review/`. Reviewer owns
  an isolated parent repair with authentic producer-map positives; worker files
  are untouched. Full-width Add32 expectations must retain65544 atEBX=9 rather
  than silently reducing to16bits. No faulty address projection is promoted.
  Isolated address repair now8failed3passed before/11passed13.11s after, with
  exact Add/Sub producer positives and missing-producer refusals. Scoped MyPy
  passes; one complexity finding is inherited from the evolving worker draft
  and still must be resolved before integration. Patch/receipts:
  `m7-unary-integration/address-review/parent-repair/`. Main Devin35525 reports
  33focused staged checks passing and proceeds to existing regression/lint/type
  checks; parent has not yet accepted its final two-file handoff.

- 2026-10-05 unary-contract parent review: frozen returned owners reproduce
  two false Add-fold values (10 instead of0;9 instead of8). Private importer
  repair prevents displacement folding across active unary evidence or pinned
  operands. Add/Sub controls now preserve exact WrTmp results0/8/65534/10;
  ambiguous compatibility views refuse. Nested signed/unsigned conversions,
  native MOVSX and corrupted native-binding controls also pass. Evidence:
  `m7-invocation-edge-feasibility/parent-review/parent-fold-repair/`.
  No production promotion: Devin87005 remains live investigating20 genuine
  focused regressions (saved-before overlay123passed). The earlier worker
  report predates those failures and cannot establish integration readiness.
  KVM marker audit separately finds0missing among97confirmed nativeCLI tests;
  parent collection-policy controls5passed0.92s. Static16/32SSA/Z3 needs noKVM.

- 2026-10-05 SetGear native recheck after parent-death integration: sandboxed
  child verifies character10:232/API12/nice10. Original acceptance node runs
  against3130unchanged source identities but fails its unchanged30s subprocess
  timeout (pytest52.09s, outer56.15s). This is a real timeout, not a KVM skip.
  Receipt:`m7-setgear-kvm-current/receipt.json`. An earlier redirected launch
  in the same directory failed to see the device; its launcher.log is retained
  separately from the successful device-backed test launch and receipt.
  Devin73340 now owns only private intra-rewrite timing under
  `m7-rewrite-cost-current/`; no production edits or proof-budget increases.
  One unchanged-CLI diagnostic may observe beyond the pytest watchdog under
  its own100s cleanup bound; it cannot satisfy the30s acceptance requirement.
  In parallel Devin87005 continues the separate staged typed-unary repair.

- 2026-10-05 continued parent review: Devin25372 reports14private fixture
  controls passing, but this does not authorize promotion. A further genuine
  imported `Iop_32HIto16` counterexample returns0x5678 for0x12345678 instead
  of0x1234: unsupported operation tokens are skipped as provenance. Saved
  reproducer:`m7-invocation-edge-feasibility/parent-review/high_half_control.py`.
  Independent production native-byte probes also find incorrect invocation
  values for XCHG AX,BX and MOVSX EAX,AX; concrete scope and source identities
  are being recorded in `parent-review/production-value-review/` under that
  task. These are evaluator defects, not yet demonstrated false whole-function
  proofs. Fix and verify before source freeze; no additional acceptance claimed.
  Devin25372 subsequently completed exit0 with14private fixture tests reported
  green. Parent independently reproduced high-half failure against the frozen
  returned helper, then changed unmatched Iop tokens to refuse; the same
  control now passes. Private containment of production capture/conversion
  errors gives7red-to-green controls and35focused passes, but MOVSX becomes
  unknown there, so containment is not accepted as capability closure.
  A genuine nested signed/unsigned conversion pair serializes to identical
  IRValue objects while requiring different results. Consumer-only heuristics
  cannot recover that lost information. Devin87005 resumes the completed
  session with bounded private ownership of a typed active-unary contract,
  its importer, native binding, and both consumers. Exact XCHG/MOVSX/conversion
  positives are required; unsupported or ambiguous forms still refuse.
  Prompt:`.cache/devin-prompts/m7-unary-value-contract.md`. Outer sandbox was
  reverified rootRO/repoRW/4GiB; this static job does not use KVM.
  Parent independently resolves the next effect-only omission: native NEG BX
  lifts to70rows with one unsupported pure widening multiply, not an unknown
  flag write. Strict signed/unsigned8/16/32-bit widening-product classification
  now requires two exact-width inputs and a double-width explicit destination.
  Saved original gives6failed scalar controls and fails the native regression;
  final classifier cohort136passed9.07s, scoped lint/MyPy pass. All70native NEG
  rows now have closed explicit effects. This does not recover the product's
  numeric value or complete the invocation. Receipt:
  `m7-invocation-edge-feasibility/parent-review/neg-effect-review/parent-integration.json`.
  Existing emitter-test enrollment carries the new controls. Final source
  freeze and whole-plan checkpoints remain pending.
  Independent classifier review found no defect in the widening-product delta.
  For the upcoming unary contract, parent isolated the staged core and proved
  three missing consumer guards: active computations were accepted as exact
  destination/JMP/CJMP literal shapes. Private scalar guard candidate now
  gives3red-to-green controls; it must be integrated together with the new
  field, not before. Evidence:`parent-review/unary-storage-{red,green}.log`,
  `test_unary_storage_guards.py`, and `scalar-unary-candidate.py` under the
  feasibility task. This isolated shape test is not invocation acceptance.

- 2026-10-05 feasibility review rejected the private draft: independent
  controls reproduce partial-width equality, captured-register identity,
  inverted masked-zero, and multiple-exit edge-pruning defects. No draft
  feasibility code is promoted. Parent deliberately stopped batch7881 after
  confirming its process identity; terminal exit1 is recorded, not inferred
  from an observation timeout. Same Devin session resumes as71279 with the
  exact counterexamples and bounded repair ownership. Frozen source and
  controls: `m7-invocation-edge-feasibility/parent-review/joint-soundness/`.
  Separately, current KVM collection controls5passed1.29s: static tests do
  not probe KVM, and unavailable native execution skips only marked tests.
  This is neither a broad-suite result nor M5/M7 acceptance.
  Producer-only fix subsequently integrated: Boolean ITE guards retain the
  authoritative typed scalar condition when richer recovery is unavailable.
  Parent preserves the old partial recognizer before the fallback, avoiding
  loss of recovered comparisons. Six baseline regressions fail; final
  importer cohort60passed16.02s, scoped lint/MyPy/startup architecture pass.
  Existing result-width test enrollment carries the permanent controls.
  Receipt:`m7-invocation-edge-feasibility/parent-review/producer-integration.json`.
  Feasibility helper remains private. Independent M7.2 reconciliation finds
  both-track measurements already present; remaining final-source/control
  linkage and refresh commands are in `m7-performance-current-audit.md`.
  Real16/shared dependency refresh now10passed24.99s, exact denominator and
  all2992recorded source identities unchanged. Receipt:
  `m7-real16-dependency-current/receipt.json`. This covers changed direct/
  transitive effects, positive caller composition and five narrowed contract
  identities; it does not claim a persistent real16 cache. Final corpus
  source freeze and checkpoint gates remain outstanding.
  Final corpus runner now requires all16real16/PE32/shared dependency controls
  and attaches only explicitly covered tracks. Parent reviewed the four-file
  harness delta and independently ran47passing tests plus14subtests20.47s;
  no mocked run is counted as corpus evidence. Receipt:
  `m7-profiled-corpus/parent-real16-binding-review/parent-acceptance.json`.
  Parent then ran the actual combined gate:16passed37.94s with unchanged
  source snapshot and explicit real16/MSC8/BC5 coverage. Receipt:
  `m7-combined-dependency-current/receipt.json`. No KVM required; these are
  symbolic dependency/mutation controls, not16unconditional proofs.
  Follow-up feasibility review found two additional conversion/exit-state
  defects; parent repaired those in staging and frozen controls now pass.
  The12native-byte fixture tests still give6passed/6failed. A further genuine
  Not1 capture counterexample remains and byte-width shift counts lose
  precision. Devin25372 continues the bounded private repair after parent
  deliberately stopped71279; no unsafe helper is promoted.

- 2026-10-05 owner-death integration: parent reviewed and corrected Devin's
  supervision barrier. A root callable starts only after its disposable
  process group has a guardian watch; the same work deadline applies.
  Parent additionally fixed hidden EOF when the guardian died before readiness,
  bounded readiness by the original deadline, and used typed status values.
  Six permanent controls fail on the saved production baseline. Integrated
  cohort180passed/1enrollment failure; corrected enrollment164passed10.14s,
  Linux process lane8passed8.92s. Scoped lint/MyPy/startup architecture pass.
  Platform process tests use the counted Linux lane and require no KVM.
  Deliberately detached sessions remain outside the owned-group guarantee;
  no SetGear acceptance or speedup claimed. Receipt:
  `m7-fork-owner-death/parent-review/integration-receipt.json`.
  Original SetGear replay attempted after integration but did not start:
  the Python launcher cannot stat /dev/kvm in its current sandbox, although
  a separate shell sees host char10:232. No API12/native evidence from this
  attempt; static comparator/process controls remain KVM-independent.
  Receipt:`m7-setgear-post-owner-guard/launch-receipt.json`.
  M5 evidence reconciliation now maps all347original indexed nodes to
  successful superseding JUnit records with unchanged test-source hashes;
  checkpoint gates remain pending. Attachment:
  `m5-original-acceptance-audit/current-checkpoint-attachment.json`.
  Parent stopped feasibility draft24377 for duplicate Jcc decoder/predicate
  semantics. Rejected source is frozen; Devin7881 now uses the authoritative
  lifted-condition producer instead, still staging only. No M5/M7 acceptance.

- 2026-10-05 parent correction to the first-callee diagnosis: exact SORTD
  header/prefix arithmetic gives SP0x0800+0x0bae without carry, so JAE can
  bypass the error call under authenticated boot/service premises. This is
  not yet a formal path-admission receipt. The invocation census follows raw
  predecessors and currently cannot consume this branch infeasibility.
  The reported downstream closure counts were inferred, not measured.
  Reviewed next work is a generic, scope-bound edge proof before callee
  census, with unknown edges retained. Devin24377 stages that experiment;
  no new indirect-call capability is assumed necessary. Review:
  `m7-initbars-first-callee/parent-review/REPORT.md`.
  Cleanup repair independently passes the ordinary-subprocess leak control,
  but parent rejects silent guardian-fork fallback, missing startup readiness
  and the extra30-second work allowance. Devin49092 repairs admission in
  staging; production timeout machinery remains unchanged. Review:
  `m7-fork-owner-death/parent-review/REPAIR_REVIEW.md`.

- 2026-10-05 caller-chain integration: three reviewed owners now carry
  declared-service assumptions through both parent replay paths and expose
  authenticated dependency-local sources without promoting refused global
  inventories. Parent corrected memo admission for replaced recompute
  authority, updated3outdated test mocks and removed an unused protocol.
  Production cohort198passed101.17s; scoped lint/startup architecture pass.
  Scoped MyPy63diagnostics exactly match the saved dirty baseline,0added.
  New native-byte controls are enrolled in the serial expanded lane and
  changed-owner checks. Receipt:`m7-post-service-chain/parent-tests/integration-receipt.json`.
  Original InitBars remains unproved; Devin90380 now stages precise typed
  census-failure locations rather than guessing which later boundary failed.
  Devin90380 subsequently finished: staged6controls pass; exact native early
  leg reports CALL_BOUNDARY_UNPROVEN at function0x10f9a/block0x10fc3/
  instruction0x10fc5. Parent independently checked original bytes e80c05:
  near target0x114d4. The next obligation is this callee's boundary and
  preservation evidence, not an inferred extra interrupt service. Typed
  diagnostic patch is now integrated after parent review:156production
  tests pass50.62s; scoped lint/startup architecture pass. One isolated
  shadow-file MyPy baseline reproduces all63current diagnostics,0added.
  Routine regression enrollment includes nested-site propagation and
  structural/budget refusals without invented instruction locations.
  Receipt:`m7-invocation-refusal-site/parent-review/integration-receipt.json`.
  Devin32061 finished the next callee diagnostic without a patch: its bounded
  receipt establishes clean14-instruction/5-block intake with3interior calls;
  recursive preservation collection reaches its15s cap. Its subsequent
  indirect-call/reachability diagnosis remains under independent parent
  review, not an observed successful closure or InitBars acceptance.

- 2026-10-05 SetGear phase evidence: one original-command diagnostic retained
  all3130source hashes and verified KVM API12. CLI imports16.9s plus setup4.3s
  consumed21.2s before the worker; the30s test kill left the fork orphaned.
  That worker continued: decompiler phase12.96s, rewrite loop43.86s, total
  worker63.06s before returning status ok. This is NOT tail/native acceptance.
  Correction to earlier wording:20s is the requested CLI timeout; existing
  large-function policy expands it to40s internally, with cooperative checks.
  No budget was changed by the diagnostic. Parent-death cleanup is now a
  bounded staged Devin35534 task; it must not replace unrelated group cleanup
  or weaken proof/test deadlines. Receipt:`m7-setgear-phase-timing/`.

- 2026-10-05 retry-outcome integration: reviewed Devin's bounded patch and
  added ordinary-import production controls. Baseline reproduces3failures
  (unstarted retries replacing completed evidence),2controls pass. Integrated
  code preserves the previous result when no retry starts; actual attempted
  timeouts remain timeouts. Focused CLI/pipeline/enrollment141passed38.91s;
  scoped lint/MyPy pass after a type-only rollback-snapshot annotation.
  Tests are enrolled in routine pipeline and changed-owner checks.
  Original SetGear still exceeds its unchanged30s subprocess deadline:
  verified KVM API12,3130source hashes unchanged,63.59s outer run. This fix
  closes a reporting defect, not SetGear or M7 acceptance. Receipts:
  `m7-retry-outcome-stage/receipts/`, `m7-setgear-post-retry/`.
  Caller-chain review independently confirms missing declared-services
  forwarding in two parent-domain replays (frozen baseline fails11.38s,
  corrected control passes15.81s). A further memo defect ignores replacement
  recompute-authority identity; parent red5.15s/green4.00s is staged only.
  Full caller-chain integration and original InitBars acceptance remain open.

- 2026-10-05 architecture checkpoint: full gate passes after correcting11
  ownership/promotion/enrollment gaps;419architecture/Make regressions pass.
  This is the full architecture gate only, not the remaining quality or
  native acceptance gates. Caller-chain draft stays unintegrated while parent
  review continues; its two reproduced memo-admission failures now pass.

- 2026-10-05 walker checkpoint: reviewed per-field direct-emission optimization
  integrated after parent parity controls and baseline identity verification.
  Production inventory/rollback37passed; scoped lint passes; MyPy35existing
  diagnostics,0added versus saved baseline. Original SetGear57172 still fails
  its unchanged30s subprocess bound despite verified KVM API12;47.50s pytest,
  3130source hashes stable. No whole-function acceptance or end-to-end speedup
  claim. Evidence:`m7-callwalk-stage/parent-review/`, `m7-setgear-post-walk/`.
  Subsequent annotation/comment-only cleanup clears the owner's35MyPy errors;
  lint/MyPy pass,683runtime code objects unchanged, and5Pyright diagnostics
  exactly reproduce against saved pre-cleanup source. Native receipt keeps its
  original source identities; no new native acceptance is implied.

- 2026-10-05 integration update: declared-interrupt repair/extraction finished;
  parent74staged controls passed before copying the reviewed owners into
  production. Make/pipeline/ownership enrollment is updated, and scoped
  lint-iteration passes after annotating the shared callable alias. Initial
  production checks76passed/8failed, with all failures in GNU Make temporary
  file creation on the read-only default temporary path. Corrected final
  checks use repository-local TMPDIR:84passed,1warning,68.66s; startup
  architecture checks pass. Receipts are under
  `m7-declared-interrupt-stage/parent-tests/`.
  Follow-up production invocation/boundary/pipeline regressions:133passed,
  1warning,70.06s. Static SORTD diagnostic finishes at14.21s: no declaration
  refuses, declared service closes468/468facts with0failures and explicit
  assumptions, foreign environment refuses. This is the first interrupt
  boundary only; full caller-chain acceptance is still outstanding.
  Original InitBars closure and M5/M7 acceptance remain unproven. Devin8224
  continues staging the observed AST callwalk optimization; none is integrated.

- Parent accepted the bounded replay-readback correction after worker74118
  finished: unreadable bytes remain typed gaps instead of fabricated zeros;
  replay,capture and program complete outcomes refuse incomplete snapshots.
  Independent final11-module cohort169passed,0failed/skipped,96.46s; scoped
  lint passed and enrollment previously passed164checks. Exact dirty-baseline
  review/hashes in `replay-unreadable-write-review/PARENT_REVIEW.md`. This
  reconciles the intervening replay delta; older505-test/public receipts retain
  their own source identities. Parent60629 finished exit0: exact30public
  recursive/terminal bridge nodes pass489.50s pytest/493.18s outer, serial and
  at unchanged budgets. All3127source hashes unchanged,0missing
  (`replay-unreadable-write-review/public-refresh-receipt.json`).
  Required project gates and M5/M7 stay open.

- Post-inventory SetGear recheck22941 finished1failed53.40s pytest/58.76s outer:
  verified character10:232/API12, unchanged20s analysis/30s subprocess bound,
  all3127sources unchanged. It is a real timeout, not the previous environment
  limitation. One stack diagnostic27476 then hit its60s safety cap without any
  stdout/stderr/cache/worker samples; it cannot support a profile or speedup
  claim. Process-group cleanup completed. Receipts:`m7-setgear-post-inventory/`.
  Devin23675 diagnostic is rejected for route attribution: its heartbeat raises
  Python thread count1→2 and disables normal fork admission. Parent reproduced
  this with the exact production guard; corrected observer preserves1thread
  and fork eligibility. The earlier daemon-thread result was instrument-induced,
  not an ordinary-run profile. Parent49541 now runs one corrected bounded
  diagnostic without heartbeat; budgets/production unchanged. Receipts:
  `m7-setgear-phase-attribution/PARENT_REVIEW.md` and
  `m7-setgear-phase-corrected/`.

- Declared-interrupt draft12319 finished but is NOT accepted: four independent
  parent controls demonstrate forged AX/BX/CX answers or preserved lanes retain
  complete=True under an unchanged environment digest. Parent preserved the
  draft and red log under `m7-declared-interrupt-stage/parent-rejected-draft/`
  and `parent-tests/red.log`. Repair70787 finished; independent parent20controls
  pass19.91s including forged answers, live-IVT writes and frame/future-code
  overlap. Parent still requires one shared DOS response owner (repair duplicated
  the encoding) and an explicit frame-load refusal control. Same session resumed
  as57181, staging only; repaired draft retained in parent-repaired-draft/.
  No production interrupt integration or original InitBars acceptance yet.

- Current M5 evidence refresh completed: parent67251 terminal0,505passed,
  0failed/errors/skips,309.48s pytest/311.09s outer with2workers,nice10,JIT.
  JUnit accounting verifies every317stale index node plus2new resolution
  controls; additional complete terminal/service-census/IVT/environment modules
  ran as well. All3127source hashes match before/after. This closes the stale
  native-control evidence gap caused by call-coordinate changes; required
  project gates and M5/M7 acceptance remain open. Receipt:
  `m5-final-source-review/PARENT_ACCEPTANCE_EVIDENCE.md` and `parent-refresh/`.
  Devin12319 now stages only an explicit conditional interrupt relation; no
  guessed DOS environment or production edit is authorized.

- Exact caller-path diagnostic now identifies the first boundary as native
  `CD21` at0x10f9c, preceded by `B430` (DOS version query). Parent independently
  decoded and hashed SORTD.EXE in `m7-bounded-invocation-review/parent-tests/boot-boundary.json`.
  The bare boot-domain attempt supplies no interior-call records and refuses
  there; raw7/materialized6 are instruction/effect facts, NOT seven calls.
  Near-call index evidence cannot by itself provide an interrupt-service
  contract. The scoped-source draft therefore does not close InitBars and is
  not integrated. Devin12558 finishes the bounded correction/report; separate
  read-only Devin80128 reconciles original M5 obligations with current source
  receipts, without running another broad gate or expanding capability scope.

- Bounded-source parent review (2026-10-05): three direct-callable revocation
  controls fail against Devin's draft (removed request, replaced same-byte
  request, mutated detached receiver). An isolated retained-receiver identity
  check passes all12parent/fixture controls in32.27s. Production is unchanged;
  this does not discharge InitBars. Parent stopped47276 deliberately (exit130)
  after its native search moved to easier boot callees; resumed the same Devin
  session `blushing-roadrunner` as12558 with the corrections and an exact-target
  60s diagnostic cap. No inventory-budget increase or weaker acceptance is
  authorized. Evidence: `m7-bounded-invocation-review/PARENT_REVIEW.md` and
  `parent-tests/{red,green}.log`. M5/M7 remain open.

- Current public-contract checkpoint is now source-bound:180public checks,
  30actual recursive/terminal bridge checks,17MSC8 and19BC5 adapter checks
  pass with0failures/0skips; all5CLI help commands exit0. Snapshot3127paths
  has no before/after drift. Of28previously audited public/docs/interface
  files, only Make/pipeline/ownership enrollment differs; public docs and
  schema/entrypoint contents remain unchanged. This refreshes public evidence,
  not native decompiler or full M5/M7 acceptance. Receipt:
  `m7-public-current-20261005/{REPORT.md,receipt.json}`. Devin's work remains
  staging-only on bounded caller authority; its native probe found the actual
  MZ-entry→main→InitBars row chain, but interior-call proofs remain required.

- Joint-control implementation parent review completed: Devin13672 terminal0;
  parent97ordinary-import tests pass73.47s with no source drift, followed by
  17focused controls62.83s after correcting3new typing diagnostics. Scoped
  lint/startup architecture/context/enrollment pass; saved baseline and fixed
  owner MyPy diagnostics match40/40. Refusal surface, premise and census now
  reauthenticate at consumption, including reconciled-but-unresolved ledgers.
  Exact unchanged InitBars remains red10selector refusals52.09s call; the
  captured intake is INVENTORY_REFUSED/BUDGET_BOUNDARIES at the unchanged
  64-boundary cap (59closed callers,5pending; raw99/classified64). Scope stays
  absent. Worker47276 now stages a bounded caller-path authority solution or
  precise blocker; it may not promote the global refusal or raise budgets.
  Receipts:`m7-combined-control-review/PARENT_REVIEW.md` and
  `m7-bounded-invocation-review/`. Original M5/M7 remain open.

- Combined-control parent review now has an independently reproduced defect:
  orphan function-level selector refusals survive both the draft surface audit
  and retained-view projection. Two native-fixture corruption controls fail
  (22.97s); no authentication checks were mocked. Exact red sources and log:
  `m7-combined-control-review/{parent-red-source,parent-refusal-red.log}`.
  Required correction: reconcile function refusals with the exact block census
  and repeat surface/premise/census authentication at consumption. Devin13672
  remains live on its focused regression review; parent has not edited its
  owned semantic files concurrently. New owner/tests are enrolled, contract
  documentation updated, startup architecture/context/ownership and parent
  scoped lint pass. Those gates do not accept the pending semantic patch.
  Static comparator work remains independent of KVM; original M5/M7 stay open.
  Parent isolated repair now passes17controls37.61s, including orphan-marker
  accounting (an additional red check established2reported versus3actual
  obligations). Devin has adopted the parent controls in production and is
  completing its refactor/regression checks. A production test overlapping that
  refactor hit an incomplete helper definition; its receipt is excluded from
  semantic evidence. Ordinary-import parent verification still must run after
  source freeze. The next exact InitBars capture now records the existing typed
  static-intake receipt, without launching an extra inventory traversal.

- Parent rechecked original acceptance artifacts: the matrix is now56supported
  bounded cells (not the old51/1/4snapshot), with M5 native capability coverage
  already reconciled in `m5-exit-audit-current/PARENT_RECONCILIATION.md`.
  Mandatory final-source/public/dependency/gate reconciliation remains open;
  optional optimization must not become a new prerequisite. Updated the current
  evidence section of `m7-final-acceptance-checklist.md` with frozen corpus,
  all14named-phase totals, baseline parity and profiler observer-effect limits.
  InitBars16604 remains red40.54s at10selector-window refusals; no assertion
  weakened. Existing typed-gate reviewer now checks whether the exact expectation
  needs a proven scope or whether an already-proven scope is lost; no new broad
  rerun, source edit or invented service requirement delegated.

- InitBars failed-frame capture now establishes the actual missing evidence:
  invocation scope is null, admission is empty and application status is empty.
  All10 jump refusals stem first from call0x10566 to0x11222 lacking a resolved
  callee preservation proof; no admitted scope was lost during application.
  Ledger counts29raw/10normalized/10classified/0materialized/10failures remain
  visible. Read-only reviewer continues at that exact callee boundary; no test
  expectation or proof gate changed. Receipt:
  `m7-native-scoped-parent/{initbars-proof-summary.json,initbars-proof-capture.log}`.
  Static KVM marker policy independently passes5controls0.76s; this is not an
  exhaustive marker audit or a broad-gate acceptance result.

- Follow-up source review locates the first missing callee boundary: mapped
  scanning uses entry0x11222 as its lower bound, rejecting the direct backward
  edge0x11236→0x11062 before call-preservation proof. Existing near-return
  support does not discharge that separate error path. Bounded staged frontend
  repair now owns `m7-backward-boundary-review/`, with closed-return/open-tail
  controls and unchanged exact-range/closure gates. The error tail has indirect
  calls; widening mapped census alone is not an InitBars acceptance claim.
  Parent independently tests Devin's initial-identity optimization: both leaf
  and fallback-region publication reject changed semantic identity (2passed
  13.43s). First diagnostic had a parent assertion using the leaf schema for
  the region report; corrected to inspect candidate.source_refusal, with the
  failed run retained. Production remains unchanged; worker cohort review and
  measured benefit remain pending.

- Devin28911 finished the bounded initial-identity revision. Parent independent
  three-function baseline/staged diagnostic takes38.639s/29.395s with identical
  complete proof/intake objects and3unknown verdicts; one pair is not a stable
  speedup claim. Import overlay keeps disk-derived semantic identity, so this
  is diagnostic evidence, not production acceptance. Parent also reproduces
  the worker's current-production unmapped-target failure18.42s: recorded
  0xffff9990 versus byte-derived0x9990; separate coordinate-owner review is live.
  Receipt:`m7-discovery-cost-review/baseline-only/PARENT_REVIEW.md`.
  M7.1 bounded public audit reports current2975source hashes unchanged but18
  paths changed since older347-node receipts; exact source-chain reconciliation
  remains required. No stale capability claim found in the four user docs.
  Exact refresh selections: `m7-final-public-review/REPORT.md`.

- Parent final isolated optimization controls66356 pass11/11 in24.55s; still
  no production adoption. Final-public review now binds28current docs/schema/
  entrypoint/enrollment files in `current-public-doc-hashes.json`; it records
  identity only, not execution acceptance. Backward-boundary review found two
  inaccurate range projections despite retained backward instructions. Worker
  revises typed decoding bounds and both callsite/invocation inventories before
  parent integration, keeping true caller entry and exact-range restrictions.

- Parent boundary review:5new staged controls pass12.42s;116existing controls
  yield115pass/1fail39.22s. The failure independently reproduces on production
  (10.70s): test fixture supplied bare object instead of registry-capable project.
  Parent changes only that fixture to SimpleNamespace, retaining all assertions;
  complete9test index module passes14.46s, scoped lint-iteration passes.
  Production semantic owners remain unchanged. Parent also found boundary
  transport still rejected backward extents; staged repair now covers byte-bound
  fresh-project reconstruction and unwitnessed-gap/open-tail refusal before
  integration. Receipts:`m7-backward-boundary-review/parent-*.log`.

- Backward-boundary integration completed in four frontend owners plus a routine
  ordinary-import regression module. Parent corrected two integration gaps:
  preserved forward transport's existing cache identity after fresh byte checks;
  updated isolated inventory-budget test stubs to the new typed census contract
  (these tests load source directly, bypassing the staging import overlay).
  Final production153tests pass56.39s; scoped lint/MyPy, startup architecture,
  agent-context and test-ownership checks pass. No InitBars success or broad
  gate acceptance inferred. Exact integration receipts:
  `m7-backward-boundary-review/{integration-hashes.json,production-tests-final.log}`.
  CALL-coordinate repair remains staged; parent independently reruns native
  controls and BC5 adapter compatibility before adoption. Worker91tests pass;
  flat32 and far-call compatibility were repaired during review, not waived.

- Parent independently verifies staged CALL-coordinate controls91pass27.76s,
  BC5 adapter19pass6.61s and MSC8 adapter17pass10.77s, then integrates5owners
  plus the durable routinely enrolled test. Original unmapped-target assertion
  remains unchanged. Scoped lint and startup architecture/context/ownership pass.
  Integrated owner MyPy has209diagnostics, identical to saved baseline; no new
  owner errors. Final production native+dosunit cohort46795 is still live.
  InitBars40033 completed red68.82s call time: still10refusals, EMPTY admission,
  first callee0x11222 unresolved. Reviewer now inspects the actual authenticated
  near-call premise boundary; raw no-premise census is insufficient diagnosis.
  Receipts:`m7-relative-call-coordinate-review/` and
  `m7-backward-boundary-review/{initbars-after.log,initbars-proof-summary.json}`.
  Update:46795 terminal0,302passed/5skipped217.99s. Five skips remain visible,
  not native acceptance. Integrated Pyright owners197versus saved201, no new
  owned-code errors; prior six staging-import errors disappear. Test annotation
  cleanup remains staged, preserving all vectors and assertions.
  Bounded InitBars follow-up now observes the actual premise failure: native
  row10560/10566→11222 is valid, but retained invocation source is absent;
  `_near_return_frame_premise` yieldsNone and continuation ledger reports
  PREMISE_ABSENT at1122f/11231. Mapped census includes the backward tail.
  Reviewer checks the static-invocation install receipt next; no guessed
  environment limitation or universal return proof substitutes for that evidence.

- Parent integrated the profile-motivated direct-call guard reorder in
  analysis_helpers: non-CALL instructions no longer request unused operands.
  Existing target canonicalization and refusal rules are unchanged. Reviewed
  native98-instruction census plus12controls preserve all targets; warmed
  ABBA helper means0.804s→0.537s, explicitly not an inventory-wide gain.
  Parent2existing target regressions pass12.28s; scoped lint and MyPy baseline/
  production both clean. Receipt:`m7-call-target-cost-review/PARENT_REVIEW.md`.

- Next exact native11222 surface retains5selector-window obligations and1
  continuation marker; the near-return-only scoped view refuses the unrelated
  markers. No authenticated scope/complete selector proof is inferred from a
  frame premise. Devin13672 now owns bounded coherent consumption of existing
  proofs, with baseline saved in `m7-combined-control-review/` and explicit
  stop if producer authority is absent. Current61.48s capped inventory profile
  still shows recursive frontend imports, not comparator intake; no end-to-end
  performance or test-budget claim follows.

- Local near-CALL intake repair is integrated after parent review. Parent
  found3authentication gaps in the worker patch and added exact project/arch
  and loader-entry/paragraph revalidation plus4durable controls. Final cohort
  53passed43.23s; startup architecture/context/enrollment and lint pass. MyPy
  has the identical34diagnostics before/after on saved dirty-source baseline.
  Exact SORTD caller10560/CALL10566 now supplies the frame premise for11222;
  its42-block boundary closes with0unresolved edges, global source still absent.
  Original InitBars remains red10refusals93.33s call: first callee failure is
  now CALLEE_INCOMPLETE, not unresolved; no whole-function or M5/M7 acceptance.
  Receipt:`m7-local-frame-review/PARENT_REVIEW.md`. Devin56294 is terminal0.

- loadProgram native-module follow-up is bounded and qualified: actual callee
  0x1019b..0x102ac has19blocks and8selector-window refusals in the raw universal
  import. IR_NOT_PROJECT_OWNED is a diagnostic-created unregistered-artifact
  precondition, not a production DS defect. No transitive preservation result
  follows. Source review confirms COD-module mapping currently feeds caller
  return-use but not segment-call contract resolution. A scoped native-module
  route would require independently authenticated scope; its availability is
  not yet established. No synthetic-RET or assumed ABI proof was substituted.
  Receipts:`m7-loadprog-next-review/{REPORT.md,native-callee/summary.json}`.

- Current KVM source audit confirms97previously identified real CLI execution
  tests are marked; no missing marker was established in reviewed native paths.
  Dynamic callback/future-generator limits remain explicit in
  `kvm-marker-current-audit/REPORT.md`; static comparator lanes stay unmarked.
  loadProgram review withdraws its suggested retry-reporting fix: the latest
  pointer diagnostic already ends validation_failed/exit4, and neither retry
  caller has a completed validation_failed result to preserve. No speculative
  reporting patch made. Native callee DS evidence, rather than synthetic RET
  behavior or compiler-name assumptions, remains the next proof question.
  See `m7-loadprog-next-review/REPORT.md` for corrected dataflow evidence.

- Local-frame repair launch (historical): exact authenticated intake receipt establishes
  INVENTORY_REFUSED/BUDGET_BOUNDARIES, with59closed caller heads and5pending
  targets exhausting64. InitBars caller is closed; its callee is pending.
  A separate typed LOCAL conditional frame authority is now assigned to Devin
  (execution handle56294); global invocation authority, budgets and pending
  obligations must remain unchanged. Before sources/hashes and task prompt are
  retained in `m7-local-frame-review/`; fresh sandbox probe confirms hostRO,
  repoRW and4GiB. No implementation acceptance yet.
  Reviewed CALL-coordinate test typing cleanup is integrated after exact hash
  checks:19passed13.13s and scoped lint-iteration green. All vectors and original
  assertions retained; independent external ArchX86 typing debt remains visible.
  Static KVM collection policy freshly passes5controls1.56s; neither comparator
  requires KVM. This is not an exhaustive runtime-marker audit.

- Parent rejects Devin16654's draft filters: APPLICATION_INPUT_STALE is also
  used for genuine stale-proof failures. Independent native-census corruption
  control passes production but fails staged coverage (1pass/1fail35.96s).
  Parent instead integrates a producer-only change retaining raw refusals on failed
  optional application, with the failed application still serialized separately.
  Both native reauthentication/coverage gates stay unchanged. Original scoped
  regression16078 and distinct-boot control both pass (2passed171.04s).
  Durable production red control records1failed/1passed34.39s. The producer
  patch now preserves raw failures and separately serialized application
  diagnostics; both strict consumer gates remain unchanged. Scoped lint passes;
  final production scoped-resolution/entry-jump cohort10576 is terminal0:
  43passed252.60s, including native mutation rejection, universal refusal and
  distinct-boot isolation. MyPy finds two return-Any diagnostics outside the
  changed function; identical-config saved-baseline verification86989 reproduces
  both (1269/1605). Earlier follow-imports=silent run20658 is not comparable.
  Producer patch verified; no M5/M7 completion claim. Evidence and exact delta:
  `m7-native-scoped-parent/`.

- Devin47012 reviews the remaining profiler coverage gap in isolated staging
  `m7-phase-coverage-review/`; parent verified rootRO/repoRW/4GiB sandbox.
  No corpus, shared semantic source or proof-budget edits authorized for this
  task. Parent retains integration and final measurement ownership.
  Update: terminal0; parent reviewed and integrated four named normalization
  hooks into the private harness, preserving incomplete/missing flags and
  explicit lower/micro-helper exclusions. Parent45tests+18subtests pass9.21s,
  probe lint passes. Calibration16765: same refusal,41.71s,420712KiB peakRSS,
  unchanged sources,31.52s closed window with zero conservation residual.
  Receipt:`m7-phase-coverage-review/`. Final corpus still pending.
  Parent starts frozen uninstrumented corpus99184 with dependency controls:
  7lanes/55obligations per phase/14serial processes,12input hashes verified,
  existing120s watchdog and inner proof budgets unchanged. Output:
  `m7-profiled-corpus/parent-uninstrumented-20261005/`. Do not edit inventoried
  sources until the uninstrumented/profiled pair finishes. Profiled pass must
  follow serially on the same frozen tree; no performance claim yet.
  Update: uninstrumented99184 terminal0. All14processes completed and all
  7lanes match cold/warm verdicts/reasons/assumptions, dependencies and contracts.
  Per phase55rows:3proved/2conditional/1counterexample/49unknown. Six dependency
  controls pass51.76s;2975source files unchanged before/after/current. Largest
  child peak399744KiB; per-run elapsed20.96–52.69s. Exact summary retained in
  `parent-uninstrumented-20261005/parent-summary.json`. Profiled93620 now starts
  in `parent-profiled-20261005/` on the same frozen tree. These observations do
  not close M5/M7 or establish speedup; real16 composition limits remain visible.

- Profiled93620 is terminal0. Frozen baseline/profiled pair now has28completed
  child runs and55accounted obligations per phase. Both modes retain
  3proved/2conditional/1counterexample/49unknown; all contracts/dependencies and
  2975source identities match. All14profile windows close with zero conservation
  residual. One row differs: real16-changed/cold InsertionSort remains unknown
  but macro_admission_refused becomes compose_budget_exceeded. Thus full
  reason parity is NOT established; instrumentation observer effect is retained.
  Baseline/profiled serial child totals487.84s/618.91s, median per-run ratio1.273;
  peak child RSS399744/462616KiB. These are diagnostic overhead measurements,
  not optimization gains. Named phase coverage remains explicitly partial.
  Reproducible comparison and verified summary:
  `m7-phase-coverage-review/{compare_corpus_runs.py,corpus-comparison.json,verified-summary.json}`.
  The static report's self-control covers14identical pairs; four corruption
  checks reject drift, outer timeout, phase mismatch and missing denominator.
  Ruff passes. The measurement freeze is complete; original M5/M7 gates remain.

- Devin20444 is live on a bounded source-only discovery-cost review, owned
  entirely by `m7-discovery-cost-review/`. Initial profile has10.425s exclusive
  wall time in discovery; distinguish it from thread CPU and do not infer a
  lift hotspot or speed gain without measurement. No production/source-budget
  edits or competing native workload authorized. Parent owns review/integration.
  Update: terminal0, four-owner draft staged only. Parent rejects integration
  pending narrower scope: the added mutable VEX memo does not itself validate
  live bytes; baseline consumers also need exact request binding, not merely
  provider checks. Parent eight-call fresh-hash experiment yields identical
  digests, median3thread0.41082s vs sequential0.48882s; sequential replacement
  rejected, no end-to-end gain claimed. Devin28911 now owns only
  `m7-discovery-cost-review/baseline-only/`: retain original image/loader reads
  and publication checks, share only initial source identity, no VEX cache.
  Parent98983 measures actual begin_lowering call counts inside discovery;
  earlier29-per-side estimate is not treated as observed. No production change.
  Update:98983 terminal1 with identical three real16-self refusals. One observed
  discovery invocation (self lowering reused),29calls:leaf15/region12/lowering2.
  Fresh hashing5.4881s inside6.0574s discovery; early imports mean these are inner
  diagnostics, not an end-to-end speed comparison. Receipt:
  `m7-discovery-cost-review/parent-hash-count/`. Native mutation/binding controls
  and actual optimization remain pending; no source freshness check removed.

- Scoped-import follow-up inventory44987 is terminal1: same180s timeout,
  1failed196.75s. The producer correctness fix does not solve the inventory
  performance blocker; budgets/assertions remain unchanged. Evidence:
  `m7-native-scoped-parent/inventory-after.log`.

- Corrected profiler calibration6020 finished: BC5 child exit2 preserves the
  same call_or_exception_boundary refusal,16.44s elapsed, unchanged source/hook
  hashes. Its one11.6775s observed window balances exclusive+unclassified time
  with zero residual. Reviewed probe/support are now wired locally into the
  private corpus runner;17controls+14subtests and scoped lint pass. Exhaustive
  normalization attribution, final corpus and gates remain open. Receipt:
  `m7-phase-accounting-parent/calibration-after/`.
  Integration type review then corrected12diagnostic-row errors using typed
  metrics/snapshots/phase totals. Combined38controls+14subtests, lint and MyPy
  pass. Calibration predates that typing refactor; final measurement must bind
  the new probe hash. No production comparator change or proof promotion.

- Parent adds `--dependency-controls` to the private fixed-manifest runner:
  it executes all6PE32 dependency controls once, rejects missing/duplicate/
  skipped/failed cases or source drift, and links the receipt only to PE32
  rows from the identical snapshot. Test/tooling/config owners now participate
  in source inventory.17synthetic controls+14subtests, scoped lint and MyPy pass.
  Actual control execution81944 is terminal0:6passed16.94s pytest/18.34s child;
  source snapshots unchanged, exact six-node XML inventory verified. Receipt:
  `m7-profiled-corpus/receipt-native-check/receipt.json`. Final corpus still
  pending; real16 cache evidence is not inferred from the PE32 controls.
- Cache follow-up81434 is terminal0. v3 remains rejected/staged: its adjacency
  key does not establish complete mutation tracking, and no end-to-end gain is
  demonstrated. Raw bundle alone cannot replace universal import because the
  latter may transform blocks during discharge. Keep the rejection and measured
  limits; no cache patch is integrated. Native scoped diagnostic16654 continues.

- Isolated indexed-inventory test99640 is terminal1 at its unchanged180s
  deadline (187.19s pytest). A bounded60s cProfile prefix identifies recursive
  callee importing:47IR imports while processing the first inventory row;
  timings overlap and are not additive or an end-to-end performance result.
  Devin30732 stages only a source/scope-safe repeated-work optimization under
  `m7-callee-import-cost/`; no proof/budget relaxation or production edits.
  Parent review of the live draft finds same-size registry replacement does not
  change its replay key (independent diagnostic receipt retained). This is a
  key-invalidation counterexample, not yet a stale-proof exploit; require a
  supported-publication whole-path control before integrating this cache.
  Update: worker30732 is terminal0. Parent reproduced two red controls, including
  native MOV-immediate mutation with equal fresh boundary coordinates. Worker
  v2 adds registry-entry identities and mapped bytes; no integration accepted.
  Its bounded diagnostic had2hits/96demands, not an end-to-end gain (and predates
  v2 authentication cost). Follow-up stays staged and prioritizes eliminating
  duplicate recursive import through existing raw/scoped owners (Devin81434,
  resumed field-argument). Parent independently runs v2's14focused controls:
  all pass7.21s; this does not establish dependency-complete cache safety or
  original inventory acceptance.
- Parent independently reproduces production native scoped resolver failure:
  `test_native_resolver_closes_scoped_body_and_revalidates_cache` fails with
  CALLEE_INCOMPLETE in14.96s. This is additional focused evidence, not an inferred
  change to the prior broad-gate count. Devin16654 diagnoses the exact scope/
  raw-bundle/collection boundary under `m7-native-scoped-resolution/`; production
  remains unchanged. The fixture uses static MZ loading and requires no KVM.
- LoadProgram diagnostic17778 is terminal0; parent replay of existing debug
  switches pins the missing evidence to local entry-DS identity at dereferences
  4139/4147. Both pointer facts are raw2/normalized2 but classified0/materialized0;
  DS access facts are UNKNOWN_REFUSE with physical_source=None. The proposed
  classified/materialized guard would not diagnose this case. No forced pointer
  commit or validation weakening accepted. Review:
  `m7-loadprogram-diagnosis/PARENT_REVIEW.md`. Next owner is the segment-contract
  producer/call-preservation state, not rewrite or rendered C.
  Parent then executed the COD image builder: the isolated62-byte fixture calls
  a registered synthetic RET at0x103d, not native loadprog. Full-module bytes
  still contain unresolved external calls. A RET-based preservation claim would
  be unsound; next work must supply authentic callee/environment evidence or
  explicitly scoped fixture assumptions, preserving separate native acceptance.

- Quality-dev71485 is terminal2: contracts305/admission1204/budgeted3 pass;
  broad units11025pass/8fail/27skip642.45s. Parent corrected four stale
  contract projections (scoped-view diagnostic, newly enrolled scoped owners,
  split GP runtime lanes, shortened agent guide); combined212tests pass20.47s
  and scoped lint passes. Four failures remain: SORTD pointer caller evidence,
  InitBars selector evidence, loadProgram validation/time limit, and the180s
  indexed inventory timeout. No broad-green or M5/M7 acceptance.
- LoadProgram fails again in isolation42.23s: pointer/value parameter mismatches
  at BP+0xa/+0xc precede terminal timeout. Devin17778 owns a read-only bounded
  diagnosis in `m7-loadprogram-diagnosis/`, with no production edits or rerun.
  Phase worker33175 is terminal0. Parent BC5 single-row calibration reaches
  the real comparator and preserves refusal; two independent tests expose
  overlapping-inclusive and cross-thread wall aggregation defects. Parent
  corrects staging;19worker and2parent controls pass, scoped lint passes.
  It remains diagnostic, not complete phase or final-corpus acceptance.

- Parent measurement review finds the existing optional profile harness still
  leaves public phase_seconds missing and declares incomplete hook coverage;
  rerunning it alone cannot close original M7 phase accounting. Devin33175
  now owns only private regular-file copies in `m7-phase-accounting-stage/`
  to improve explicit boundary/setup/other accounting, with synthetic controls
  and honest thread/process limits. No production, corpus, proof, or concurrent
  pytest execution authorized. Sandbox rootRO/repoRW/4GiB verified; source
  copies and baseline hashes retained. Quality-dev71485 remains live; contract
  305, admission1204 and budgeted3tests passed before the broad unit phase.

- Header intake is now integrated in production. Parent corrected the frozen
  boot-field consumer protocols; production MyPy and startup architecture gates
  pass. Four durable production test modules pass28controls16.92s, covering
  pending inventory, intake guards and actual-MZ conditional return evidence.
  The prior original SORTD failure remains unresolved; no function acceptance
  follows. Receipts: `m7-header-invocation-parent/production-controls.log` and
  `production-types-architecture-retry.log`. Required quality-dev now runs as
  process71485 with six test slots and one comparator admission worker.
- Devin71391 is terminal0; its read-only tail diagnosis is retained in
  `m7-terminal-tail-review/REPORT.md`. The proposed guard requires undeclared
  runtime stack/data premises and is not authorized evidence for current
  invocations. A reachable near RET alone also cannot prove preservation through
  unresolved callbacks. No guard implementation or proof promotion accepted.
  Devin62466 now audits only original M7 corpus/performance release receipts in
  `m7-release-receipt-review/`; no production edits or competing test runs.
- Release-receipt audit62466 is terminal0. Parent rejects its stale claims that
  confidence and near-return scope repairs remain staged: production consumers
  and prior121/82-pass integration receipts confirm those integrations. Final
  corpus obligation remains55rows per phase over7lanes, with current phase
  timings and dependency-control linkage on frozen sources. Do not duplicate
  completed integration or overlap that run with quality-dev71485. Reconciliation:
  `m7-release-receipt-review/PARENT_REVIEW.md`.

- Original SORTD static pointer-output comparison is terminal on both sources:
  baseline1fail94.59s (case77.382s), staged1fail70.73s (case68.171s), same
  caller-target IR_BUILD_REFUSED. Overlay imports occur before pytest timing,
  so totals are not an end-to-end speed comparison; one case sample shows no
  added slowdown but proves no function fix. Receipt:`m7-header-invocation-parent/
  static-comparison.json`. Header stage remains awaiting production promotion.
  Devin71391 (`rainbow-parsnip`) now owns a bounded read-only terminal-tail
  diagnosis under `m7-terminal-tail-review/`: reuse existing M5 outcome owners,
  no repeated SORTD replay, tests or source edits. Sandbox rootRO/repoRW/4GiB
  verified. Original M5/M7 acceptance stays open.

- Final merged header stage passes52controls17.38s (isolated imports avoid
  duplicate production/staged budget-test module names); corrected owners are
  scoped-lint/MyPy clean. Parent read the complete new boot owner and domain
  dispatch diff; header-only seeds remain CS/SS/SP with unknown GP/DS/ES.
  Before promotion, an original static SORTD pointer-output baseline now runs
  under an explicit180s outer diagnostic cap; staged comparison will follow
  serially. This test needs no KVM. No original-function acceptance inferred.

- Header worker66887 terminal0. Parent corrected the5independent admission/
  resource failures in an isolated copy:6controls pass2.06s; combined25pass
  10.95s; actual-MZ automatic-source callee controls3pass1.87s (valid return
  resolves, corrupted return refuses, universal publication remains denied).
  Exact final-worker diff reviewed; its mapped-byte type guard retained.
  Only the2corrected owners were reconciled into terminal worker staging,
  with its final version saved in `before-parent-admission-repair/`. Final
  staged lint passes; merged controls95505 and scoped types now run. No
  production header integration or original SORTD acceptance yet.

- Header correction66887 remains staged. Parent now has5independent failures:
  late-covered pending accounting, decode after boundary-budget exhaustion,
  stale refusal after retained-source replacement, reentrant intake restart,
  and authority installed despite an incomplete inventory ledger. The last3
  reproduce in2.77s through the explicit staged overlay, including an actual
  minimal MZ ledger corruption. Exact source snapshots, tests and logs live in
  `m7-header-invocation-parent/`; no header integration is accepted. Earlier
  parent pending-callee positive is now green in the worker's stage, but does
  not discharge these admission/resource requirements.

- Call-inventory optimization provisionally integrated after parent empty-query
  fix:49staged controls and60production rollback/helper/regeneration controls
  pass; scoped lint and MyPy with snapshot provider pass. New durable test is
  enrolled. Enrollment67pass plus8temporary-directory failures, then the same
  8pass with writable TMPDIR. Native SetGear could not start: exact KVM opener
  reports ENOENT in this launch. No native speedup/function acceptance claimed.
  Receipt:`m7-call-inventory-parent/REVIEW.md`. Worker5902 terminal0.
  Header66887 still stages its correction; parent reproduced2new accounting/
  pre-decode-budget defects in `m7-header-invocation-parent/` for final review.

- Call-inventory parent found one concrete regression: empty expected-name
  query loses its no-traversal fast path (baseline1pass/candidate1fail).
  Worker42controls pass, but saved full-guard timing is slower:5.559s→9.340s,
  despite60→30walks. Parent alternating same-AST observation-only measurement
  separately gives median CPU0.737141s→0.363808s. Neither measurement proves
  native improvement. Review/receipts:`m7-call-inventory-parent/REVIEW.md`.
  Wait for terminal5902, restore the empty-obligation guard, then independently
  verify final stage before considering integration. Header66887 remains live.

- Call-inventory parent review: exact candidate diff inspected; saved production
  baselines still match. Six independent baseline/candidate controls pass13.94s:
  failed rollback raises for total/named loss; the next rewrite reads the
  replaced live tree. Receipt:`m7-call-inventory-parent/initial-review.json`.
  Worker5902 is still validating its full staged cohort; no integration or
  end-to-end speedup follows from these focused controls.

- Parent KVM audit recheck: all97source-audited test functions carry their
  requires_kvm marks; collection controls5passed0.83s. Static comparator work
  remains independent of KVM. Header15118 is terminal0; its12+114+72staged
  positives do not resolve the parent pending-callee red. Exact stage saved in
  `m7-header-invocation-stage/before-parent-correction/`; resumed same Devin
  as66887 for bounded caller-frame intake repair and eager-scan cost review.
  Current sandbox verified rootRO/repoRW/4GiB. Call-inventory5902 remains live,
  staging only; no native performance or M5/M7 acceptance claimed.

- Bounded call-inventory optimization started as5902 in `rainbow-parsnip`:
  `_rewrite_round_apply_8616` currently scans the same unchanged AST for total
  calls and then named calls; the candidate must combine only these adjacent
  observations, with fresh evidence after each rewrite/restore and no cache
  across passes. Current source and baseline saved in `m7-call-inventory-stage/`.
  Worker may edit staging only and run focused parity/traversal-count checks;
  no native speedup is presumed. Header15118 still runs its scoped checks;
  the independent pending-callee intake failure remains unresolved.

- Snapshot observer28155 completed; parent independently verified spawned-child
  binding, corrected runner path/cleanup/single-run guards, and ran46726.
  Actual analysis worker completes63pickle snapshots in4.270727s with no
  completed deepcopy fallback; all5cache events miss, sources unchanged.
  CLI still returns timeout (35.255s diagnostic, inner20s unchanged). This
  confirms path usage, not an end-to-end speedup or function fix. Per-child
  KVM/init limitation and exact receipts:`m7-snapshot-worker-profile/PARENT_REVIEW.md`.
  Header-input stage has a separate parent red: minimal MZ CALL→pop-cx/JMP-cx
  cannot install its source because transitive inventory requires callee
  closure first (INVENTORY_REFUSED at0x10020). No backward error tail exists
  in this fixture. Review:`m7-header-invocation-parent/REVIEW.md`; worker15118
  still runs, no production intake integration yet.

- Snapshot v3 is provisionally integrated after real-angr manager-binding
  regression2passed12.25s and final production rollback/regeneration/ownership
  cohort84passed13.15s. Parent added durable mutation/alias, missing-tree,
  corruption, fallback and unexpected-reducer controls, fixed one return type,
  and enrolled the helper/tests; lint, scoped MyPy and startup architecture pass.
  Native acceptance remains RED: verified same-process KVM API12 then original
  SetGear test exceeds unchanged30s subprocess timeout (1failed39.39s;
  `m7-pickle-parent-review/setgear-verified.xml`). Earlier redirected launch
  attempts saw missing KVM before pytest and remain separate receipts. A
  follow-up parent-only cost hook observed0calls and is explicitly invalid
  profiling evidence; it cannot establish snapshot usage or native speedup.
  Header-input Devin15118 remains active, staging only. Snapshot observer
  preparation is active as28155 in resumed `rainbow-parsnip`: static synthetic
  child-binding verification only; parent owns the one subsequent actual
  diagnostic because the KVM-enabled worker launcher failed before startup.
  Task:`m7-snapshot-worker-profile/`. M5/M7 stay open.

- P1 header-derived invocation intake started in private staging as15118
  (resumed Devin `tremendous-sunfish`). Parent verified DOSMZ supplies only
  header CS/IP/SS/SP and a load paragraph; current declared-boot intake requires
  environment fields and cannot be reused by inventing zero GP/segment values.
  Task requires a separate typed static input, independently relocated source
  and mapped-byte authentication, unknown registers kept unknown, and unchanged
  scoped/universal refusal boundaries. Baseline and task:
  `m7-header-invocation-stage/`, `.cache/devin-prompts/m7-header-invocation-stage.md`.
  Production remains read-only for this worker; no P1 acceptance yet.

- Per-edge frame transport is integrated after Devin65034 terminal0 and parent
  full-delta review. Parent staged controls20passed23.29s; final production
  cohort100passed42.39s, scoped lint and mypy-dev pass. Shared callee imports
  now use the actual transporting edge with decoded-byte/native agreement;
  conditional publication and scope isolation stay enforced. New tests are
  enrolled in the serial scoped-IR lane and ownership manifest. Receipt:
  `m7-per-edge-parent-review/INTEGRATION.md`. P1 invocation installation/P3
  backward-tail and original SORTD acceptance remain open. SetGear98388 ended0;
  its v2 rollback parity failure remains rejected. Same Devin session resumed
  as32291 with the exact manager-binding control and typed snapshot obligation.

- 2026-10-05 parent review: corrected per-edge stage independently passes the
  two original transported-instruction corruption controls (2passed5.70s;
  explicit staged-owner import asserted). Devin65034 is still running its
  broader scope controls; no production integration yet. SetGear98388 remains
  live and has replaced the rejected event cache with fresh pickle snapshots.
  Parent found a new real-angr parity defect: replacing the live CFunction
  after capture changes the manager attached during rollback. Baseline passes,
  candidate fails (1failed/1passed25.12s). Saved baseline is byte-identical to
  current production. Required binding and exception-policy corrections are
  recorded in `m7-pickle-parent-review/REVIEW.md`; no speedup accepted.

- SetGear profiling worker76588 terminal0: one fresh diagnostic36.302s,
  all5cache events miss, unchanged source snapshot; inner20s analysis still
  times out during repeated rewrite snapshots/AST walks. Parent rejects its
  staged event-only rollback cache: independent same-guard replay restores
  4calls before versus3in the candidate after an unreported insertion and a
  subsequent lossy pass (1failed23.07s). Cycle detection and the existing AST
  generation token are insufficient state witnesses (real value/type mutation
  controls retained). No candidate integration or native speedup claimed.
  Devin session `rainbow-parsnip` resumed as98388 with exact parent failures;
  receipt:`m7-setgear-current-profile/PARENT_REVIEW.md`.

- Independent staged per-edge frame task87863 (`tremendous-sunfish`) now has
  13focused worker positives and a real before-variant callee-unresolved
  counterexample; full staged scope controls and parent review remain pending.
  Scope stays exact decoded call-edge transport for shared callees, preserving
  context-free ambiguity, scope isolation and backward-tail refusals. Baseline
  and output:`m7-per-edge-frame-stage/`. Production remains unchanged.
  Parent subsequently found2actual decoded transport-corruption failures:
  a66E8 wide CALL and an E9 JMP borrow the source index's word-frame premise
  when coordinates match. Correct staged-overlay replay2failed5.00s;
  `m7-per-edge-parent-review/PARENT_REVIEW.md`. Existing worker positives do
  not close this gap. Worker87863 is terminal0; same Devin session resumed as
  65034 with the two parent failures and exact overlay instructions. The worker's
  out-of-scope PROGRESS append was removed precisely; parent owns progress docs.

- 2026-10-05 current checkpoint: Devin's logical-transfer typing repair is
  independently reviewed against its saved dirty baseline; all14parent controls
  pass30.00s. MyPy-dev and full architecture checks are terminal green (the
  duplicate invocation-domain architecture registration was removed; typing-only
  provider enrollment remains). Evidence: `m7-logical-transfer-types/parent-tests.log`
  and `m7-register-return-parent-review/{mypy-dev-final,architecture-full-final}.log`.
  Comparator integration gate passed305contracts25.43s and1204comparator tests
  277.44s with2comparator workers and unchanged budgets; log
  `m7-register-return-parent-review/comparator-current.log`. Bounded Devin
  task `m7-current-caller-review/` reviews the remaining exact SORTD caller without
  production edits; original native regressions remain unaccepted.

- SetGear latest verified-device replay is a real failure, not a KVM skip:
  launcher and pytest child share API12, then the original subprocess hits
  its unchanged30s timeout (1failed59.86s pytest). Exact JUnit:
  `m7-register-return-parent-review/setgear-verified-current.xml`.
  This supersedes the environment-only diagnosis for this run; no source,
  timeout or acceptance assertion was relaxed.

- Parent reproduced missing-detail Capstone exceptions in near-call frame
  premise construction/freshness. A bounded staged fix handles only
  CS_ERR_DETAIL as absent evidence; unrelated decoder errors propagate. Review
  controls and saved owner baseline are in `m7-near-call-detail-review/`.
  Saved-owner controls3failed/1passed; candidate4passed. Integrated exact delta
  after production-baseline comparison; canonical three-module suite86passed
  98.95s, scoped lint/MyPy-dev/startup architecture pass. This is a boundary
  refusal repair, not a claim that the native timeout or remaining SORTD callers
  close. Earlier305+1204gate receipt predates this small integration.

- Devin caller review87757 terminal0: current exact caller replay88.424s retains
  the same five selector refusals and absent invocation authority. Parent
  accepted the independent backward-tail/scope obligations but rejected raw
  E8-scan counts as decoded-caller proof and any claim that every future bound
  entry guard is impossible. Receipt:`m7-current-caller-review/PARENT_REVIEW.md`.
  Devin76588 now profiles the separate SetGear timeout under verified KVM,
  staging only, bounded one diagnostic with unchanged inner20s budget;
  prompt/baseline in `m7-setgear-current-profile/` and `.cache/devin-prompts/`.

- KVM distinction is explicit in README and agent execution rules: static
  real16/PE32 SSA/Z3 comparison does not need KVM. Marker controls5passed and
  static comparator smoke4passed; earlier marker audit added94function marks.
  Device visibility currently differs between command launches: direct API12
  and sandbox API12 probes succeeded, while SetGear's run skipped and a later
  verified-device launcher failed with ENOENT. Preserve both observations;
  no native acceptance follows from a probe in another process environment.

- Typing-provider enrollment is now complete for this change: MyPy-dev's
  remaining4diagnostics are all in logical_memory_register_transfer, with
  missing-provider errors eliminated (no ignores/casts). Bounded Devin63964
  owns only that source file; saved dirty baseline and reviewed source facts
  are in `m7-logical-transfer-types/`. Worker reports scoped types/lint clean
  and is running relevant controls; parent review remains pending. Full
  architecture gate22777 is active, log `m7-register-return-parent-review/architecture-full.log`.

- Integrated proof cohort82passed; parent fixed the real scoped-view union
  annotation afterward. Typing checkpoint remains red: exposing invocation,
  boundary and IR record owners under follow_imports=skip reveals missing
  re-export providers plus four logical_memory_register_transfer diagnostics.
  Do not call the integrated gate green or add casts/ignores to hide missing
  owned types. Logs:`m7-register-return-parent-review/mypy-dev-{domain,records}.log`.

- Reviewed scope repair integrated after exact saved-baseline verification:
  10production files,3promoted test modules. Canonical-import cohort82passed
  57.81s; startup architecture and scoped lint/type-doc pass. Before integration
  the parent combined run had81pass/1test-import failure; importing the coverage
  owner directly resolves that harness error (1passed13.02s). Registered the
  proof/view owners, width fast controls and serial scoped proof controls;
  durable contract:`reference/near-return-continuation-contract.md`.
  Parent adds explicit scoped-view union annotation; MyPy-dev then reports only
  five missing-domain-type diagnostics. Enrolled the real invocation-domain
  owner in that cohort and checking again; no casts/ignores or semantics relaxed.

- Devin58544 terminal0 after reproducing all6parent reds, then repairing
  exact-ledger consumption and decoded near16 call-width admission/freshness.
  Parent reviewed both owner deltas against the saved baseline; worker reports
  72staged+10parent controls and scoped lint clean. Independent combined82-node
  parent run now starts on the final staged sources, no result inferred yet.
  Receipt:`m7-register-return-parent-review/final-combined.{log,xml}`.

- Current SetGear replay is environment-limited, not a pass:1requires_kvm
  skip31.61s. JUnit and direct kvm_access_evidence agree missing/errno2 for
  /dev/kvm in this process environment. Historical availability is not current
  access; keep native acceptance open. SSA/Z3/static review remains available.
  Receipt:`m7-remaining-acceptance/setgear-current.{log,xml}`.

- M5 current scope/evidence review sealed as implementation coverage, not
  milestone acceptance:347distinct passing nodes share one2845-file snapshot;
  I/O refresh50passed93.60s/97.18s outer, unchanged sources. Explicit initialized-
  component and environment premises remain conditional; arbitrary-entry rows
  stay unupgraded. Current evidence index now lists required checkpoint gates
  as its remaining obligation. Review:`m5-original-acceptance-audit/FINAL_SCOPE_REVIEW.md`.
  Original SetGear failed node now rechecks on this production tree, receipt:
  `m7-remaining-acceptance/setgear-current.{log,xml}`. Devin58544 remains staging-only.

- Current M5 per-node index materialized:297distinct passing nodes from the
  recursive positives,180prefix controls and114service/fault controls, with
  identical2845-file before/after snapshots across all receipts. The superseded
  deadline failure remains a separate recorded attempt. Index is explicitly
  incomplete pending I/O and final scope/clause reconciliation:
  `m5-original-acceptance-audit/current-evidence-index.json`. No milestone claim.

- Final service/fault cohort terminal0:114passed42.12s pytest/47.01s outer,
  unchanged2845-source snapshot; includes both actual-binary symbolic x87
  refusals. Ordered-I/O50-case refresh now runs serially: old receipts predate
  source changes included in the global model fingerprint, so no current-model
  claim is inferred from that older green run. Receipt roots:
  `m5-original-acceptance-audit/{service-final-refresh,io-final-refresh}/`.

- Remaining M5 prefix is terminal0:180passed/0failed/0skipped across15modules,
  1140.74s summed process elapsed; all2845source/test hashes unchanged. Combined
  with the separately terminal three recursive positives, all183previously
  interrupted-prefix nodes now have explicit passing per-node receipts on the
  same production sources (earlier deadline failure remains recorded).
  Final service/fault refresh now runs because its earlier receipt predates
  added symbolic x87 controls; unchanged I/O ownership is under dependency
  reconciliation. Receipts:`m5-original-acceptance-audit/{prefix-remaining-final,service-final-refresh}/`.

- Scope-repair worker28372 terminal0; parent launches bounded follow-up58544
  on exactly the two staged owners/tests for ledger reconciliation and decoded
  near-call width admission. Baseline preserved in before-parent-ledger-width;
  rootRO/repoRW/4GiB boundary reverified. Production remains frozen.
  Historical M5 near-indirect gap is independently reconciled: current actual-MZ
  self/equivalent/corrupt near-call tests all pass, as does unknown-target
  refusal. Fresh JUnit plus production-frame review recorded in
  `m5-original-acceptance-audit/NEAR_INDIRECT_RECONCILIATION.md`; no narrower
  scope decision or duplicate implementation is needed.

- Parent finds a second staged scope-premise defect: actual decoded66E8 near
  CALL (dword return address) is admitted as the required return-word premise.
  Ordinary E8 positive passes; wide-call refusal fails:1failed/1passed26.69s.
  Earliest repair belongs in premise construction/freshness, with real decoded
  width facts replacing address/size-only test rows. Receipt/review:
  `m7-register-return-parent-review/CALL_FRAME_WIDTH_REVIEW.md`. No integration.
  M5 remaining-prefix suite has99terminal passes and continues.

- Parent scoped-view ledger candidate:8passed58.91s, exit0. This closes the
  five malformed-counter controls in the isolated candidate while retaining
  native-byte revocation and universal-publication rejection. Reconciliation
  into Devin's final staged owner and scoped lint/types remain pending;
  candidate Ruff reports one unused import and two complexity findings.
  Exact before/candidate sources and review:`m7-register-return-parent-review/LEDGER_REVIEW.md`.

- Parent rejects staged scope repair pending ledger fix: five independent
  counter mutations (each count independently incomplete/nonzero failure)
  still authorize complete scoped coverage. Exact red:5failed44.75s,
  `m7-register-return-parent-review/scope-ledger.log`. Separate parent candidate
  checks exact integer counters against the retained proven-block count in
  the scoped projection owner; all eight parent controls now run against that
  candidate. Worker tree and production remain untouched by this parent fix.

- Parent scope-repair controls:3passed50.01s in staging. Actual-MZ raw
  conditional artifact cannot publish universally; mutating caller or callee
  bytes invalidates retained view/coverage/closure. Worker reports62staged
  positives/controls and is still producing baseline/type evidence. Parent
  now checks five incomplete evidence-ledger mutations before acceptance.
  Receipt:`m7-register-return-parent-review/{scope-freshness,scope-ledger}.log`.
  No production integration. M5 remaining-prefix run has terminal13passes
  across its first two modules and continues into PE32 recursion.

- Exact equivalent-changed pytest recheck now terminal0:1passed,99.57s outer
  elapsed, unchanged source snapshot and unchanged proof budgets. Together
  with the two passing original controls, all three assertions have terminal
  passing evidence on the same production tree; retain the earlier deadline
  failure as timing-sensitivity evidence, not a stable performance claim.
  Remaining180prefix nodes now run serially by module, fail-fast with per-node
  JUnit and source snapshots in `m5-original-acceptance-audit/prefix-remaining-final/`.
  Production stays frozen; Devin28372 still tests the staged scope repair.

- Recursive positive cohort is terminal:2passed/1failed342.15s, unchanged
  sources. Equivalent-changed alone refused joint_deadline_exceeded; identical
  and undeclared-environment assertions pass. Same-budget changed-body profile
  subsequently completes conditional/joint_physical_model_not_closed in100.51s,
  counters213/213/213/213/0 and unchanged sources. Its142semantic hashes cost
  54.51s cumulative (overlapping timings, not an additive phase total).
  This demonstrates timing sensitivity, not stable acceptance or a measured
  speedup. Exact failed pytest node now reruns without instrumentation, serially,
  preserving original budgets and source freeze. Receipts:
  `m5-hash-traversal-stage/{parent-positive,parent-changed-recheck}/` and
  `m5-original-acceptance-audit/recursive-changed-profile/`.

- Full architecture gate now terminal0:decompiler full architecture checks
  passed, including the promoted confidence owner; no dynamic-access exemption
  added. The first original recursive positive (identical component) passes
  under unchanged request/joint budgets after digest-only integration. The
  undeclared-environment and equivalent-changed controls are still running;
  do not count a terminal three-case cohort or M5 acceptance yet. Receipts:
  `m7-confidence-evidence-parent/architecture-full-final.log` and
  `m5-hash-traversal-stage/parent-positive/tests.log`.

- Integrated hash freshness/final-seal cohort:28passed/1external warning,
  23.41s; scoped MyPy and lint/type-doc pass. Original identical, undeclared-
  environment and equivalent-changed recursive positive controls now run
  serially, fail-fast with live failure diagnostics and source snapshots,
  under unchanged300srequest/120sjoint budgets. No speedup/proof claim yet.
- Full architecture check found only missing promotion registration for new
  confidence_evidence (Make typed/Ruff enrollment already present). Added it
  to the canonical promoted-owner registry; no debt/exemption added. Final
  full architecture check rerunning. Confidence121-test result stays focused
  evidence, not full release-gate acceptance.

- Parent hash regression against unchanged production:2failed/7passed,
  5deselected19.52s; failures count native-source scans2/3 rather than1.
  Exact-baseline verified integration adds only two pure-digest snapshot
  wrappers using existing active-capture semantics. Routine model-refresh
  tests now cover both new owners and exception cleanup; scoped lint/type-doc
  passes. Freshness/final-seal cohort and scoped MyPy running; original
  same-budget recursive positives still pending. Receipt:`m5-hash-traversal-stage/`.

- Confidence repair integrated after exact dirty-baseline verification and
  independent final56pass/3fail red →59pass green. Parent added explicit role
  type guard to preserve malformed diagnostics. Production confidence plus
  ownership cohort:121passed/1external warning29.47s, exit0; scoped lint,
  type/doc ratchet, MyPy and startup architecture pass. New typed reporting
  owner and59controls enrolled in Make/fast pipeline/ownership with producer
  contract documentation. Full architecture check running; no semantic proof
  or broad-release acceptance claimed. Receipt:`m7-confidence-evidence-parent/`.
- Hash-traversal Devin78162 terminal0 with14staged controls; parent reviewed
  both minimal digest-only wraps and begins existing routine model-seal tests
  extended to both owners against pre-change production. No hash optimization
  integrated yet; same-budget recursive positives remain required afterward.

- Confidence Devin42355 terminal0: parent independently checks final candidate
  plus3malformed-role controls, obtaining56passed/3failed5.17s. Parent's final
  candidate retains all worker typing fixes plus the explicit str guard;
  combined59-case verification is running in staging. No production integration.
- Bounded hash-traversal Devin78162 stages only bound_operand_model_hash and
  outcome_scope_model_hash using the existing active-capture pattern. Reviewed
  pure-DAG opportunities reduce native leaf calculations2→1 and3→1 within
  one digest construction. Domain-consumer hashes are explicitly excluded:
  source/domain validation separates them and final freshness is mandatory.
  No global cache or before/after boundary sharing. Prompt and exact baseline:
  `m5-hash-traversal-stage/`; rootRO/repoRW/4GiB sandbox reverified before launch.

- M5 profile completed on unchanged sources:136.49s instrumented public call,
  141semantic-source hash invocations78.93s cumulative,184native-model hash
  calls79.75s;22domain-consumer prerequisite validations29.96s. These are
  overlapping diagnostic times, not additive phase totals. Fresh serial-vs-
  threaded source hashing ABBA(8runs) preserves identical digests but shows
  no serial speedup (~0.40–0.42s each); retain threaded implementation.
  Next bounded review targets duplicate native digests inside a single
  identity-validation traversal only, preserving independent proof-boundary
  freshness. Receipts:`m5-original-acceptance-audit/recursive-positive-profile/`
  and `hash-abba.json`; no budget increase or production optimization yet.

- Exact M5 positive diagnostic is terminal:144.30s, unchanged sources;
  recursive_joint UNKNOWN/joint_deadline_exceeded with detail
  `address_model_original_deadline_exhausted: original loaded-relation deadline exceeded`.
  Counters189/189/189/179/10; no domain scope or assumptions admitted.
  Public300000ms request retains the existing120000ms joint-stage cap;
  empty assumptions are honest refusal projection, not a serialization defect.
  Parent starts cProfile on that exact path/budget to attribute cost before
  optimization. Receipt:`m5-original-acceptance-audit/recursive-positive-diagnostic/`;
  diagnostic profiling:`recursive-positive-profile/` under the same directory.

- M5 terminal-prefix attempt exposes2recursive-positive failures (missing
  expected assumptions),9passes; parent interrupts after the second failure
  to retain tracebacks rather than spend further proof budgets blindly.
  Pytest exit2,723.77s; source snapshot unchanged. Of183selected nodes, only
  the first14-node module was scheduled; remaining outcomes are pending, not
  passes. An exact same-budget diagnostic replay now retains the full public
  report in `m5-original-acceptance-audit/recursive-positive-diagnostic/`.
- Bounded M7 receipt audit completed: `m7-remaining-acceptance/REPORT.md`
  distinguishes11historical native failed IDs from later focused repairs;
  none of those IDs is covered by the193+10alias/segmented-memory cohort.
  It records existing phase instrumentation and the required final-source
  refresh rather than treating that instrumentation as missing work.

- Parent confidence review adds3independent malformed-role controls: staged
  string-effect roles containing list/dict values raise TypeError during set
  membership instead of recording malformed evidence. Exact red-source hash
  preserved; a separate parent snapshot with explicit str guard passes all3
  controls5.70s. Devin's typing repairs are still active; parent fix/tests must
  be reconciled into its final candidate, not overwritten from a snapshot.
  Receipt:`m7-confidence-evidence-parent/PAYLOAD_REVIEW.md`. No integration.

- 2026-10-05: Alias-fixture follow-up is terminal:10passed/1external warning,
  39.32s, exit0. Unproved DS byte pairs and wrapping pairs refuse; the proved
  adjacent pair retains the original replacement/value assertions. Receipt:
  `m7-remaining-dynamic-parent/alias-fixture-tests.log`. This resolves that
  focused fixture failure, not the full release gate.
- M5 interrupted-prefix closure now runs exactly183previously inferred nodes
  (145recursive/callback plus38scope consumers) serially by module, retaining
  per-node JUnit reports and source snapshots in
  `m5-original-acceptance-audit/prefix-terminal/`. No already-terminal tail
  cohort is repeated, and solver budgets are unchanged. Production integration
  remains frozen while this proof run executes; both Devin repairs stay staged.

- Parent rejects near-return scope integration: the actual-byte positive
  returns an unregistered premise-derived IR artifact whose ordinary coverage
  refuses ir_not_project_owned. Explicit universal publication then accepts
  that same conditional artifact PROVEN and universal coverage becomes complete.
  Not publishing in one resolver is insufficient protection. Reproducer and
  rejection: `m7-register-return-parent-review/scope-probe.json` and
  `SCOPE_REVIEW.md`. Bounded staged Devin scope repair active; no integration.
- Indexed DS byte-pair failure is an invalid fixture admission: it supplies
  no alias identity/no-wrap evidence but expects a word store, contrary to
  current widening ownership. Parent preserves that unproved case as a refusal
  and adds exact adjacent-identity positive plus segment-wrap refusal. No
  production behavior changed; original positive replacement/value assertions
  remain for proved input. Scoped lint passes; focused tests running.

- Parent independently replays the repaired near-return proof: all4original
  counterexamples plus partial CH overwrite and implicit AH/LAHF overwrite
  now refuse (6/6); structured records are retained in
  `m7-register-return-parent-review/repair-counterexamples.json`. Original
  red evidence is preserved separately. This clears those defects only;
  full proof/seam review and final production tests remain before integration.

- Parent baseline classification: indexed DS byte-pair coalescing failure
  reproduces unchanged against all4saved pre-change modules loaded through an
  isolated import hook (1failed27.16s). Both runs fail changed-is-True at the
  same assertion. This is pre-existing, still unresolved release evidence;
  it does not invalidate the193passing changed-surface controls or make the
  cohort green. `m7-remaining-dynamic-parent/baseline-failure.log` records the
  exact loaded source paths; no stash/reset or clean-HEAD substitution.
- Register-return repair worker is terminal0 with53staged tests passing;
  parent independent replay of4original corruptions plus2carrier-clobber
  controls is running. No production integration or original SORTD acceptance.

- 2026-10-05: Parent reviews/integrates three-owner dynamic-access repair
  plus AST-identical trivial_copy diagnostic documentation. Parent first
  reproduces worker adapter swallowing AttributeError from evidence truthiness;
  narrows the catch to attachment lookup and adds5routine controls. Scoped
  lint/type-doc passes and4owner architecture findings are0 (15resolved).
  Focused integration:193passed/1failed69.15s; failure is indexed DS byte-pair
  coalescing in test_x86_16_cli. Exact saved-source baseline reproduction is
  running in an isolated import process; not classified yet. Receipt directory:
  `m7-remaining-dynamic-parent/`. No green integration claim.
- Confidence reporting draft remains rejected: parent concrete probes show
  empty array candidate counted as evidence, confidence2.0 and negative counts
  admitted without malformed diagnostics. Separate bounded staged Devin repair
  is active; no production integration. Evidence: `m7-confidence-evidence-parent/`.

- 2026-10-05: Scoped-consumer tail completes67passed/1external warning,
  374.33s pytest (383.39s elapsed); all2844 recorded source/test hashes match
  before/after and the original interrupted scoped-run start. Seven cases
  overlap the prior prefix; remaining38cases retain explicitly reconstructed
  progress evidence, not a fabricated terminal cohort. Updated parent review
  in `m5-original-acceptance-audit/REFRESH_REVIEW.md`.
- The actual-MZ/PE32 x87 instruction-scope refusal controls are integrated in
  existing routine test_symbolic_terminal_faults.py:2passed35.08s,Ruffclean.
  Both lanes assert no trace and typed INSTRUCTION_SCOPE refusal. No KVM;
  no production semantic edit. M5 sealing and M7 gates remain open.

- 2026-10-05: Ordered-I/O remainder completes50passed/1external warning,
  257.68s pytest,268.83s receipt elapsed,2844source/test hashes unchanged.
  Parent-refresh before hashes exactly equal io-refresh after hashes. This
  closes fresh I/O/caller-premise execution evidence without upgrading any
  conditional result; scoped-consumer tail and M5 sealing remain pending.
  Reconciliation and inferred-prefix limitations: `m5-original-acceptance-audit/
  REFRESH_REVIEW.md`; full per-node output in `io-refresh/tests.log`.

- 2026-10-05: Source-frozen scoped-consumer refresh also hit its700s outer
  limit (exit124,705.09s),45passing indicators/no failures;2844hashes stable.
  Same-tree collection identifies105selected cases. Only the5unfinished
  modules are rerunning with per-node verbose results; receipt directory
  `m5-original-acceptance-audit/scope-tail-refresh/`. The12-module M5 run
  selected195cases;145recursive/callback cases precede the partially run
  ordered-I/O modules. Both I/O modules (50cases) are rerunning in full in
  `io-refresh/`. Prefix identities are explicitly inferred from ordered
  progress indicators, not represented as a terminal passing pytest receipt.
- Register-return Devin reproduces22failing/31passing staged controls before
  repair, including return-slot overlap, operand width, stale BP and ENTER
  nesting. This strengthens the prior rejection; no production integration.

- 2026-10-05: Serial12-module M5 refresh reached its1200s outer timeout
  (exit124,1203.78s elapsed) after151passing indicators, no failure indicator.
  All2844 pre/post source/test hashes match. This is incomplete execution,
  not a passing cohort. Exact serial collection reconstruction is in progress
  to select the unfinished tail; future execution retains per-node output.
  Receipt: `m5-original-acceptance-audit/parent-refresh/receipt.json`.
- Fresh dynamic-access census confirms22findings across5owners. Disjoint
  staged Devin tasks now own the three-owner10finding boundary/attachment
  repair (`m7-remaining-dynamic-stage/`) and7confidence evidence-contract
  findings (`m7-confidence-evidence-stage/`). Neither may edit production or
  run pytest during the proof freeze. Parent staged5debug-only findings in
  trivial_copy with executable-AST-identical boundary documentation. No
  checker exemptions or production integration; counts are baseline, not green.

- 2026-10-05: M7 execution-spec reconciliation removes the stale blanket
  flat32 indirect-call refusal statement. It now describes complete finite
  target coverage with actual callee effects, and separates ordinary-call
  recursion refusal from opt-in conditional recursive-component reports.
  This is a documentation correction supported by existing production
  driver controls, not a new proof capability or final M7 acceptance.

- 2026-10-05: Parent resolves the M5 symbolic x87 coverage question with
  actual MZ and PE32 FLD1-before-exit bytes: both self-comparisons refuse
  instruction_scope_refused/unmodeled_register_file. Diagnostic receipt
  `m5-original-acceptance-audit/x87-symbolic-probe.json`; matching durable
  regression is staged there until the source-frozen proof runs finish.
  This confirms an honest scope limitation, not floating-point support.
  Historical storage-fixture repair recommendation is already integrated
  in commit c72d22b3a; no duplicate Devin task launched.

- 2026-10-05: Parent refreshes the four-module declared-service/fault cohort:
  112passed,1external warning,50.64s pytest (57.19s receipt elapsed). All2844
  recorded source/test hashes remain unchanged before/after. This replaces
  the stale service receipt for current M5 evidence, without promoting
  conditional environment results to universal proof. Serial recursive/
  callback refresh remains live; the11-module scoped-consumer refresh has
  started, both with frozen sources. Receipt: `m5-original-acceptance-audit/
  service-refresh/receipt.json`. M5/M7 remain open.

- Parent corrects another audit staleness: invocation-scope protection is
  integrated, with historical87 contract/20 native controls, not merely staged.
  Current23-file receipt comparison finds9 changed paths. Hash-authenticated
  archived sources establish4 changes are documentation-only;3 have executable
  AST changes and2 lack an exact matching archive. Current-source reconciliation
  remains required; do not rerun or count the unchanged/documentation-only
  subset as a new capability. Receipts: `m5-original-acceptance-audit/
  parent-scoped-integration-hashes.json` and `parent-scoped-drift-classification.json`.

- M5 audit parent reconciliation verifies25/25 recorded production owners and
  15/15 receipts unchanged;19/20 tests unchanged, with the intentional new
  near-indirect controls accounting for the remaining test. Its near-indirect
  implementation-gap inference is rejected by the actual-MZ controls above.
  A serial12-module M5 refresh is running with pre/post source/test snapshots;
  production sources stay frozen. The prior112-test service/fault receipt has
  3 changed shared dependencies among172 recorded paths (straightline_ssa,
  real16_call_retry, real16_macro_retry); refresh that separate cohort next
  instead of treating the old result as current acceptance. Hash reviews:
  `m5-original-acceptance-audit/parent-*-hash-verification.json`.

- Parent corrects M5 audit's proposed near-indirect implementation gap: actual
  MZ bytes computing BX=callee_linear-(CS<<4), then CALL BX, already prove
  across the admitted CS aliases. New routine controls cover self/equivalent
  callee encodings (passed) and mutated result (observable_mismatch); existing
  unresolved CALL AX refusal remains. Each composed case verifies both target,
  return and CS-restoration proofs. Focused4passed27.35s; lint clean.
  `test_near_indirect_call_refuses` had an incorrect CALL BX comment despite
  encoding CALL AX; documentation corrected without changing its bytes.
  Receipt: `m5-near-indirect-control/`. Audit remains parent-reviewed evidence,
  not authority to narrow M5 scope or claim acceptance.

- Parent rejects staged register-return implementation: four independently
  decoded corruptions falsely prove (partial return-word overlap from either
  side, wide JMP ECX after POP CX, stale BP delta after ADD BP,1). Source/test
  hashes and reproducer retained in `m7-register-return-parent-review/`.
  No production integration. Original worker terminated; separate bounded
  repair task owns only the same staging directory and must repair general
  width/overlap/register-update rules, add red controls and retain error-tail
  refusals. Its passing17-test report was not sufficient soundness evidence.

- Dynamic-access scan reaches34 findings before the latest local boundary-doc
  update. Four reviewed angr AST traversal/diagnostic owners then resolve12
  further findings (4+1+6+1) through local optional-field contracts. Their
  executable ASTs are independently identical and per-file checks now report0;
  Ruff passes. No checker relaxation, module-wide exemption, traversal change
  or proof capability is claimed. Receipt:
  `m7-dynamic-access-review/ast-boundary-doc-review.json`.

- Reviewed five flagged accesses in addressing_helpers/condition_trace as
  genuine third-party pyvex/angr variant boundaries. Local docstrings now name
  the optional fields and preserve-unknown behavior; no module-wide exemption
  or checker change. Independent executable-AST comparison is identical for
  both files; scoped lint passes and their per-file dynamic checks report0.
  Receipt: `m7-dynamic-access-review/external-doc-review.json`.
- Bounded read-only Devin audit `m5-original-acceptance-audit/` is checking
  original M5 clauses against production controls and source-bound receipts.
  It must distinguish M5 gaps from M7 release/performance work and adjacent
  decompiler regressions without narrowing scope or claiming acceptance.
  Separate register-return staging remains subject to parent review.

- Direct word-global matching now consumes the existing typed Capstone operand
  view. Missing base/index evidence remains unknown instead of being fabricated
  as zero. Red controls:2failed/5passed; final provenance/prefilter/performance
  contract cohort:10passed39.43s; scoped lint passes. Actual 16-bit decoded
  direct/indexed/byte-load controls preserve accepted/refused forms. Isolated
  MyPy shadow baseline and final each report the same125 error messages,
  with0 new/removed; whole-module typing is not clean. Receipt logs and
  `global-address-type-parity.json` in `m7-dynamic-access-review/`.
  This is a focused fail-closed repair, not full decompiler acceptance.

- Discovery isolation now reads/writes its two owned signature-policy
  attachments through an explicit Protocol, retaining independent optional
  attachment boundaries and detached signature-only metadata. Added controls
  cover absent metadata, absent library setting, and both absent. Existing
  baseline1 passed; final4 passed14.28s; scoped lint/MyPy passed and the
  per-file dynamic-access check reports0 (formerly2). Receipt logs:
  `m7-dynamic-access-review/signature-*`. No additional semantic proof claimed.

- Current-tree PE32 dependency/cache controls: all6 production cases pass in
  60.76s (65.38s including snapshot/process overhead), with1425 recorded
  source/test hashes unchanged. Both adapters retain sealed unconditional
  cold/repeat proofs and invalidate direct/transitive mutated callees; BC5
  checks actual VEX cache hits, MSC8 uses first/repeat without that cache.
  Receipt: `m7-dependency-positive/current-parent-recheck/receipt.json`.
  This refreshes dependency evidence, not full corpus/release acceptance.
- Phase instrumentation already exists and was reviewed/executed in
  `m7-corpus-performance/parent-phase-corpus/`:14 attempts,55 obligations per
  phase, seven matching diagnostic pairs. Do not rebuild it as missing work.
  Current drift check finds101 changed files among its1413 recorded paths,
  zero missing; it does not detect additions. Historical phase coverage has
  named-hook/overhead limits and cannot certify final-tree performance.
  Receipt: `m7-phase-measurement/current-drift.json`. The later uninstrumented
  corpus run has no phase timings of its own; these are distinct receipts.

- Dynamic-access recount verifies53 findings after the primary-lane and
  assignment-field repairs. The subsequent dead-setup repair replaces five
  more flagged lookups with an explicit initialized-counter contract and
  already-type-guarded operator fields. Its per-file gate now reports1
  remaining heterogeneous statement-container finding (previously6).
  Dead-setup regression passes5 before and5 after (16.50s final); scoped
  lint/MyPy pass. Pruning evidence gates and decisions remain unchanged.
  Receipts: `m7-dynamic-access-review/dead-setup-*` and `dynamic-after.txt`.

- Explicit-contract cleanup replaces the string-selected primary semantic-lane
  getter with independent typed field reads, retaining each absent-attachment
  boundary and invalid-type/closed-loop failures. Two controls verify a missing
  sibling cannot erase an unmaterialized lane. Widening and trivial-copy owners
  now directly read lhs/rhs after their existing CAssignment type guards.
  Baselines: pipeline16 and assignment15 passed; final combined33 passed in
  24.46s; scoped lint and MyPy passed. Dynamic-access recount is pending; no
  full-gate or semantic-capability claim. Logs: `m7-dynamic-access-review/`.

- Fresh full architecture gate after promotion reconciliation reports exactly
  58 findings, all `promoted-typed-file-dynamic-attr`; the 91 enrollment and
  nine GNU-lane findings are gone. This remains a failing gate, not acceptance.
  Log: `m7-promotion-reconciliation/architecture-after-promotions.log`.
  Corpus harness now avoids adding another ten nice levels to an already-niced
  parent; actual subprocess verifies nice=10 and scoped lint passes. Prior
  timings are retained, not reinterpreted as controlled performance evidence.
  Receipt: `m7-corpus-performance/nice-verification.json`.
- Devin register-return implementation is staged only under
  `m7-register-return-stage/`, with no production edit authority. Outer sandbox
  rootRO/repositoryRW/4GiB verified before launch. Parent review must establish
  generic entry-stack continuation provenance and preserve unknown tail/call
  refusals before any integration; a staged result cannot close M5/M7.

- Parent reviewed Devin's Sleep repeatability diagnosis against the retry
  owner: a shared wall-clock deadline changes which stages execute. Required
  macro retries stopped at the first deadline gate now explicitly report
  `compose_budget_exceeded`, preserving prior evidence and UNKNOWN status;
  unresolved candidates retain their existing reason. Deterministic clock
  regression fails before the repair; all 15 retry-budget controls pass after
  it (2.56s), with scoped lint clean. This improves budget visibility, not
  cache parity or proof coverage. Receipt: `m7-sleep-repeatability/`.
- Promotion reconciliation focused cohort passes 55 tests in 32.69s; scoped
  lint passes. The wider architecture/type census still requires refresh.
  Read-only pointer diagnosis identifies the unresolved entry-stack return
  and backward error-tail closure at the prologue callee; no name-based
  exemption is admitted. Receipt: `m7-pointer-caller-refusal/REPORT.md`.

- KVM audit applied94missing function-level marks across14testfiles. Actual
  pytest collection selects all94requiredfunctions (161parameterized cases
  across those files including earlier marks); staticSSA/IR/Unicorn/GCC/mocks
  remain unmarked. Hook/provenance15controls pass. Core comparator needs no
  KVM; the earlier pointer deferral was incorrect classification. Fresh
  staticpair: exactbinaryboundary passes, pointercaller IR_BUILD_REFUSED
  remains. Native device verified available. Receipt `kvm-marker-audit/`.
- Frozen representative corpus completes14serial processes/110obligations
  with unchanged sources. Eachphase:3proved/2conditional/1counterexample/
  49unknown. Contract/dependency parity7/7; exactrowparity6/7: real16changed
  Sleep keepsUNKNOWN but refusal detail differs. Cold521.566s/repeat382.923s;
  maxRSS399896/397688KiB. Phase timings and dependencycontrol linkage still
  missing; no M7performance acceptance. Receipt `m7-corpus-performance/
  parent-run-20261004-final/PARENT_REVIEW.md`. GNUlane integration independently
  passes297tests; actual43GNUcases retained. M5/M7 remain open.

- Devin tooling-type repair removes8measured errors from3owners; parent
  independently checks25tests and248832validator combinations without
  acceptance changes. Optional Borland debug child rendering now retains
  unknown? rather than crashing on absent type children: red1failed8passed,
  final9passed; MyPy/Ruffclean. Receipts `m7-tooling-types/PARENT_REVIEW.md`,
  `m7-borland-optional-types/PARENT_REVIEW.md`. Frozen corpus execution is
  running; initial real16 self cold/repeat preserves3unknown outcomes with
  unmapped-call/macro-boundary reasons. KVM is now available and its launcher
  check passes; it applies only to native execution, not SSA/Z3 comparison.
  User requested complete requires_kvm marker audit; source-traced audit is
  in progress. No broad or milestone acceptance follows.

- Refreshed full architecture census158findings (formerly316):91promotion
  entries,58dynamic-boundary findings and9new GNU Make oracle skip findings.
  The GNU controls remain required; a bounded explicit external lane repair
  is in progress, rather than deleting skip/refusal evidence. Full typing
 627errors span78files; a bounded Devin owns3tooling modules with8diagnostics.
  Expanded promotion-owner typing verification remains pending. Receipt:
  `m7-promotion-reconciliation/architecture-current.json` and
  `typed-errors-by-file.json`; Devin log `m7-tooling-types/devin.log`.

- Final Make inventory integration and QA reconciliation pass225 parent tests
  in21.06s; actual Makefile gate now reports0 findings after removing11
  redundant entries, adding13 missing fast targets and enrolling the reader
  controls. Duplicate/refusal diagnostics remain enforced. Devin optional
  artifact repair preserves missing-evidence behavior; parent36controls pass
 10.83s. Full enrolled typing census on1414unique files still reports627
  errors, including1 in the91promotion candidates; no broad-quality acceptance.
  Receipts: `m7-qa-enrollment-repair/PARENT_REVIEW.md`,
  `m7-optional-attachments/PARENT_REVIEW.md`,
  `m7-promotion-reconciliation/typed-error-summary.json`.

- Parent independently verifies the 12-file public-contract documentation
  patch preserves executable ASTs and module docstrings. The final staged
  Make inventory reader passes178 tests in17.68s; production integration
  with typed diagnostic consumption and root-bounded includes is in progress.
  Receipts: `m7-public-contract-docs/PARENT_REVIEW.md`,
  `m7-make-parent-review/PARENT_TEST_REVIEW.md`. A fresh two-case pointer
  regression attempt stopped before pytest because the verified KVM launcher
  could not stat `/dev/kvm`; no native result is claimed. Log:
  `m7-native-current-pointers.log`. Broad/native/corpus acceptance stays open.

- Guarded-test routing is now explicit: 19 host-only functions stay in the
  focused pool; nested pytest and Linux descendant controls have sequential
  lanes; the GP-word DOS control stays an external/native obligation in
  default/expanded tiers. Parent reproduces 89 routing/receipt/Make controls
  and an actual four-case run with zero skips (10.986s serial, 6.772s Linux).
  The architecture tier contract requires the added lanes: positive baseline
  failed before reconciliation; final controls pass 32 tests. Make provider
  failure/empty inventories refuse instead of silently omitting tests, and
  explicit profile/target selections retain their scope. Native GP execution
  remains untested here. Parent reviewed the generic full-suite light-worker
  exclusivity repair: exclusive light paths run in deterministic standalone
  waves, preserving heavy reservations and limits. The partition/live cohort
  passes 34 tests in 13.20s. No broad-green claim is made. Receipts:
  `m7-skip-lanes/`, `m7-light-exclusivity/`.

- Reviewed Devin's 66 module ownership declarations and independently checked
  all 66 executable ASTs unchanged; ownership-header findings are now zero.
  Parent clarified the Lowering projection-integrity boundary while retaining
  IR ownership of SSA construction. These are documentation/gate repairs,
  not newly proved binary capabilities. A separate bounded documentation job
  addresses 40 public-contract docstring findings. The staged Make parser
  still awaits parent review after an additional unsupported-global-assignment
  counterexample; no unsound candidate is integrated. Receipt:
  `m7-owner-doc-headers/PARENT_REVIEW.md`.

- Parent-reviewed gate reconciliation and documentation split reduce the full
  architecture census from 316 to 295 findings. Current gate/namespace controls:
  24 passed; existing documentation/project-map controls: 31 passed. Canonical
  hard rules and acceptance remain in AGENTS; detailed Devin/compaction guidance
  and module evidence move to linked references without dropping requirements.
  Two typed repairs retain class-level scan limits and private Enum identity;
  parent independently reproduces 101 focused passes in 19.94 seconds.
  Scoped MyPy passes with the imported typed placement owner included; the
  earlier two-file no-any-return finding was incomplete checking scope, not
  evidence requiring a source cast or suppressed diagnostic.
  The Make inventory remains staged: parent found a further conditional-override
  false-completeness case and requested a bounded correction rather than
  accepting its 133 passing tests as soundness. Final gates, eleven native
  failures and fixed-corpus performance acceptance remain open. Receipts:
  `m7-final-architecture/`, `m7-doc-map-size/`, `m7-typed-small/` and
  `m7-make-parent-review/CONDITIONAL_OVERRIDE_REVIEW.md`.
  Source checkpoint remains uncommitted: this environment rejects Git index
  writes because `.git` is read-only; all reviewed edits remain in the worktree.

- Reviewed and integrated Devin's exact fingerprint parser using one IR syntax
  owner, preserving both existing list/tuple and keyword contracts. Parent
  native capture retains20inputs/19completed outputs from the real SetGear
  worker. Four alternating workload replays preserve every result: baseline
  median3.362s, integrated1.008s. This is normalization cost, not whole-function
  completion. Focused cohort384passes before/after (28.08s/16.84s); scoped
  lint/MyPy, architecture and ownership pass. Basta reports60existing findings,
  none on the changed owners. SetGear and eleven native broad failures remain
  unresolved; final gates/corpus remain required. Quality-hard25795 exits2 at
  the full architecture guard after lint/mypyc smoke:320diagnostics including
  static Make-variable inventory, stale pipeline contracts and documented
  ownership/type debt. Broad pytest did not run in this attempt. A separate
  Devin stages only the named-variable inventory repair. Receipt:
  `m7-fingerprint-split-parent/REVIEW.md`. User requested a checkpoint and
  shorter paths; a separate Devin stages a checked batch-rename tool only.

- Typehoon pruning remains unpromoted after paired native measurement:
  706/706constraint sets equal, stock0.531842s/staged0.528424s; no useful
  native gain despite synthetic speedups. Parent also reproduced72wrapper
  cases and8192ordered path sequences. SetGear still times out. Receipt:
  `m7-typehoon-parent-review.md`. Static-only Devin58037 now stages an exact
  fingerprint-splitter optimization targeting the measured character loops;
  no candidate or new acceptance yet.

- Retired the normalization-memo experiment after native measurement:
  retained20calls/1cheap hit;6oversized misses consume3.368of3.408s recorded
  normalization elapsed. Synthetic reuse does not demonstrate a native gain.
  Exact hash checks preceded restoration of the three pre-change sources;
  the added test and full delta remain staged. Restored validation57939 passes
  287tests25.96s. This supersedes the integration checkpoint below. Receipt:
  `m7-memo-native-counts/REVIEW.md`. Typehoon Devin38721 remains active.

- Reviewed Devin's request-local condition-normalization memo and integrated
  it after exact baseline checks. Parent added strict256entry/4096combined
  character bounds and independently verified parity, saturation and Unicode
  controls. Four-module validation cohort291passed23.33s; scoped lint,
  ownership and seven-owner MyPy pass. Native SetGear replay could not start:
  `/dev/kvm` is absent in the current environment. No native speedup or fixed
  regression is claimed; final corpus/gates remain open. Receipt:
  `m7-setgear-memo-parent/PARENT_REVIEW.md`.

  Native availability recheck: direct probes see char10:232, but both documented
  launcher attempts fail `/dev/kvm` lookup before pytest. The filesystem/device
  boundary remains intact. Static-only Devin38721 now assesses exact Typehoon
  constraint-generation optimization under bounded staging; no candidate or
  speedup is accepted. Prompt: `.cache/devin-prompts/m7-typehoon-path-cost.md`.

  Native follow-up succeeded through the documented launcher with log capture
  inside its sandbox. The unchanged test still fails its30s outer watchdog
  (pytest57.30s). Diagnostic outer60s/analysis20s also fails: subprocess51.487s,
  inner timeout19s, pytest79.21s. Four integrated source hashes stayed unchanged.
  This supersedes the missing-device blockage for these runs, but establishes
  no native speedup or repaired SetGear regression.

- Actual SetGear fork-worker profile retained850samples over19.382s from
  `_DirectAddrCliRun8616.direct_decompile_job`, plus two independently
  identity-checked stack dumps. The hottest sampled leaf is fingerprint
  argument splitting; separate stacks also show angr type solving. Recorded
  sources did not change. Diagnostic pytest still fails (59.70s); this is
  hotspot evidence, not a repaired regression or native speedup. Devin19997
  is investigating a bounded staged optimization. Parent receipt:
  `m7-setgear-analysis-parent-review.md`. No production patch is accepted.

- SetGear watchdog-only explanation is rejected: diagnostic outer60s with
  unchanged analysis20s and all original assertions still returns timeout
  after19s of analysis (subprocess51.145s; pytest1failed87.48s). No test cap
  changed. Existing39module mypyc import smoke passes; two alternating
  import pairs save around1.2s at roughly6MiB extra RSS, not native acceptance.
  New bounded Devin profiles the actual fork worker. Receipts:
  `m7-setgear-watchdog-experiment/REVIEW.md`, `m7-import-cost/REVIEW.md`.

- Explicit declared-startup probe authenticates the real SORTD image but
  refuses invocation inventory at0x1151c before pointer-output assertions.
  Census raw10/normalized5/materialized4/failure1 is retained incomplete.
  The unresolved tail jumps indirectly through a memory slot populated by
  an entry POP; proving segment identity and memory preservation is still
  required. No default scope changed. Receipt:
  `m7-declared-pointer-probe/REVIEW.md`.

- Startup export-laziness experiment is rejected: Devin56649 terminal0,
  reported means22.37s baseline/22.89s staged, mandatory bootstrap/lifter
  import work remains, and generated initializer expands to2223lines.
  Production sources match saved baselines. No native improvement or gate
  acceptance follows. Receipt: `m7-platform-startup/PARENT_REVIEW.md`.

- SetGear also fails unchanged in isolation: subprocess30s, pytest75.19s.
  Parent startup profiles measure help3.18s, import decompile3.77s, and
  import angr plus X86_16 platform27.22s (platform cumulative15.065s).
  The worker's50s diagnostic is not comparable test-budget evidence; no
  semantic or timeout repair is accepted. One bounded Devin now stages a
  startup optimization preserving required registration/bootstrap/exports.
  Receipt: `m7-setgear-focused/PARENT_STARTUP_REVIEW.md`. M5/M7 stay open.

- Devin's bounded Loadprog probe found409 repeated expression candidates in
  3150load scans, but all predicate scans took only0.140s and their containing
  routine0.236s. Parent independently checked the fork-child events against
  the111.28s failing regression; every invocation's candidate/call counts
  agree. The memo remains private staging: measured benefit does not justify
  promotion or another native replay. Production owner/tests retain their
  baseline hashes. Receipt: `m7-load-scan-memo/PARENT_REVIEW.md`. The existing
  native timeout and original M5/M7 remain open.

- Post-retry corpus refresh completed14serial attempts,55obligations per phase,
  with1424source paths unchanged. Each phase:3proved/1counterexample/
  2conditional/49unknown. Contracts and dependencies match in all seven pairs;
  real16 changed InsertionSort retains UNKNOWN but differs in refusal detail
  (`paired_region_graph_unproved` vs `macro_admission_refused`). Fresh dependency
  controls:9passed55.02s, bound to this source snapshot. Total child elapsed
  542.73s, peak child RSS393.09MiB; bounded profiling is not a speedup claim.
  Receipt: `m7-post-retry-corpus/PARENT_REVIEW.md`. Native failures, the public
  scope decision and final project gates remain open.

- The unchanged SORTD indexed-address inventory also times out in isolation:
  subprocess limit180s, total197.88s, one failed test. Reducing the worker pool
  is therefore not an established fix. The scheduling audit identified an
  unused heavy/exclusive scheduler path, but its proposed integration remains
  unaccepted pending measured benefit and exact-selection preservation. Receipt:
  `m7-unit-scheduling-audit/parent-inventory-serial.log`. A bounded Devin audit
  now investigates the inventory path; a separate read-only audit checks the
  pointer-output regression's invocation-domain authority. Neither changes
  proof domains, test expectations or milestone acceptance.

- Reviewed Devin retry-budget diagnostics integrated into the real16 public
  path without extra clock reads or changed proof budgets. Parent reproduced
  20baseline-vs-staged controls; durable tests enrolled with144focused
  test/pipeline/ownership checks passing. Existing public macro/caller tests:
  19passed150.61s. Scoped lint/MyPy/architecture/ownership pass. Actual SwapBars
  CLI exposes loop/region/macro remaining budgets and retains UNKNOWN. Receipt:
  `m7-retry-budget-evidence/PARENT_REVIEW.md`. Earlier corpus dependency checks
  passed9controls against1423unchanged paths before this integration; they are
  retained historical evidence, not final-source acceptance. Serializer's
  duplicated-schema design was rejected on two reproduced byte-parity defects;
  the worker finalized a no-patch report, and no serializer was promoted.
  Receipt: `m7-source-serialization-cost/REPORT.md`. M5/M7 remain open.

- Frozen corpus refresh completed all14 serial attempts (55 obligations per
  phase; sources unchanged). Per phase:3proved/1counterexample/2conditional/
  49unknown. Five PE32 lanes preserve all compared projections; both real16
  lanes retain statuses/assumptions/contracts/dependencies but each changes one
  refusal detail at the bounded retry boundary. Peak child RSS392.3MiB;
  profiling coverage remains partial, not full phase attribution. Receipt:
  `m7-corpus-reason-repair/PARENT_REVIEW.md`. The later retry-budget diagnostics
  integration is recorded above; serialization concluded without a patch.
  Loadprog probe could not start: `/dev/kvm` is absent in the current execution
  environment. Native evidence remains pending; M5/M7 remain open.

- Frozen quality-dev22422 ended2: broad unit phase10718passed/19failed/
  23skipped in1617.47s; earlier precheck296, admission1204 and budgeted3
  passed. Parent repaired four failing cases across three test modules:
  explicit I/O-model mock argument, selected-function relift guard, and exact
  invocation/dependency serialization expectation. Full affected cohort
  82passed108.17s; lint-iteration passes. Devin95488 diagnosed four nonleaf
  failures as lost typed reasons, not stale fixtures. Parent factored shared
  scope authentication and typed revalidation; original tests stay unchanged.
  Before:4failed/11passed; after:48focused proof/budget/native-scope controls
  pass130.41s. Scoped lint and two-owner MyPy pass. Eight broad failures are
  repaired; eleven native refusals/timeouts remain open.
  Counts are reconciled cases, not a new broad green run. Gate receipt:
  `m7-transitive-refresh/GATE_RESULT.md`; focused receipts:
  `m7-fixture-boundary-refresh/REVIEW.md`, `m7-entry-schema-refresh/REVIEW.md`.
  Typed refusal repair: `m7-nonleaf-gate-repair/PARENT_REVIEW.md`.
  Parent rejected unproved registry-reuse premises in Devin's IR-cost audit;
  its30s probe did not reach the analysis worker. Loadprog's audit locates an
  abort cascade but does not prove initialized binary state or justify changing
  pass order. Both parent reviews retained; no optimization or M5/M7 acceptance.

- Parent reviewed Devin's far-helper test correction and preserved independent
  native/Unicorn post-return comparisons and corruption controls. Near tests
  now retain architectural CALL frame effects for zero/nonzero helper inputs.
  Transitive-chain failure reproduced as compose-budget exhaustion under six
  workers:8/9pass87.82s versus9/9pass58.99s with two, identical proof budgets.
  Every pipeline tier now retains these controls in a two-worker
  `binary-budgeted` phase ahead of broad units. Pipeline67tests and scoped
  lint/type/ownership/context checks pass. This does not close full gates or
  M5/M7. Receipts: `m7-far-helper-tests/PARENT_REVIEW.md` and
  `m7-transitive-refresh/RESULT.md`.

- Reviewed typing repair integrated: parent corrected a redundant cast missed
  by Devin's incomplete overlay and verified the actual384-file development
  MyPy cohort. Production MyPy and scoped lint/type-doc now pass; affected
  scope/state/budget/relift cohort62passed23.31s. Fast admission previously
  passed1204tests230.52s; the following broad run was deliberately interrupted
  at1690passed/2failed/2skipped after finding stale indirect-budget mocks.
  Parent repaired their explicit I/O argument without changing budget controls.
  quality-dev retry is running; M5/M7 remain open. Receipt:
  `m7-gate-type-repair/PARENT_REVIEW.md`.

- Fast-pipeline refresh reached comparator admission after296precheck passes;
  admission stopped at1089passed/1failed218.91s. The failure was a stale
  two-argument wrapper around the now three-argument scoped proof validator
  in `test_native_relift_scope.py`. Parent forwards the offered invocation
  without changing production semantics or the validation-count assertion.
  All7module controls pass13.72s; scoped lint/type-doc passes. Full fast
  pipeline retry is running; no broad green result is yet claimed. Logs:
  `m7-native-helper-call/parent-pipeline-fast*.log` and
  `m7-gate-type-repair/parent-relift-tests.log`.

- Integration gate refresh: quality-dev stopped in linters-dev before tests.
  Parent repaired missing boot/image contracts in the development MyPy cohort;
  all20adapter diagnostics disappeared. Twelve partial-import narrowing
  diagnostics remain in three IR owners; Devin stages a bounded fix under
  `m7-gate-type-repair/`. mypyc smoke was environment-limited by unwritable
  default temp directories; retry with repository-local TMPDIR passes all39
  compiled imports. No broad green or new milestone acceptance follows.

- Native helper CALL retention: parent reviewed and integrated Devin's lifter
  deletion, rebuilt the mandatory Cython backend, and independently compared
  compiled before/after probes. Registered near/far helpers now retain native
  CALL/frame effects; unregistered controls are unchanged. Parent corrected
  byte-store assertions and the fixture's CLE linear-address capacity. Final
  four-module cohort:54passed/1warning14.80s; scoped lint/type-doc passes.
  Eight new controls are enrolled in comparator-check-fast and the routine
  pipeline/ownership manifest. This is focused regression evidence, not M7
  corpus or final-gate acceptance. Receipt: `m7-native-helper-call/`.

- Parent executed the exact retained SORTD MZ prefix with Unicorn under two
  generic entry selectors. Both17-instruction paths return normally through the
  actual helper, preserve CS, and retain the original module bytes. The second
  CALL1056f reaches0132c forCS0124 versus1132c forCS1000, with matching expected
  call frames. This is a concrete counterexample to one unconditional target,
  not whole-function inequivalence or evidence of a particular historical false
  proof. Original universal topology assertion remains unresolved; do not erase
  its refusal or import a boot assumption implicitly. Receipt:
  `m7-generic-selector-audit/replay_selector_witness.json`.
  Conditional service-bridge expansion was intentionally stopped (Devin45987
  terminal1 after parent SIGINT): M5 implementation is already reconciled and
  that bridge cannot meet the generic assertion. M5 checkpoint gates remain
  required. Devin57578 was intentionally interrupted after its staged native
  helper CALL repair was copied for parent review; see the checkpoint above.

- Explicit declared-boot invocation adapter and header-rooted inventory are
  integrated after parent review. Parent repaired the projection property call,
  reproduced and fixed three stale-authority exception paths, and requires
  bytes-like loader results. Reviewed Devin bounds extra-root consumption
  (including duplicate floods) and census enumeration; overflow refuses rather
  than publishing a truncated index. Parent independently reproduced both
  resource defects against the saved baseline without unbounded allocation.
  Final adapter/budget/boot-prefix cohort54passed1warning24.27s;1238recorded
  semantic-source hashes unchanged. Scoped Ruff/type-doc, resolved-import MyPy,
  architecture and ownership pass. Native adapter tests are routine-enrolled
  in the serial expanded lane; budget controls run in the unit lane. These
  limits do not bound work already done by third-party decoders. Receipt:
  `m7-public-scoped-adapter/PARENT_REVIEW.md`. Returning-service bridge remains
  staging only; original SORTD, M5/M7 and final corpus/gates remain open.

- The six actual-PE cold/warm and transitive-callee invalidation controls are
  now ordinary-import tests in `test_flat32_dependency_cache.py`, enrolled in
  the default/expanded relational binary lane and ownership/lint configuration.
  All six pass in the76-test production invocation/dependency cohort. The
  serial run took53.36s with1429recorded source/test hashes unchanged. This
  replaces staging-only enrollment, not the final fixed-corpus M7 receipt.
- Boot-prefix call evidence and exact post-return SP propagation are integrated
  after parent native review (plain RET, RET2 and disagreeing-return controls).
  The registered-prefix test is red on saved production and green after repair;
  scoped lint/type, architecture and ownership pass. Real SORTD still refuses:
  parent byte inspection identifies its first unresolved row as INT21/AH30,
  correcting the worker's indirect-call diagnosis. Declared returning-service
  state remains a missing invocation-census connection. Receipt:
  `m7-boot-call-prefix/PARENT_INTEGRATION.md` under the implementation cache.

- Fresh SORTD diagnostic localizes the next integration gap: the catalog-derived
  invocation index omitted the actual MZ startup. Parent added its binary-derived
  boundary in a private probe and confirmed startup-to-caller-to-InitBars edges;
  both ancestor artifacts register with complete coverage. The boot invocation
  census then refuses `path_decode_mismatch`. The300s outer diagnostic watchdog
  expired before a final scoped-view result;16semantic-source hashes stayed
  unchanged. This is no production fix or proof gain. A bounded startup-only
  Devin task owns the next diagnosis, avoiding another full InitBars replay.
  Receipts: `m7-sortd-startup-index/PARENT_REVIEW.md` and
  `m7-sortd-scoped-probe/PARENT_REVIEW.md` under the implementation cache.
- Startup census repair is now integrated after parent review. Natural decoding
  overran a legitimate frontend block partition. Parent rejected the worker's
  claimed-IR-length bound using a dropped-suffix control, then bound census
  extents to the independent frontend boundary. The native split-block
  regression is enrolled;48production invocation/guard controls pass22.20s.
  Lazy collection of parent-call records skips work not consumed by the boot
  proof or an absent parent retry. Scoped lint, MyPy and architecture pass;
  four native import/resolution controls pass142.41s with stable source hashes.
  Actual startup now retains
  `call_boundary_unproven`; original SORTD and M5/M7 remain open. Receipt:
  `m7-startup-census-repair/PARENT_REVIEW.md` in the implementation cache.
- M5 ordered-I/O caller propagation is integrated on real16 and both PE32
  drivers. Combined controls171passed/1failed; the one DX test helper is repaired
  and its final21-test module passes. Semantic sources stayed frozen. Original
  M5.1–M5.3 reconciliation found missing returning DOS/BIOS services and actual
  PE32 import-service binding. The reviewed real16 returning-service slice is
  now integrated, together with the reviewed PE32 import-service slice. Parent audit:
  `m5-exit-audit-current/PARENT_REVIEW.md`.
  Parent review found incomplete service-event verification and PE32 export-name
  case loss; the latter has a reproduced red control. Repeated opaque PE32
  responses also need occurrence-bound inputs. Parent repaired real16 census
  authentication using complete bounded native decode, entry/edge checks and
  closed event accounting. Staged checks:31census,21actual-MZ,121existing terminal
  tests passed. False positive fixture expectations (flags/residual frame writes)
  and lost fault-site assumptions were corrected without weakening observables.
  Schema, CLI, specification and routine enrollment are integrated; scoped
  lint/type and architecture gates pass. Production terminal regression:
  174passed/1warning in93.84s; full M5/M7 acceptance remains unclaimed.
  Latest production checkpoint:357passed/1warning in52.02s across terminal,
  service census, IVT, configured limits, thunk census, schemas/CLI and PE
  boot/replay controls. Scoped lint and architecture pass. Parent reviewed and
  integrated Devin's explicit flags-string parser check; MyPy passes with the
  two required dependency owners included (five prior Any diagnostics were
  follow_imports=skip scope artifacts). Post-fix schema/CLI48passed16.69s. Receipt:
  `m5-terminal-integration/PRODUCTION_CHECKPOINT.md`. Actual import/IAT binding,
  case-sensitive export identity, occurrence-fresh opaque effects and bounded
  native event accounting are integrated. These focused checks do not close
  M5/M7 or final gates. Dependency-identity assertions are now reviewed and
  integrated. Scoped CFG-view review repairs and the low-overhead SetGear relift
  harness are complete in private staging; current worker ownership is recorded
  in `ACTIVE_HANDOFF.md`.
  Parent's staged PE32 identity repair has7passing controls against5failed/2passed
  on the submitted baseline. The initial27passed/1failed real16 forgery result
  is superseded by the authenticated census controls above; historical details in
  `m5-services-parent-review/PARENT_REPAIR_CHECKPOINT.md`.
- M7 conditional nested-call scope repair remains private. Parent-review fixes
  have19synthetic passes against12failed/1passed on the saved baseline: common
  invocation scope, dependency census, shared recursion/work guards and malformed
  chain refusal. Explicit scoped native application now has7passed21.99s;
  the known-unimplemented generic-importer positive was deselected and remains
  an obligation. No native importer coverage gain is established. A separate
  scoped artifact/closure consumption path is still required; passing a proof's
  scope into generic artifact publication would be unsound. See
  `m7-scope-importer/LOCAL_WORKER_REVIEW_FIX.md`; universal consumers must
  continue to refuse conditional admissions.
- Parent native controls found seven retained-evidence corruption cases
  incorrectly accepted by the initial scoped-view prototype. The reviewed
  repair now passes39synthetic and12native controls; parent also reproduced and
  fixed bool/float evidence-counter acceptance. Bulk CFG projection retains raw
  instruction identities and explicit pending edges. The scoped coverage consumer
  passes two parent-native controls in46.86s: authentic entry-only acceptance and
  rejection after native-byte mutation. Independent coverage review then found
  ignored function-only refusals: parent reproduced2false accepts and repaired
  refusal reconciliation;30synthetic controls pass16.36s on the current view.
  Devin's segment-state transport has10parent controls passing19.98s. Parent
  scoped closure and caller-preservation changes fail3actual-MZ controls on the
  old owners and pass3native+6universal controls99.92s on the final snapshot.
  Five-owner scoped MyPy and Ruff pass; semantic hashes stayed stable. Receipts:
  `m7-scoped-coverage/PARENT_REVIEW.md` and `m7-scoped-closure/PARENT_REVIEW.md`.
  These remain staged transport checks, not production integration or M7
  acceptance. Authentic parent-call consumption of an in-flight scoped callee
  also has a native red/green control (51.53s/59.09s). The explicit scoped importer
  passes2parent native controls44.90s; full raw/stub/census JSON outputs match
  the saved-before importer byte-for-byte. Receipt:
  `m7-scoped-import-builder/PARENT_REVIEW.md`. Parent fixed five staged domain
  typing diagnostics. The resolver's frozen first candidate now passes two
  parent-native controls221.94s with that newer domain snapshot: nested CALL
  closure, scoped/universal cache isolation, native-byte invalidation and two
  distinct authentic boot authorities. A fixture initially requested A while
  B's source was installed; that refusal is retained as a negative control.
  Timing includes brief worker overlap and is not performance evidence.
  Receipt: `m7-scoped-callee-resolution/PARENT_REVIEW.md`. Final worker static
  cleanup, production wiring, original failing-function replay and gates remain.
  The unchanged original SORTD InitBars test was then replayed through staged
  owners:1failed88.73s at the universal artifact's refusal assertion. This
  explicitly leaves the original function unresolved; the scoped fixture
  positives do not authorize universal publication or replace that obligation.
- Scoped transport is now integrated into12 production owners with11
  ordinary-import test modules. Parent review caught a cycle-guard lifetime
  regression in Devin's final refactor (2red/2green seam controls); the repaired
  native/guard batch passed4controls193.85s. Parent also cleared14 typing errors
  in the new resolver owner and removed an impossible metadata lookup on the
  immutable frontend boundary. Ordinary imports then exposed a circular registry
  import hidden by the staging loaders; deferring that lookup fixed collection.
  Production contract/universal cohort:87passed20.43s. Scoped lint/type-doc
  ratchet and startup architecture checks pass. The20 native controls passed
  serially in346.27s (one dependency warning); all23 recorded source/test hashes
  stayed unchanged. Full M5/M7 acceptance and original SORTD remain open.
  Fast controls are enrolled in the unit pipeline; the native lane is a
  prerequisite of `test-pipeline-expanded`. Receipt directory:
  `m7-scoped-integration/`. Devin performance/test-enrollment jobs terminated on
  a model rate limit; parent completed ordinary-import enrollment locally.
- The outcome-matrix reconciliation now records56supported bounded evidence
  cells,0unverified,0missing. Fresh production fault/service/public controls:
  112passed19.42s. Explicit service/exception premises remain conditional and
  execution_status=not_run; no arbitrary-entry theorem or final-gate pass is
  inferred. Receipt: `m7-outcome-matrix/RECONCILIATION.md`.
- The fixed55-obligation, seven-lane baseline is retained. All14 cold/repeat
  phase diagnostics completed with unchanged1413-file Python/native/JSON
  inventory and inputs. All seven pairs match verdict/reason/assumption,
  contract and serialized dependencies. `m7-corpus-performance/parent-phase-corpus/`
  retains phase/RSS evidence; instrumentation and unclassified time remain
  explicit, with no optimization speedup or final acceptance claim.
- Ten broad failures remain unresolved; no fresh broad gate is claimed.
  A serialized Loadprog refresh fails in62.80s with retained semantic IR
  refusals and nine uninitialized segment-carrier reads. The prior16→14
  call-accounting error is absent. Receipt: `m7-loadprog-final-refresh/RESULT.md`.
  SetGear's coordinated diagnostic ends at the unchanged30s watchdog. The relift
  observer records5requests,1miss/4hits and0.209s total lifting: this run rejects
  the proposed differing-expectations cache-miss explanation. External sampling
  captured imports only, so it establishes no analysis hotspot or speedup.
  Receipts: `m7-relift-aggregate/PARENT_RESULT.md` and
  `m7-setgear-external-profile/RESULT.md`. Do not raise the analysis timeout.
  A subsequent worker-ready sample reached actual analysis:273samples over
  5.46s,26sampling errors, with2.52s inclusive in status-flag projection/lift
  context. This partial sample identifies a candidate cost, not the complete
  timeout cause or an end-to-end speedup. Receipt:
  `m7-setgear-ready-profile/RESULT.md`. A separate Devin task is investigating
  the two status-flag owners in private staging; native measurement and parent
  review remain required before integration.

Paths above are relative to `.cache/comparator-implementation/`. Finish the
original exit matrix and required gates before announcing plan completion.

## Earlier checkpoints

2026-10-04 review: Devin's tagged near-pointer wrapper call-accounting fix is
integrated after independent baseline13failed/7passed and final89passed controls;
scoped lint/MyPy and ownership selection pass. Actual nested machine calls remain
counted and their removal still rejects. Native loadprog validation is pending.
The frozen representative corpus completed14processes,55obligations per phase;
all contract/dependency identities match, but both real16 lanes retain refusal
detail differences. This is no final-gate or performance acceptance. Receipts:
`m7-near-helper-call-guard/PARENT_REVIEW.md` and
`m7-corpus-performance/parent-current-baseline/PARENT_REVIEW.md` under
`.cache/comparator-implementation/`. Parent then fixed missing exact CLI import
admission: architecture-fast and5architecture controls pass. Native loadprog
retry reached the180s outer watchdog; no native function acceptance follows.

M5 Devin review found a list/dict SSA-output mismatch and missing retained-event
checks on flat32 call coverage. The second Devin repaired both in isolated
staging (43synthetic passes;14red controls against the original stage). Parent
reproduced the original MZ refusal, then observed conditional caller proofs on
actual MZ and both PE32 drivers with the repaired snapshot. The MZ regression
passes; PE pytest assertions used a wrong report-field path, corrected and
checked against both saved native reports without rerunning proofs. Subsequent
parent native closure cohort20passed: nested premises propagate and removed,
extra or reversed I/O produces mismatches on all three lanes. Extended controls
stopped at9passed/1failed: real16 immediate-port mutation still refuses. Devin
is repairing that isolated admission gap; final interface review and routine
enrollment remain before integration.
Evidence: `m5-ordered-io-native-review/PARENT_REVIEW.md`. Neither M5 nor M7 closes.

Parent review follow-up: the private M5 integration overlay passes64synthetic
controls after architecture, public ambient-scope and final-I/O-state retention
repairs. Immediate-port lifting now has a Devin native red/green result, but
final integration still requires correct unsigned immediate-port width and the
combined native cohort. M7 invocation staging was rejected: retaining a premise
did not prevent universal closure consumers from ignoring its scope. Parent
confirmed the exact consumer/cache path and canceled that attempt (exit1);
new bounded Devin task `m7-invocation-scope-repair` owns the correction. Receipts:
`m5-ordered-io-integration-review/REVIEW.md` and
`m7-nested-invocation-parent-review/REPORT.md`. No staged patch is accepted as
original M5/M7 completion.

At this earlier checkpoint, M5 environment premises still needed propagation through returning
callees on both public architectures (Devin staging `m5-ordered-io-callers`). M7
still needs corpus/performance and final gates. The ten outstanding broad failures
all reproduced in `m7-final-failure-refresh/execute-n9rlhp11/`: 10 failed,
3 warnings, 602.83s, exit1, source hashes unchanged. The retained-closure
budget-order correction is reviewed
and applied to the enclosed-entry staging owner only; parent synthetic controls
pass12/12, native baseline1failed/5passed23.10s and staged6passed25.97s.
Census observer corrections
pass3/3 and Ruff: no repeated closure validation, immediate first-refusal receipt.
Evidence: `m7-retained-budget-order/PARENT_REVIEW.md` and
`m7-closure-census/OBSERVER_REVIEW.md` under `.cache/comparator-implementation/`.
The subsequent bounded callee probe identifies repeated raw imports with the
same selector-window refusals (not more-than64 unique callees); its300s watchdog
exited124 with unchanged sources. Exact records and cache-invalidation limits:
`m7-callee-refusal-probe/run-parent/PARENT_FINDINGS.md` and `CACHE_REVIEW.md`.
Final refused-import caching is not accepted; mutable premise/registry evidence
must remain eligible for reproof.

Latest checkpoint: bounded real16 indirect-call composition is integrated with
complete finite-target coverage, actual callee effects, guarded state merging,
return/CS restoration and transitive identities. The production integration
cohort passed168tests275.31s with frozen hashes; after two local annotation fixes,
the final18-test public/multiarm/budget cohort passed40.51s with frozen hashes.
Six-owner scoped lint and MyPy pass; tests, ownership and execution scope are
enrolled. Actual-MZ two-target positives prove, second-arm corruption fails,
missing targets and cap overflow refuse. Receipt:
`.cache/comparator-implementation/m5-real16-indirect/production-integration/`.
This closes the bounded indirect implementation slice, not original M5/M7.

Earlier checkpoint: bounded integer fault terminals integrated for actual MZ/PE32;
parent integrated cohort131passed68.00s with frozen source hashes. Review caught
and fixed shared signed-DivMod divisor extension: native PE corrupted-prefix false
proof now rejects, correct negative-divisor prefix proves. CLI/schema/spec and
routine test enrollment updated. Evidence: `.cache/comparator-implementation/
m5-fault-integration/` and `m5-signed-divmod/`. Fault equality stays conditional
on declared no-handler/site relations; no general exception handling is claimed.
Remaining original-M5 acceptance reconciliation, M7 corpus/performance and final
gates remain open. This checkpoint does not close M5 or the original plan.

Historical parent review follow-up: staged real16 indirect native cohort improved from
13 failed / 17 passed to 3 failed / 27 passed after correcting a fixture's
linear-load-base versus selector confusion; the public positive now proves.
Remaining controls are malformed: changed pointer words become the caller's
RET target, XOR/INC changes flags unlike MOV, and unconstrained DS writes may
alias the far return frame. These require honest fixture repairs, not weakened
observations. Evidence: `m5-real16-indirect/budget-before-i3wp3k47/` under the
comparator implementation cache; no production indirect integration yet.
The prepared M7 closure census also needs lifetime-safe session identity and
bounded refusal accounting before its expensive replay; Devin is repairing
diagnostics only. Neither checkpoint closes M5/M7.

## Required notification for original-plan completion

User instruction (2026-09-29): the implementing agent must explicitly notify
the user when the original M0-M7 plan is complete, without waiting for the later
coverage/resource experiments or D0-D5 delivery additions to be completed.

For this checkpoint, original scope means the objective, shared proof contract,
M0-M7 exits and acceptance matrix preceding the additions titled "Prioritized
coverage and resource work" and "Staged delivery and planning estimates".
Those additions do not enlarge the original completion denominator. Where an
added technique helps discharge an original obligation, its evidence may be
used, but implementing every proposed technique is not a new prerequisite.

Retain the original two-track, semantic, execution and gate requirements.
Partial/conditional proofs or unresolved required acceptance cannot be announced
as original-plan completion. Once all original obligations are accepted, send a
separate user-facing completion message identifying the accepted scope, evidence
and reproducible usage command; list the later additions as a separate remaining
queue. Record that notification in this ledger. A file update alone is not the
requested user notification, and continuing later work must not delay it.

## Completion ledger (updated 2026-10-03)

**M5 PE32 internal integration checkpoint, 2026-10-03.** Four reviewed
image-bound recursive owners and ordinary-import controls are now in production.
Actual-PE/model/interval and pipeline/ownership cohort185passed295.25s;
scoped lint/type ratchet and MyPy4owners pass. Tests are enrolled in the routine
relational lane and cheap admission lane; execution-spec7.7 states the conditional
scope. No new public driver option or unconditional theorem is claimed. Receipt:
`.cache/comparator-implementation/m5-pe32-recursive-review/integration-receipt.json`.
Real16 public integration remains staged pending two reproduced intake defects;
terminal integration and M7 final gates remain open. Devin is staging the actual
SORTD entry-domain blocker under a verified repository-only sandbox.

**M5 parent boundary review, 2026-10-03.** Staged PE32 review repaired an
incorrect interval-disjointness goal (3 independent failures); the final actual-PE
plus boundary cohort passes43tests101.26s. Separate terminal consumer controls
exposed incomplete solver-output projection admission; its staged repair requires
complete unique observations and records refusal counters. The real16 public
wrapper no longer relabels arbitrary-entry member obligations from an initialized
component theorem; the separate component report remains available. Final terminal cohort59passed17.25s; actual-
MZ/public domain and budget cohort8passed48.39s. These are staged repairs,
not M5 acceptance.
Receipts: m5-pe32-recursive-review/, m5-symbolic-terminal-review/ and
m5-real16-public-review/ under `.cache/comparator-implementation/`.
M0–M4/M6 remain accepted6/8; M5/M7 and final gates remain open.

**M5 final-seal optimization integrated, 2026-10-03.** Parent reviewed and
integrated the final address-closure fingerprint batching:9source scans become1
inside that synchronous seal, with independent initial/final freshness checks
unchanged. Component ABBA4.18–4.35s before/0.68–0.97s after; no end-to-end ratio
claimed. New ordinary-import controls and routine enrollment join a156test
passing production cohort; scoped lint/ratchet/MyPy pass. The3previously failing
recursive consumers now pass266.98s serially at unchanged budgets (receipt:
`m5-address-seal-batch/parent-consumer-after.log`). Parent also
reproduced6green staged budget/cache-identity controls after earlier failures.
Devin batches reached a temporary service rate limit; parent continues locally.
Receipt: `.cache/comparator-implementation/m5-address-seal-batch/PARENT_REVIEW.md`.
M5/M7 remain open.

**M5 staged terminal parent repair, 2026-10-03.** Devin repaired unmapped-read
admission. Independent parent review then exposed partial-store loss of initial
read lanes and recycled-object-ID memoization skipping later accesses. Parent
repaired both in the staged memory-effect owner;54combined controls pass, plus
2actual-PE initialized-data controls. The saved prior owner fails the identical
partial-store PE control (1failed/1passed). Scoped lint/ratchet/MyPy pass.
Production/public integration and durable enrollment remain pending. Separately,
3cheap parent controls reproduce enlarged10s/30s/120s child budgets in the
public recursive adapter; its worker was deliberately interrupted and resumed
with budget caps and domain-bridge review. No budget enlargement is accepted.
Receipts: `.cache/comparator-implementation/m5-symbolic-terminal-review/REVIEW.md`
and `m5-real16-public-review/REVIEW.md`. M5/M7 remain open.

**M5 deadline attribution, 2026-10-03.** A full actual-MZ terminal-address
joint-proof profile reaches the unchanged120s deadline with99semantic-source
scans taking62.24s cumulative. These are overlapping profile costs, not a
controlled speedup measurement. A bounded final-seal batching experiment is
staging only, preserving independent before/after freshness checks; no proof
budget or source-admission rule changed. The public real16 adapter also remains
under review for child-budget caps and the bridge between initialized-root
joint domains and public per-function contracts. Receipts:
`.cache/comparator-implementation/m5-joint-deadline-profile/REVIEW.md` and
`m5-real16-public-review/REVIEW.md`. M5/M7 remain open.

**M5 parent review: terminal read-permission defect, 2026-10-03.** The staged
symbolic terminal adapter admits actual PE32 programs reading unmapped address
zero as equivalent terminal transitions, including a read whose value is later
overwritten. Two independent parent controls fail (35.82s); integration is
blocked pending complete read-effect/permission admission. Existing code-write
and unmapped-write controls independently refuse correctly. This is a staged
defect, not an accepted capability. Receipts:
`.cache/comparator-implementation/m5-symbolic-terminal-review/REVIEW.md` and
`read-permissions-red.log`. Separately, the three updated recursive downstream
consumer tests all hit the original loaded-relation deadline (437.10s total).
No budget was raised, no broad pass claimed; avoid repeating under concurrent
heavy proof jobs. M0–M4/M6 remain accepted6/8; M5/M7 remain open.

**M5 recursive scope integrated, production validation pending, 2026-10-03.**
Devin revision3 finished53staged tests in544.28s. Parent reviewed all four owner
deltas, independently reproduced the actual-MZ conditional joint positive in
95.04s and checked12intake/ledger/assumption controls. Parent added missing raw/
normalized counter validation before integration. Declared exclusions reach
shared obligation verdicts with both binary hashes; they never create an
unconditional theorem. Integrated code, durable tests, relational-lane ownership
and execution-spec7.6. Ruff/type-ratchet/scoped MyPy pass. Ordinary-import57test
suite finished51passed/6failed; a subsequent scope cohort passed50tests, while
the updated three downstream consumers still exhaust their proof deadlines.
No final production or M5 acceptance yet. Receipts:
.cache/comparator-implementation/m5-recursive-scope/parent-r3-review/REVIEW.md,
integration-before/, integration-source.sha256 and integration-tests.log.
M7 caller worker resumed after correcting demonstrably malformed fixture
instruction heads; the independent M7 acceptance checklist retains original
56cells, three-track measurements and final gates. M0–M4/M6 accepted6/8;
M5/M7 remain open.

**Recursive operand-cost checkpoint, 2026-10-03.** Exact successful theorem
queries are reused within one operand proof only, capped at256formulas. Complete
premises, per-occurrence facts, original deadlines and source/model checks remain
intact. Focused cohort10passed23.75s; scoped lint/types pass. Native RET probe
retains7facts while solver checks fall5→4. The unchanged actual-MZ recursive
positive passes72.85s test time/90.00s total under the original120s budget;
earlier baseline and pre-reuse runs timed out. Shared-host timing is variable,
so no stable end-to-end speed ratio is claimed. Receipt:
.cache/comparator-implementation/m5-model-seal-cost/REVIEW.md.
M5/M7 and final broad acceptance remain open.

**Development-cost checkpoint, 2026-10-03.** Parent extended consumer-local
model-digest capture: physical bounds 2 scans to 1, address closure 8 scans to 1,
with identical ABBA digests. Measured local address hashing falls from
7.34–7.76s to 0.89–1.65s; this is not an end-to-end proof speedup. Final focused
cohort9passed/1deadline failure; saved baseline also exceeds the unchanged120s
deadline. Scoped lint/type checks pass. Receipt:
.cache/comparator-implementation/m5-model-seal-cost/REVIEW.md.
New `lint-iteration` checks explicit owned files with Ruff then the type/doc
ratchet; broad checks remain checkpoint obligations. Existing Make routing
cohort40passed15.87s. M0–M4/M6 remain accepted6/8; M5/M7 remain open.

**M5 I/O and recursive parent-review checkpoint, 2026-10-03.** IN now advances
observable I/O state even when its value dies; native-byte/frontend-bit helper
widths normalize for both IN/OUT. Final three-lane I/O module38passed19.42s;
full serial dosunit-tool plus prior I/O controls245passed268.97s. Earlier wider
two-worker327pass/1AIL-call failure remains unclassified; independent before/
current replays and32context tests pass. Failure assertions now retain full
comparison diagnostics; no budgets changed. Receipt: m5-io-read-state/REVIEW.md.
Parent rejected recursive v2 intake/ledger defects with two independent red
controls; private minimal repairs pass seven controls. Declared environment
assumptions still need shared-proof propagation; draft is not integrated.
Review/correction prompt: m5-recursive-scope/parent-r2-review/ and
.cache/devin-prompts/m5-recursive-scope-r3.md. Existing Devin sessions remain
live; do not start duplicate jobs. M0–M4/M6 accepted6/8; M5/M7 remain open.

**M5 native environment admission checkpoint, 2026-10-03.** Parent reproduced
an exact IN AL,60h;RET effect proposal incorrectly admitted as PROVED before
the guard. Reviewed Devin's instruction-ID classification and integrated only
the independent byte-level port/machine-state exclusions, using the existing
decode pass. Original guard cohort6failed/4passed; final guard/environment/AAM/
actual-MZ recursive cohort66passed118.52s. Ruff/MyPy/Pyright clean;126enrollment
controls passed7.37s. No unmodeled machine-state instruction may be treated as a
no-op or folded constant to establish a native effect binding. Receipt:
.cache/comparator-implementation/native-environment-guards/REVIEW.md.
The unaccepted recursive outcome scope is being corrected in resumed Devin
session56385/thread-cafe; M7 caller-domain work resumed95563/atom-geometry;
separate PE32 recursive intake52168 is staging only. M5/M7 remain open.

**M5 implementation checkpoint, 2026-10-03 (not milestone acceptance).** Parent
reviewed and integrated Devin's finite acyclic PE32 indirect-call composition:
each constant selector leaf must resolve to a declared callee, retain its own
return proof and merge complete callee effects through the existing composer.
Parent independently reproduced two baseline failures,32staged positives and
negative controls, plus six additional repeated-target/memory-effect controls.
Final ordinary-import production cohort123passed92.39s; scoped Ruff/MyPy clean;
126pipeline/ownership controls passed5.37s. Tests are enrolled in early comparator
admission, focused pipeline and ownership. No budgets or refusal gates weakened.
Receipt: .cache/comparator-implementation/m5-flat32-callbacks/PARENT_REVIEW.md.

Parent also integrated the instruction-owner AAM0 divide-fault repair after
independent Unicorn/staged-binding counterexamples.12focused controls pass9.71s,
including native proof-boundary refusal; scoped Ruff/Pyright clean. Receipt:
.cache/comparator-implementation/aam-zero-fault/REVIEW.md. Recursive outcome
scope remains unaccepted: the staged closed-machine declaration is not a
source-proved asynchronous-environment theorem. Devin27705 and44514 terminated
on a provider rate limit (reported reset11:01UTC); preserve their staged work
and resume bounded corrections after availability. M0–M4/M6 remain accepted;
M5/M7 and final gates remain open.

**M4 accepted, 2026-10-03.** Parent reviewed the full original relational-loop
requirements against binary-derived controls: existing19 public cases,12 new
corruption/exhaustion cases, six integrated actual-PE relation positives through
both drivers (6passed64.01s), six actual-MZ register controls, and20 rotation,
condition, progress and refusal controls (72.22s). The PE positives retain
register permutation, multiplier3/offset7 recurrence and saved-stack invariant
proofs with full modeled state. New controls are enrolled in the default
relational lane; enrollment regression passes. Unsupported graphs/relations
retain typed refusal, synthesis exhaustion stays unknown, and no bounded
execution is promoted to divergence proof. Exact source/input hashes, reports
and requirement matrix: .cache/comparator-implementation/m4-exit-controls/
ACCEPTANCE.md and relations-receipt-index.json. Acceptance covers admitted
function relations over shared input memory, not initialized-image equivalence
or arbitrary loop decidability. M0–M4 and M6 are accepted (6/8); M5 and M7 remain
open. Both M5 Devin implementations are staging only; final release gates remain
unresolved.

**M6 accepted, 2026-10-03.** Parent reconciled the original concrete-execution
requirements with the fresh 228-test native/reset/initialized-program selection
(90.32s), reviewed 21-test capture/public-PE selection (106.63s), and current
296-contract/993-comparator gate including device/video controls. These cohorts
overlap and are not summed. Original/equivalent/corrupted executions, reset and
snapshot isolation, deterministic captured/fuzz vectors, initialized MZ file
scenarios and import-free PE32 output/exit scenarios are covered. PE termination
uses a declared synthetic service, not a general Windows environment. Execution
remains concrete evidence, not universal proof. The supplemental sub_319B0
witness retains its rebased-stack/catalog-boundary qualifications. Receipt:
.cache/comparator-implementation/m6-acceptance-parent/ACCEPTANCE.md and
current-receipt.json; the latter explicitly distinguishes current hashes from
unrecorded pre-run provenance. M0–M3 and M6 are accepted (5/8); M4, M5 and M7
remain open. M4's 12 missing exit controls passed; actual-PE relation coverage
is undergoing final reconciliation. Devin is staging M5 recursive fault and
environment closure; no new recursive proof is yet accepted.

**M2 and M3 accepted, 2026-10-03.** The unchanged M2 selection finishes
323 passed / zero failures. The integrated early gate finishes 296 contracts
and 993 comparator tests with zero failures (42.92s + 295.74s, two workers).
Scoped four-owner lint/type gates pass. Independent requirement audits reconcile
direct near/far/operand-size calls and closed matched-loop induction, including
checked callees inside loops and both actual PE32 public drivers. Native
mutation, return, frame, full-state and dependency controls remain enforced.
Receipts: m2-region-target-parent/ACCEPTANCE.md,
m3-flat32-call-loop/ACCEPTANCE.md and early-gate-call-loops/acceptance-receipt.json
under .cache/comparator-implementation/. Acceptance retains admitted functions
over shared input memory, explicit refusals and separate initialized-image
obligations. M0–M3 are accepted; M4–M7 remain open. Earlier checkpoint wording
below records historical states, not additional completion requirements.

2026-10-03 parent integration checkpoint: the three M2 omitted-callee failures
were deterministic scanner refusals of symbolic direct JMP targets. Discovery
now consumes the existing native terminal-jump theorem, with downstream
full-control proof unchanged; six public cases and eight native mutation/domain
controls pass. The original 323-test M2 selection is being refreshed, not reduced.
Devin's flat32 call-loop composition is integrated after parent source review:
38 controls pass, including four new actual-PE32 public cases through both
drivers. Callee effects, return targets and every paired transition are proved;
no paired-call assumption or larger budget was introduced. Guarded capture-vector
tests include parent-discovered coordinate and non-SS reseeding refusals.
Early admission now catches the M2 regression before broad suites; expensive
replay cohort checks share one xdist group to avoid repeated fixture setup.
The 19-test public M4 refresh passes; its missing exit-matrix cells and M5
public recursion/indirect/environment obligations remain open. Integration
and gate receipts are under m2-region-target-parent/, m3-flat32-call-loop/ and
m6-vector-parent/ in .cache/comparator-implementation/. This checkpoint does
not change the accepted milestone count; M0/M1 remain accepted.

2026-10-03 reviewed capability checkpoint: guarded real16/flat32 runtime capture
now shares production replay guards; parent98replay/full-state/observation tests
pass. Captures are execution evidence only; page-grant provenance cannot authorize
new byte ranges in a runtime vector. Converter integration remains open. Original
M2/M3 audit gaps G2 and G3 now have reviewed, routine-enrolled binary controls:
stack/value/pointer arguments and nested/early-exit/partial-register/far-call loops.
Flat32 call-in-loop gap G1 remains under implementation. Fresh early gate passes
296contracts+928comparators in14.39s+112.28s with2workers and unchanged budgets;
this is not a matched before/after speedup measurement or M7 acceptance. Receipts:
.cache/comparator-implementation/{m6-guarded-capture,m3-loop-controls}/PARENT_REVIEW.md.
M0/M1 remain the only accepted original milestones.

**M1 accepted (contracts/accounting/cache binding only), 2026-10-03.** Parent
requirement audit records current public-domain integration, rejection controls,
296contract+884comparator early-gate passes,104public-boundary passes and9additional
projection/provenance passes. All8 frozen tiny controls retain their exact
expectations and budgets. Fixed15BC5 cold/warm statuses/reasons/assumptions and
oracle329/candidate356lowered parts are identical, with source/input hashes
unchanged (0cold cache hits,686warm hits;76.87s/22.38s). The15corpus functions
remain refused; parity is not equivalence. Receipt:
.cache/comparator-implementation/m1-public-domain-parent/ACCEPTANCE.md.
M2–M7 and all final project/release obligations remain open.

M1 public-domain checkpoint: corrected Devin proposal integrated after parent
review. Both public wrappers publish typed architecture/widths/projection,
calling/return contract, environment and outcome scope, sealed into abi_hash.
No inferred language ABI; unverified nonreturning scope remains not_established.
Parent caught and fixed confusion between the real16 loader's32-bit address
carrier and16-bit operand mode. Public boundary cohort104pass; adapter19/17pass;
enrollment161pass; scoped Ruff/MyPy/Pyright and structural/type gates pass.
Early admission96623 running with2workers; M1 exit remains open. Receipt:
.cache/comparator-implementation/m1-public-domain-parent/REVIEW.md.

M6 staged vector experiment is not promoted: parent inserted CPUID before the
capture point and reproduced staged CAPTURED versus production replay
UNSUPPORTED/undeclared_machine_input. Guarded runtime capture must share the
production execution checks; bounded Devin7552 owns staging only. Receipt:
.cache/comparator-implementation/m6-parent-prefix-scope.json.

Parent gate triage: three former timeout failures were rerun serially with
unchanged limits (3failed/111.25s). ChangeWeather and MONOPRIN __fimemset now
reach native MS C validation and explicitly fail on missing /dev/kvm; both
tests now carry requires_kvm, with all assertions retained. The independent
fimemset GCC behavior/corruption controls remain executable:8passed/2explicit
KVM skips,17.64s; Ruff clean. SetGear still times out and remains unresolved.
This classifies two environment requirements, not passing release coverage;
the broad10122pass/15fail/19skip result remains historical and red. Receipt:
.cache/comparator-implementation/gate-live-feedback/PARENT_TIMEOUT_TRIAGE.md.
M1 public-domain Devin draft was rejected for overclaiming flat32 whole-state
scope and unverified outcome admission; bounded correction62334 and M6 replay
vectors60179 remain staging only. M0 alone accepted.

2026-10-03 — **M0 accepted (baseline/audit only).** The additive current
manifest preserves the original 3/2/15 representative selections and adds the
verified full MSC6 real16 rebuild and frozen tiny controls. Six fresh command lanes
plus the source-checked changed-real16 supplement account for 55 representative
rows, including the separately identified 15-row historical assumption lane.
All eight tiny controls meet their expected outcomes at unchanged proof budgets.
Raw reports, a 1,236-file source snapshot/hash inventory, dirty patch/status,
tool/native identities and exact commands are retained and independently checked.
Refusals and conditional outcomes remain unproved. Source metadata now identifies
the current snapshot, with old values explicitly historical. Original M0.1–M0.4
and its per-track baseline/capability-matrix exit are satisfied. Receipt:
.cache/comparator-implementation/m0-current-baseline/ACCEPTANCE.md.
M1–M7 remain open; this is not original-plan completion. Historical ledger
entries below retain their status as observed at their earlier checkpoints.

2026-10-03 measured CALL-transfer/gate checkpoint: parent reviewed and integrated
adjacent proof-selection/projection traversal reuse, without a new cache or
larger proof budgets. Native relifts fall2→1per transfer; controlled ABBA
20-transfer benchmark0.77–0.86s→0.40–0.41s with identical full projections.
This is a local benchmark, not whole-pipeline speedup. Saved baseline2expected
reds/5passes; integrated51controls pass, scoped Ruff/MyPy/Pyright clean.
Immediate failed-node/phase/traceback reporting is wired into unit/relational
lanes, preserving outcomes;71pipeline/reporting and71enrollment controls pass.
Final early gate296contracts+821comparators passes2workers, comparator246.45s.

Broad pre-integration quality-dev result is10122passed/15failed/19skipped,
1583.39s. Three comparator failures pass focused serial recheck at unchanged
limits; preserve the broad failure result. No repeated broad run is counted.
Tiny frozen supplement has7of8expected outcomes after correcting two unsupported
MSC8 CLI flags; the remaining changed-call positive is budget-limited UNKNOWN.
Parent built unchanged full SORTDEMO.C with installed MSC6/system DOSBox, clean
compile/link,69relocs and20mapped procedures. The3frozen selected functions are
all present, but their combined comparison hit120s process watchdog with no
report. This is an available candidate, not an accepted corpus proof. Native
Devin capture now covers6selectors; parent verified8raw capture pairs, without
promoting concrete service observations to general policies. Original M0–M7
remains incomplete. Receipts: native-relift-cost/PARENT_REVIEW.md,
gate-live-feedback/PARENT_REVIEW.md, tiny-acceptance-manifest/PARENT_REVIEW.md,
real16-candidate-build/PARENT_REVIEW.md, real16-native-services/PARENT_REVIEW.md.


2026-10-03 ROM/native-entry checkpoint: parent integrated reviewed read-only
ROM declarations and exact read coverage while preserving writable RAM boundaries.
209focused/134enrollment pass;3parent forgery reds repaired,2mutations detected;
scoped lint/types clean. Early gate296contracts+814comparators passes2workers.
Synthetic SORTDEMO reaches1964 then AXEF00 refusal. Independent native-entry
capture now verifies26256loaded bytes/34relocs; production initializer matches
917504declared bytes and16register fields exactly, with no service policy claim.
Quality-dev first stopped on omitted SegOffset typing owner; inventory fixed,
retry58991 live with comparator2/later6workers (97pool controls). Native service
capture Devin79549 and true full-program candidate build Devin36342 are staging
only. M0/M1 audit identified missing tiny manifest/real16 candidate and stale
matrix; parent rejected narrower "M0 exit met" promotion. No original M0-M7
acceptance. Receipts real16-rom-contract/PARENT_REVIEW.md, real16-native-entry/
parent-projection-review.json, m0-m1-exit-audit/PARENT_REVIEW.md.


2026-10-03 functionality-state checkpoint: parent reviewed and integrated Devin's
explicit INT10/AH1B/BX0 policy with live BDA reads, bounded destination/IVT/frame/
code/source guards and complete68-byte receipts. All public projections and
routine gates enrolled. Expanded integration280pass57.33s; enrollment134pass;
scoped Ruff/MyPy/Pyright clean; two independent guard/receipt sabotages rejected.
Frozen SORTDEMO now1906instructions(previous1892), then honest undeclared ROM
read0xC2A66, not termination or native agreement. Parent independently matches
the64-byte table to native capture; separate1MiB capture includes unchanged ROM.
Six-worker early gate296contracts then1failure/22pass; exact failing transitive
callee control passes serially under unchanged budgets. Two-worker retry14191
finished0:296contracts+682comparators pass with unchanged budgets and source
hashes. ROM contract Devin51498 owns staging only. Original M0-M7 and broad25
failure result remain open. Receipt: real16-video-state/PARENT_REVIEW.md.

2026-10-03 initialized-video-query checkpoint: parent reviewed Devin's explicit
INT10/AH0F policy and integrated live-vector/handler/frame gates plus all public
projections. Frozen SORTDEMO now reaches1892instructions (previous1860), then
honestly refuses AH1B. Kvikdos itself lacks that service; /dev/kvm is absent in
this sandbox. Libdosbox recorder intake is under bounded investigation, not a
replacement completion criterion. Integration160pass, enrollment93pass, final
early gate296contracts+449comparators pass. No native, whole-program or full
M0–M7 acceptance follows. Receipt: real16-video-query/REVIEW.md.

2026-10-03 cache/callee/timeout follow-up: VEX cache v7 now binds fresh loaded
bytes, lifting artifacts, architecture and semantic configuration. Real-MZ
mutation controls reproduced two stale hits before the repair; both PE32
adapters retain warm parity and reject changed loaded code. Parent reviewed
Devin's transitive-callee audit: the defect certified a call part, not the
public whole caller. Identical-body discharge now requires a complete leaf;
nonleafs require existing closed proof facts. A deterministic ctypes control
also exposed wrapped/swallowed alarm expiry; expiration now produces a typed
budget refusal and retains the cause. No proof budgets were increased.
Early-gate and scoped-linter enrollment is fixed and tested. Retained parallel
failures distinguish a parent source-edit race from load-sensitive budget
refusals; the final checkpoint and receipts are in
[the acceptance checklist](binary-behavior-acceptance-checklist.md).
This is M1/M2/M7 progress, not original-plan completion.

2026-10-03 native reset and M1 seal review integrated. Parent rejected Devin's
first reset ledger because failure resurrected as OK with an untracked fd;
the revised ledger keeps refusal sticky and drops uncertain failed-close
numbers. Independent8compiled probes pass129.38s. Actual128-dup guest red on
saved production24.80s;13native controls green with staged builder48.47s.
Minimal production patch preserves native GNU header features. Final14native
controls pass110.87s (concurrent load), including4100-dup exhaustion, repeated
refusal and fresh-worker recovery; no-KVM failed-close ownership control1pass
36.58s. No descriptor anchors,16KiB bounded ledger. Stdio/external-state/full
snapshot obligations remain open. Production source/spec/test hashes retained
at native-fd-provenance/parent-review/INTEGRATION.md.

Parallel M1.1 audit identified three untested public-boundary questions, not
three demonstrated production defects. Parent reviewed/enrolled8PE32 seal
controls for changed bytes/sources and missing/malformed function inventories;
exact-source mutation experiment stays diagnostic, not a brittle routine gate.
Independent mutant1pass14.95s; combined seal/native-protocol/enrollment168pass
46.95s. Final early gate296contracts49.02s then311comparators156.60s under shared
native compilation load. Scoped Ruff/MyPy/Pyright/type-ratchet pass. Real16
conditional and candidate-only public controls still need reconciliation;
original M0-M7 stays incomplete. Receipts m1-evidence-audit/seal/PARENT_REVIEW.md.
Final standalone adapter checks also pass:19BC5/17MSC8 in separate two-worker
processes (22.83s/32.80s). All owned processes are terminal at this checkpoint.

2026-10-03 M6 device-information checkpoint: typed bounded stable-handle
inventory admits AX4400 only, preserving AX/upper EDX/unowned flags, clearingCF
and retaining complete query/response receipts. Unknown handles, other IOCTL
selectors and handle-state changes remain refused. Boot/CLI/schema/model/docs/
routine gates share the contract. Five fresh native query captures supply this
actual environment's response words; the first query cutpoint matches all
captured integer registers and654784declared RAM bytes exactly. Actual replay
advances1759→1847instructions; adding captured initial BIOS-data bytes advances
to1860 and an honest INT10/AH0F refusal at0110:33E9. No all-input/termination
proof inferred. Integration71pass29.50s; enrollment134pass8.78s; final early gate
296contracts15.02s then303comparators70.22s. Scoped Ruff/MyPy/Pyright/type-ratchet
pass. Receipts real16-device-info/REVIEW.md. Parent independently found a new
staged Devin reset flaw: ledger overflow gives RESET_FAILED once, then OK with
an untracked descriptor still open. Native compiled poison_probe exits1; patch
remains unpromoted pending repair. Original M0-M7 stays incomplete.

2026-10-03 M6 vector checkpoint: explicit full-IVT policy now models AH35
queries and AH25 updates with complete before/after receipts. DOS summaries
require the declared external INT21 entry to remain unchanged; process-owned
handlers, undeclared slot21 bytes and active return-frame corruption refuse.
Boot/manifest/schema/report identities and ordinary/early gates consume the
same policy. Final vector controls19passed11.97s; mixed integration307passed
50.49s; scoped Ruff/MyPy/Pyright/type-ratchet pass. Final dependency-chain
gate296contracts12.88s with2workers, then291comparators58.47s with5workers
(one slot reserved for Devin). These are focused gates, not the full suite.
Actual original/original replay advances1719→1759instructions and honestly
refuses AX4400/BX4 device information. At the retained native1719-instruction
cutpoint, all captured integer registers and all654784 declared RAM bytes
match exactly, including the previous interrupt-frame discrepancy; no bytes
are normalized or discarded. Retained capture is not fresh KVM acceptance.
Receipts: real16-vectors/REVIEW.md and native-cutpoint-comparison.json.
Fresh direct KVM execution subsequently became available (device10:232/API12).
Repeated native capture has the same zero-difference result; production native
reset/snapshot/abort/resize controls12passed20.00s. Earlier device-limited
invocations remain skips, not passes. Native descriptor provenance remains
independently staged with Devin; the rejected anchor design is not deployed.
Broad failures, full M6 termination/reset and original M0-M7 acceptance remain
open.

2026-10-03 M6 interrupt memory correction: enabled ordinary INT21 summaries now
retain checked saved IP/CS/FLAGS bytes before service reads, including output
buffers overlapping their own frame. Returning summaries restoreSP; frame
bytes remain observable. Code overlap, undeclared stack bytes, frame wrap,
prefixed forms and service writes into the live return frame refuse. No handler
control is guessed. Entry semantics bind environment identity and CLI/schema;
tests/docs preserve exact write projections. Saved baseline7red/1pass; expanded
integration308pass/2stale write expectations, both fixed and independently
rerun in29passing frame/file-copy controls. Final early gate296contracts14.22s
then272comparator controls56.34s; scoped Ruff/MyPy/Pyright/type-ratchet pass.
The captured native frame has a routine regression. Actual original/original
startup still refuses AH35 at1719instructions. Fresh KVM unavailable; original
M0-M7 remains incomplete. Receipts: real16-interrupt-frame/REVIEW.md.

2026-10-03 M6 explicit RAM: one bounded initial-memory owner now combines the
process allocation, optional MCB and up to32 explicit disjoint extra regions.
CPU accesses, observations and input/output buffers share exact coverage;
aliases, gaps and page padding remain rejected. Bytes and coordinates bind
boot/environment identity; executable scope and DOS allocation grants stay
unchanged. Integration153passed43.84s; final memory19passed11.66s; scoped Ruff,
type-ratchet and ownership pass. Routine pipeline and owned contracts enrolled.
Actual captured environment bytes advance startup1198→1719instructions, then
INT21/AH35 refuses. Native post-service comparison agrees on all registers
except ES:BX/IP and1219 of1225 replay-written bytes; the remaining6 are the
interrupt frame belowSP. Cutpoints differ, so this is not native equivalence:
vector service and interrupt-frame effects remain explicit obligations.
Receipts: real16-extra-memory/REVIEW.md and native-comparison.json. M6 and the
original M0-M7 plan remain incomplete.

Latest Devin reset stage rejected after independent compiled-source review:
held reference descriptors change DOS overflow-handle values (21differences
in80allocations, first84→145). Production backend still matches its saved
pre-task hash. Worker reported14passes before terminating on model rate limit;
parent guest replay could not run without /dev/kvm. The compiled probe requires
no KVM and is retained as the next repair's mutation control. Avoid descriptor
anchors and speculative interposition; preserve native observables and bounded
ownership. See native-overflow-reset/PARENT_FINAL_REVIEW.md. No full M6 reset
or whole-plan acceptance claimed.

2026-10-03 M6 resize boundary implemented: source-bound native before/after
capture established the first/final-MCB transition; the explicit
`kvikdos_single_tail` policy now models INT21/AH4A success, exhaustion and bad
metadata, preserving upper halves and unowned flags and recording checked
before/after metadata receipts. Other blocks/chains refuse. The initial full
allocation and MCB enter boot/environment identity; physical RAM remains
available after shrink. Native fixed PSP comes from the backend environment
contract, not binary-name recognition. Public schemas, docs, result comparison,
typing/lint and routine tests are coherent. Six native KVM cases match; replay
baseline6red/1pass, integration173pass, native/PE32 cohort52pass. A stale Make
dependency assertion from the earlier gate change was caught and corrected;
final pipeline/ownership/allocator/Make controls182pass. Scoped Ruff/Pyright/
type-ratchet/ownership pass. Receipts: real16-resize-policy/REVIEW.md.
Actual startup advances from39steps to1198, then refuses undeclared DOS
environment memory at0640. Explicit extra initial-memory declarations are the
next M6 obligation; full allocator/snapshot/environment and original M0-M7
acceptance remain open. Devin handle-reset review resumed after its service
rate limit (log native-overflow-reset/devin-review-after-reset.log); its staged
patch remains unpromoted pending parent review.

2026-10-03 bounded gate optimization: `test-pipeline-fast` now requires shared
decompiler contracts followed by fail-fast comparator admission before the broad
suite. Dependency edges serialize pytest pools under parallel Make. Four new
ordering controls fail the saved baseline; worker-budget controls also reject
the previous six-worker contract startup. The unchanged296contract controls
measured28.68s with six workers and15.05s with two; only this small precheck is
capped at two, preserving serial requests. Comparator admission retains the
requested pool. These shared-host measurements are not whole-suite acceptance
or an end-to-end speedup. Receipts: early-gate-order/.
Final actual dependency-chain gate:296passed15.94s with two contract workers,
then264passed60.03s with six comparator workers. All31Make controls pass4.40s;
scoped Ruff/Pyright and startup context pass. Broad gate remains unresolved.

M6 native entry evidence: captured Kvikdos registers and guest memory before its
first KVM_RUN. Owned MZ loader relocation bytes, CS:IP0110:0F9A and SS:SP07A5:0800
match the capture. PSP0100 has651264allocated bytes. Public original/original
initialized replay reaches39instructions and refuses INT21/AH4A at0110:1011,
ES0100/BX15EA. Unlike the previous synthetic small arena, this requests shrink.
The capture closes the initial-allocation question; it does not model resize,
MCB/handle/service state, establish full snapshot isolation, or close M6.
Receipts: native-boot-capture/{hashes,environment,replay}.json.

2026-10-03 M2 root-bound call improvement: a generic nested callee summary can
lose caller-proved pointer/return-slot disjointness. A typed nested return-proof
failure now permits one retry over exact root-derived state using the existing
composition and solver owners. Generic summaries are not reused by address in
that mode; lifted blocks are reused. All work/deadline caps remain shared, and
root-frame failures skip the redundant retry. Failed-attempt proof records and
equality-cache roots are discarded. Declared stack premises still constrain only
root ESP and remain conditional. Native caller->wrapper->store controls change
from refusal to passed (equal) / failed (changed memory); both PE32 drivers have
positive/mutation/bad-return controls. Final new/domain/budget49controls pass;
integration/real16 cohort251passes and both adapter suites19/17pass. Scoped
Ruff/Pyright/type-ratchet pass. Tests join routine pipeline, ownership, lint and
fast comparator gates. Frozen BC5 self/changed samples remain15refused each;
no corpus gain or whole-plan acceptance claimed. Receipts: contextual-flat32/.
Devin reset-review launch terminated on service rate limit; its older staged
overflow-fd patch remains unpromoted. Original M0-M7 remains incomplete.

2026-10-03 reviewed checkpoint: scheduler EOF now waits for actual process exit
or the original deadline, without polling closed pipes. Saved-baseline red and
33passing scheduler/7passing fork controls cover the repair. Concurrency fixture
observations now survive a peer's departure; the previously measured8-second
waits disappear without reducing deadlines or inventing observed peaks.
Scheduler plus BP cohort57passed21.56s serial after this cost repair.
Devin's three NOP fixture files were reviewed against unchanged dirty baselines
and integrated; source-bound native coverage and corruption gates stay intact.
Parent81controls pass; scoped Ruff and Pyright pass after an explicit located-
instruction fixture assertion. Expanded comparator-check-fast242passed109.61s
with2workers. It now catches the scheduler race and these fixture failures before
a broad run. No broad acceptance or controlled whole-suite speedup is claimed.
Native overflow-fd repair remains unpromoted on ownership/failure-propagation
grounds; InitBars still has a semantic materialization failure and discovery
cost. Receipts: scheduler-review/,nop-fixture-review/,initbars-cost/ and
native-overflow-reset/PARENT_EARLY_REVIEW.md. Original M0-M7 remains incomplete.

2026-10-03 gate result: comparator-check-fast189passed89.05s with2workers;
full changed-surface type-ratchet passes and scoped production Pyright is clean.
Broad fast pipeline:25failed/9510passed in1953.63s with4workers, following
296passing contracts. Previous failure diff:12retained,5no longer failing,
13newly observed. New NOP/coverage fixtures and scheduler/live-function failures
need diagnosis; source evidence must not be weakened to clear them. The failed
pipeline prevented this Make invocation from reaching decomp-opt-regression.
All jobs are terminal. Original M0-M7 is not accepted; no whole-suite controlled
speedup follows from these differently loaded runs. See `collection-cost-review/`
failure-diff.json and final logs, plus the current acceptance checklist.

Native reset repair accepted for its measured channels: parent independently
reproduced5staged/baseline controls, then integrated video/environment clearing
and mapped-handle draining. Ordinary existing worker-native module now includes
the four reset regressions and compiles one wrapper per cohort. Production
6native controls pass42.36s;37worker/range/protocol/snapshot controls pass16.07s.
No staging loader or frozen implementation is used by production tests.
Overflow handles and external state are not isolated by this patch; parent
explicitly rejected their claimed invisibility. M6.2 and the original plan
remain open. Receipts: `native-reset-repair/PARENT_REVIEW.md`,
`production-native.log`, `production-fast.log`.

Type-ratchet cost checkpoint: parent profiling found38ASTparses,33changed-line
queries and58subprocesses for three files (18.30s). Explicit per-file source/
changed-line/AST traversal reuse reduces this to5parses,3queries,8subprocesses
(5.00s under concurrent load). No global cache or cross-run reuse is introduced.
The deterministic work-count regression fails the saved baseline11versus1;
all50unchanged controls plus two new work/invalidation controls pass. Production
52tests pass3.01s, scoped Ruff/Pyright and self-ratchet pass. Existing routine
test enrollment retains these controls. Full changed-surface ratchet is running;
this profile is not a whole-project performance claim. Receipts: `type-ratchet-cost/`.

The entry-domain staged shared budget now passes16worker controls and terminates
the actual SORTD replay, but converts no caller refusals:7remain CALL_ON_PATH.
The remaining gaps are an invocation-domain premise and an unresolved nested
callee. The stage is not promoted and does not satisfy M2. Native reset worker
has5passing controls, including saved-baseline mutation; independent parent
native verification is running. Parent rejected its overflow-handle
guest-invisibility claim because native handle>=20 maps directly to host fd.
M6 full isolation remains open even if the three-channel repair is accepted.

Latest execution checkpoint: the bounded directory-report cache is now integrated
in Make and both pipeline pytest lanes. Ordered collection and exit-code parity
passed for normal, duplicate, parametrized, missing-selector and import-error
cases; directory mutation and custom-collector controls pass. Focused cache
tests7passed; pipeline/Make/ownership integration150passed. The prior interrupted
gate remains interrupted evidence. A fresh `collection-cost-review/quality-dev.log`
gate uses4pytest slots, with one serial slot each reserved for entry-domain
call binding and native reset repair. End-to-end timing is pending.

The early `comparator-check-fast` gate is integrated; its original eleven-module
selection passed182tests in128.91s with3workers. The added collection-cache
module needs a fresh combined measurement. Timeout-readiness repair is integrated
after frozen-baseline red, delayed-start and broken-cleanup controls; final
timeout/Make cohort27passed. Production timeout budgets were not increased.

Native reset now has an authentic KVM red: a reused VM retained video byte90
where a fresh VM returned0 (1failed44.34s). Devin's wrapper repair remains staged.
Entry-domain call binding also remains staged: parent found nested imports reset
the64-resolution allowance. Shared aggregate-budget controls are required before
promotion; see `entry-domain-call-binding/PARENT_AGGREGATE_BUDGET_REVIEW.md`.
Neither focused success nor these in-flight tasks complete an original milestone.

Measured collection bottleneck: parent sampled two live pytest workers in
directory/file collection and retained a two-second syscall trace. The fresh
quality-dev was deliberately interrupted to validate this bottleneck instead
of continuing the costly collection route: terminal exit2,322passed/5warnings
1394.51s after the earlier296-contract lane passed. This is interrupted evidence,
not a new broad success or17-failure clearance. A bounded40-file collection
probe confirms1640file-discovery hook calls versus41with staged unchanged-Dir
report reuse; ordered node IDs match,1.927s versus1.507s. The plugin is not
promoted: duplicate/parametrized/missing-selector and mutation controls remain
required. Receipts: `collection-cost-review/` and `control-budget-stage/logs/`.
Queued native-reset, timeout-fixture and focused-comparator checks have started.

Execution control: the [original acceptance checklist](binary-behavior-acceptance-checklist.md)
now enumerates the original milestone obligations and the7behavior x2architecture
x4control-class matrix. It preserves the original scope and frozen corpus;
it is not new acceptance evidence or an implementation-effort percentage.
The KVM sandbox launcher now succeeds (exact device/API checks retained),
superseding the earlier missing-device observation. Native reset validation
remains queued behind the current six-slot allocation.

Call-binding review clarification: the retained SORTD CALL at0x10929 has
bytes E8 68 FE and physically targets0x10794. The analysis helper normalizes
that target through36NOPs to catalog entry0x107b8. Parent independently checked
both binary hashes and file bytes and located the padding canonicalization
in analysis_helpers. Native entry and catalog identity must remain distinct
unless the skipped-byte effects are authenticated. Devin's staged transport
remains under development; this finding is not a new callee/caller proof.
Receipt: `entry-domain-call-binding/PARENT_TARGET_REVIEW.md`.

Latest parent control-budget checkpoint: the reviewed shared-premise solver
optimization is integrated. Independent unchanged controls passed34/34; the
new deterministic native four-query regression failed the saved production
baseline and passed the candidate. Final production cohort35passed/3warnings
34.98s; scoped Pyright0errors and Ruff clean. Per-arm source/domain checks,
aggregate deadline/query limits and unknown refusals remain unchanged.
Receipts: `control-budget-stage/PARENT_REVIEW.md` and `logs/production-tests.log`.
A fresh quality-dev is now running with5pytestworkers and3compilerworkers,
reserving one serial test slot for the staged entry-domain call-binding Devin.
No broad-gate result, corpus conversion or original milestone exit is claimed.

Native NOP corpus check after integration: exact SORTD callee0x10794 now has
coverage_complete=true and closure_complete=true with36NOPs and no refusals
(`nop-parent-verification/caller-review/callee-closure-current.json`). Its caller
0x108d0 still retains7pending jumps: CALL0x10929 lacks a bound preservation
proof. Source review identifies an unconditional importer-time CALL_ON_PATH
gate; later segment preservation contracts are not connected there. A bounded
staged Devin task now owns that transport, preserving native call/source/domain
binding and refusal defaults. No caller/function acceptance follows from the
callee result.

Countdown-budget Devin task is terminal with a staged one-owner optimization:
one shared premise solver across ITE arms and incremental SimpleSolver under
unchanged query/deadline limits. Worker reports34unchanged controls passing and
304.7ms->65.4ms on the failing attempt; parent review and independent34-control
plus corruption/budget verification are running. It is not promoted yet.

NOP integration checkpoint: parent verified saved dirty-source hashes and
promoted the reviewed native-binding repair plus bounded immutable-fact cache.
Six IR owners and three ordinary-import test modules are enrolled in Make,
pipeline and ownership gates. Production cohort78passed/3warnings81.70s;
final NOP cohort31passed/3warnings47.08s after explicit type narrowing;
enrollment123passed18.36s. Scoped Ruff and six-owner Pyright pass. SORTD swaps
still fails caller-target completeness atIR_BUILD_REFUSED in a focused replay;
no function fix or new corpus coverage is claimed. Final project gate remains
due; prior broad17failures are not cleared by these focused results. Receipts
and exact production-before hashes: `nop-parent-verification/`.

NOP parent performance repair (still staged): independent measurement found
100repeat coverage checks over36NOPs performed100native lifts and cost3.3209s.
Parent reused the existing architecture/exact-byte bounded cache with16entries,
at most4096code bytes and2048statement projections per cached entry. Cached
values contain immutable mark/transfer facts only; current loader bytes,
decoded extents and artifact provenance remain checked per evaluation. Native
relifts isolate frontend condition-recorder state. Oversized entries bypass
the cache rather than reducing proof capability. Same measurement now records
0repeat lifts/0.1034s; this is local repeated-query cost, not corpus speedup.
All30existing staged controls independently pass after this change
(3workers,51.60s). The new warm-cache/stale-byte control also passes
(1control,21.62s including imports). Receipts:
`nop-parent-verification/{coverage-cost,cached-coverage-cost,cached-tests}.log`.
No NOP production promotion or M0-M7 acceptance yet. A separate one-slot Devin
task is profiling the reproducible countdown control budget failure under
unchanged limits (`control-budget-stage/`).

Latest broad refresh: `nonleaf-parent-final/quality-dev.log` is terminal exit2.
Its main five-worker cohort records17failed/9488passed/19skipped/69warnings
in2323.00s; the preceding296-contract lane passed. No NOP staged code was
promoted during this gate. Four real16-control-boundary failures now have a
focused serial recheck running; no failure attribution is established yet.
Parent independent NOP verification uses a frozen private candidate with three
workers, alongside Devin's one-slot staged checks (aggregate remains at most6).
The M6 native reset test could not launch: the verified KVM transport reports
FileNotFoundError for `/dev/kvm`; this is environment-limited, not a test pass
or evidence that the reset defect is fixed. Native receipt:
`m6-snapshot-audit/parent-native-reset.log`. Original M0-M7 remains incomplete.

Parent verification update: frozen staged NOP candidate independently passes
30controls/3warnings45.61s with3workers (`nop-parent-verification/tests.log`).
Production remains unchanged. Focused serial real16-control-boundary replay
is terminal1:25passed/1failed/1warning35.37s; the remaining failure is
test_countdown_head_branch_proof_through_boundary. Three of the four broad
boundary failures did not recur in this replay; no blanket baseline or load
attribution is justified. Broad failure delta is retained in
`nonleaf-parent-final/quality-dev-failures.json` (six new, ten previous failures
absent). Required project acceptance is still open.

M6 source-audit checkpoint: a separate read-only Devin audit is terminal and
parent reviewed the native wrapper plus kvikdos reset/handle/exit source.
The wrapper snapshots only conventional-memory bytes; reused sessions retain
unreset video RAM and a process-static DOS handle map in the inspected paths.
Parent added a native MZ writer/reader repeated-reset regression under
`.cache/comparator-implementation/m6-snapshot-audit/test_parent_native_reset.py`;
execution is pending the six-slot test budget and verified KVM availability.
`PARENT_REVIEW.md` rejects treating memory-only checkpoints or identical
oracle/candidate residual state as full M6 acceptance. Fresh process isolation
does not reset host filesystem/output effects. Original snapshot/environment
obligations remain open; no production reset repair is claimed.

Parent NOP-census review checkpoint: the first staged Devin deliverable is
not accepted. An independent native `a3 34 12 c3` control replaces the STORE
head with a fabricated mark-tagged NOP and still obtains coverage.complete=True
(ledger 1/1/1/1/0). The immutable regression and red receipt are
`nop-census-stage/after/tests/test_parent_nop_binding.py` and
`nop-census-stage/parent-binding-red.log` under `.cache/comparator-implementation/`.
This is a coverage/source-binding defect, not a demonstrated whole-function
false equivalence. A bounded staged-only Devin repair is running; production
has not received the NOP patch. The fresh broad quality-dev passed its
296-contract lane and entered the five-worker fast pipeline; its final outcome
is still pending. No original M0-M7 acceptance follows.

Further parent source review identifies two mandatory NOP integration consumers:
the invocation engine's exact origin-field binding must include the new field
(otherwise even unchanged ordinary origins refuse), and its scalar simulation
must consume authenticated native NOP effects explicitly. Added parent controls
for origin equality and mutation; execution remains pending while the current
gate and worker occupy the six test slots. Evidence and bounded follow-up scope
are retained in `nop-census-stage/PARENT_CONSUMER_REVIEW.md` and
`.cache/devin-prompts/nop-invocation-consumers.md`. No consumer repair is yet
claimed; the NOP patch remains unpromoted.

This ledger records finished implementation steps, rather than treating a
partially implemented milestone as accepted. `DONE` means the bounded step has
parent-reviewed implementation and focused evidence recorded below. `PARTIAL`
means implementation exists but its stated acceptance still has open work.
`OPEN` means the milestone exit has not been established. Historical focused
results are identified as such; they are not results of the current full run.

| Milestone | Finished steps | Step status | Remaining milestone acceptance |
| --- | --- | --- | --- |
| M0 — Baselines and audit | Saved actual source/binary/build baselines; audited proof promotion; current complete representative and tiny-control matrix. | ACCEPTED | Original M0 exit accepted 2026-10-03; refusals in its baseline do not close later proof milestones. |
| M1 — Evidence contracts | Shared typed obligations, explicit public domains, identity/provenance binding, dependency closure, complete accounting and both-track integration; current rejection, fixture-retention and cache-parity evidence. | ACCEPTED | Original M1 exit accepted 2026-10-03; final project/release gates remain M7 obligations. |
| M2 — Direct calls | Full-state direct-call composition, near/far/operand-size frames, argument/alias/return/cleanup and dependency controls; unchanged 323-test selection and current early gate pass. | ACCEPTED | Original M2 exit accepted 2026-10-03; arbitrary unresolved calls remain refused. Final release gates belong to M7. |
| M3 — Matched loops | Full-state closed induction, nested/early/partial-register and near/far call-loop controls; reviewed flat32 callee composition and actual PE32 public proofs through both drivers. | ACCEPTED | Original M3 exit accepted 2026-10-03 for admitted closed matching graphs; different shapes, recursion and environment proof remain separate milestones. |
| M4 — Relational loops | Reviewed register/affine/stack relations, split/merged covers, rotation, condition/progress and full-state invariants; actual-MZ and both actual-PE public driver controls pass. | ACCEPTED | Original M4 accepted 2026-10-03; unsupported relations and invariant exhaustion stay unknown. Representative release corpus and project gates remain M7. |
| M5 — Recursion, indirect calls, environment | Recursive components, finite indirect calls, faults/terminal outcomes, ordered-I/O caller propagation, DOS/BIOS queries and PE import services are integrated with explicit scopes. | PARTIAL | Bounded implementation/evidence reconciled in m5-exit-audit-current/PARENT_RECONCILIATION.md; required final checkpoint gates remain open. Initialized recursive components and environment contracts remain conditional; arbitrary-entry rows are not upgraded. |
| M6 — Differential execution | Independent function replay, immutable snapshots, full observations and guarded deterministic capture/fuzz vectors; initialized MZ file/seek/output/device/termination and bounded PE32 program scenarios. | ACCEPTED | Original M6 accepted 2026-10-03 with fresh228-test selection, reviewed21-test capture selection and current early gate. Declared-service/import-free PE32 limits remain explicit; universal environment proof belongs to M5. |
| M7 — Integration and release | Schemas, CLI/report surfaces, routine test enrollment, scoped types/lint and measured bounded proof work implemented. | PARTIAL | Cold/warm corpus/performance/dependency-cache evidence and passing final project/release gates. |

Latest completed broad `quality-dev` (22422): exit2; main cohort
19failed/10718passed/23skipped in1617.47s. Eight failing cases were subsequently
repaired with focused evidence; eleven native regressions remain unresolved.
The later post-retry corpus refresh and nine dependency controls pass their
accounting/check obligations but do not replace this red broad gate. Receipts:
`m7-transitive-refresh/GATE_RESULT.md` and `m7-post-retry-corpus/PARENT_REVIEW.md`.

Earlier broad `quality-dev` (79472): exit2; main cohort
13failed/10483passed/23skipped in1008.86s. Three stale ledger assertions were
subsequently repaired with a seven-test focused pass; the broad run remains red.
PE32 public integration later passed32production and126enrollment/ownership
controls; those focused results do not replace the broad gate.

Historical broad `quality-dev`: exit2; main cohort21failed/9476passed/
63warnings in2126.09s, actual3pytestworkers. Earlier296contracts used6workers;
the fast runner's hard-coded worker setting was corrected for future runs.
Seven failed tooling controls now pass in the focused81-test runner/Make cohort;
the remaining14 broad failures are unresolved. This does not retroactively pass
the broad gate. Exact inventory: native-dos-process-stage/quality-dev-failures.json
under .cache/comparator-implementation/. Nonleaf segment preservation is now
parent-reviewed/integrated with60production controls passing; a new5-worker
quality-dev is running. Native NOP census repair remains staged. Neither result
establishes full milestone acceptance.

Earlier broad `quality-dev` main cohort: 70 failed / 9,123 passed /
64 warnings in 1,656.88s; its subsequent regression lane did not run because
Make stopped at the failing fast pipeline. The exact 70-node inventory spans
21 modules and is retained in the native CFG task's
`broad-failure-inventory.json`; the failures are not collectively classified
as baseline debt. Later focused contract repairs and staged invocation
controls pass, but whole-suite and release acceptance remain open.

Current production-control checkpoint (2026-10-02): the reviewed entry-jump
and invocation-domain owners are integrated and routinely enrolled. Their
combined target/context cohort passes 157 controls; the post-refactor target
and invocation-boundary cohort passes 47, and scoped Pyright/Ruff pass.
A preceding native-stack consumer cohort had 12 failures / 32 passes.
The caller-entry-context failure is now repaired at its fixture authority:
the backward CALL refuses without a CS-domain premise, and passes only with
authenticated initialized-MZ invocation evidence; all 10 segment-use controls
pass. The other 11 allocation/cleanup consumer failures now have a reviewed
bounded Devin repair: symbolic operands consume the native target-binding
theorem, with call-encoding equality and a separate original-domain proof for
slice fallbacks. Parent independent final run: 42 passed / 3 warnings in
23.14 seconds; Ruff passed. Exact dirty-baseline delta and review qualifications
are retained in `.cache/comparator-implementation/native-stack-symbolic-call/`.
This binds the tested call, not whole-image correspondence or initialized
invocation. The broad failure total has not been refreshed.
These results do not establish corpus coverage, final gates or M0–M7 acceptance.
Parent review rejected the first native adapter draft: it rewrote an unbound
symbolic CALL operand to a decoded constant without discharging the target
theorem. The draft and failing corruption control are retained; only its owned
files were restored to the saved dirty baseline. The resumed repair described
above consumes the existing source-bound target proof. Separately, the stale SSA
cache builder mock is repaired against the retained-IR contract, with 11 controls
passing; this does not establish slice-coordinate closure.

Current flat32 frontier (2026-10-02): a bounded read-only Devin investigation
traced BC5 `sub_401234` to unconstrained entry-ESP return-slot/global-store
aliasing. The current one-function diagnostic remains refused; no corpus
conversion is claimed. The parent confirmed the existing input-constraint channel
is absent from call-return proof and final composed comparison, and ran the
unchanged composition cohort: 19 passed / 3 warnings in 9.55 seconds. The optional
stack-domain API now has parent review: 62 proof/MSC8/BC5 adapter controls passed
in 34.47 seconds, with scoped Ruff and Pyright clean. Caller-declared premises
remain conditional and visible. Constraints apply only to root-frame obligations;
nested premise-dependent calls remain refused pending correct domain transport.
Parent moved the new controls into the required ownership directory and enrolled
them in routine gates; 130 moved-control/enrollment checks passed in 16.78 seconds.
Driver exposure now has parent-reviewed focused evidence. A source-frozen
BC5 sub_401234 original/original run at timeout-ms5000 remains refused: no
premise gives call-return timeout; a hypothetical explicit ESP interval exposes
the expression cap. No corpus conversion is claimed. Diagnostic DAG traversal
gets past that cap but still refuses an outside-function edge at0x49f780.
The bounded resource-owner review is complete: distinct retained DAG nodes are
counted with separate edge/depth/cycle guards; configured limits remain unchanged.
Parent review and current benchmark qualifications are recorded below.
Receipts: .cache/comparator-implementation/flat32-domain-public-checkpoint/.
API receipts:
`.cache/comparator-implementation/flat32-stack-domain/`. No default OS premise or
larger resource budget follows from this finding.

CMP16 bounded direct-address follow-up (`--addr 0x101a7`, outer 180-second limit)
terminated124 with postprocess validation still changed. It is not a passing
rerun of the earlier exact-slice gate. A separate parent typed-AST probe confirmed
goto observables record heap object repr: regenerated identical arithmetic targets
have equal boundary fingerprints but different controls. The bounded target-identity repair is now parent-reviewed: deterministic typed
identity plus explicit incompleteness replaces detached object IDs. Identical
unknowns refuse; result/snapshot admission rejects retained semantic failures.
Independent final cohort338passed, including width/operator/index mutation
controls; actual node release is separately verified by weak reference. A stale
switch fixture now retains its unproved return delta after an independent16-bit
Z3 countermodel, rather than expecting an unsupported precision suppression.
Function and whole-gate acceptance remain open; logs/probe receipts are under `real16-invocation-domain/`, repair receipts
under `goto-target-identity/` in `.cache/comparator-implementation/`.
Current shared-tree type ratchet, ownership and `linters-dev` pass. The refreshed
optimization regression gate fails on its first `CMP16.EXE` invocation with
zero generated functions and return code 2; later binaries did not run. Its
subprocess failure cause remains under diagnosis. Historical green optimization
results cannot substitute for this failed current checkpoint.
The optimization guard now retains full child stdout/stderr and generated
artifacts for failed runs, including partial raw timeout streams; it prints the
retained directory and includes paths in failed JSON reports. Successful runs
are still cleaned. The diagnostic and pipeline-enrollment cohort passes 60
controls, with scoped lint/type/ownership checks passing. This reporting repair
does not discharge the `CMP16` validation or any original milestone exit.

**No milestone is marked fully accepted by this ledger.** Completion percentages
are not established from these unequally sized steps. The historical three-worker quality-dev gate failed: preliminary cohort
296 passed; main cohort 8,868 passed, 28 failed and 1 skipped. Current-tree REP
store revalidation passes19 tests without a REP edit; it does not retroactively
accept that broad gate. The latest isolated corpus saved-phase aggregation
retains all20 selected functions; real16 and BC5 proof refusals remain open.

The last completed `test-pipeline` checkpoint has 24 failed / 8,971 passed /
5 skipped in its main cohort and 306 passed / 1 skipped in its relational
cohort; two fixture/build lanes also failed (one passed lane, three failed).
Later KVM-bound gate attempts stopped before Make/test startup. The newest
combined-program scoped cohort passes 104 controls; it does not supersede
the failing project gates or establish full M6 acceptance.


Latest production checkpoint (2026-10-01): reviewed real16 native control-domain
routing is integrated with bounded memoized encoding, shared solver/deadline
budgets and enforced closed evidence accounting. Native target proof excludes
pair relocation rewrites. The production dosunit/control cohort passes 243 tests
with 5 skipped, using exactly three workers; new helper/test Pyright reports
zero errors. Independent review reproduced three defects before parent fixes.
The typed-import errors are fixed by a reviewed four-entry config patch.
The reviewed enum conversion fix passes native warm-cache and status controls.
The mandatory Cython isolated-package repair is now parent-reviewed and integrated;
native import smoke passes39modules and the combined source-bound boot/backend
cohort passes158controls. Current quality-dev has passed linters/type ratchet,
startup and296ownership controls and is live in fast external pipeline; no final
project acceptance is claimed. The fresh unchanged-selection 20-function corpus run finished with complete
accounting: real16 self still refuses three, MSC8 self passes two and BC5 refuses
fifteen. A BC5 cold/warm timeout changes one refusal reason; parity is unaccepted.
These checks do not close
M0-M7 or the earlier near-return selector-window prerequisite. Detailed receipts
and previous gate failures remain recorded below.

Current follow-up (2026-10-01): shared symbolic CALL-target binding and
retained semantic-projection/decoded-index transport are integrated. The
production four-module gate cohort passes 59 controls; its 13 new admission
controls are routinely enrolled. Parent-reviewed native fixture repairs close
all 24 input/pointer-return consumer failures: the combined original consumer
and retention regression cohort passes 43 tests. Original test bodies and
assertions remain intact; scoped Ruff, typing and owner type ratchet pass.
The actual near-return cohort passes 30 tests with one stack-entry-context
failure at SELECTOR_WINDOW_UNPROVED. Independent 16-bit replay confirms that
its backward CALL has different physical targets for different admitted CS
values, so the guard must remain; explicit proved selector-window/domain
support is still required. Final project/corpus gates and original M0-M7
acceptance remain open. Detailed receipts are in the latest checkpoints below.

Earlier M5 checkpoint: bind each CALL to its own continuation, rather than only
proving membership in the global continuation set. Parent reproduced an actual
real16 swapped-continuation false proof (1 failed, 1 passed before the fix), and
the corrected focused real16 pair passes (2 passed). The first combined run has
2 real16 passes and 4 flat32 failures at the existing typed conditional-exit
lowering refusal. The parent then found that VEX continued lifting instructions
after JECXZ. Relifting through the decoded exiting instruction separates those
fallthrough effects while preserving the existing unsafe-effect refusal.
The focused CALL/contract cohort passes 38 in 29.41 seconds; after the small
lowering refactor, the combined CALL/contract, flat32 adapter and real16 region
cohort passes 77 in 31.15 seconds, both with exactly three workers. Ruff and
changed-owner Pyright pass. Contract tests are enrolled in the fast lane and
actual-binary binding tests in the default/expanded lane. The bounded Devin
review ended after 480 seconds without files; parent native boundary controls
reproduce four failures against the saved dirty baseline and pass after the
split, retaining two unsafe-effect/fault refusals. The current combined cohort
passes 58 and the actual-MZ joint cohort passes 5. Scoped Ruff, MyPy, Pyright,
type, startup and ownership checks pass; stable-checkpoint gates remain open. The real16
region test that failed in the broad run passes in this focused run; the cause
of that discrepancy is not yet classified.

The user-requested full pytest run is terminal: exactly `-n 3`, exit 1,
15,789 passed, 223 failed, 179 skipped and 164 warnings in 2,594.02 seconds
(43 minutes 14 seconds). One worker terminated unexpectedly and was replaced.
Comparator-related failures include 26 dosunit tests, one real16 finite-region
test and the four flat32 CALL-continuation cases. Failures also affect CLI,
SORTDEMO and other decompiler surfaces. Their causes are not collectively
classified as baseline debt or unrelated failures. Full output and a structured
result are retained in the ignored `.cache/pytest/user-three-workers/pytest.log`
and `result.json`. This run does not establish full-suite acceptance.

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
in-scope 386 operand/address overrides; and the currently supported flat i386
PE32/ELF32 adapters. Bit width is not an executable-format contract. Unsupported
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

## Staged delivery and planning estimates (2026-09-29)

Deliver usable checkpoints before the complete M0-M7 acceptance. The initial
delivery target is the real16 function-comparison workflow already relevant to
this workspace. Flat32 keeps its own acceptance and remains a required final
track. A pilot on one track does not close a two-track milestone or establish
whole-program DOS behavior.

The estimates below are planning judgments, not measured implementation rates
or deadlines. They assume one primary implementation/review stream, working
days of approximately six to eight engineering hours including validation,
available required backends, a fixed small corpus and no major new model defect.
Each row is additional effort after its prerequisites. Existing partial code
may reduce the effort; known gate failures and new soundness findings may expand
it. Reestimate after D0 and each accepted delivery using observed work/results.

| Delivery | User-visible result and acceptance boundary | Additional effort estimate |
| --- | --- | --- |
| D0 — Stable baseline | Immutable source/binary snapshot, fixed target manifest, current verdict matrix and classified blockers for the selected public path. Preserve the known failed gates and close or explicitly refuse affected proof paths. | 1-2 working days |
| D1 — First usable real16 pilot | Reproducible existing public command, input manifest and report for selected function pairs with direct calls and matched loops. Positive and deliberately corrupted binaries establish the published supported scope; UNKNOWN/CONDITIONAL remain visible. | 1-3 working days |
| D2 — Cheaper and broader comparison | Priority experiments 1-2 accepted on the frozen corpus: direct state relations and shared memory expressions, with measured coverage/time/RSS and full observation parity. | 3-7 working days |
| D3 — Different loop shapes | Priority experiments 3-4: bounded unequal-step matching and invariant refinement, including unrolling by two, remainder paths, rotated guards and distinct counters. Publish exact accepted relation families and refusals. | 5-10 working days |
| D4 — Repeated use and both tracks | Priority experiment 5 with cold/warm/cache-disabled parity; repeatable batch workflow and both MSC8/BC5 flat32 adapter acceptance for the selected supported corpus. Existing flat32 checks continue before this delivery. | 3-7 working days |
| D5 — Wider binary/environment acceptance | Remaining M5-M7 obligations: recursive and indirect calls, address/fault/environment closure, initialized whole-program scenarios and representative release gates for both tracks. | 15-40+ working days; lowest confidence |

Planning envelope: D1 in roughly 2-5 working days; D1-D4 in roughly 3-6 working
weeks. Reserve roughly 2-4 calendar months or more for the complete admitted
plan, with low confidence until D0 and explicit environment scope are settled.
Unmodeled services/devices, unavailable execution backends or new false proofs
invalidate that envelope; do not promise full arbitrary-binary equivalence by
a date. Time spent waiting on user input, hardware or external services is not
included. These estimates do not assert continuous unattended execution.

### What makes an intermediate delivery usable

Each delivery supplies a reproducible command and fixed example inputs, a pinned
source/binary/model identity, a capability/refusal matrix and preserved detailed
evidence. Reports distinguish proved equivalence under the declared function
contract, modeled/replayed mismatch, conditional proof and unknown. A function
contract must never be displayed as full initialized-program equivalence.

Require focused semantic positive/mutation/refusal controls and applicable
project gates for the checkpoint. A known relevant false proof blocks that
path. An unresolved broad gate means an explicitly experimental pilot, not a
green release; do not silently relabel failures as unrelated. Preserve the last
accepted checkpoint as new capabilities are developed, with opt-in retries until
their benefit and correctness are established. No commit/publication is implied
by this planning update.

### How to shorten time to useful results

- Select the first fixed corpus from actual user functions and their common
  refusal causes. Extend generic proof obligations that unlock that corpus;
  never add binary/address/name-specific proof exceptions.
- Finish D0-D1 before expanding exploratory recursive/environment work unless
  it blocks the selected proof path. Keep the full M5 scope on the ledger while
  delivering independently proved direct-call/loop capabilities first.
- Freeze the source checkpoint before acceptance runs. Keep ongoing work in an
  isolated checkout so broad runs do not become unusable through source drift;
  never reset or stash the shared dirty tree to create a baseline.
- Use focused regressions and scoped static checks during changes, then one
  coordinated required gate run per stable checkpoint. Fix relevant failures
  and rerun as required; avoid overlapping or repeatedly restarting broad gates.
  Retain the workspace pytest limit of three workers and aggregate proof budgets.
- Profile complete comparison runs before optimizing. Advance a bounded piece
  of priority 5 only if repeated proof work is the measured bottleneck and its
  identity/freshness prerequisites already hold. Do not build a second cache or
  rewrite the prover merely to anticipate future costs.
- Independent fixture, adapter-parity or reporting work may be delegated only
  with user authorization, disjoint ownership and parent acceptance. Shared
  semantic owners and broad acceptance runs remain coordinated; more workers
  alone do not imply faster completion or permission to raise resource limits.
- Reestimate after every delivery from completely proved corpus pairs at the
  same budget, measured end-to-end cost and the next unresolved prerequisite.
  If a research slice exceeds its agreed timebox, retain its explicit refusal
  and publish the accepted supported slice without claiming full-plan completion.

Execution adjustment after the user's plan update (2026-09-29):

1. Finish the already-green CALL-continuation patch's bounded review/static
   checks, then close that work item before expanding recursive proof machinery.
2. Reuse the existing M0 binary manifest: all four recorded SORTDEMO, SORTD and
   C23216 image hashes were freshly verified unchanged. Freeze the corresponding
   source checkpoint and exact public-function selection; do not rebuild a new
   corpus or treat these binary hashes as semantic acceptance.
3. Complete the D0-D1 public-command matrix for the selected direct-call/loop
   pairs, including equivalent modifications and deliberate corruptions. Keep
   both flat32 adapter regressions in the focused checkpoint.
4. Group the 223 broad failures by demonstrated cause and affected requirement.
   Start with the 26 dosunit failures and public-path blockers. A focused pass
   alone does not classify a prior broad failure as unrelated or repaired.
5. Run required broad gates once this checkpoint is stable. During edits use
   focused semantic controls and scoped static checks. Keep three pytest workers;
   the 43-minute full-suite run and 31-second focused run have different scopes
   and do not constitute a measured speedup of the full suite.

The repeated timed-out Devin handoffs recorded below are a coordination cost.
Use one bounded independent deliverable per job, inspect its actual output,
and return unfinished work to the parent at the deadline instead of repeatedly
delegating the same unresolved semantic prerequisite. These execution changes
preserve the original M0-M7 completion requirements and notification boundary.

## Prioritized coverage and resource work (2026-09-29, planned)

Objective: prove more original/rebuilt pairs within the same declared time and
memory limits. The trade-off is proof coverage versus search/formula cost;
soundness, complete observations and the admitted input domain are fixed.
These five experiments refine M2-M7, not a separate proof engine or an accepted
implementation milestone. Existing relation, region, memory and summary owners
are starting points: first identify the missing obligation and measured cost,
then extend the existing mechanism. Do not duplicate an already accepted path.

The order below governs new coverage/resource experiments. Outstanding false
proofs, machine-model prerequisites and acceptance failures keep priority over
optimization. Preserve the completion ledger and its unresolved requirements.

| Order | Experiment | Milestones | Reason for priority |
| --- | --- | --- | --- |
| 1 | Prove relations directly between executions | M3-M4 | Simple equality or affine relations can survive complex bodies without discovering either loop's closed form. |
| 2 | Share memory expressions and prove only differing updates | M4, M7 | Reduce duplicated array/store terms while retaining equality over the full memory contract. |
| 3 | Adapt comparison boundaries and match bounded groups of steps | M4 | Extend rotation/reblocking to bounded unequal-step correspondence, including compiler unrolling. |
| 4 | Propose and refine a bounded family of invariants | M4, M6 | Recover missing state relations after cheaper correspondence attempts fail. |
| 5 | Expand reuse of discharged obligations and summaries | M2, M7; M5 after joint acceptance | Reduce repeated proof work after obligation identity and dependency invalidation are stable. |

### 1. Direct relations between executions

Compare a paired transition under a candidate relation such as equal scalar
values, a register permutation or an exact-width affine map. A body containing
multiplication or other nonlinear operations need not have a closed-form loop
summary when a simple relation is inductive on the two executions. Sharing SSA
terms requires identical operators, widths and related operands; similarity of
instructions, names or syntax is only proposal evidence.

Prove initiation, every continuing transition, all exits and the declared
observable effects. Start with existing equality/permutation/affine owners;
no arbitrary nonlinear invariant synthesis is implied. Preserve full cutpoint
state and termination/divergence obligations.

Experiment: actual real16 and flat32 binary pairs with the same nonlinear
recurrence but changed registers or block boundaries; include changed operands,
guards, final flags and hidden stores. Success is more completely proved pairs
at the frozen budget, or lower formula/proof cost on the already proved pairs,
with no lost accepted case or mutation admission. Disable the new proposal or
term-sharing path to reproduce the baseline if acceptance fails.

### 2. Shared memory with explicit differing updates

Represent related input memory with shared expression DAGs where the declared
relation permits it. Identical proved address/value updates can share a result;
retain differing updates as ordered stores over that base. Prove complete array
equality, including untouched bytes, rather than narrowing observations to the
addresses visited by samples. Distinct loaded images and layout relations must
retain their existing initialization and translation obligations; never assume
their initial arrays equal merely to enable sharing.

Preserve physical segment aliasing, access widths, wrap policy, last-write
behavior and read dependencies. Reordered updates require proof of commutation
under the domain, including observable event/fault ordering. An unresolved
alias remains in the general array formula. Region grouping must not discard
intermediate code writes or native access prerequisites.

Experiment: array-writing loops with overlapping pointers, DS/SS physical aliases,
changed addresses/stores and initialized data differences. Record distinct DAG
nodes, stores and solver time. Accept a reduction only with unchanged full-memory
verdicts and the shared positive/mutation controls. Keep the general array path
available under the same total deadline; switching paths cannot reset budgets.

### 3. Adaptive boundaries and bounded unequal-step matching

Extend finite partitions/covers with deterministic proposals for 1:1, 1:2 and
2:1 groups of transitions before trying any larger configured group. Group sizes
are local proof steps, not a bound on the number of loop iterations. Retain every
intermediate branch outcome, early return, call, fault and observable event.
Moving a boundary past a temporary flag/register mismatch is permitted only when
composition preserves all intervening uses and effects; it does not authorize
dropping that component from the state contract.

Each paired macro-transition must have complete finite path coverage and prove
its successor relation. Both sides must make finite nonzero progress; a region
that may cycle internally needs a separate accepted progress proof or refuses.
No path can disappear because the convenient continuation was selected. Preserve
relative termination/divergence and all unmatched remainder paths.

Experiment: loop rotation and unrolling by two, with zero, one, odd/even and
wrap-boundary cases, nested early exits and calls. Require all-input proof for
equivalent binaries and rejection of a dropped remainder, skipped exit/event or
one-sided divergence. These are explicit M4 acceptance controls. Record searched
maps/groups and newly discharged pairs. Disable enlargement and retain existing
finite reblocking if the bounded extension fails acceptance. General loop
fusion/fission and arbitrary irreducible CFGs are outside this experiment.

### 4. Bounded invariant proposals and counterexample refinement

Use typed SSA facts first to propose exact-width equalities, affine counter or
pointer/index relations, bounds, phase bits and supported memory invariants.
Optional deterministic executions may rank or suggest candidates, but the
binary proof must not depend on traces being available or treat sample agreement
as a premise. Define a finite template family and proposal/refinement cap.

An internal-state SAT result may reject the proposed simulation without proving
a reachable binary mismatch. Refine a candidate with a needed domain relation
only after proving its initiation and preservation; never assume the offending
state unreachable or narrow the original input domain to remove it. Every final
candidate still requires complete exit, memory, control and progress proofs.

Experiment: upward/downward counters, pointer versus index, parity phases and
internal states excluded by an entry-established bound. Include plausible but
noninductive proposals and overflow/alias mutations. Success is additional
complete proofs within the unchanged budget; report proposals tried, rejected
and discharged. Exhaustion remains UNKNOWN. Disable this retry and retain the
earlier proof attempts and their diagnostics if it has no measured benefit.

### 5. Reuse of discharged obligations and summaries

Keep required M2 summary handling and M1 identity checks in place from the start;
this final experiment expands reuse across repeated regions/calls and runs.
Reuse only a completely discharged obligation under its exact scope, checking
the current caller precondition and continuation relation. Bind keys to binary
and loaded-image content, model/solver semantics, widths, ABI, observations,
input/memory/environment domains and the full dependency identities. Byte-equal
bodies alone do not prove equal callees, loaded data or environment effects.

Track partial/conditional evidence separately; a local recursive certificate
cannot become an unconditional public proof through caching. Preserve independent
freshness checks at producer/consumer boundaries and before/after seals. Do not
replace current source/image validation with metadata-only or persistent hash
reuse. Invalidate transitive dependents when a premise changes.

Experiment: change one callee, its loaded data, a model owner or an input contract
in a repeated-call corpus; compare cold, warm and cache-disabled verdicts and
dependencies. Success is less repeated work with identical evidence and reliable
invalidation. Incremental solver contexts are an optional measured subexperiment,
not an assumed speedup. Cache-disabled execution remains the rollback/control.

### Shared budget and acceptance protocol

- Freeze the M0 manifest, current source/binary baseline, admitted domains,
  observables, solver settings and worker count before each experiment. Record
  each track separately, with both MSC8 and BC5 adapter outcomes for flat32.
- Fix per-function and total deadlines, aggregate memory limits and caps for
  DAG nodes, region paths/groups, proposals and refinements before the run. Begin
  with existing admitted budgets; retries consume the remaining budget rather
  than receiving a new allowance. Publish exact limits and typed exhaustion.
- Preserve the existing proof attempt's budget; make extra searches bounded and
  optional until the fixed manifest establishes their benefit. Change one
  mechanism at a time. Cold/warm timing and proof counts need controlled repeated
  measurements; source hashing alone is not end-to-end improvement.
- Count every manifest pair, including missing mappings and refusals. Record
  fully proved pairs separately from CONDITIONAL, UNKNOWN and execution agreement,
  plus end-to-end time, peak RSS, solver calls, formula size and required fact
  counters. Do not convert an unknown into a pass by reducing observations.
- Require real compiled/assembled positive, corruption and incomplete controls,
  independent replay where available, scoped checks and the existing milestone
  gates. Only fully discharged obligations increase the proof-coverage count.
  A soundness correction may remove an old false proof; explain that separately
  from optimization regressions. No complete or cheap arbitrary-binary decision
  procedure is promised by this work.

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

For each semantic milestone: focused red/green tests, changed-surface
`make quality-dev PYTHON=./.venv/bin/python`, regular `quality-fast`, and
`quality-hard` before the incremental/PR checkpoint. Run the affected flat32
standalone checks as well. Run `test-pipeline` before claiming decompiler
semantic improvement and `test-pipeline-expanded` for a broad slow audit.
Use repository execution guidance for `PYTHON_JIT=1`, pytest workers, compact
logs and serialization. Existing debt and environment skips remain separate.

Milestone dependency order: M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M7, with M6 starting
after M1 and expanding at every milestone. Ship each milestone for both modes
with separate acceptance evidence; success in one mode does not close the other.
Within these dependencies, use the prioritized coverage/resource experiments
above; their order does not postpone mandatory correctness or model closure.
The first implementation slice is M0 plus M1, followed by one proved direct-call
chain in each architecture. No agents or external workers are launched by this plan.


## Implementation evidence (2026-09-28, in progress)

### Execution-speed checkpoint (2026-09-29)

Fresh profiling identifies source/model hashing as a current cost: 70 semantic
scans take 10.98 seconds of one 20.78-second profiled native checker. This is a
different current workload from the older 120-second timeout and is not a
controlled before/after comparison with that older result.

The source owner now deduplicates/orders canonical relative string keys and
hashes independent file chunks with at most three threads per invocation.
Every file is freshly read; no file content, digest or executor persists across
calls or proof boundaries. Canonical digest content and all freshness checks
are retained. Pytest still uses exactly three workers.

Six alternating isolated runs compare the exact saved pre-edit hash function
with the production function on unchanged current sources. Median fixture/receipt
plus checker time is 22.42 seconds before and 21.20 seconds after (5.4% lower).
Checker-only medians are 19.89 and 19.65 seconds. Both variants retain the same
76 hash calls, 161 raw/normalized/classified/materialized facts, zero failures,
six frames, 120,000 ms budget and conditional verdict. These shared-host,
three-sample-per-variant results support a modest workload-specific improvement;
they do not establish a whole-suite or corpus speedup. An initial harness with
an extra baseline key-conversion pass was corrected and its timings superseded.
Normal production verification passes 58 focused controls plus 5 actual-binary
controls. The latter remains conditional, not whole-binary equivalence.

The D0-D1 public pilot now has a saved 1,149-file source checkpoint, copied
SORTDEMO/catalog inputs, exact command, source hashes and final report under
`.cache/comparator-implementation/optimization-checkpoint-20260929/pilot/`.
Source identity stayed unchanged through the run. SwapBars, InsertionSort and
Sleep remain three required, attempted, unresolved obligations. All report an
InitBars control-admission failure because group_lookup admits the entire
catalog before selecting the requested function and its call closure. The next
bounded work item is to prove the reachability scope and correct that admission
boundary while retaining unsupported reachable effects and every requested
denominator. This pilot is not accepted equivalence or a green release.

A native MZ diagnostic now reproduces that scope problem independently: the
same caller/callee bytes prove when selected alone; adding an unreachable
DIV/RET function to the catalog changes the result to unsupported-return-control
refusal for that unused function. The binary image is identical in both cases.
The admission-scope repair is the next public-workflow task; the existing refusal
for a reachable division fault must remain intact.

The admission-scope repair is now implemented in `real16_call_evidence.py`:
the requested catalog identity is resolved first, and complete body validation
follows only decoded direct-call targets. Entry alias collisions still refuse,
and reachable malformed bodies retain their state, fault and external-effect
checks. A native MZ regression was red before the change (unreachable DIV/RET
refused the caller) and green after it; the reachable DIV/RET still refuses.
The neighboring call/loop/region cohort passes 41 tests with three workers;
scoped Ruff, MyPy and Pyright pass. The saved pre-edit sources are under
`.cache/comparator-implementation/admission-scope/baseline/`.

The fresh public SORTDEMO self-comparison now passes that former global
admission barrier but remains `unknown`: InsertionSort and Sleep report
`call_target_unmapped`, and SwapBars reports
`paired_region_admission_refused`. All three requested obligations remain
attempted and unresolved in `.cache/comparator-implementation/admission-scope/pilot-self-report.json`.
This is a completed bounded repair, not D1 or original-plan acceptance.
Independent 16-bit decoding of the frozen image locates direct CALLs from
InsertionSort to 0x1222 and 0x491, and from Sleep to 0x1222 and 0x137e;
none is a declared entry in the 20-function catalog. These decoded targets
are diagnostic facts, not proof of callee semantics. The next pilot action is
to recover/check their binary bounds and effects or retain an explicit
unmapped-call refusal; do not fill them by source or symbol name.
The changed-surface `quality-dev` run passed its scoped linters, startup and
ownership checks and the 296-test pre-pipeline cohort. Its fast pipeline
recorded a failure early in a much larger three-worker pytest inventory; the
run was interrupted after 11% to avoid repeating a known failing broad gate.
No complete gate result or failure attribution is claimed. A separate
three-worker maxfail diagnostic was also interrupted during collection without
producing a traceback. The native positive/refusal pair was rerun afterward
and passed. The final post-refactor real16 call/loop/region cohort passes
41 tests with exactly three workers; scoped Ruff and MyPy remain green.
Full gate acceptance remains open.

The next M5 native-control step now admits an indirect callee exit only as a
proposal consumed by the existing caller boundary: its full physical target
must prove equal to that CALL's continuation, and CS restoration must prove.
Root-level indirect exits and arbitrary callback destinations still refuse.
The lifter now retains a structured indirect-successor marker from VEX, and
register/memory near CALL/JMP composes the architectural offset with CS in loader
execution; operand-size-32 control retains all EIP bits. The typed
`NearTargetDomain` distinguishes architectural operands from already-decoded
execution control; relative branches keep their existing contract.
The native saved-return-jump control
was red before implementation, then exposed the missing CS contribution at
the caller boundary. It is now green. The adjacent call/loop/region/stack cohort
passes 83 controls with three workers, including four independent Unicorn JMP
coordinate cases. Two additional dword controls pass: an intact saved-EIP jump
proves; setting target bit16 refuses. Scoped MyPy (including FunctionCtx's
contract owner), Pyright, type/startup/context/ownership checks pass. Ruff passes
the focused owners; the whole SSA module still has an unchanged pre-run
complexity diagnostic in `_region_adopted_layout_pairs`, independently matched
against the exact dirty baseline. Artifacts are under
`.cache/comparator-implementation/indirect-return/`.

A bounded sandboxed Devin audited the two historical region-call normalization
tests. Parent confirmed that their synthetic balanced-call omission lacks a
complete callee state relation; the production gate correctly refuses it.
Only those two test functions changed to assert the exact refusal while keeping
normalization facts observable. Parent independently reproduced 2 red controls
before and 2 green controls after. Devin timed out while writing its report;
its source delta was nevertheless reviewed against the saved dirty baseline.
The previous full-run dosunit failure set was rerun directly: 24 fail and 2 pass
in 21.09 seconds with three workers. A separate diagnostic records each current
call refusal, without relabeling all failures as stale tests. REP summary and
AIL-call failures, shifted-call observability, and the remaining synthetic
call-proof expectations still need individual resolution. This bounded batch
avoids another full-suite collection run and does not establish release gates.

The companion near-CALL target controls independently reproduce 2 failures
and 6 passes before correction, then 8 passes. They check native and loader
coordinates for both operand widths, saved architectural return offsets and SP.
The final shared-tree call/loop/region/stack plus corrected fixture cohort passes
91 tests with exactly three workers in 17.28 seconds. No corpus speedup is
claimed from that focused timing.

Binary diagnostics also confirm that the missing SORTDEMO target 0x1222 has a
saved-return-register indirect jump and a separate failure path into further
calls. The new generic return capability addresses one obligation; catalog
closure, nonreturning/environment outcomes and clock/device effects remain
unproved. The public pilot has not been promoted or rerun as accepted proof.

The dirty pre-run comparator sources and binary hashes were saved under ignored
`.cache/comparator-implementation/`; no shared sources were reset. Three sandboxed
Devin tasks cover direct flat32 calls, real16 internal-state retention, and finite
flat32 CFG reblocking. Their patches require parent review and reproduction.

Implemented shared typed obligations, contract identity, dependency closure and
serialization. Missing, duplicate, unexpected, stale, cyclic, assumption-bearing
and failed-fact evidence cannot establish unconditional proof. Both staged flat32
drivers now bind their reports to binary/source/model/ABI fingerprints and retain
requested-function identities. Default selection retains original `sub_*` names
when candidate correspondence is absent.

A real BC5 binary regression exposed lost lazy flags between blocks: changing a
comparison operand could pass. Full internal-state lowering repairs that case;
the two cross-block register/flag controls pass. The existing MSC8 focused suite
passes all 29 tests after repairing a stale exit tuple unpack. These are focused
results, not a representative corpus acceptance.

Independent flat32 Unicorn execution is available through
`z3func.py replay-flat32 --oracle-exe ORIGINAL --candidate-exe REBUILT
--vectors MANIFEST.json --out REPORT.json`. It executes linked i386 images in
fresh guests, captures writes and observations, and keeps agreement separate from
proof. Four execution tests and two public-CLI tests pass, including deliberately
changed return values and stores, fault/budget refusals and fresh-state checks.

The new contract/replay tests are enrolled in the normal curated pipeline and
focused ownership rules. The integration run had 151 passes and one unrelated
ownership expectation failure for indexed-address IR; baseline classification is
reproduces with the new comparator ownership rule removed in an isolated
process. No full pipeline or quality gate success is claimed yet.

The real16 public wrapper now binds binary and loaded-image identities, semantic
source fingerprints, full catalogs/mapping, and full modeled state. It scans raw
VEX effects before liveness can discard an unused port read. Complete direct
near-call inlining retains SS:SP/memory, flags, segments and high register halves,
and requires actual return-target and CS restoration proofs. Parent admission
tests demonstrated that missing whole-body size/hash could pass in the initial
worker implementation; the corrected admission/call suite passes 14 tests.

A further parent solver regression demonstrated that conditional IP was skipped
when both branches were code addresses, incorrectly passing reversed branch
selection. Replaying the saved pre-run helper reproduces the red result; the
fixed solver compares conditional control and handles one-bit counterexample
inputs. The focused integration batch has 25 passes and one provenance-seal
failure caused by concurrent source edits; the two public positive/mutation
cases subsequently pass with parent source edits stopped. Reviewed call owners
pass Ruff, Pyright and MyPy. The hard gate failed on other worktree surfaces and
the comparator Makefile grouping; the grouping was corrected and focused gate
enrollment checks now pass. No broad gate success is claimed.

Fresh bounded representative results: the two frozen C23216 selections remain
unmapped; SORTDEMO SwapBars/InsertionSort/Sleep lower 37 parts without refusals,
but all three whole-function obligations remain unknown due to unproved callees.
The same-binary representative run is not modification acceptance.

Pending acceptance: project gates, far/operand
variant call relations, calls inside loops, representative changed-binary
acceptance, general loop relations, recursive/indirect/environment contracts,
independent real16 execution verification, and performance/dependency-cache
measurement. The broader milestones remain open beyond these bounded capabilities.

Parent continuation evidence: the frozen broad quality-dev run ended with
7,180 pipeline passes, 37 failures and one skip (log in ignored comparator
implementation cache). No global gate acceptance is established. The staged
real16 matched-loop/call owner passes seven actual-MZ controls, including callee,
high-half and guard mutations, recursive-call refusal, missing dependencies and
exhausted call budgets; it is not yet enrolled or accepted as a public capability.

A new independent-execution red control exposed a frontend coordinate defect:
CALL stores a loaded linear return address instead of the architectural IP.
For a callee reading its saved return word, the composed SSA proof reported
passed while Unicorn returned different BX values for original and candidate.
Correction is required at the frontend and in its consumed continuation contract;
existing real16 call proof results do not close real-machine acceptance. A bounded
sandboxed Devin worker is staging that frontend correction while parent integration
and independent real16 replay work continue. The full plan remains active.

Initialized-image admission is now a shared typed owner consumed by the public
real16 and both flat32 reports. Function proof scope is explicit; changed or
missing loaded-image identities leave initialized-function acceptance unknown.
Eight focused admission tests pass, including actual MZ bytes with identical
function code and a changed initialized global. The saved wrapper baseline had
no corresponding admission evidence. Scoped Ruff/MyPy/Pyright checks pass, and
the new regression is enrolled in curated tests and ownership selection. The
flat32/report plus Make inventory recheck passed 39 tests with repository TMPDIR;
eight broad failures were the read-only host temporary-directory boundary.

The saved-CALL-word regression is now a routine public real16 test and currently
fails as expected: the public comparator itself reports proved for a concretely
different return-word reader. Frontend coordinate repair and corresponding
return-boundary consumption remain required before call capability acceptance.

The new initialized-image owner also selects its regression through normal
focus tooling; the resulting 12-file focused batch passed 192 tests. The real16
replay Devin reached its bounded timeout after staging code and 21 controls;
parent reproduction/review and completion of its lint refactor are pending.
The frontend coordinate worker remains independent and staged.

Parent replay reproduction passed all 21 staged controls before and after
extracting guest setup; the staged production owners now pass Ruff. These
remain pending model review and public integration. The coordinate Devin timed
out with a partial stack-helper overlay; parent independently constructed a
fast-path prototype. After using the required 8-bit VEX shift operand, all
three public controls pass under that isolated prototype, including the saved-IP
false-proof regression. Shared frontend sources are still unchanged; coherent
fast/emulated-path integration and its broader checks remain required.


Parent coordinate integration checkpoint: the frontend now shares a typed
CS-relative saved-IP/EIP versus loader-control conversion owner. Fast near
CALL/RET and emulator return paths consume it; indirect near CALL now delegates
saved-IP construction to the same stack helper. Two independent Unicorn
word/dword frame controls fail against the saved pre-edit stack semantics; the
46-test shared stack/public-call/composition batch passes after correction.
A separate indirect-call regression reproduced the old loaded-address value
(0x2442 instead of architectural 0x0102); its fix and expanded frontend checks
are in progress. The owner is enrolled in typed/lint and test-focus selection.
This corrects a demonstrated false proof; it does not close far-call acceptance.

Parent continuation checkpoint: direct far16 composition now decodes the
actual CALL frame and recovers pre-CALL CS from post-CALL stack memory. A
relocated fixture with different caller/callee selectors passes, while changed
return value, stack store, cleanup and a near RET cannot pass. The frozen
pre-edit call owners refuse the positive control as a nonconstant target.
The shared public near/far batch passes all 11 controls, including the saved-IP
false-proof regression; independent Unicorn execution checks the far return.
Native frontend hardware expectations were retained. The frontend batch has
281 passes and one unknown public proof result during concurrent source work;
the original failure cause was not fully captured. The stable 11-test public
rerun passes. Broader gate acceptance remains pending.

Independent real16 replay is now publicly registered as `replay-real16`.
The integrated replay/manifest suite passes 62 controls; subsequent added
controls remain subject to the next shared run. The parent reviewed the Devin
CLI split, preserved its frozen baseline, independently reproduced frame-cause
loss and a mixed-key TypeError, and replaced serialized-status accounting with
typed replay rows. Reports bind executed image hashes, code ranges, complete
declared vector state, masks and zero-initialization assumptions. Scoped Ruff,
Pyright, Make lint/type-contract and ownership checks pass. Agreement remains
execution evidence only. An additional regression reproduced unmapped omitted
segment defaults; the guest now maps their zero-initialized address space.

The parent integrated closed matched call-loop induction and extracted one
CALL post-state owner consumed by both acyclic and loop proofs. The two public
controls prove an equivalent callee edit and refuse a changed callee; the saved
pre-integration retry leaves the equivalent case unknown. Seven direct loop
controls and independent zero/one/100-iteration checks pass. Full final shared
near/far/loop integration checks, nested-loop acceptance and project gates are
still required. Operand-size control coverage remains open: the newest bounded
Devin audit ended with source findings only, without a runnable probe or tests;
the parent must verify those findings before accepting them. M4/M5 and broad
corpus/performance acceptance remain open for both architectures.

Final shared checkpoint at 2026-09-28 14:22 UTC: all 98 near/far/call-loop,
public proof, replay, manifest and observation controls pass in 131.61 seconds
with seven workers. The shared changed-owner lint/type-contract/ownership gate
and explicit Pyright check pass. The zero-default segment regression failed
before its guest mapping fix and passes in the shared run. The next quality-dev
gate is running; no global gate result is claimed yet. A bounded parent
operand-override probe contradicts the unfinished Devin source audit: current
far32 lowers without refusal and self-compares passed, while near32 lowers
without refusal but refuses a nonconstant target. This is diagnostic evidence,
not operand-variant acceptance; return/control width and independent mutation
controls still need verification.

The quality-dev checkpoint's 296-test regression group passes. Its full fast
pipeline is queued behind another workspace gate's serialization lock. A
cancellation attempt could not access the process consistently; no process was
signalled. Resume/poll the existing run rather than launching another broad gate.

Parent replay review checkpoint: 36 staged MZ execution controls pass, including
full default segment/control/defined-flag observations, flag-mask narrowing,
actual CPU divide faults, initialized-image relocation, contiguous offset
straddles and MZ header geometry. The observation Devin reached its timeout with
a partial patch. Parent rejected promotion of code-coverage escapes to known
outcome mismatches, repaired coarse privileged MOV-segment classification, and
made patch/observation straddles coherent with the declared linear policy.
Independent saved-baseline geometry checks and scoped typing remain pending.
A new bounded sandboxed Devin owns staged manifest/CLI work only; core replay,
public integration, reports, enrollment and acceptance remain parent-owned.


Expanded coordinate evidence: the 350-test frontend/hardware batch finished with
342 passes and eight failures in far RET, IRET, and operand-size return/call
checks. These remain open, including the architectural-register versus loader
control projection in the native hardware harness. No broad frontend acceptance
is claimed. The corrected replay owners are now integrated as production modules
with a separate typed execution-comparison owner; all 36 production replay
controls pass, and scoped Ruff/Pyright checks pass. The six owners and both replay
test files are enrolled in curated Make checks and ownership selection. The
independent saved-baseline geometry run reproduces four defects (linear straddle,
short header, relocation table outside header, and truncated page count); two
malformed-size controls already refused on the baseline. Public replay CLI,
scoped MyPy/enrollment results, and all wider milestone gates remain pending.


Replay enrollment and combined scoped Ruff/MyPy/type-contract checks pass after
removing dynamic register-constant lookup and annotating the PyVEX type boundary;
Pyright also passes. Full default replay admission now refuses decoded floating
and vector register groups because their state is absent from the integer
observation contract. Focused floating-state refusal controls are being verified
against the frozen pre-admission decoder. The manifest/CLI Devin timed out after
staging its command module and an early partial handoff, without tests or a final
validated report; the parent must finish and review that module before wiring it.
An isolated native-coordinate probe passes four of five failing hardware groups;
a far-16 CALL mismatch remains. This supports an explicit execution-coordinate
contract investigation, not changing hardware expected values or acceptance.

Full-control correction checkpoint: the parent reproduced another concrete
false proof against the frozen pre-edit owners. A far32 callee corrupts the
upper saved EIP word; the old proof passes with two return-target obligations
reported discharged, while independent execution escapes the original's code
range and returns from the candidate. SSA now preserves `control_ip` at 32 bits
before projecting legacy word IP, and call composition refuses that pair as
`return_target_unproved`. A routine actual-MZ/independent-execution regression
retains the case. Architectural CS entry domains are nonempty, callee entry
preconditions are checked, and continuing loop steps prove domain preservation.
Physical loop successors cannot match solely after word-delta wrapping.
The 12-control loop suite and 19-control domain/staged-snapshot suite pass;
scoped Ruff/MyPy/type-contract/ownership and explicit Pyright checks pass.
The final shared integration batch passes all 80 controls in 135.65 seconds
with seven workers. Six additional actual-MZ nested-call-loop controls pass:
the equivalent changed callee proves, an inverted inner-exit guard stays
unknown, and independent zero-trip/one/1,000-call executions agree for the
equivalent pair and expose the terminating guard mutation.

The reviewed Devin replay snapshot change is integrated: image loading and
initial fingerprints share the same immutable binary bytes, with final file
mutation checks retained. Parent reproduction passes all four staged controls;
three corresponding production regressions are enrolled without importing
ignored baselines. The bounded sandboxed Devin staging normal near32/far32
controls reached its 900-second deadline without runnable tests or a handoff.
The unfinished worker's frame observations are not accepted evidence. Parent
construction and reproduction now pass twelve near32/far32 controls across
two batches: original/original, equivalent changed callee, return-value and
cleanup mutations with independent frame execution, plus public equivalent
and mutation reports. Public positive obligations prove through complete call
inlining and return-value mutations report counterexample. Root cleanup that
escapes the declared code range remains an execution gap, not a known outcome
mismatch. The operand controls are enrolled in routine checks and ownership.

The previously running quality-dev gate is terminal: its 296-test regression
group passes, and the fast pipeline reports 7,270 passes and 24 failures.
Failures include four far operand32 return-coordinate assertions, two far-probe
lifting assertions, and decompiler output/timeout failures. This is not a green
global gate; causality for shared-tree failures remains to be classified.
M4/M5, representative modified-binary acceptance, full operand controls and
corpus/performance/release gates remain open for both architecture tracks.

Physical-continuation follow-up: acyclic call control also used a word-masked
continuation delta. The frozen owner admits physical `0x11204` as delta 4 in a
function beginning at `0x1200`; the corrected owner refuses it. Acyclic walking
and CALL continuation admission now retain the exact physical difference.
The 40-control call/domain batch passes after correction; scoped lint/type
checks and Pyright pass. A scoped MyPy run initially lost FunctionCtx fields
through a skipped import, so Make now selects the owned contracts with call
consumers instead of silencing the resulting Any diagnostic. Eight modular
literal/malformed-boundary controls pass; malformed operator fields remain
unresolved rather than crashing or inventing a target.

Flat32 parity after the shared SSA control-width correction passes all 36
routine MSC8/BC5 comparator, direct-call, reblocked-loop, independent replay
and replay-CLI controls in 38.81 seconds with seven workers. Final ownership
and scoped Ruff checks pass. This verifies that bounded accepted flat32 surface;
it does not close the remaining relational/recursive/environment milestones.

M4 finite-region checkpoint: both architecture adapters now consume a shared
typed CFG partition and ordered cutpoint proposal. Real16 composes finite
regions with checked direct callees and proves full-state transitions under
explicit physical PC correspondence. The public wrapper now retries call-free
functions through this path and reports the authoritative retry evidence in
`backend.function_proofs`. Register, affine recurrence and stack relations are
still outstanding; this checkpoint does not close M4.

The positive split-loop MZ control initially refused because SSA GET FLAGS
bypassed the latest register version. FLAGS reads now consume sequential writes,
and output omission cannot discard internally consumed writes. Seven focused
VEX/SSA controls pass; six fail against the saved pre-fix owner. Independent
guest replay agrees for equivalent loop binaries and rejects guard/store changes.

A wider before/after check exposed an existing false proof: ABI composition
treated a truncated conditional PC as an exit without visiting either successor.
Composition now consumes full loaded control, keeps exact physical indices,
refuses ambiguous legacy keys, and refuses unresolved continuing edges. The
equivalent reblocked branch, changed branch and bounded-loop controls pass.

Final shared-tree focused verification reports 227 passes and 26 failures in
208.22 seconds. All 103 controls outside the older SSA test file pass, including
both flat32 lanes and real16 public region/call proofs. An isolated run of the
saved pre-fix SSA owner reproduces all 29 prior SSA failures: three now pass,
with no new failures in that comparison. The 26 remaining failures are not
accepted as a green gate. New contracts and tests are enrolled in routine
typing, lint, ownership and pipeline checks. Scoped Ruff and Pyright pass for
the new owners; the older `_region_adopted_layout_pairs` complexity debt remains.
The first quality-dev run stopped at the changed-file annotation gate for the
shared sandbox launcher. The current launcher now has the required annotations
and its focused ratchet passes; quality-dev is rerunning against the current
tree. No global acceptance is claimed.

The bounded sandboxed Devin FLAGS test task exited at its 480-second deadline
after creating provisional staged tests, without a completed report. Parent
review found signature and control-observation weaknesses and independently
constructed the production VEX regressions; the worker's unfinished results
are not accepted proof. The complete plan, including M4 relations, M5,
modified-binary corpus, performance and release gates, remains active.

The next M4 register-correspondence control is established from actual MZ code:
the original decrements AX; the candidate swaps AX/CX, decrements CX and restores
the registers before return. Independent guest replay agrees for AX inputs
0, 1, 2 and 65,535 with CX initialized independently. Current finite-region
identity proof honestly reports unknown at three paired transitions. The fixture
and fresh SSA are saved in the ignored M4 register stage for the next relation
implementation; execution agreement has not been promoted to semantic proof.


M4 register-relation staging checkpoint: the isolated real16 implementation
passes six actual-MZ identity/permutation/mutation controls. The isolated
flat32 owner passes twelve controls across MSC8 and BC5, using binary-derived
entry effects only to propose a bijection; Z3 must discharge initiation,
interior preservation and final identity. Rejected identity attempts remain
visible. Shared typed proof-scope admission now distinguishes arbitrary
cutpoint SAT from a complete-function counterexample. These are staged results,
not production or milestone acceptance. Strict full-register flat32 controls,
public real16 controls, serialization/deadline checks and final integration
remain pending. A staged replay batch lost a worker; that batch is not green.
The bounded public-fixture Devin timed out after writing provisional tests;
the parent is reviewing and reproducing them independently.


M4 register integration checkpoint: register proposals, full-state relational
real16 induction, both flat32 adapters and typed cutpoint-scope admission are
now integrated. The first shared batch passes all 105 controls, including
strict flat32 terminal register/lazy-flag projections, all mutation controls,
public real16 proofs and existing reblocked/call-loop coverage. A later batch
passes all comparator controls and reports 86 passes with one unrelated
ownership-selection failure for IR core. In an isolated process, removing
the new comparator ownership rule leaves that failing selection unchanged.
The new matched-CFG retry controls prove under both flat32 drivers after
retaining raw internal SAT diagnostics as UNKNOWN at function scope.

The frozen pre-change owners fail both public real16 positives and both flat32
register positives. The direct real16 baseline test did not collect because
it imports the new RegionObligation enum; that collection error is not red
semantic evidence. Scoped MyPy now consumes the owned proof/serialization
cohort, and the annotation gate passes after the new module's future import
was added. Pyright and Ruff pass. The staged replay worker failure did not
recur for the three routine guest vectors; the saved 65,535 vector passed
but took 202 seconds and stays explicit slow evidence. Full gate acceptance
is still pending. The preceding quality-dev result was 7,523 passes, 27
failures and one skip; failures are not hidden or counted as acceptance.
The quality-hard gate is running on the integrated checkpoint.

Final scoped follow-up: the 32 contract/register/retry controls pass in 70.09
seconds. Scoped MyPy and the changed-owner annotation gate pass; Pyright
reports no errors. The hard gate remains live; do not equate this scoped
checkpoint with full M4, corpus or project acceptance.


M4 affine staging has independent real16 byte execution agreement for an
interior BX translation by seven, restored before return, at counts 0, 1, 2
and 255 with wraparound input. The permutation-only region proof records two
unknown transition obligations. The new private typed affine owner proves
16 modular-inversion, entry-backedge and refusal controls at 8/16/32 bits;
scoped Ruff and Pyright pass. Actual binary proof controls are still being
diagnosed and are not accepted. The 32-bit LEA bytes differ from real16: the
BX addressing ModRM selects EDI in flat32, so the parent corrected the flat32
fixture to EBX-base ModRM 0x5b. Devin verified the decoding issue but timed out
without tests or a patch; no worker proof claim is accepted. A frozen private
frontend is used for staging because concurrent frontend edits changed the
source identities between original and candidate lowering in the first probe.
The live hard gate remains active; no semantic production owners changed
while it runs.

M4 affine integration checkpoint: the shared modular relation owner, real16
region consumer and both flat32 adapters are integrated. Byte-exact conditional
instruction-prefix relifting fixes the flat32 JECXZ/LOOP boundary without
dropping effects inside an instruction. The integrated additive/register batch
passes all 97 controls. Scaled 3*x+7 recurrence controls prove in real16
(including the 386 address override) and both flat32 drivers; restoration and
LOOPE mutations refuse. Four low-half synthesis controls fail on the frozen
pre-change owner and pass after exact projected-zero OR normalization; all 22
modular contract controls pass. Independent scaled guest replay passes eight
controls with wraparound and nonzero real16 high halves. Three public real16
additive/scaled/mutation reports pass their expected verdicts. Scoped Ruff,
MyPy and Pyright pass. These results do not close M4 or the complete plan.

The prior quality-hard gate is terminal and failed architecture/ownership
checks in the shared tree; no green broad acceptance is claimed. The sandboxed
conditional-boundary Devin timed out without producing tests or a patch, so
its investigation is not acceptance evidence. Finite shared-guard region
cover staging passes five progress/closure contracts and three actual-MZ
rotation/mutation controls. Flat32 rotation staging is delegated separately;
production integration and broad gates remain pending.

Rotation staging now has parent-reproduced controls for both flat32 drivers.
The bounded Devin timed out after writing tests; the parent reviewed its exact
file, reproduced all six controls and fixed import-only lint findings. Five
additional controls reject effects in shared guards, including flat32 stores.
Eight independent guest rotation controls agree for the equivalent loops and
retain execution exhaustion as INCOMPLETE for a divergent mutant.

A typed partition/cover proposal now preserves the original graph path and
its rejection reason, while recording complete block coverage and repeated
member occurrences. The unpatched staged real16 consumer passes 22 rotation,
mutation and graph controls; both unpatched flat32 consumers pass 24 rotation
and affine controls. The combined staged batch passes all 57 controls. A later
14-control flat32 batch verifies typed refusal of incomplete member/progress
evidence and retains all guard/store mutations. Internal control tokens are
separate from cutpoint tokens, and every finite internal continuation is
checked. This remains ignored staging, pending production integration,
fingerprints, enrollment, public proofs and final gates. The current
quality-dev gate remains active after its 296-test regression group passed;
its complete fast-pipeline result is not yet available.

M4 rotation/public-report staging checkpoint: parent independently reproduced
Devin's four real ELF32 controls through both public drivers. Equivalent loop
rotation proves with all eight GPRs and full memory; the stride mutation refuses.
Initialized-image/startup equivalence remains explicitly unproved. The staged
source-identity regression exposed an omitted arithmetic helper; conservative
owned-Python dependency sealing fixes it, with five focused controls passing.
These changes remain isolated pending final source review, enrollment and gates.

M4 stack correspondence: independent MZ replay agrees for four boundary loop
counts, but the original full-state identity induction cannot prove the swapped
stack fixture (one focused positive remains red). Finite byte-permutation
contracts, SSA entry-store synthesis and both consumer integrations are being
staged. The original fixture also needs a saved-byte/live-register invariant;
that obligation is retained separately. No stack memory is discarded, no alias
assumption is introduced, and this work does not close M4.

M4 memory-contract checkpoint: a bounded sandboxed Devin added elementary
byte transpositions and 25 real SSA/Z3 contract controls. Its process timed out
during typing; the parent independently reviewed the source and reproduced
all contract controls. Parent entry-store synthesis handles finite cycles,
changed values and missing anchors, with complete-memory entry proof controls.
Both staged consumers retain typed register-plus-memory attempts. The final
private batch has 51 passing contract, synthesis, source-closure, rotation and
public ELF32 controls; all eight touched production-style owners pass MyPy,
Pyright and Ruff. This batch excludes the still-red full stack equivalence
positive and does not substitute for project gates.

The direct real16 stack probe establishes two distinct SSA-derived anchor
proposals. Frame coordinates prove initiation and loop preservation, while
full exit state times out at the explicit 30-second solver bound. Stack
coordinates prove initiation but fail preservation and exit. Both outcomes
are retained; neither is complete equivalence. The restored-stack positive
remains red, and the original saved-DX fixture still requires an additional
inductive memory/scalar invariant. A separate bounded Devin is preparing
actual-ELF32 replay controls for this storage transformation.

M4 stack/invariant staging follow-up: discharged full-array lemmas now resolve
the restored-both-values exit obligations in real16 and both flat32 adapters.
The original saved-DX fixture additionally needs an independently proved memory
fixed point. The new typed projection preserves all scalar, event and control
components and every unmentioned memory byte; ordered byte stores retain exact
alias semantics. Twelve actual SMT projection controls pass. Nine explicit
real16 obligation/binary controls and ten actual-ELF32 controls across both
drivers prove the positive and reject initiation, preservation and exit
mutations. Flat32 checks include all modeled registers, lazy flags, segments,
return control and full memory. The recorded pre-invariant flat32 consumer
refuses the same positive. These checks remain private staging.

Binary-derived invariant synthesis passes ten entry-proof controls for both
endians and widths 8/16/32/64, including unbound and memory-dependent refusals.
The split-byte regression fails on the saved pre-grouping owner: separate byte
proposals cannot establish a saved word, while the combined proposal includes
an unrelated non-preserved counter. Grouping by typed scalar source yields
the complete saved-word candidate. Automatic real16 proof now passes within
the unchanged 30-second proof budget: five materialized facts, zero failures,
two selected saved-DX bytes, and four retained attempts. Proposal priority uses
already discharged transitions and exact changed-byte overlap only to schedule
work; every accepted attempt still proves initiation, preservation and exit.
A combined final cohort is running. Automatic flat32/public discovery,
production promotion, durable enrollment and broad acceptance remain pending.

The bounded invariant-synthesis Devin timed out without a patch; the parent
implemented and checked the contract and synthesis directly. The latest broad
quality-dev gate is terminal with 7,628 passes, 40 failures and one skip. Failure
modules are recorded for classification; these counts do not establish causality
or project acceptance. The full M4-M7 and representative corpus obligations
remain active.

Final invariant cohort: 73 controls pass in 45.72 seconds with seven xdist
workers and grouped scheduling for the expensive real16 memory proofs. The
earlier ungrouped cohort retained 71 passes and two positive-proof refusals;
budgets were unchanged in the grouped repeat. Cache and scheduling conditions
were not controlled as a benchmark, so this is acceptance evidence for that
bounded test lane, not a claimed end-to-end performance gain. The split-byte
synthesis regression is now green, bringing that owner to eleven controls.
Eight staged owners pass scoped Ruff and MyPy; staged import-root Pyright is
checked separately. Production/public integration remains open.

Production M4 integration checkpoint (2026-09-28): reviewed finite overlapping
region covers, ordered full-memory byte permutations, fixed-point memory
invariants and automatic bounded candidate scheduling are now production owners
for both adapters. The parent saved the actual dirty pre-promotion sources;
stricter production lifting checks and affine proof method reporting were kept.
The SSA output-lemma owner was promoted separately with 12 durable array/scalar/
flag/unknown-lemma controls and 61 existing solver/call controls passing.

Fresh production red controls show real16 loop rotation refused with
`cfg_shape_mismatch`, and three flat32 semantic-source tests failed to seal
indirect arithmetic/frontend dependencies. The corrected production cohort
passes 105 tests, including rotation/stride/guard/memory mutations, alias-safe
invariant contracts and independent concrete replay. All 19 integrated owners
pass scoped Ruff, MyPy and Pyright; Make changed-file linter/type/doc ratchets
pass. These focused results do not establish broad gate acceptance.

A bounded sandboxed Devin ported three actual-binary public test modules from
reviewed staging to the production driver seams, preserving every assertion;
parent compared the entire delta against saved absent-file baselines and staged
source. The worker's 16-test run passes, but parent reproduction and existing
public/call/loop regressions remain in progress. Fifteen new test modules and
fourteen new owners are enrolled in Make, ownership selection and the curated
pipeline. Documentation now states finite-cover progress, coordinate identity
at entry/return, independent invariant initiation/preservation, complete memory
observations and unchanged total retry deadlines.

The full plan remains open: remaining M4 acceptance controls, M5 joint recursive/
indirect/environment proofs, M6 representative initialized-program scenarios,
and M7 performance/corpus/project gates still require their own evidence.
A new bounded Devin is staging typed SCC grouping contracts for M5; grouping
will grant no proof and cannot replace joint transition/termination obligations.

Parent production public reproduction closes 100 focused controls across the
reviewed public MZ/ELF tests and existing call, loop, register and affine suites
in 269.04 seconds. The slowest saved-register public tests take 72–82 seconds
including fresh lifting and comparison. Six measured actual-binary modules now
run in a required `binary-relational` lane in default/expanded pipelines; smaller
contract tests remain fast. A dedicated enrollment control fails before the lane
exists and the final pipeline suite passes 55 tests. Inventory/ownership checks
pass 11 tests with repository-local TMPDIR. The lane's 300-second budget reports
runtime independently; it does not change any solver timeout or proof verdict.

Broad gate setup with scoped KVM transport fails before Make starts because
`/dev/kvm` disappeared after an earlier successful char10:232/API12 sandbox probe.
The device was rechecked absent. An environment-limited `quality-dev` run without
KVM is active: scoped/global development linters, compiled import smoke and
startup architecture checks have passed, and 296 preliminary tests pass. The
curated fast pipeline is still pending/running; no full gate pass is claimed.

The M5 SCC staging worker returned a typed iterative grouping owner and 28 tests
but its process hit the 600-second boundary after writing its handoff. Parent
saved the exact worker delta, independently checked all 512 directed three-node
graphs against NetworkX SCCs, and found admission-boundary defects. Directly
constructed graphs bypassed discovery size limits; input streams were fully
consumed before checking limits; combined admission/discovery replenished time
and step budgets. Focused parent red controls reproduce those defects. Parent
corrections pass 34 tests with a single shared budget and bounded input intake;
Ruff, strict MyPy and Pyright are clean. The owner remains ignored staging,
not a recursive equality proof or a production capability. Actual-MZ local
recursive block probes accept equal mov/xchg effects and reject changed counter,
call target and return cleanup, but joint return-frame/termination closure is
still required before whole-function admission.

A further bounded Devin is staging reversed-branch cutpoint bijection proposals
for M4 equivalent-condition coverage. Each proposal still requires complete
state/control/progress solver discharge; graph correspondence alone grants no
equality. No production sources will be changed while the broad gate runs.


Production equivalent-condition checkpoint (2026-09-28): bounded branch
bijection proposals now share one search deadline and result/state bounds;
ordered graph work cannot bypass a zero cap or expired deadline. Parent red
controls reproduce both defects in the worker version. Complete proposals alone
grant no proof; real16 tries them through the existing full-state, control,
initiation/preservation/exit and finite-progress obligations. Exact wrong-map
attempts, graph coverage and typed search completeness remain reportable.

The reviewed isolated cohort passes 30 controls. Independent total-map
enumeration agrees across all 2401 two-region pairs plus 256 larger samples.
Production reproduction passes 39 new/existing real16 and both-flat32-driver
controls; two sealed public actual-MZ controls additionally prove the equivalent
JE/JNE reversal and refuse a changed guard. Guard, stride, counter direction,
hidden-store and final-flag mutations cannot prove. The exchanged-effect diamond
retains its failed ordered map before proving the alternative. A red JSON
serialization control drove a typed diagnostics projection rather than exposing
layout frozensets. Production scoped Ruff/MyPy/type/doc checks and Pyright pass.

The initial branch worker timed out after producing its staged module/tests;
parent reviewed and repaired the delta. An independent-oracle Devin timed out
without a deliverable; parent implemented and checked that oracle. New contract
tests are fast; actual-byte/public branch controls join the required slower
binary-relational lane. Metadata validation has 112 passes and three unrelated
ownership-expectation failures, reproduced identically with only this enrollment
delta removed from the actual dirty source in an isolated process.

The earlier environment-limited broad gate is terminal: 2558 curated passes,
four failures, then fatal pytest-xdist KeyError gw8; the diagnostic crash omitted
individual failure details. Those counts establish no full acceptance or causal
classification. KVM reappeared and the exact scoped API12 probe passes; a new
KVM-bound quality-dev run is active with a separate cache and JUnit receipt.
Remaining M4 obligations, full M5 recursion/indirection/environment, M6 initialized
program scenarios and M7 corpus/performance/project gates remain open.


M5 frame-model checkpoint (2026-09-29): parent native POP evidence exposed a
frontend near-RET defect: an admitted CS=0x66, saved IP=0xFBC0 returns to physical
0x10220 in an independent Unicorn guest, while the old VEX/SSA control term
reached0x0220. The earliest-layer repair keeps the saved offset word-sized and
composes the loaded destination at dword width. Both RET and RET imm16 controls
fail against the saved old source and pass against the isolated repair and
production. Five actual-binary/native frontend controls and44 existing call/
operand/control controls pass; the register-permutation obligation assertion
now distinguishes its three mandatory obligations from optional memory-invariant
obligations, with all six positive/mutation cases passing. The new actual-return
regression is enrolled in the required binary-relational lane. Pipeline/inventory
metadata passes64 tests with repository-local TMPDIR.

The latest KVM-bound quality-dev run is terminal:296 preliminary tests pass;
the curated lane has7844 passes and23 failures in1924.55seconds. Exact failures
are retained in m4-condition-stage/quality-dev-terminal-summary.json. One is the
corrected comparator assertion above; the other22 decompiler failures remain
unclassified against the actual dirty baseline. No whole gate acceptance is
claimed. Fresh production development linters/type ratchets pass; compiled import smoke passes for39 modules.

Recursive frame owners remain ignored staging. They propose a finite modular
slot frontier that saturates on stack wrap. A free arbitrary-index theorem
checks every initialized slot and rank without nested quantified-array queries.
Only an independently discharged scalar frontier-advance lemma enters the
array-preservation solver; all checks share the original deadline. Separate
nonvacuity witnesses never restrict the preservation theorem. The final mixed
cohort passes13 initiation/body/push/pop/cleanup/wrap/deadline and actual-return
controls. After a useful nonvacuity-owner extraction, nine frame controls pass
and both flat32 PUSH controls reach their unchanged30-second deadline. This
resource sensitivity remains unresolved; the staged frame slice is not accepted
as a production recursive capability. Scoped Ruff, strict MyPy and Pyright pass
for those owners. Whole recursive acceptance still requires full state/control,
frame initiation/preservation/return closure, joint dependencies and relative
termination; caller-frame/fault, straddle and executable-memory domains must be
explicit before promotion.

Two bounded sandboxed Devins were used for call-graph admission. The broad
attempt timed out without a patch. The narrow input-boundary attempt produced
a reviewed patch but timed out without a handoff. Parent freezes its exact
delta, independently reproduces15 red cases against the saved original module,
and checks all17 boundary cases grouped into eight worker tests. After fixing
the original nullable-transfer test fixture without changing its refusal
assertions, the combined original17 and new8 tests pass25 controls. Admission
remains structural staging; ambiguous root aliases, complete successor closure,
fresh-cutpoint traversal, exact lowering failure causes, grouping budget bounds
and owner/lint debt remain open. Full M4-M7 acceptance remains outstanding.

Mandatory default test-pipeline is now running against the saved current source
manifest in a read-only-host/writable-repository sandbox. The exact device
precheck finds /dev/kvm absent again, so this run is explicitly environment-
limited; no DOS runtime acceptance follows from its result.

M5 checked-memory refinement checkpoint (2026-09-29): parent independently
proves native Store byte coordinates globally, then substitutes only equal
address expressions while retaining every prior store and data value. A second
global theorem proves byte-address comparisons equivalent to finite slot-rank
predicates before native read-over-write expansion is refined. Every required
pointer/bounds/slot/root/selector/return conjunct is checked against the same
premise and original deadline, using independent native solvers. Empty, partial,
duplicated, contradictory or expired refinement evidence cannot authorize a
replacement or discharge a whole obligation.

The mixed staged cohort passes34 controls; both actual flat32 PUSH seams now
pass in approximately6-8seconds within their unchanged30-second deadline.
An additional11-control final-source cohort includes both drivers' actual
caller-frame corruption binaries and rejects them with retained countermodels;
it also repeats all four valid flat32 CALL/RET seams. Seven further controls
include actual real16 operand32 CALL/RET frames and all supported byte-comparison
widths. These are overlapping focused cohorts, not a full-suite acceptance.
All six staged proof owners pass scoped Ruff, strict MyPy and Pyright. These
local frame facts still grant no recursive component/function equivalence.

Two narrower sandboxed Devins now close ambiguous root aliases and resolved
successor-set incompleteness in staged real16 admission. Parent reads every
owned delta and reproduces the saved dirty baselines in isolated processes:
root1red/3pass, successor3red/5pass. Final original17 + input8 + root4 +
successor8 tests pass37 controls. Stable IDs retain priority; ambiguous aliases
refuse; resolved control requires exact declared/discovered successor equality.
Known arms of an opaque control retain partial evidence while an explicit
refusal prevents graph admission. Fresh symbolic cutpoints are the next bounded
Devin task; faithful lowering causes and bounded grouping still remain open.

Mandatory default test-pipeline is terminal2. Its four selected lanes fail:
curated unit lane7845pass/28fail/1skip, binary-relational48pass/1fail, and both
external DOS lanes fail. The exact compare16 compiler stderr confirms absent
/dev/kvm, so DOS outcomes are environment-limited. The saved-memory real16
positive comparator failure is being independently reproduced at its original
solver budget. The28 decompiler failures remain unclassified against the dirty
baseline; none is labeled preexisting without evidence. Source hashes confirm
every production source in the gate-start manifest stayed unchanged throughout
the run. Terminal report, complete output and source audit are retained under
the recursive stack staging directory. The saved-memory positive API probe and
isolated positive/mutant pytest both pass at the original solver budget
(2pytest controls102.33s); the exact broad-run failure cause is still unresolved,
and its failed lane is not upgraded. Full M4-M7 and release acceptance remain
open.


M5 native joint-obligation checkpoint (2026-09-29): parent constructs complete
same-coordinate recursive proposals for real16 and both flat32 drivers, without
callee inlining or assumed recursive summaries. Every full-state transition,
exact static dispatch, entry frame, both sides' BODY/PUSH/POP preservation and
atomic lockstep progress enters one acyclic shared obligation report. Missing
nodes/outputs/dispatch, raw countermodels and incomplete materialization refuse.
Constant native IP is explicitly compared through a bijective solver-output
label projection; no layout address or machine state is normalized or omitted.
The two valid flat32 reordered native bodies discharge all modeled facts;
identical native caller-frame corruption still fails frame closure. All valid
examples remain CONDITIONAL because physical/caller/fault/image/environment
scope is unclosed. No production recursive validation=passed is granted.

The sandboxed diagnostic Devin patch is parent-reviewed: exact lowering reason
and message survive, only the compose budget stop is a deadline, and ordinary
unsupported blocks retain sibling frontiers. Saved dirty baseline is5red/1pass;
current real16 admission47 controls pass. A second tests-only sandboxed Devin
adds12 native flat32 admission controls; parent independently reviews and runs
them. The earlier flat32 implementation Devin timed out without a patch; parent
owns the adapter. Final combined parent cohort passes81 focused tests in61.15s,
including real16/both flat32 joint checks and8 independent native scope controls.
New proof owners pass scoped Ruff, strict MyPy and correctly configured Pyright.
Ignored staging review: m5-recursive-stage/JOINT-PARENT-REVIEW.md.

The native access-scope owner records the documented segment-straddling
exclusion and both conflicting byte-address sequences; ordinary unaligned and
page-crossing accesses stay in scope. Symbolic physical-domain closure remains
required. Different layouts, mixed/operand32 recursive relations, bounded
admission grouping/term work, production integration, remaining M4-M7 and the
failed broad pipeline acceptance remain open.

The final expected-node manifest tightening is independently rechecked by all14
joint controls, with clean scoped builder checks. The bounded static-control
implementation Devin timed out without a patch; parent now owns the staged
iterative evaluator and integration. A disjoint tests-only Devin independently
checks its finite work, exact arithmetic, partial evidence and refusal contract.
That output is pending review; no recursive production capability follows.

M6 flat32 replay checkpoint (2026-09-29): default native observations now include
all modeled integer registers, EFLAGS, loaded EIP and the six segment selectors.
Missing or duplicate register evidence refuses as incomplete; decoded floating
point and vector register-file instructions refuse before execution. Public CLI
reports the actual observation projection and retains the distinction between
execution agreement and proof. A saved dirty baseline has17 failing state/scope
controls. A separate actual4GiB address-space regression fails before explicit
guest lifecycle cleanup and passes afterward. Native diagnostic reservations
remain approximately70MiB through16 fresh guests after cleanup, rather than
growing by approximately1GiB per guest. This is resource evidence, not a proved
cause of the earlier crashed worker cohort.

Final replay tests pass27 controls including public ELF mutation controls,
full observations, unsupported register files and the4GiB regression. Routine
pipeline/ownership enrollment passes118 controls. Scoped replay strict MyPy and
Pyright pass. The changed production surface still requires the project gate;
these checks do not close initialized whole-program execution or M4-M7.

M5 bounded-control checkpoint (2026-09-29): parent staged iterative memoized
literal/ITE evaluation replaces recursive unbounded target evaluation in real16,
both flat32 native admission paths and joint proof admission. Every unique node
charges the existing walk/SCC step budget, with the original absolute deadline.
Cycles, malformed terms, contradictory ITE widths, oversized widths/literals and
cumulative target-set allocation return typed refusals; known opaque targets
remain diagnostic evidence without admitting graph closure. Saved scalar and
joint-adapter baselines reproduce the2,000-conversion RecursionError, and two
ITE-width controls fail before correction. Final112 evaluator/admission/joint
controls pass in136.23seconds. Five staged owners pass Ruff, strict MyPy and
Pyright with explicit project/staging import roots. The tests-only sandboxed
Devin timed out without files; parent implemented and reviewed the current
owner, tests and integration. No production recursive pass is granted.

Separate30 initialized native recursive replay controls pass in19.73seconds,
covering real16 high halves/segments and full i386 state, zero/one/many calls,
wraparound and base/stride/target/flag/store/cleanup mutations. Progress mutations
exhaust their execution budget and remain incomplete. These execution controls
and the staged evaluator still require production promotion/routine enrollment.

A fresh KVM-bound quality-dev run is active with an immutable production source
manifest. The exact device API12 precheck and sandbox binding succeeded;296
preliminary checks pass. The main fast pipeline remains pending, so no full gate
acceptance is claimed. Interim audit verifies2,534 production hashes unchanged;
13 saved pytest-owned transient fixture paths are separately classified and
excluded with reasons while the complete original manifest remains retained.


M5 initialized-byte checkpoint (2026-09-29): complete same-coordinate loaded
snapshots now propose an exact finite byte-XOR relation. Six independently
accounted premises cover snapshot/mask binding, involution, global read/frame,
arbitrary-store translation, mask erasure and finite initialization induction.
The map retains all other memory; it does not classify code as unobservable.
Independent staged algebra tests pass57 controls. Native full-state consumption
checks every register/control/flag/memory/I/O output and refuses incomplete,
stale, cyclic or expired evidence. Its14 controls pass, including actual MZ
and both flat32 recursive cutpoints. Branches discharge; unconstrained CALL/RET
stack/code aliases retain countermodels. These are local cutpoint results,
not whole-binary mismatches or accepted recursive summaries.

The native identity control exposed an existing production SSA composition
defect: every array input, including I/O, was substituted with program memory.
Exact named-array substitution now preserves distinct arrays and explicit
unbound inputs. Saved dirty baseline:3 red and1 compatibility pass; repaired
cohort:15 passes. Broader final composition:93 passes covering near/far/operand
calls, loops and both drivers. Enrollment metadata:118 passes. The unchanged
SSA-owner Ruff complexity debt remains visible; no gate is weakened. Actual
file/loader snapshot binding and its native integration are under independent
parent/Devin validation; initialization algebra alone closes no physical scope.

The later KVM-bound quality-dev gate is terminal2:296 preliminary passes;
curated7876 passes/19 failures in2167.09seconds. Terminal audit records4 changed
production files during that run (Makefile, frontend lift owner and both
pipeline/ownership metadata owners). Complete start manifest and terminal audit
are retained. This run is not fixed-tree acceptance, and its failure causes
remain unclassified. New array-composition changes occurred after its terminal
audit. Fresh semantic checkpoint gates are still required. Full M4 differing
relations, M5 recursive/indirect/environment closure, M6 initialized startup
scenarios and M7 corpus/integration/release gates remain open.


M5 loader-binding checkpoint (2026-09-29): actual MZ/ELF32/PE32 factories bind
immutable file bytes, loaded coordinates and model identity. MZ relocation and
entry-register facts are explicit; minimum DOS allocation remains unspecified.
CLE initialized ELF/PE zero tails are retained. Live mutable projects are checked
before/after native use. Parent red controls close ELF TLS/PE section allocation
budget bypasses before loading. The tests-only Devin timed out124 without either
owned deliverable; parent owns the tests and independently reviewed all evidence.

Actual PE controls expose the installed loader's inclusive-end truncation.
Production flat32_pe_loader now establishes one bounded contiguous initialized
image before root-view binding and relocation; both driver adapters consume it.
Ordinary byte reads alone missed a second VEX backer-boundary defect, which the
native RET regression detects. Saved original drivers are2 red; the final
cohort passes190 tests in49.46seconds, including both formats/drivers' initialized
native obligations, loader/relocation mutations, existing calls/loops and routine
enrollment. Strict MyPy and correctly scoped Pyright pass the production owner
and both adapter scopes; all scoped Ruff checks pass. BC5 loader certificates
now bind the owned loader source. No recursive/whole-program pass is granted.

A fresh quality-dev run is active with2,542 saved production hashes. KVM is absent
at this launch; runtime outcomes remain environment-limited. The earlier19
failures/source-drift limitation, all unclosed caller/fault/code-alias/address/
environment requirements and full M4-M7 acceptance remain outstanding.

The new gate interim audit already detects a concurrent real16 frontend source
change. The exact observed source and start hashes are retained. This run remains
diagnostic; an isolated actual dirty-source snapshot is required for fixed-tree
acceptance if concurrent edits continue. Preserve the shared edits.

### Derived real16 entry-domain checkpoint (2026-09-29, staged)

Added a typed scalar-domain certificate with separate nonvacuity, loader/seed
binding, original/candidate bootstrap initiation, universal physical stack
geometry and every supplied native effect's preservation obligations. Native
comparison consumes the complete image/effect/model-bound ledger and retains
all register, control, memory and I/O outputs. Missing, duplicated, unknown,
stale-model, changed-snapshot and corrupted-counter premises refuse before SMT.
The certificate remains a scalar theorem; its binary-equivalence property is
always false. Binding supplied effects back to independently decoded immutable
image bytes, complete recursive caller frames, dispatch/progress, faults and
environment closure remain required for promotion.

The initial seven MZ controls failed because the test declared only the bootstrap
CALL bytes while requesting continuation lowering. Extending the declared range
to the actual complete eight-byte bootstrap fixes the fixture without relaxing
graph admission: seven controls pass. Final source/initialization/native cohort:
108 passes in83.46seconds, including default alias countermodels and both flat32
adapters with real ELF/PE loads. The domain source seal now covers nine producing
and consuming owners; the retained old seal misses six dependency mutations and
the new nine mutation controls pass. Scoped Ruff and strict MyPy pass.

A bounded sandboxed Devin strengthened the independent scalar oracle to fixed
configured selectors and mismatching inputs. Parent reviewed its exact test-file
delta and reproduced the isolated missing-SS/missing-CS mutation controls. The
combined contract/native/bootstrap cohort passes71 tests in79.36seconds. The
actual bootstrap CALL is included in the effect ledger and compared over its
full state. This is a staged proof checkpoint, not full M4-M7 acceptance.

The final bootstrap corruption control additionally passes: unconstrained
comparison retains an alias countermodel, and overwriting the saved return word
is rejected by full-state comparison even when the scalar domain theorem proves.
The focused updated control passes in42.76seconds. The broad quality-dev run is
terminal with296 preliminary passes and7924 curated passes/25 failures/1 skip
in1818.60seconds, exit2. Its start-to-terminal audit detects three changed files;
full failure identities and hashes are retained. No fixed-tree acceptance or
baseline-cause classification follows. Required default/expanded and release
gates remain outstanding.


### Independent real16 source/domain/native connection (2026-09-29, staged)

Fresh decoding now binds the actual relocated immutable MZ bytes to every
supplied bootstrap/joint effect. Complete control/register/flags/memory/I/O
states are compared over unrestricted inputs when fresh VEX composition has a
different literal representation. No fields, caller assumptions or code bytes
are omitted. Native instruction groups and original opaque helpers refuse
unsupported events even when subsequent lowering would discard them. Relocated
word mutations, fabricated effects and omitted live outputs are rejected.

A seven-premise wrapper connects both independent source receipts, the exact
bootstrap/all-node manifest and the loader-derived scalar theorem under one
absolute deadline. An immutable proposal digest covers all joint effects,
initial state, dispatch, metadata and bootstrap; a six-premise consumer rechecks
ledgers, current immutable loads, byte hashes, domain and semantic owners before
reuse. Removing only the content check in an isolated diagnostic makes the
metadata corruption control falsely succeed; the implemented check rejects it.
The deliberately broken control is one expected failure in115.63seconds.

The native relation owner consumes these prerequisites before and after full
initialized-memory comparisons of the bootstrap and every recursive cutpoint.
Complete required facts include unattempted transitions after refusals. A valid
actual recursive MZ pair discharges every local native relation; changed
proposal content and expired deadlines refuse before native solver work.
These local proofs retain all five physical/model requirements and never grant
recursive or whole-binary equivalence. Caller-frame initiation, complete joint
composition, faults/services, differing layouts and remaining M4-M7 stay open.

Final source/domain/native cohort:25 passes in122.97seconds. After merging the
VEX type/control admission into its existing decode check, the three affected
source/consumer/native controls pass in99.14seconds. Six staged proof owners
pass scoped Ruff, strict MyPy and project-interpreter Pyright. Earlier combined
source/domain/default initialization/both-flat32 contracts:186 passes
in113.22seconds; that cohort preceded the final content-consumer integration.
No production recursive capability or fixed-tree project-gate acceptance follows.

The first sandboxed flat32 permission Devin is terminal0. Parent retained its
exact three-file proposal/report and confirmed all four saved baseline hashes
unchanged. Its12 reported controls do not cover a file mapping with no access:
parent actual ELF32 probe shows p_flags=0 dropped, then an observation supplies
RW and the guest store succeeds. Promotion remains pending. A separate
bounded sandboxed Devin follow-up owns that no-access declaration correction
and ELF/PE controls; the retained terminal sources are its red baseline.

### Actual real16 caller-frame and joint composition checkpoint (2026-09-29, staged)

The complete image-bound scalar certificate now binds its actual domain fields
to one loader-derived factory. A saved dirty consumer falsely accepted changed
alignment; the focused red control fails before correction. Alignment and both
selector mutations now refuse reuse. Caller-frame initiation proves the actual
bootstrap CALL's independently decoded return word, stack bounds/alignment and
exact selectors over arbitrary remaining registers/background memory. An actual
MZ CALL-to-JMP mutation refuses initiation; a missing or corrupted saved word is
rejected by the frame oracle. Final source/domain/frame/native cohort:27 passes
in96.93seconds; three proof owners pass scoped Ruff, strict MyPy and Pyright.

A composed report includes actual entry initiation, every full initialized native
transition, both sides' BODY/PUSH/POP frame preservation and complete atomic
dispatch/progress in one acyclic graph with a fixed denominator. Its two focused
controls pass in94.27seconds. Only complete composition removes CALLER_ENTRY
from the remaining requirements; missing source evidence and expired deadlines
retain the entire denominator. Valid examples remain CONDITIONAL with physical
code/address/fault/environment requirements open and binary proof always false.
A source-owner mutation additionally exposes an omitted dispatch evaluator in
the joint model seal (one expected red in51.60seconds); corrected sealed checks
pass three controls in78.68seconds. No production recursive capability or
whole-program acceptance follows.

The no-access permission follow-up Devin is terminal0 and independently reviewed:
parent red has two expected ELF/PE failures in47.70seconds; corrected controls
pass14 tests in36.30seconds. A disjoint sandboxed follow-up stages explicit
scratch mapping and typed read-only observations. Parent review and promotion
remain pending, including complete observation manifests and finite repeated
declaration/claim work. Full M4-M7 and the failed fixed-tree project-gate
acceptance remain open.

### Flat32 declared memory and observation promotion (2026-09-29)

Parent independently reproduces the observation-created mapping defect on the
saved dirty baseline: stores to unmapped and CLE synthetic bytes return only
because the address was observed. The staged repair instead records unmapped
or protected faults and preserves unsupported provenance. The worker's exact
three-file delta/report is retained before parent correction. Its18 green
controls miss three independently reproduced failures: both sides lose the
same requested observation, both return truncated captured bytes, and repeated
overlapping declarations bypass the distinct-page budget. Parent regressions
fail all three in26.58seconds; an aggregate observation-byte control separately
fails in32.79seconds. Corrected staged cohort:22 passes in26.43seconds.

Production now owns typed replay contracts, declared permissions and memory
binding in separate focused modules. Observations cannot create mappings;
patches seed already mapped bytes; caller scratch is explicit data-only VECTOR
storage and cannot widen file permissions. FILE NONE is retained as a declaration.
Complete required-observation manifests, byte counts and per-page provenance
survive into API and CLI reports; missing evidence cannot reach agreement.
Distinct mapped bytes, total page claims, vector metadata and aggregate byte
work are separately bounded. The public CLI defect has one expected baseline
failure in14.20seconds and explicit scratch/missing-observation controls now
pass. Typed fixture helpers and22 permission/observation controls are enrolled
in routine pipeline, ownership and Make gates.

Final production replay plus enrollment cohort:169 passes in54.11seconds.
Six owners pass scoped Ruff, strict MyPy and project-interpreter Pyright.
An initial production test extraction omitted one fixture constant (29 controls
passed, three modules failed collection); the final169-control run follows
that correction. A mistyped enrollment-test path also yielded zero tests and
is not counted as evidence. No execution agreement becomes a proof.

Fresh quality-dev has a saved2,548-file dirty source baseline. The first attempt
ends2 during compiled-import setup because the outer sandbox lacks a writable
temporary directory; all baseline hashes remain unchanged. A repository-TMPDIR
retry is active. KVM is absent; DOS runtime evidence remains environment-limited.
A bounded sandboxed Devin stages actual real16 fetched-byte preservation;
parent review, integration and all physical/fault/environment closure remain
open. Full M4-M7 and release acceptance remain outstanding.

### Ordered native access and code-prefix checkpoint (2026-09-29, staged)

Raw unoptimized VEX intake now retains dead reads and every intermediate store
before liveness filtering. Actual save/write/restore bytes demonstrate that net
memory equality can conceal a transient code overwrite. Finite expression/access
intake and one original deadline retain typed refusals. The byte projection
oracle separately proves domain nonvacuity and each preservation implication;
model rendering is charged to the same deadline. Final focused cohort:8 passes
in65.86seconds. These are local evidence controls, not program equivalence.

The bounded code-fetch Devin timed out124 with one untested partial owner and
no test/report deliverables. Parent review rejects its final-memory-only approach
and missing model-seal dependency path. Its exact terminal proposal is retained;
it is not an accepted implementation. A separate parent owner freshly decodes
every consumed actual MZ request, checks each raw store prefix against all fetched
ranges and retains all reads for later fault/address proofs. Recursive composition
now requires this child and seals all three new owners. Three independent source
mutation controls fail on the saved old joint seal. A separate expected red shows
that missing requests must retain the graph-derived denominator; the correction
is implemented. Final code-prefix/joint cohort:11 passes in76.25seconds. The
three touched proof owners pass strict MyPy; all four proof dependencies pass
configured Pyright and scoped Ruff. A contended intermediate run exhausts its
original deadline during final receipt consumption; the typed child reason and
cause now survive into the parent report without replenishing the budget.

The repository-TMPDIR quality-dev retry is terminal2:296 preliminary passes;
curated7955 passes/29 failures/1 skip in2007.38seconds. All2548 recorded production
source hashes match at terminal. This is fixed-source failure evidence, not
acceptance. The launch sandbox lacked KVM; its failure causes are not presumed
pre-existing. Parent subsequently verifies the exact KVM device/API12 through
the scoped repository-only sandbox and launches one bounded diagnostic Devin
rerun of the29 failures. It is terminal0 with14 passing and15 failing tests in
493.80seconds of pytest execution, with every saved source unchanged. Parent
retains the exact worker output and independently distinguishes three compiled
REP-store oracle mismatches, two validation refusals, one signature assertion,
eight timeout results and one ASan address-space refusal. These are observed
failure surfaces; feature-regression provenance and timeout causes are unresolved.
The ASan control independently passes in6.27seconds under the parent's normal
address-space limit without any source changes. No full gate is thereby green.
A disjoint bounded Devin now stages per-raw-access first-MiB address bounds;
architectural wide-operand segment scope and faults remain separate requirements.
Full M4-M7, physical/fault/environment closure, production recursive promotion
and release gates stay open.

### Native operand and consumed MZ scope checkpoint (2026-09-29, staged)

Decoded logical segment/offset coordinates now retain the original unsplit
operand width for every raw native occurrence. Independent SMT checks establish
coordinate binding and original-operand segment scope separately: two valid
physical byte addresses cannot admit an original word at offsetFFFF. Near CALL/
RET operand overrides retain SP16 and require sufficient alignment for their
original width. Declared predicates still need independently proved initiation.

Parent corrections require exact unique occurrence manifests, valid lowered
access facts and all five evidence counters; malformed saved ledgers refuse.
Operand model seals now include the authoritative raw occurrence producer.
The saved pre-correction controls produce two expected failures in29.73seconds;
the corrected raw/operand/scope/code-prefix/joint cohort passes36 in69.09seconds.

A new source connection consumes the established immutable MZ/code-prefix
manifest, independently re-reads and decodes every requested operand block,
uses actual bootstrap constants or the consumed cutpoint domain, and reconsumes
the source/domain receipt before final model admission. Missing requests retain
the joint-graph denominator. Child proof budgets are bounded by the original
absolute parent deadline; the old API fails this control in34.57seconds. The
connected operand cohort passes24 in57.40seconds. All four touched owners pass
scoped Ruff, strict MyPy and configured Pyright. These results grant neither
physical allocation/permission evidence nor fault/environment/binary closure.

The earlier physical-address and REP diagnostic Devins both timed out124; exact
partial outputs remain frozen and unaccepted. Parent independently recompiled
the three frozen generated kernels and confirms their return/EDI controls agree
while the high byte lands at0x20000 rather than the retained oracle's0x10000.
That is a reproducible oracle mismatch, not architectural acceptance or an
earliest-layer fix. Segment-end exclusions remain explicit, and existing failed
gate controls are not weakened. A separately sandboxed bounded Devin review
also reached its480second limit with no owned patch, tests or report. Parent
verified the physical owner, raw collector and code-prefix hashes unchanged;
the operand-scope hash changed through the parent's absolute-deadline API fix.
Final shared raw/operand/bound-source/prefix/joint cohort:41 passes in88.96seconds.
Parent physical-contract controls expose two independent expected failures
in31.01seconds: incomplete ledgers could grant local bounds, and block closure
could omit nonvacuity or hide duplicate obligations. Corrected block manifests
require exactly one witness and each unique access. Native solver outcomes and
deadline flags remain typed; UNKNOWN is no longer diagnosed as an empty domain.
Six local physical controls pass in39.03seconds, including actual dead reads,
intermediate writes, first-MiB violations and64bit extent arithmetic. Scoped
Ruff, strict MyPy and configured Pyright pass. The final physical cohort passes
seven in39.84seconds, adding actual-MZ source/domain consumption, stale-receipt
refusal and preserved missing-request/expired graph obligations. Duplicated
source ownership and final raw-access accounting still need review before
composition or production acceptance.
Production integration and full M4-M7 acceptance remain open.

### Mandatory recursive data-address prerequisites (2026-09-29, staged)

The joint theorem now requires both source-bound native operand coordinates/
original segment scope and every raw physical data-access bound before frame
induction. These children and their counters remain in the report, including
typed deadline refusals. The required denominator includes both new children
before any source refusal. Changing their owners invalidates the joint model.
Saved-baseline controls:5 expected failures/4 passes in59.30seconds, plus2
expected failures for ignored timeout children in73.88seconds. A separate
37.21second expected red verifies native child deadline reasons survive source
composition. Nine isolated controls pass in95.39seconds after correction.

The bounded physical-source Devin timed out124 after a partial owned patch;
its exact terminal owner/tests are frozen, common source inputs unchanged.
Parent rejects its first countermodel control because the selected first block
has no raw accesses. The corrected saved-baseline control independently shows
21 required rows versus the complete31 after an early access countermodel.
Physical source intake now reuses the checked code-prefix producer and freezes
every known raw occurrence before address queries. Unproved complete source
results refuse; both direct and transitive source/model owners are sealed.
Parent expected red:1 source-admission failure/1 pass in44.93seconds and1
transitive-seal failure in35.56seconds. Final shared joint/source cohort passes
14 in111.20seconds; three owners pass Ruff, strict MyPy and configured Pyright.

A combined isolated17-control run retains a30second final-receipt deadline
failure:16 pass/1 fails in108.50seconds. The exact same positive fixture passes
separately with its unchanged budget (19.95second test body). This is measured
resource contention, not a widened test budget or hidden semantic success.
The final shared physical/bound-source cohort passes14 in89.62seconds with
unchanged positive budgets, including the corrected31-row early-countermodel
ledger and actual MZ receipt controls. Fetch scope, permissions,
faults, environment, production promotion and full M4-M7 remain open; the joint
verdict remains conditional and binary equivalence remains false.

### Native fetched-span prerequisite (2026-09-29, staged)

`real16_fetch_scope.py` owns three separate local facts: native predicate
nonvacuity, complete CS-relative decoded extent and complete first-MiB physical
extent. Loader-linear addresses are checked before word projection. Unsigned32
start/size and unsigned16 CS use64-bit arithmetic, with explicit bounds proving
the arithmetic cannot wrap. Legacy VEX IP is not architectural IP evidence.
The source-prefix connector now requires a matching complete fetch child before
preservation queries; its seal includes this owner and the coordinate contract.
Source/domain admission, control correspondence, permissions, faults and events
remain separate. Local geometry grants no binary proof.

Saved source refusal:1 expected red in76.49seconds. Initial corrected cohort:
13 passes/1 test-selection failure; the parent selects the actual bootstrap by
binding.entry rather than assuming it precedes graph rows. Existing budgets
then expose two combined deadline failures and an isolated prefix deadline.
One bounded saved-source profile reports old15-second producer proved in14.51s
and new producer refused in15.26s, with4.37s inside eight fetch checks. The
optimized implementation uses one incremental native context per span and
bitvectors throughout. Fetch/source controls pass17 in130.35seconds with
unchanged budgets. No end-to-end performance gain is inferred from the profile.

Saved joint refusal-controller replay independently rejects lost prefix deadline
causes (1 expected red in137.21seconds). Prefix and before/after receipt causes
now retain typed DEADLINE, and failed prefix counters prevent induction.
Final fetch/joint cohort:20 passes/1 recursive positive budget failure in247.26s.
The native child exhausts120seconds; the legacy parent branch reports UNKNOWN.
Entry/native/frame cause propagation and final positive acceptance remain open.
Four owners pass Ruff, strict MyPy and configured Pyright. Exact sources, logs
and unresolved obligations are retained in `fetch-scope-checkpoint-evidence.json`
under the recursive stage. Production integration, full M4-M7 and project gates
remain open.

A420-second sandboxed read-only Devin attempt retains a partial REP store-owner
note, without an accepted patch or final report. Parent confirms the runtime
word-store widening path admits structural adjacency without segment-wrap
evidence, verifies five saved worker inputs unchanged and rejects its unverified
exhaustive producer claim. A generic widening correction and binary regression
acceptance are still required.


M5 bounded model-seal and REP widening checkpoint (2026-09-29): parent measures
repeated native semantic fingerprints across the joint dependency graph. A fresh
ContextVar scope shares a leaf only during one digest traversal; independent
before/after proof seals always start fresh, including nested scopes. Native
identity also binds the snapshot owner and archinfo/capstone versions. Cold/warm
two-traversal profile changes26.89/16.35s to8.17/7.16s, semantic-hash calls14 to2
and source reads15,242 to2,416. This is a microprofile, not a general end-to-end
performance claim. Snapshot controls and the actual recursive positive pass6
in204.26s with the existing120,000ms proof budget. The positive remains
conditional and closes caller entry only. Three owners pass configured Pyright
and strict MyPy; scoped Ruff passes after one test-import formatting correction.

A sandboxed Devin adds actual-codegen/typed-identity store controls. Parent
reproduces6 expected failures/2 passes on the saved dirty production baseline,
then requires the existing alias-owned byte identity join before runtime word
store widening. Symbolic/wrapped/different-region identities retain two byte
stores; successful joining retains the word identity, source addresses and equal
segment carriers. Store/snapshot cohort passes13 in71.58s. The store regressions
are enrolled in both routine Make test lists and their owning manifest.

Binary regression acceptance remains open. The first three-case CLI run reports
two unavailable-KVM tail validations and one decompilation timeout. Parent
compiles both available unchanged partial-C outputs and their memory/return
oracles agree; that is diagnostic evidence only. A verified launcher probe sees
character10:232/API12 with rootRO/repoRW/4GiB, but subsequent same-launcher
attempts cannot stat /dev/kvm and fail before pytest. No unavailable run grants
validation=passed. Exact sources/evidence are retained in the recursive stage's
snapshot-store-checkpoint. Entry/native/frame typed deadline propagation, third
REP binary acceptance, production promotion and full M4-M7 gates remain open.


Nested deadline checkpoint (2026-09-29): parent controller tests reproduce three
lost entry/native/frame causes; native producer tests reproduce three lost
before/transition/after causes; entry producer tests reproduce three lost
before/clause/after causes. Each saved-source cohort has3 expected failures and
3 nondeadline passes. Enum-based propagation preserves DEADLINE through these
boundaries with unchanged counters, children and required denominators. The
combined accounting/routing cohort passes18 in132.61s; three owners pass strict
MyPy and configured Pyright. These instrumented controls do not establish
semantic premises. The actual positive recheck still exhausts its original
120,000ms budget during entry consumption (6 controls pass/1 positive fails in
262.15s), exposing the producer-level cause loss corrected afterwards. Final
positive acceptance remains pending; the budget is unchanged.

Two subsequent sandboxed Devins time out124 without patches or terminal reports.
Parent supplies the controls and an AST import inventory after checking the
saved owners. The actual real16 joint slice has34 local modules/7,686lines.
An ignored package candidate uses an explicit recursive_proofs namespace and
valid stack subpackage, preserving code bodies, annotations, docs and conditional
limits. Parent checks all34 executable ASTs, excluding namespace imports and
declared hash-path relocation, with zero other differences; Ruff and all34
imports pass. A structural doc/type-presence audit has no findings. This
candidate is not public integration or semantic acceptance. Its model identities
change with source/import owners; existing proof caches must be invalidated.

The first new quality-dev run stops at compiled-import smoke because no writable
temporary directory is available. Its corrected repository-TMPDIR run passes
compiled smoke39modules, startup checks and296 preliminary tests; the main fast
pipeline remains active. No whole-gate pass or full M4-M7 completion is claimed.
Exact owner deltas and evidence reside in joint-deadline-parent-baseline; the
package candidate and its separate manifest remain staged for review/validation.


Production namespace checkpoint (2026-09-29): parent generated the complete
eight-module fixture closure and independently reran the candidate controller
cohort:20pass/66.91s. The actual MZ joint positive plus4refusal controls passes
5/197.99s under the unchanged120,000ms joint budget; successful local induction
is still CONDITIONAL and binary_equivalence_proved=False. The34owner namespace
audit Devin times out124 before a final report, but leaves its script and JSON.
Parent reads/reproduces those artifacts:132import rewrites,5exact stack-owner
path relocations, zero other executable deltas, unresolved imports or baseline
drift. This is migration evidence, not new binary proof acceptance.

The36module package (34owners plus2package initializers) now lives under
tools/dosunit/recursive_proofs. Four deadline/accounting test roots are in the
fast lane; actual-byte controls are in the binary-relational default/expanded
lane. Independent fixture builders remain test support. Package README records
the initialized-domain boundary, finite modular stack frontier, current model
requirements and refusal/freshness rules. Public compare-binary16 still uses its
existing shared arbitrary input-memory contract; this package is not used to
promote narrower initialized-domain results under that contract.

The first production-tree cohort has24passes/1deadline failure in301.87s; the
actual positive expires at the original operand-scope boundary. That run is not
accepted. A measured source-key bottleneck is addressed in ssa_provenance:
exact lexical descendant parts produce the same pathlib keys, with pathlib
fallback retaining outside-root errors. All source sets/bytes/digests remain
fresh; there is no persistent content or metadata cache. Seven isolated parity
and mutation controls pass, including same-size/same-mtime edits and source
addition/removal; their durable production versions are enrolled in fast gates.
Alternating fresh full-source scans over1103current paths produce identical
digests: original2.07-3.11s, optimized0.83-1.48s under shared contention. These
are source-hash timings, not an end-to-end performance acceptance claim.
The final-tree proof/freshness run passes34controls but the actual positive
again exhausts120,000ms, this time in physical-access checking (1fail/34pass,
261.90s). This remains unaccepted. All37production owners pass
configured MyPy/Pyright; scoped Ruff,42file doc/type/dot-access checks, startup
architecture and ownership validation pass. Whole quality-dev subsequently acquires the serialization lock and runs the
main fast cohort; prior preliminary296passes are not whole-gate proof.
Full M4-M7, physical/fault/environment closure, public recursive integration and
both flat32 adapter acceptance remain open.

A fresh exact-boundary KVM recheck fails before child launch because /dev/kvm
is absent; no DOS execution acceptance is inferred. Parent is profiling the
current production joint checker at its unchanged budget before selecting any
additional performance work.

The current production joint cProfile (one unchanged120,000ms checker call)
ends UNKNOWN/DEADLINE at physical access after120.05s. It observes52fresh
_semantic_hash calls/78.67s,58native-binding seals/83.40s (nested time), and
8receipt consumers/39.31s, of which16_source_valid checks take24.86s. These
are overlapping cumulative profile times, not additive savings. The exact
profile is retained in production-promotion-baseline/joint-current.pstats and
joint-current-profile.json. A bounded sandboxed Devin reviews sharing one
explicit fresh native-model value inside ONE consumer invocation, retaining
an independent final complete-model refresh. It also reviews typed child
deadline causes; no cache across producer/consumer boundaries is authorized.
A one-case production positive recheck runs separately at the same budget to
measure test contention; it cannot replace the failed full focused cohort.


### Receipt-consumer freshness and typed deadlines (2026-09-29)

The isolated actual-MZ positive also fails its unchanged120,000ms deadline
(caller-frame boundary;234.90s pytest total), so test contention alone does not
explain the earlier refusals. Bounded sandboxed Devin82457 leaves a static audit
and patch sketch; the wrapper exits124. Parent reviews the report and exact
source baseline before applying its own narrowly scoped production delta.

Each receipt consumption now computes one explicit local fresh native-model
leaf for both source receipts. All independent image/ledger/block-byte/effect
checks remain per side; the final complete-model hash independently refreshes
that leaf. There is no persistent cache or reuse across consumer invocations,
proof boundaries or before/after seals. This removes one full semantic scan per
consumer, without an end-to-end speed or binary-proof claim.

Three typed child DEADLINE causes now remain DEADLINE rather than becoming
STATE/SOURCE/JOINT. Exact partial facts, six required rows, failure counts and
cause details remain visible. Before the delta, deadline controls show3failures/
3nondeadline passes; local-sharing controls show1failure/3corruption passes.
Afterward all30new/existing routing and accounting controls pass in114.89s.
The two new durable roots are enrolled in fast Make/pipeline/ownership gates.
Ruff, configured Pyright, doc/type/dot-access, startup architecture and ownership
checks pass. Strict MyPy passes the complete37owner recursive/call-contract
cohort; narrower skipped-import invocations are not typed-owner acceptance.

All five actual-binary controls pass at the original120,000ms proof budget
(143.60s pytest total;86.17s positive call). This closes the local actual-MZ
regression for this tree, while its result remains CONDITIONAL with all four
code-memory/address/fault/environment requirements open. Changing system load
precludes attributing a controlled end-to-end speed gain to this patch alone.
The seven fresh-source parity/mutation controls also pass.

Whole quality-dev93212 exits2:8008passes/23failures/1skip in2395.46s, following
39compiled-module and296preliminary passes. The run spans source edits and is
not a stable final-tree gate. Its newly stale exact slow-lane inventory is
reproduced red and corrected to include the recursive actual-binary root,
retaining fast-lane exclusion. All56pipeline-controller tests then pass12.83s.
Other failures include missing KVM, recovery timeouts, a process-fixture failure,
and semantic/signature refusals. Their origins remain unverified; none is
classified as an unrelated baseline failure without isolated evidence. No remaining recursive model requirement is removed by these fixes.
Dirty pre-edit sources, exact parent deltas, red/green logs and audit artifacts
are retained under the recursive stage's receipt-consumer-review directory.


### Explicit loaded-memory seed and closure audit (2026-09-29)

One bounded saved pre-run _dos_envSize regression reproduces the broad gate's
validation-failed exit4 (368.42s pytest total). Its2546copied Python sources and
the saved original remain byte-identical. The current-tree recheck times out
with exit3 (201.98s), so current behavioral delta remains unresolved; no second
baseline attempt or function-fixed claim is made. Saved sources are isolated,
never restored into the shared tree; read-only binary/config assets are linked.

Devin73749 audits code-memory/address closure within the verified rootRO/repoRW/
4GiB sandbox. It exits124 before writing the requested report. Its CLI diagnosis
is not accepted as proof. Parent independently reads the exact source owners:
code-prefix queries cover every request's fetched span and every intermediate
store, while operand scope includes a genuine logical/native address equality
obligation. The missing code-memory composition is an explicit absolute loaded
byte domain and its initiation/preservation connection to those projections;
relative XOR transport over a free array cannot supply that predicate alone.
No assumption is removed by the audit.

The initialized-memory owner now provides seed_loaded_array: revalidate the full
canonical snapshot, write its literal bytes into an arbitrary32/b8 background
array under the original deadline, and retain every other byte. Use this only
at loader entry; later cutpoints must retain mutable data and prove their actual
memory invariant. This makes the finite seed underlying the relative transport
theorem executable and testable for both real16 and flat32 snapshots. It is not
yet a fetched-code-domain certificate consumed by recursive composition.
Five focused regressions fail before the constructor exists. Afterward78seed,
receipt, freshness and pipeline-controller controls pass147.97s, including
last-flat32-address bytes, an unrestricted outside index, reseeding identity,
proved XOR transport, stale snapshot refusal and deadline/sort boundaries.
The new root is enrolled in fast Make/pipeline/ownership gates. Complete37owner
MyPy, configured Pyright, Ruff, doc/type/dot-access, startup architecture and
ownership checks pass. Final actual-MZ5controls pass180.48s at the unchanged
120,000ms proof budget (positive call114.69s); result remains CONDITIONAL/local.
Full-plan, broad-gate and both-adapter acceptance remain
open; no CODE_MEMORY/ADDRESS_MODEL/FAULT_DOMAIN/ENVIRONMENT promotion is made.


### Absolute fetched-code invariant composition (2026-09-29)

The code-prefix producer retains its exact request manifest, protected ranges
and content proposal identity. The new fetched-code owner binds every protected
span to current immutable loaded bytes, constructs the loader-only literal seed
with arbitrary outside memory, proves the absolute code predicate nonempty and
true of that seed, and consumes every universal raw store-prefix witness.
The child is local code stability; it never grants a binary verdict.

The joint checker requires this complete child before entry/native/frame
induction, binds its model owner, retains its partial ledger and counters and
freezes the added obligation before any refusal. Three controller controls
reproduce the missing prerequisite (3 failures/21.75s). Two nested intake
controls reproduce lost typed deadline causes (2 failures/2 passes/21.70s).
Both causes now remain DEADLINE without replacing the original budget. The
final controller/pipeline/ownership cohort passes131 in56.33s with three pytest
workers. Complete recursive/call-contract MyPy, configured owner Pyright, Ruff,
type ratchet, startup architecture, context and ownership checks pass.

The final actual-MZ joint/fetched-byte cohort passes13 in73.30s with three
workers. The recursive positive uses49.73s of its unchanged120,000ms joint
budget. Complete local composition now removes CALLER_ENTRY and CODE_MEMORY;
ADDRESS_MODEL, FAULT_DOMAIN and ENVIRONMENT remain explicit assumptions.
Status remains CONDITIONAL and binary_equivalence_proved=False. Public
compare-binary16 retains its distinct arbitrary shared-memory contract.

The new controller root is enrolled in the fast Make/pipeline/ownership lane;
the actual-byte root is enrolled in default/expanded binary-relational lanes.
Exact dirty baselines, parent deltas, red/green logs and static checks are
retained in the recursive stage's fetched-code-integration directory. Shared
worker-limit and unrelated SS-identity enrollment edits are preserved and
separated from this parent's semantic delta. Bounded sandboxed Devin source
review and the broader final-tree gate remain pending at this checkpoint.
Full M4-M7, execution acceptance and both flat32 adapter acceptance remain open.

### Fetched-code provenance intake and three-worker gate (2026-09-29)

The fixed-source `quality-dev` attempt uses three pytest workers throughout.
Its preliminary cohort passes296; the main fast cohort passes8104 and fails14
in2134.27s. The complete Make attempt exits2 after2413.26s, and independent
before/after fingerprints confirm unchanged implementation, Make and pipeline
sources. The failures are retained in the fetched-code-integration gate log;
they are not classified as unrelated baseline debt. The gate is not accepted.

A bounded sandboxed Devin review identified an omitted reusable theorem
premise. The parent reproduces both controls against the exact dirty pre-fix
sources: an authentic MZ with changed loader SP, identical loaded snapshot and
different file/register identities incorrectly receives a complete local code
invariant; malformed prefix side metadata raises IndexError. Both controls
fail in65.11s with three workers. The review's separate claim of unsealed
shared dependencies is rejected: the native semantic digest already includes
every Python owner below tools/dosunit recursively.

The prefix result now retains its producer source/domain receipt. A focused
intake owner reconsumes that receipt using the current loads, proposal,
bootstrap, request manifest and scalar domain under the original absolute
deadline. The authoritative consumer exposes completeness only for its exact
six unique proved provenance obligations and complete counters. Manifest
mismatch refuses before any untrusted side indexes the request tuple.
Fetched-code establishment retains this child, adds a required SOURCE row,
and requires child completeness; its frozen denominator is11 plus the number
of requests. It still preserves unrestricted mutable data at later cutpoints.

All19 fetched-code/controller controls pass in66.52s with three workers,
including changed headers, missing producer receipts, changed scalar domains,
malformed sides and nested deadline causes. Complete recursive/call-contract
MyPy, configured changed-owner Pyright, Ruff, type ratchet, startup architecture,
agent context and ownership checks pass. Actual recursive-binary composition
passes5 in233.95s with three workers; the positive test call takes119.84s,
including its input/prerequisite preparation. The joint proof's120,000ms
budget is unchanged. This is not a controlled performance comparison with the
previous run. A final semantic project gate remains pending; the earlier
fixed-source broad gate failed14 and is not upgraded by these local results.

A separate bounded Devin control-head staging attempt times out with exit124
and no worker report. The parent rejects integration of its partial certificate:
its saved child checks lack complete current source/model/ledger consumption.
The ignored candidate and exact parent review remain available for a bounded
follow-up. No ADDRESS_MODEL, FAULT_DOMAIN, ENVIRONMENT or binary-equivalence
requirement is removed by this provenance fix. Full M4-M7 and both flat32
adapter acceptance remain open.

### REP and AIL control parity checkpoint (2026-09-29)

Completed a bounded real16 summary repair: REP admission now comes from exact
decoded instruction bytes through a typed owner. Isolated default-address16
MOVS/STOS/SCAS/CMPS byte/word forms retain complete loaded control and the
modeled direction dependency. Leading instructions, overrides and other forms
retain native IR instead of losing effects in an inappropriate summary.
An actual high-loaded MZ regression preserves control_ip above64KiB.

The public REP STOSW self-control is PROVED under the existing functional model;
changing STOSW to STOSB is UNKNOWN with zero discharged obligations. Independent
Unicorn execution confirms distinct word/byte memory writes. This is supported
model evidence, not whole-DOS or M0-M7 acceptance.

Completed AIL control projection repair: original binary IR owns full-width
CALL/RET destinations, while converted AIL supplies the effect state. This
avoids converted CALL target narrowing and omitted RET destinations. Direct
AIL branch lowering also retains32bit destinations and signal-exit metadata.
The original missing-control regression is reproduced before the repair; the
focused final AIL/REP cohort passes38 with exactly three workers. New contract
regressions are enrolled in the routine Make/pipeline/ownership lists.

The bounded read-only Devin diagnosis exits124 without a final worker report.
Parent reproduction independently verifies the missing control_ip failure and
conversion boundary before accepting any conclusion. Exact dirty baselines,
red/green logs and parent reproduction are retained under
.cache/comparator-implementation/rep-ail/. Ownership and startup architecture
checks pass; the new instruction owner passes MyPy and configured Pyright.
The wider real16 call/loop/region plus flat32 affine cohort passes93 in46.80s.
Added native word/dword RET parity controls then expose an operand32 AIL IP
write refusal; the repair preserves full pending control and the legacy word
projection. All four AIL controls fail against saved dirty pre-run sources in
an isolated process and pass on the final source. quality-dev first fails on
unwritable temporary directories; the repository-local TMPDIR rerun passes296
preliminary tests and is running the main pipeline at this checkpoint. Existing SSA layout-pair complexity debt remains visible; no
full-project gate or original-plan milestone is marked accepted by this slice.

### Full mapped-image cache correction checkpoint (2026-09-29)

Completed the previous REP/AIL gate intake: quality-dev's repository-local
TMPDIR run ends with296 preliminary passes, then8185 passed/28 failed/1 skipped
in701.20s, exit2. This is a failed gate; many failures stop at unavailable KVM,
and remaining failures have not all been classified. Standalone adapter checks
must use separate subprocesses to avoid their bare-module import collisions.
The architecture-aware REP owner is now repeat_string_contracts.py; standalone
MSC8 passes61 and the prior BC5/real16 REP cohort passes42. MSC8 stack-cleanup
controls require the honest whole-function refusal while retaining failed
cutpoint ESP evidence and independent native replay. No verdict is upgraded.

Completed a new M7 loaded-image defect repair. An independent frozen BC5 cold
versus warm load comparison proves different mapped bytes despite identical
section hashes. The missed byte is0x800002 (full128, cached0), outside every
main-image section. Section-only certificates therefore did not reconstruct
the actual loaded image. Cache fingerprints now include every mapped byte and
loader coordinates; admission requires equality after bounded section patches,
and certificate version3 invalidates the old certificates. Differences beyond
those patches retain the normal loader. Fresh cold/warm loads agree on all
mapped spans. No unsupported relocation patch is guessed.

Image identity now merges contiguous backers before hashing while preserving
holes and coordinates. The fragmentation regression fails against the saved
pre-run owner (1 failed/2 passed) and passes on the final owner. The cache's
unsectioned-byte corruption control also fails before repair. Focused final
image/cache checks pass14 in36.14s; separate BC5 adapter checks pass26 in7.13s
and MSC8 adapter checks pass61 in14.81s. Each pytest invocation uses-n3.
Scoped Ruff, MyPy and interpreter-configured Pyright pass. Timing overlap makes
these unsuitable for a before/after performance claim. Evidence and exact dirty
baselines are under.cache/comparator-implementation/image-identity/.

Parent intake of the bounded BC5 Devin corpus run preserves all15 selections:
both self and rebuilt runs refuse15, with zero discharged obligations. Those
reports predate the cache repair and retain the defective loaded-image receipts;
they are diagnostics, not current acceptance. A new read-only bounded Devin
MSC8 corpus intake is running, with parent acceptance pending.

The new KVM-enabled quality-dev attempt refuses before Make: /dev/kvm is absent
at this attempt. The previously successful explicit-path KVM regression is a
historical local result, not evidence that this device is presently available.
No full gate or M0-M7 milestone is accepted by this checkpoint. Remaining work
includes current frozen-corpus results, broad-gate classification, M5 control
and environment obligations, and original loop/call acceptance across both
architectures.

Fresh post-repair BC5 corpus attempts finish with all15 requested functions
refused in each of self and rebuilt cases. The self loaded-image relation now
correctly proves identical, with no erroneous cold/warm mismatch; function
proofs still refuse. Exact receipts are in image-identity/current-bc5/.
Parent inspection of Devin's current MSC8 compare.json confirms self2/2 passed
(counters2/2/2/2/failure0, initialized-image relation proved), while rebuilt
2/2 refuse at region_lowering_incomplete and uninterpreted_x86_flags
(counters2/2/2/2/failure2, initialized-memory relation unknown).
All recorded MSC8 baseline source hashes remain unchanged. These retained
selections are corpus evidence within the declared model, not whole-plan
acceptance; the MSC8 worker's final report is still pending at this checkpoint.

### Exact arithmetic branch conditions checkpoint (2026-09-29)

Completed a bounded flat32 semantic improvement in the shared SSA owner.
The new typed x86_lazy_conditions owner admits concrete COPY and VEX i386
ADD/SUB/ADC/SBB/LOGIC/INC/DEC byte/word/dword thunks for all16 branch predicates.
It retains modular carry/borrow, overflow, low-byte parity and saved INC/DEC
carry. ADC/SBB consume the XOR-encoded second dependency. The same contract
owns admission and Z3 interpretation. Symbolic/invalid IDs, shifts, rotations,
multiplication and complete EFLAGS/carry materialization remain abstract;
no observation, fault or environment domain is narrowed.

Before implementation, independent native-instruction condition controls fail22
and pass8. After implementation they pass30, including6128 predicate checks
against independently observed Unicorn flags. Actual ADD versus LEA/TEST
function-byte controls under both adapters establish self/equivalent/mutated
GPR-return verdicts, with memory/control retained by call composition. Four of
those six controls fail against the saved dirty pre-run evaluator and pass on
the current source. The37-control cohort passes in33.04s; final neighboring
adapter/real16 REP/AIL and IR coverage controls pass106 in61.04s. Each invocation
uses exactly-n3. Tests are enrolled in Make, ownership and the routine pipeline.
The execution specification records the exact admitted helper scope.

The wider comparator cohort finishes269 passed/20 failed/5 skipped in51.28s.
All20 failures reproduce against saved pre-change SSA source in an isolated
process (20 failed in42.60s). Bounded intake records13 callee_not_proven,
5 call_target_unproven,1 slice_too_large and1 observable_mismatch. This proves
that these failures predate this arithmetic change; it does not settle whether
each test or production behavior should change. Their obligations remain open,
and no expectations or refusal gates are weakened to obtain green tests.
Evidence is retained under.cache/comparator-implementation/lazy-conditions/.

The previous SSA layout-pair complexity violation is removed by extracting its
literal-pair adoption loop.64 deterministic adversarial-row comparisons against
the saved owner retain exactly its old conflict/invalid-input behavior. Whole
SSA and new-owner Ruff pass. New-owner MyPy and configured Pyright pass. An
unconfigured whole-SSA Pyright audit still reports203 legacy diagnostics;
that is not presented as a green whole-module type result.

quality-dev first stops in mypy-dev at the IR coverage owner's missing explicit
None guard. The guard now preserves its typed IR_NOT_PROJECT_OWNED refusal;
existing IR ownership/census controls are included in the106 passing cohort.
The final configured mypy-dev check passes. The coordinated quality-dev rerun
passes its linter/startup/ownership phase and296 preliminary tests in9.64s;
the main three-worker pipeline is running at this checkpoint. /dev/kvm is still
absent. Full-project acceptance is pending the actual terminal result.

Fresh MSC8 retained selection: self2 passed, rebuilt2 refused with the same
region_lowering_incomplete/uninterpreted_x86_flags causes. Counts are2/2/2/2
with failure0 for self and failure2 for rebuilt. Both reports seal the new
condition owner's source hash; no selected corpus coverage gain is claimed.
The retained real16 self run completes in83.25s with all3 obligations UNKNOWN;
20 catalog functions and399 SSA parts per side are lowered and compared before
selection. Known-call/loop retries remain unproved. The next measured public
workflow investigation is demand-driven selected-function/callee lowering,
while preserving every requested obligation, reachable dependency, candidate
edge and environment refusal. It is not implemented at this checkpoint.

The prior MSC8 Devin intake produced its final artifacts before its CLI timed
out; the parent reviewed the actual reports/source receipts. A separate bounded
read-only arithmetic audit exits124 without a report or patch. Its partial
transcript is not accepted review evidence; three owned source hashes remain
unchanged. No original-plan milestone or full-binary acceptance is announced.

### Invocation-local real16 self-lowering reuse (2026-09-29)

Completed: identical executable paths/catalogs and fresh binary/source identities
reuse one sealed lowering through independent deep copies. Both sides still
load their images, seal/check provenance, scan environment effects and consume
every existing proof gate. Reports expose `lowering_reuse`; retained evidence
counters are not a count of physical duplicate lift executions. No persistent
cache, selected-scope reduction or refusal weakening is introduced.

Parent red control: 1 failed/3 passed. Final native wrapper/reuse/nested-loop
cohort: 22 passed in26.55s with-n3. Controls cover path/catalog differences,
nested mutable independence, both sides' admission checks and binary drift.
Ruff, scoped Make lint/type/architecture/ownership, configured mypy-dev and
scoped Pyright pass. A standalone follow-imports=silent MyPy invocation reports
the existing SSA lifter re-export diagnostic; configured Make checks pass.
Devin's bounded sandboxed read-only audit produced a report before CLI cutoff;
parent reviewed its source claims and added the stronger fresh-identity guard.

Frozen self workflow, serialized with PYTHON_JIT=1, repository TMPDIR, unchanged
budgets/selection and no pytest pool: actual baseline31.93s (two lowerings,
3.18/3.38s); final current27.05s (one lowering3.13s, copy0.246s); saved-driver
diagnostic baseline31.56s (two lowerings3.95/3.44s); current repeat30.27s
(one lowering4.66s, copy0.242s). Current compare/retry phases remain about
12s/2.2-2.4s. All three obligations, verdicts, refusal details, methods and
evidence counts match the paired saved-driver run. Timings vary; do not claim
a general14-percent speedup or a corpus proof-coverage gain. Receipts and exact
driver baseline are under.cache/comparator-implementation/self-lowering-reuse/.

The preceding quality-dev ends8253 passed/29 failed/1 skipped in1172.25s.
All28 previous failure fingerprints persist; the additional positive nested-loop
failure passes in the focused cohort and remains unresolved at broad-gate scope.
Final-source quality-dev is running separately after all focused checks and
benchmarks. No original M0-M7 milestone is promoted. Demand-driven lowering
still needs binary call closure, candidate-only edges, alias collision and
global/environment evidence coverage; it is not implemented by this reuse.

Follow-up intake (2026-09-29, staged): parent inspected actual MSC8 SSA artifacts
and found carry-only helpers with concrete SUB16/SBB32 operation ids5/12 in the
retained refusal. An ignored staged owner projects CF through the existing
BELOW condition contract, admits no new arithmetic operation/full EFLAGS, and
passes standalone Ruff/MyPy. Native carry/adapter mutation controls are staged
but not executed; no production carry integration or new binary verdict exists.

The bounded unmapped-target Devin exits124 without a final report. Parent
independently checks the MZ header, catalog and native instruction operands:
loaded target0x2222 corresponds to module offset0x1222; no catalog entry owns it.
Its decoded path restores a saved continuation through an indirect jump and
branches to a separate failure path. This is not just a coordinate mismatch;
neither a helper name nor an invented body bound may discharge it. Exact binary
hash/native-decode receipt is retained in self-lowering-reuse/unmapped-native-facts.json.
These are bounded native facts, not a whole-function proof. The current gate
remains live; semantic sources are held stable until its terminal result.

### Exact carry-helper checkpoint (2026-09-29)

Completed production CF interpretation and matching admission through the
existing integer BELOW condition contract. COPY and arithmetic ids1..21 retain
their existing widths/dependency semantics; invalid/symbolic/malformed calls
remain abstract. Full EFLAGS and other arithmetic families remain unmodeled.
No observation or input-domain projection is narrowed. The evaluator's summary
dispatch is factored without relaxing its complexity guard.

Red:48 failed/11 passed in5.22s against saved dirty SSA. Green:96 carry/condition
controls in11.85s, including384 new native CF observations and both adapters'
self/equivalent/corrupt return projections. Final neighboring real16 REP/AIL,
freshness, binary-wrapper/reuse and region/loop cohort163 passed in73.75s.
Every pytest invocation uses-n3. New controls are enrolled in Make, ownership
and the routine pipeline; execution spec and owner docs record admitted scope.
Whole SSA/new-owner/test Ruff passes. Scoped Make/static/architecture/ownership,
configured mypy-dev and new-owner MyPy/Pyright pass; scoped Make explicitly
skips legacy SSA full typing, not presented as a green full-SSA type result.

Fresh frozen MSC8: self2 proved; rebuilt1 counterexample and1 UNKNOWN. Function
sub_319B0 changes from uninterpreted_x86_flags to observable_mismatch under the
declared SSA model, with EAX/EBX/ESP and memory differences. sub_2B0D0 retains
region_lowering_incomplete. Counts remain2/2/2/2; failure0 self/failure2 rebuilt.
No independent whole-program execution or generated-function fix is claimed.
Artifacts/source receipts are under.cache/comparator-implementation/carry-helper/.

The preceding final-source reuse quality-dev terminates8266 passed/31 failed/
1 skipped in910.88s. All29 previous fingerprints persist; added split-region
and segment-preservation-summary failures pass in an isolated saved-SSA-baseline
attempt (2 passed). Their broad-gate causes remain open, not declared fixed.
Parent separately reproduces import-order-dependent duplicated contract classes:
canonical-first shares module/class identity, legacy-first does not; late
preservation-stage modules can also duplicate. Existing package alias scanning
only covers already imported children. A bounded Devin is staging a cold import
compatibility owner under ignored import-identity/worker/, without production
edits/tests. Causal linkage to broad failures and final gate acceptance remain
unproved. No original M0-M7 milestone is fully promoted.

### Cold import identity checkpoint (2026-09-29)

Parent review rejects the staged finder: importing canonical code during
find_spec returned identical first objects but left divergent sys.modules
entries and repeated imports. Production discovery now returns an alias spec
without executing code; create_module imports canonical code and exec_module
restores its spec. Both package entry layouts install this owner before X86_16
initialization. The one-shot package scan is removed. Strict contract/class
guards remain intact. Comparator freshness and persistent function IR/SSA
source manifests include the entry points and new import owner.

Cold subprocess regression: all4 import-order/layout cases fail before the
fix (22.58s). After integration,21 import/segment-preservation/region tests
pass (32.24s). Expanded focused check-files passes108 tests (38.82s), including
canonical metadata/reload/repeated-import controls and same-size/same-timestamp
mutation checks for all3 added comparator source dependencies. All use-n3.
New-owner Ruff/Pyright and configured MyPy/type-ratchet checks pass. Final
static/cache-scope check-files passes6 tests in20.63s. A pre-existing obsolete
150-file source ceiling failed at164 (161 before the3 added package sources);
the test now rejects downstream semantic layers directly instead of bounding
IR owner count. Final-source quality-dev is running; existing broad-gate causal
linkage remains unproved until its terminal result.

Final carry refusal-control cohort from the prior checkpoint passes97 tests
in18.97s. No original M0-M7 milestone is promoted by these focused results.

The combined carry/import quality-dev checkpoint is terminal: repository-contract
stage296 passed in17.35s; broad unit-focused stage8358 passed/8 failed in928.32s,
all-n3. All8 failure fingerprints were present in the preceding31-failure run;
23 prior fingerprints are no longer observed. This comparison does not isolate
the causal contribution of the combined changes. Remaining failures: nested
call-loop positive, SORTD RunMenu/InsertionSort/InitMenu, two COD loading wrappers,
inbox-long and setgear CLI. The gate exits2; later Make stages do not run.
Fresh isolated native nested-loop diagnostic proves all7 transitions with
counts7/7/7/7/failure0; its broad-run discrepancy remains unresolved.

Final report-closure follow-up: flat32 report snapshots omitted the outer package
shim even though lowering freshness and persistent IR/SSA snapshots included it.
An isolated red fixture confirms an equal-size/equal-timestamp outer-shim change
was invisible. Public report closure now seals that entry point when present;
installed layouts retain their inner-only entry point. Both layout entries and
the import owner have mutation/deletion controls. Final scoped check-files:
254 passed in48.02s, with configured lint/type/architecture/ownership checks.
This small follow-up occurs after the broad run; it is covered by focused checks,
not presented as a subsequent green broad gate.

Fresh final MSC8 receipts bind all3 entry-point/import files: self2 passed
(6.59s); rebuilt1 modeled mismatch/1 incomplete-lowering refusal (7.13s).
Shared proof counters2/2/2/2/failure0 self and failure2 rebuilt. Startup/services
and whole-program execution remain unproved. Artifacts are under
import-identity/msc8-final/. The final bounded sandboxed Devin review times out
at330s without a report or production edits; it grants no acceptance evidence.
Full original M0-M7 acceptance remains open.

### Nested-loop order diagnosis (2026-09-30)

The strict nested-call-loop regression now saves both SSA documents and the
typed proof on failure, without weakening its expected verdict or accounting.
An ignored worker-local diagnostic records preceding test IDs. With Make's
startup `PYTHONHASHSEED=0` and exactly three workers, the targeted preceding
cohort passes287 tests in79.45s; collecting the entire inventory before running
the same cohort passes287 in293.15s. The isolated native nested proof discharges
7/7/7/7 obligations with failure0. These checks do not reproduce or close the
previous broad-run failure. A correctly seeded full diagnostic is still active;
its terminal receipt is required before assigning a cause.

The earlier unseeded full diagnostic records8345 passes/25 failures in949s,
but is not comparable to the Make gate because its startup hash seed differed.
Its failures must not be counted as new accepted baseline fingerprints. Targeted
collection is the measured cheaper local diagnosis path; full collection remains
required where import/order effects are under investigation. No end-to-end
production optimization is claimed. An identity-keyed substitution-cache lead
has no established failing lifetime: the direct caller creates a fresh cache and
retains the source tree throughout recursion. No speculative fix was applied.

The sandboxed address-closure Devin audit times out124 after630s without a
report or source patch. A new static-only,180s-bounded Devin collection audit
owns only an ignored report; parent review remains required. No original
milestone is promoted by these diagnostics.

The seeded full diagnostic is terminal1:8353 passed/17 failed in714.64s,
exactly-n3. Its captured nested-loop failure is a genuine output mismatch,
not a solver deadline: identical loop bytes lower one TEST/JZ predicate as
AX==5 and the other from architectural FLAGS. Parent reduces it to two native
lifts: a prior image publishes CMP provenance at a branch successor, and an
unrelated image later has a Jcc at that same address. The lifter's executable
Jcc fallback consumes the address-only pending CMP metadata.

The independent predicate regression gives4 semantic failures/2 adjacent-CMP
passes in13.77s before the fix. Executable IR now consumes only actual adjacent
producer evidence or architectural FLAGS. The existing metadata-transfer control
remains; its separate direct-execution test now requires refusal of unbound
pending evidence. Six repeated-image/polarity controls, the strict nested-loop
positive, loop mutations, frontend condition and capture/transfer neighbors pass
together:92 passed in43.64s, exactly-n3. Scoped Ruff and changed-lifter Pyright
pass. The dirty lifter/test baselines and exact delta are retained under
order-diagnostic/pending-cmp-baseline/. The first test-construction attempt used
unmaterialized expected terms and failed at the test boundary; only the corrected
4-failure/2-pass cohort establishes semantic red evidence.

This closes the bounded root-cause investigation, not a subsequent broad gate,
tail-validation or original M0-M7 acceptance. The17 diagnostic failures include
ten TidShowRange cases absent from the earlier eight-failure gate. All ten fail
before their behavioral oracle executes: AddressSanitizer cannot reserve shadow
memory and explicitly reports an address-space-limit failure. The origin of
that inherited limit is not yet verified; those runs grant neither positive nor
mutation-rejection evidence. The180s static Devin collection audit also
times out124 without a report or patch and grants no acceptance evidence.

Follow-up native truth check exposes a separate full-state false proof: CMP AX,5
versus CMP BX,7, each followed by a Jcc with coincident successors, compares
`passed` while an independent guest produces FLAGS0x46 versus0x97. The lifter
suppresses CMP's status write solely because a direct Jcc follows. Parent records
ten expected semantic failures across word-immediate, register, stack-memory,
absolute-memory and byte-immediate forms and both branch polarities (10.74s,
-n3). All four simple-CMP paths now publish the shared Eflags owner's effect;
direct predicate metadata does not establish that FLAGS are dead. Existing
liveness controls retain elimination of earlier overwritten writes while
requiring the final CMP write at the actual block cutpoint.

The branch-only quality-dev run is deliberately stopped143 after its296
repository-contract passes and before a complete broad result. This avoids
continuing a checkpoint with a now-known false proof; no partial broad count is
reported as a gate result. Combined corrected-source focused checks are running.
The first CMP test attempt referenced a nonexistent enum member and is not
semantic red evidence. After correcting the oracle, an isolated pytest plugin
reexecutes only the saved dirty lifter and registers it as the sole real16
backend inside each clean worker: all10 cases fail because the actual verdict
is PROVED instead of COUNTEREXAMPLE. No shared source is restored or reset.
Final combined checks pass119 tests in26.25s, exactly-n3; Ruff and changed-lifter
Pyright pass. The strict nested positive and retained adjacent-CMP/earlier-dead
flag controls pass. No performance gain is inferred from differing cohorts.
The combined-source quality-dev checkpoint is starting; subsequent gates and
full original acceptance remain pending.

### Address-coordinate and launch-scope intake (2026-09-30)

Completed bounded parent/agent read-only review: existing code-prefix fetch
geometry, source-bound original-operand scope and raw physical-access bounds
do not alone discharge ADDRESS_MODEL. The missing obligation is architectural
control-coordinate correspondence at each request head and BRANCH/CALL/RET
successor, including near-word wrap. The authoritative frontend coordinate
owner supplies CS-relative offset and loaded continuation projections; a new
certificate must consume those contracts and the immutable native/control/frame
receipts, rather than treating modeled target membership as architectural proof.
ADDRESS_MODEL remains open. A bounded ignored native probe is pending; no new
production theorem or original milestone is accepted by this review.

Parent startup probes from angr_platforms/ establish a launch-policy difference:
Python -c with repository-root PYTHONPATH imports sitecustomize.py and applies
hard/soft RLIMIT_AS6442450944; without that PYTHONPATH, sitecustomize is absent
and both limits are unlimited. The current Make gate's three workers also have
unlimited address space. This is a verified mechanism capable of preventing
ASan's roughly14TiB virtual shadow reservation; the earlier diagnostic's exact
environment still needs confirmation before causal attribution. Sanitizers,
resource policy and oracle expectations are unchanged. A sandboxed150s Devin
intake owns only an ignored report. The combined-source quality-dev gate remains
running with exactly three pytest workers; its terminal result is pending.

The parent independently reproduces a native coordinate mismatch from ignored
probe bytes eb1e at CS:IP1234:fff0: Unicorn JMP rel8 reaches1234:0010
(loaded0x12350), while current lifted control_ip resolves to0x2350. This is
concrete frontend control evidence, not a whole-function comparator result.
A shared coordinate-helper correction is staged outside production while the
gate runs. Its focused regression and final integration are still pending.
Source-snapshot verification finds two concurrent changes since gate start:
alias/segment_stack_restore.py and scripts/test_pipeline.py. Retain the terminal
gate receipt, but do not describe it as fixed-source final acceptance. The150s
Devin launch intake exits124 without a report; no review evidence is accepted.

The combined-source quality-dev gate is terminal2: repository contracts296
passed18.16s; broad cohort8370 passed/32 failed/1 skipped1181.76s, exactly-n3.
The prior nested-call-loop failure is absent from this terminal failure list.
Two public register-loop UNKNOWNs and one CFG status-flag liveness expectation
are prioritized for focused intake; the other failures are not collectively
classified. Later Make stages do not run. Final hash check records additional
concurrent IR vex_control_flow.py/vex_import.py changes, alongside the earlier
stack-restore and pipeline changes. This result is not fixed-source acceptance.
The first wrap/control and public-loop focused intake is starting after the
broad pool has exited; no overlapping pytest pool is launched.

Focused intake is terminal:10 failed/8 passed31.93s. All five public register
controls pass, so their two broad UNKNOWNs remain unclassified; nine independent
native near-control cases reproduce the wrap/high-address mismatch. The remaining
failure is an obsolete CFG-liveness expectation: the block contains two CMPs,
and only the first overwritten write is a DCE candidate. The expectation now
requires one surviving final CMP FLAGS write while retaining the exact first
candidate/materialization ledger. This preserves the corrected full-state
cutpoint behavior rather than suppressing flags again. Neighboring final
flag-context/liveness, public register and call-loop cohort passes77 tests44.52s,
exactly-n3. Changed-file lint/type/startup/ownership checks and26 owned tests
pass30.76s, also-n3. Public register tests now
save the complete serialized report for any UNKNOWN result so a later broad
failure retains its typed refusal and provenance. Expectations remain strict.

The proposed relative-coordinate helper is not integrated into native lowering.
Its symbolic result would also require direct-call/dispatch consumers to prove
targets under their existing domain, rather than requiring literal control.
Integrate the missing coordinate theorem first for the existing fixed-CS recursive
domain, keeping wrap/model mismatches refused. Do not trade direct-call capability
for a standalone arithmetic patch or announce a frontend repair from staging.

### Native control-coordinate prerequisite (2026-09-30)

Parent promoted the reviewed local native-control primitive and a source-bound
connector. Recursive induction now requires every manifest block's full loaded
control target to match its architectural near16 target before consuming
entry/frame/dispatch evidence. Fixed-CS WORD wrapping is explicit; RET uses the
actual pre-terminal SS:SP word. Bootstrap uses the loader's concrete16 CS and
imposes no invented stack alignment. Missing/stale manifests, wrong heads,
unsupported terminal widths, countermodels and expired deadlines refuse.
The connector reuses the complete prefix/source consumer before and after work;
it does not create a second source/domain authority or replenish time.

Independent native controls retain3 low-address positives and9 wrap/high-address
countermodels. Eleven bootstrap/RET/refusal controls include an odd-SP bootstrap
positive. The production gate prevents false promotion; it does not repair the
frontend coordinate mismatch. Existing literal direct-call consumers and the
staged symbolic helper remain unchanged. ADDRESS_MODEL, FAULT_DOMAIN and
ENVIRONMENT remain open; local joint acceptance is still CONDITIONAL.

Focused red: actual-MZ joint regression fails without the mandatory control
receipt (1 failed24.54s). Final combined focused cohort:43 passed44.89s, exactly
-n3, including actual-MZ composition and a refused control child stopping
induction. Scoped check-files passes98 tests32.83s with configured lint/MyPy/
type/startup/ownership checks; final changed-owner Pyright reports0 errors.
Controller mocks were updated to represent the new prerequisite, without
weakening production refusal or expected ledgers. An earlier run during parent
source edits is invalid as final evidence. A subsequent11pass/1UNKNOWN run
coincided with other frontend changes; its cause remains unclassified. The
isolated MZ positive passes1 in29.95s. No broad fixed-source acceptance follows.

A90s repository-sandboxed Devin read-only review exits124 without a report or
patch. No review claim is accepted. Source identities retain fresh reads at
independent boundaries. Routine default/expanded binary lanes now enroll the
new controls. No original M0-M7 milestone is fully promoted by this checkpoint.

### Symbolic control consumer prerequisite (2026-09-30)

The actual frontend near16 EB/E8/E9 candidate was independently reproduced:
full loaded native targets improve3/12 to12/12, saved CALL words remain4/4,
and the candidate executes exactly12 times. It is still staged: conditional
transfers, operand widths, branch consumers and recursive domain/dispatch
admission must remain coherent before frontend integration.

Production `real16_control_resolution.py` proves a proposed full32 target over
every CS alias admitted by the existing architectural entry domain.
`checked_call_site` consumes it only with the existing composition session;
`compose_call_poststate` supplies that session. It never assumes nominal CS or
compares only the low word. Target metadata supplies a proposal, never proof.
Wrong targets, alias-dependent wrap, narrow control, missing budgets, unknown
and solver completion after the original deadline refuse. A backward target
whose function entry moves above it exposes a real alias-dependent wrap and
is deliberately refused. New controls are enrolled in routine binary lanes
and ownership, with the proof owner in configured typing and lint scopes.

Initial focused regression6failed/1passed0.87s. Final scoped check-files passes
327 tests47.22s, three workers, including additional boundary controls and
configured lint/type/startup/ownership checks.
Changed proof/call owners pass Pyright with0 errors. Original M0-M7 milestones
remain open; this local prerequisite is not binary equivalence acceptance.

After adding refusal of negative/over-DWORD metadata targets, the final
selected-owner check-files cohort passes273 tests54.23s with three workers;
Pyright remains0 errors. Parent also reproduces36/36 staged conditional/
operand32 full loaded controls and4/4 CALL32 saved words. Full architectural
EIP and condition-target metadata need review; the frontend remains unchanged.

The expanded staged oracle is now independently reproduced after worker
completion:38/38 full loaded controls,38/38 full architectural EIP projections
(including EIP0x10020),5/5 CALL32 saved words. All deliberately corrupt targets
and saved words are refuted. Baseline17/38 is the worker's saved-source result.
Candidate execution counters identify12 simple,16 LOOP/JCXZ and10 operand32
roots. The integration blocker is explicit: symbolic Jcc destinations leave
`ConditionIR.taken_target=None`. Next preserve binary-derived relative-target
evidence in typed condition/CFG consumers and discharge dispatch under the
established domain before enabling the lifter patch. No frontend capability
loss or missing target metadata is accepted as parity.

### Exact symbolic acyclic successors (2026-09-30)

Parent red controls expose both absent symbolic-edge composition and a false
literal acceptance: a declared successor0x10210 aliases0x210 through the
legacy word-wrapped delta helper. Acyclic composition now consumes the same
exact loaded-successor intake as matched induction. Each symbolic ITE arm must
prove one declared full32 destination under every entry CS alias and the
unchanged session deadline. Both arms and full machine state survive merging;
an opaque arm cannot disappear even behind a constant predicate. Alias-dependent
wrap, distant metadata, narrow control and expired time remain explicit refusals.

Initial red5failed/2passed1.11s; separate narrow-control red1failed/7passed2.05s.
Scoped336passed46.47s predates the final width guard; final scoped check-files
passes337 tests54.99s, three workers, with configured lint/type/startup/ownership
checks. Changed owners pass Pyright with0 errors. New tests are enrolled in
routine binary lanes and ownership. These
are comparator-consumer prerequisites, not original M0-M7 acceptance.

A bounded Devin staging job is live for the source-bound decoded-relative-edge
contract. Its sandbox was reverified rootRO/repositoryRW/4GiB. Ownership is
ignored staging files only; parent owns production integration and acceptance.

### Source-bound relative edges and coherent condition identity (2026-09-30)

The bounded Devin staging job terminates0. Its exact-byte decoder was reviewed
and promoted as frontend `relative_control_edge.py`; projection arithmetic is
centralized in `control_coordinates.py`. Complete binary bytes determine typed
form, operand width and signed displacement. Unsupported/truncated/prefixed
forms retain typed refusals. Parent also rejects coordinate coercion and forged
fields. Source labels are provenance only. Native control proof intake consumes
the shared decoder while retaining its existing near16 refusal scope.

ConditionIR and its builders can retain the immutable raw edge when loaded
CFG targets remain unresolved. Sort/dedup identity includes exact head, bytes
and source identity. No nominal CS or guessed physical page fills the targets.
Initial storage regression3failed/34passed9.40s; isolated37passed10.53s.
Scoped check-files1958passed284.12s, three workers, with configured lint/type/
startup/ownership checks; changed-owner Pyright0 errors. One preceding combined
worker exit during a Unicorn case remains unclassified.

A further Alias regression shows that one-block condition selection ignored
different raw edges and silently selected one (1failed16.55s). Its ambiguity
identity now includes the retained edge; final scoped checks pass38 tests9.37s
with three workers, configured lint/type/startup/ownership gates and Pyright0 errors.
The relative-edge tests are enrolled in routine binary lanes and ownership.
Frontend producers/CFG binding and the default native-control patch remain
open. Original M0-M7 acceptance remains unchanged.

The preceding broad quality-dev terminated2:296 contract passes, then
8406passed/35failed/1skipped808.08s, exactly three workers. Source drift
invalidates fixed-tree acceptance; three public controls report source change
during lowering. One owned inventory mismatch was corrected and61 focused
checks pass13.78s. The remaining31 broad failures are unclassified.


### Structural joint-layout prerequisite (2026-09-30)

Extracted `derive_joint_frame_layout` in the admission owner: exact manifest,
full machine state, matched coordinates, declared edge metadata and declared
graph closure yield frame layout without claiming actual dispatch. The existing
`admit_joint_system` still resolves full control on both sides and rejects
unproved symbolic destinations. Real16 consumers retain strict admission until
a separately required domain-scoped dispatch certificate is integrated.

New controls reproduce2 failures9.53s before implementation. Final scoped
check-files passes100 tests44.85s with three workers and configured lint/type/
startup/ownership checks; changed-owner Pyright reports0 errors. Logs and saved
pre-edit production source are under `.cache/comparator-implementation/structural-admission/`.
This prerequisite leaves the domain/dispatch circularity in consumers open;
original M0-M7 acceptance and whole-binary equivalence remain unproved.


### Domain-scoped real16 dispatch checkpoint (2026-09-30)

Source/domain and frame consumers now derive structural layout without claiming
actual dispatch. The generic `admit_joint_system` remains strict. New
`real16_domain_dispatch.py` consumes current source/domain receipts before and
after checking both sides of every non-RETURN transition. Each cutpoint premise
must be SAT; full DWORD destinations must lie in the exact declared successor
set; every declared edge must be feasible. CALL has only the callee target.
Per-CALL saved continuations and RETURN closure remain mandatory frame facts.
The joint ledger requires the new complete dispatch child before lockstep
progress; missing, stale, infeasible, countermodel, UNKNOWN or expired children
retain the complete denominator. The new verifier and structural owner are
sealed transitively. Domain and layout ledgers explicitly claim structural
evidence rather than completed dispatch.

Initial unavailable-child collection refused; subsequent behavioral red
reproduced2 failed/2 passed21.93s at the old strict-domain admission dependency.
After integration, fixed-tree controls pass12 tests47.78s; independent frozen
integration controls pass21 tests52.91s. Final frozen check-files passes112
tests74.25s with exactly three workers, configured lint/type/startup/context/
ownership gates and no production typing skips. Changed-owner Pyright reports
0 errors. All8 changed owners/tests match the frozen acceptance sources.

The earlier live scoped run had106 passes/6 failures44.86s:3 model-change
refusals amid concurrent range-owner edits, and3 obsolete controller denominator
assertions (corrected). This is recorded rather than claimed green. The first
integration run also overlapped parent source edits; it is not acceptance.
Frozen gate setup initially lacked root/context/ownership support files; those
checks refused before pytest and the missing real support files were copied.
No shared source was reset or stashed.

A bounded Devin read-only review terminated0 in a verified rootRO/repositoryRW/
4GiB sandbox. Parent reviewed its exact dependency claims and updated controller
mocks, complete denominators and model seals. Source/domain receipt consumers
now intentionally establish prerequisites only; component progress separately
requires dispatch. Logs, dirty baselines, exact parent deltas, source hashes and
reviews are retained in `.cache/comparator-implementation/domain-dispatch/`.

The frontend remains unmodified by this checkpoint. Bounded source review finds
no proved selector-domain receipt in the inspected Jcc/LOOP frontend path; raw
relative-edge producers and proof-backed CFG binding remain next. Native repair
is still staged. The actual recursive component remains conditional on remaining
physical/fault/environment scope, and original M0-M7 acceptance remains open.


### Frontend relative-edge producer checkpoint (2026-09-30)

The frontend recording boundary now attaches exact decoded conditional bytes
before writing emulator and module condition caches. The focused IR provenance
owner is `ir/condition_relative_edge.py`; CMP, TEST-builder, consumed arithmetic
and plain LOOP routes share it. It retains head/encoding/form/displacement and
never fills unresolved loaded targets. Retained-edge source drift becomes a
typed ConditionFailure; unsupported encodings grant no raw-edge proof and keep
the existing guard. Cache test mocks now supply their missing instruction bytes
instead of widening production exception handling. Native control effects and
concrete CFG binding remain unchanged by this checkpoint.

Initial binary controls produce5 failures13.58s:4 reproduce missing raw edges,
while TEST AX,AX has no captured condition even before the patch. That existing
capture limitation is recorded, not fixed by this work. The TEST-builder route
is verified with native OR AX,AX; the saved dirty recording method independently
reproduces its absent raw edge in an isolated process. Intermediate scoped
check-files85passed10.30s; final changed-lifter/IR scoped gate426passed22.95s
with exactly3 workers, configured lint/type/startup/context/ownership checks and
changed-owner Pyright0 errors. Five binary producer controls retain closed
1/1/1/1/0 condition-capture counts. Unresolved-target, wrong-owner and source-
drift controls are included, and tests are enrolled in ownership/binary lanes.
Dirty source and exact parent delta/logs are under
`.cache/comparator-implementation/frontend-relative-producers/`.

The inspected frontend still lacks a validated selector-domain receipt at the
concrete CFG binding boundary. Proved binding, deferred taken-side cache
propagation, native default repair and final project/corpus gates remain open.
This records a producer prerequisite, not original M0-M7 or binary acceptance.

### Current frozen corpus checkpoint (2026-09-30)

The three-track public CLI corpus now has current results under
`.cache/comparator-implementation/corpus-current-20260930/`, with commands,
logs, reports and `current-results.json`. After execution all 1,144 frozen
source hashes and all 10 input hashes match their manifest. This snapshot
contains the dirty working sources; it is not a clean-HEAD baseline.

| Track/run | Current result | Observed elapsed time |
| --- | --- | --- |
| real16 self | 3 requested, 3 unresolved; paired-region admission refuses, with underlying unmapped call targets | Timing not recovered from this run |
| MSC8 self | 2 passed, exit 0 | 3.617 s |
| MSC8 changed | 1 refused lowering, 1 observable mismatch, exit 1 | 3.439 s |
| BC5 self cold | 15 refused, exit 2 | 7.045 s |
| BC5 changed | 15 refused, exit 2 | 6.002 s |
| BC5 self warm | 15 refused, exit 2 | 8.960 s |

BC5 exit 2 is a completed refusal result, not a CLI crash. Its existing
call-proof retry ran for every requested function. The self-cold nested call
reasons are five unresolved indirect targets, three indirect jumps, two edges
outside declared function ranges, and one each return-target timeout,
return-target mismatch, inline-depth limit, block limit and loop-induction
refusal. The generic public call-boundary reason must not be interpreted as
missing retry wiring. The next bounded BC5 diagnosis is the concrete return
mismatch in `sub_4023F4`; limits will not be raised without measurement.

MSC8's changed `sub_2B0D0` refuses an incomplete candidate block; call retry
also reports overlapping function ranges. `sub_319B0` supplies register,
stack and memory countermodels. Independent execution of that countermodel
is still pending, so this is a modeled mismatch rather than replay acceptance.
Real16 exposes an unmapped target `0x2222` for all three selected functions.
Independent byte decoding confirms CALLs at `0x176e` (`e8b10a`), `0x180e`
(`e8110a`) and `0x1f3e` (`e8e102`) really target that address. This corpus
refusal is missing callee catalog coverage; address truncation is not its
established cause. The separate WORD/full-control native defect remains staged.

One isolated BC5 return diagnostic reached the first call in `sub_4023F4`:
CALL at `0x402492`, bytes `e815edffff`, target `0x4011ac`, continuation
`0x402497`. The callee stores through pointers and ends with RET 4. Under
unconstrained memory those stores require proof that the return slot survives.
The diagnostic timed out after 1,024 ms rather than reproducing the earlier
mismatch; no independent countermodel was obtained. No implementation defect
or safe nonaliasing premise is established. Its artifacts are retained under
`bc5-return-diagnosis/`; all frozen source hashes still match afterward.

These single cold/warm observations establish no cache speedup; the warm
observation is slower. RSS records are cumulative child peaks, not per-job
measurements. Rebuilt real16/mutation runs, representative replay and final
project gates remain open. No original M0-M7 milestone is newly accepted.

### SCC admission and flat32 return evidence checkpoint (2026-09-30)

Parent reproduced four false call-cycle promotions against the saved dirty
SSA owner: conditional, unsupported, unmapped and unrecognized member statuses
all rolled up as `passed`. A conditional SCC summary also reported passed with
zero members in every status count. The new typed SCC admission owner requires
nonempty unconditional evidence, retains incomplete denominators and preserves
counterexample priority. Loop and call rollups consume that same owner. Six
nearby optional-value typing errors were removed without changing their reads.
Binary/source model seals already include every owned Python dependency, so
the new owner participates in invalidation.

A bounded Devin job terminated 0 after adding typed flat32 return-failure
evidence and three actual-byte RET 4 controls. Parent reviewed every delta
against the saved dirty sources and independently reproduced the baseline
failures in an isolated process. Return-slot corruption now retains the solver
countermodel, target/continuation and comparison origin without changing the
refusal. Parent corrected diagnostic address meaning: CALL's exact VEX IMark
and owning block are separate fields on both success and failure reports;
comparison side is an enum. Disjoint stores, observable store removal,
unconstrained aliasing, definite corruption and both comparison sides are
covered. Shared owners serve MSC8 and BC5. No premise, limit or verdict gate
was weakened.

Final focused regression: 44 passed, 3 warnings in 22.54 s, exactly three
workers. Ruff passes; new/changed typed flat32 and SCC owners have Pyright 0
errors. The explicit whole legacy SSA audit remains non-green: saved dirty
baseline 203 errors, final 197; no errors in the touched SCC functions.
Configured scoped lint/type, startup, context and ownership checks pass, with
their legacy-file exclusions retained visibly in logs.

The immutable broader checkpoint verified all 1,152 file hashes afterward.
Its regression is not green: 227 passed, 19 failed, 5 skipped, 3 warnings in
25.28 s with three workers. A bounded diagnostic independently reproduced all
19 assertions: 16 call-proof/target coverage failures, one lowering slice
budget refusal, one modeled caller mismatch, and one obsolete flag control.
The last used exact COPY carry semantics while expecting an uninterpreted
result; its control now uses an unsupported operation and separately verifies
exact COPY, and passes in the final focused run. Two earlier broad tests also
expected unproved cycles/indirect transfers to pass; their replacements assert
explicit refusal and absent semantic evidence. The remaining failures have
not been waived or collectively classified as unrelated debt. No current full
suite, project release gate or original M0-M7 acceptance is claimed.

Saved sources, exact parent/Devin deltas, red/green logs and diagnostic reports
are under `.cache/comparator-implementation/scc-status-admission/`,
`flat32-return-evidence/` and `return-and-scc-frozen/`. The frozen checkpoint
predates the corrected COPY test; its failed result is preserved unchanged.

Follow-up closed-counter publication: SCC summaries now publish the five typed
fact counters for every materialized component verdict, including refusals.
The final configured scoped gate passes 336 tests, 3 warnings in 68.72 s with
three workers, plus lint/type/startup/context/ownership checks. Changed typed
owners' final direct Pyright remains 0 errors. The broader failed snapshot
and the legacy typing debt above remain separate, unresolved evidence.

Independent native alias witness: Unicorn executes the RET 4 caller/callee
with a valid mapped stack and EAX pointing at its saved return slot. The clean
binary returns EAX=9; adding a pointer store changes the saved continuation to
`0x2a` and faults there. Repeated corrupted execution is deterministic. Memory
observations retain both saved values. Faulted replay remains incomplete,
never agreement/proof. The complete concrete-replay file passes 5 tests in
1.39 s with three workers; it is enrolled with the flat32 call owners. This
is a realizable corruption witness, not a replay claim for the corpus's
unreproduced BC5 countermodel.

### Batched callee-index proof regression (2026-09-30)

Current-tree focused reproduction confirms that the full-index fixture resolves
both direct callees, but supplies no discharged proof for their differing nested
CALL targets (`0x1515` and `0x3737`). Mapping, normalized instruction signatures
and matching synthetic SSA outputs cannot prove these missing effects. The test
now checks exact resolved identities, `callee_not_proven`, absent proof fact,
one pending callee proof, and refusal rather than expecting equivalence.
This preserves index-resolution coverage and strengthens its proof boundary;
it does not establish binary-backed positive call composition or waive the
remaining caller regressions. Red/diagnostic/green artifacts and the saved dirty
test baseline are under `.cache/comparator-implementation/flat32-return-evidence/`.
Original M0-M7 acceptance remains open.
Focused corrected index regression passes 1 test with exactly three workers;
Ruff passes for the test owner. An intermediate run retained a second obsolete
`equivalent=True` assertion and failed; that assertion now explicitly verifies
`False`. All logs are preserved. No broad gate result follows from this check.

### Complete shifted-callee public call controls (2026-09-30)

Parent current-tree real16 call matrix passes 84 tests in 41.73 s, exactly three
workers: public near calls, complete direct-call composition, far calls,
operand-size variants, and call-in-loop positives/mutations. This is current
focused evidence rather than full-project acceptance.

Read-only bounded agent audit groups the old caller failures by missing
callee effects, layout-dependent saved-return memory, and unproved stack-slot
relations. The branch-inverted relocated callee is a valid whole-caller positive:
its caller remains at the same address, with the same saved continuation.
The legacy stopped-at-CALL block comparison instead observes unequal internal
`ip`/`control_ip` destinations (`0x1210` versus `0x1230`); it has already retained
its region-equality callee fact. Parent independently verifies the public
complete-call path proves this binary pair without hiding those outputs.

Routine enrolled public controls now preserve that positive and reject a
changed BX constant in the relocated callee. Both require complete-call method,
two proved return targets and both dependency sides. The public file passes
5 tests in 22.90 s with three workers; Ruff passes. Diagnostic JSON and saved
dirty test source are under `flat32-return-evidence/`. Legacy block-call result
semantics and other unresolved broad regressions remain open; no wholesale
conversion of positives to refusal and no milestone promotion is claimed.
The final public-control `make check-files` gate passes: 5 tests in 32.64 s,
three workers, configured Ruff, startup architecture, context and ownership
checks. The test-only owner remains outside promoted MyPy scope, as explicitly
reported by the gate. No production type claim or project release follows.
Current flat32 call matrix independently passes19 tests in14.06s with exactly
three workers, including nested chains, conditional calls, changed cleanup,
return-target corruption and alias refusals. This validates shared synthetic
composition controls, not the still-refused representative BC5 sample.
The shifted-callee public controls also gain independent Unicorn replay of both
AX branch classes. Native observations require BX=0x1111 for AX=1 and BX=0x2222
otherwise, restored SP=0x1000, architectural continuation IP=0x203, and the same
saved-return word0x203 in live stack memory. This is bounded execution evidence;
the public symbolic proof supplies the separate all-input obligation. Final
test-owner hashes are in `call-controls-final-source-hashes.json`.
Final shifted-callee gate after native controls passes7 tests in23.96s with
three workers and configured lint/startup/context/ownership checks. Both test
owner hashes match the saved receipts after completion.

Bounded helper closure audit is in `real16-helper-closure-audit.md`. Parent
independently verifies the exact23 bytes and full instruction decode of helper
`[0x2222,0x2239)`. The successful arm ends POP-derived JMP CX after changing SP;
two guard failure edges reach0x2233, then tail0x2062. That tail includes further
calls, indirect targets and DOS interrupts. No nominal stack assumption removes
these edges. The catalog lacks helper/tail entries; extending it alone does not
prove helper return or environment closure. Next retain exact helper blocks and
both guards, then discharge source-bound domain/frame/control obligations or
model the fallback closure. Historical reports can refuse earlier at an unrelated
trap, so this byte audit does not claim a new current corpus result.

### Reviewed signature controls and actual helper replay (2026-09-30)

Bounded Devin job terminates0 in a freshly verified hostRO/repositoryRW/4GiB
sandbox. Parent independently compares its delta against saved dirty sources:
only the four owned test functions changed. Alias resolution and signature
trim/hash discovery assertions remain; no callee proof fact or pass is admitted
from names, mappings, masked immediates, an indirect-jump prefix, or INT16 bytes.
The signature body with INT16 currently refuses at missing correspondence/proof,
not at an explicit environment-effect verifier. Parent corrects that distinction
and renames the immediate-corruption test to describe refusal.

Parent saved-source red reproduces4 failures in9.94s, three workers. Final
combined discovery/refusal, complete-call positive/corruption and native replay
controls pass9 tests in20.35s, three workers. Configured lint/ownership passes;
legacy test exclusions remain visible, and direct Ruff checks both test owners.
No production source or proof gate was weakened. Logs, exact parent/Devin deltas
and final test hashes are under `call-signature-review/`. Remaining old caller
regressions are not waived; whole-project gates remain open.

Actual immutable corpus helper intake is under `real16-helper-intake/`:
a separate exact-byte catalog proposal, lowered document and composed refusal.
Parent verifies all four helper cutpoints0x2222/0x2229/0x222f/0x2233, both guard
arms and indirect-successor metadata. Dynamic lowering also follows external
failure-tail bytes outside its declared23-byte body; composition refuses
`function_range_incomplete` (recorded delta65088). This isolated proposal does
not modify the frozen corpus catalog and cannot prove the selected caller.

Production replay independently executes the actual MZ helper bytes for five
explicit initialized vectors. Three successful inputs agree with deterministic
self replay and reject changing `mov sp,bx` into `mov sp,ax`; two inputs reach
external tail0x2062 and remain INCOMPLETE, including self comparison. Registers,
stack/guard-memory observations, writes, typed events and image/relocation hashes
are retained. Every original run repeats identically; source bytes remain
unchanged. Caller frame is synthetic, with external trapCS:IP=0100:E000,
DS=5000 and SS=6000; it is not an initialized whole-program execution or replay
of a corpus solver countermodel. The backend rejects a trap overlapping loaded
image bytes, so the original in-image continuation was not used as its trap.
No concrete agreement changes symbolic proof status. M6 whole-program/service
coverage and all original milestone acceptance remain open.

### Actual stack-array call controls (2026-09-30)

Fresh dosunit module baseline:197passed/13failed in33.16s with3workers.
Three failures used fabricated scalar memory outputs or treated BP/SP offsets
-6 and -4 as equal without a frame relation. These controls now lower actual MZ
CALL callers with full internal state and real array memory, then compose their
complete RET callee. Equivalent BP-4 disp8+NOP and disp16 encodings keep CALL
and saved continuation at the same coordinates; changed store values remain
observable. Both actual return targets and dependency sides must be proved.
The positive proves; both mutations yield `memory_expr_changed` with models.

Initial converted run has1pass/2fail because two assertions still requested
scalar-output diagnostics. Those now explicitly require array-memory mismatch.
Final focused3pass in20.60s with3workers; direct Ruff passes. Tests are renamed
to describe complete-call comparison. Exact saved dirty sources and logs are
under `call-memory-controls/`. This replaces unsound synthetic expectations
with binary positives/corruptions rather than weakening a proof gate. Remaining
legacy regressions and release acceptance remain open.
Production replay independently executes complete initialized callers for the
actual stack controls. Equivalent disp8/disp16 binaries agree; a changed stored
word mismatches. All three images repeat deterministically, preserve BP=0x1234,
return with SP=0x1000, and retain the declared stack bytes including the store,
callee saved continuation and root frame. File/image/relocation hashes and
registers, memory writes and outcomes are in `call-memory-controls/native-results.json`.
The explicit external root trap and selectors describe one admitted test vector;
this is separate from all-input symbolic proof and corpus countermodel replay.

### Call-bound control-output normalization and selector-domain review (2026-09-30)

Caller proven equivalent via a shifted/mapped callee still failed on raw
``ip``/``control_ip`` outputs holding absolute call targets (oracle 0x1210 vs
candidate 0x1230) although the callee discharged through ``region_equal``.
Production fix in ``tools/dosunit/straightline_ssa.py``: new
``_with_call_bound_control_outputs`` evaluates only ``ip``/``control_ip``
output terms through the existing call-return term evaluator and rewrites a
term to the same semantic callee-proof token used for ``call_target`` when it
matches the call destination in the appropriate architectural domain. DWORD
outputs require an exact physical target (raw target or resolved linear entry).
Only WORD ``ip`` permits the logical entry IP or physical low-word projection;
narrow ``control_ip`` does not establish a physical-target correspondence.
Unrelated control values and fallthrough continuations stay observable;
applied bindings are recorded under ``call_compare["normalizations"]``.
Requires an already proven-equivalent callee; no mapping or signature
correspondence is promoted to proof. Focused result: the shifted-call and
mapped-direct-call controls prove end to end (the mapped-direct fixture runs
with ``max_solver_inputs=0`` since its 25-input lifted block is not the
solver-gate subject); full ``test_dosunit_tool.py`` is 210 passed, 0 failed.
Scoped comparator cohorts re-verified green. Remaining legacy caller
refusals are preserved, not waived; original M0-M7 acceptance stays open.

Parent domain review reproduced three false bindings against the saved dirty
baseline: a logical low-word collision cannot prove an equal full physical
destination. Six domain controls cover exact DWORD destinations, unrelated
physical targets, logical WORD IP and narrow physical-control refusal. An
intermediate shared-tree edit left ``logical_ip`` undefined (6 failed/15 passed);
the parent corrected the live setup to separate logical IP from the typed set
of physical targets. Final symbolic-control module:21 passed in1.99s. Current
dosunit/public-call/symbolic-control cohort:235 passed,5 skipped in21.24s, all
with exactly3workers. The skips require KVM; they supply no execution acceptance.
Direct shared-config Ruff passes for the production owner and control tests.
These are current focused results, not final project gates or a frozen corpus
acceptance. Concurrent edits in this shared tree remain separately attributable.

Parent review of the staged near-return candidate builder
(``.cache/devin-staging/near-return-ast-20260930/``) found its selector
evidence walk over-admitted three C-promotion-unsafe forms: ``Mul`` of two
unsigned-word operands (0xFFFF*0xFFFF overflows host int32 signed ``int``
promotion), ``Neg`` of a signed i16 operand (-(-32768) is UB on DOS int16),
and ``Shl`` of a u8-typed left operand (promotes to signed int16 on DOS where
255<<15 overflows). The staged module now refuses ``Mul`` entirely, admits
``Neg`` only on provably unsigned-word operands, and admits ``Shl`` only when
the left operand carries an exact ``uint16_t`` declared type plus a proven
literal count below 16. All 55 focused staged and parent controls pass;
Ruff and Pyright report zero findings on the staged module. The builder
remains staged and unpublished: pointer/segment/native representation,
prototype integration, body census, replay, and tail validation are still
owed before any production claim.

Current configured owner gate after the control-domain correction:
`make check-files` for straightline_ssa.py and symbolic-call-control tests,
exactly3pytest workers, is terminal with327passed/2failed in92.31s. Startup,
context and ownership checks pass; configured MyPy skips these legacy files.
Failures are the equivalent near32 public operand-call case and the equivalent
NOP/INC-BX/RET public call-loop induction case: both return UNKNOWN instead of
PROVED. Their cause is not yet classified. This contradicts accepting the
current owner gate and takes priority over uncatalogued-leaf implementation.
Preserve the domain safety regression; investigate exact refusal obligations
and architectural target projections before changing any normalization rule.

Public-refusal follow-up (2026-09-30): both previous failing cases prove in
fresh production diagnostic processes; operand-call plus loop-call modules
pass46/20.09s with3workers. The same configured owner gate, rerun with an
ignored failure-report capture plugin, passes329/58.05s with3workers; startup,
context and ownership pass. No production source was changed between the red
gate and these diagnostic runs. Therefore the earlier two refusals remain an
unclassified intermittent/shared-state or resource condition, not a verified
fixed regression. Fresh reports and capture tooling are retained under
`.cache/comparator-implementation/public-refusal-review/`. This green scoped
run supplies current gate evidence but cannot erase the contradictory earlier
result or establish deterministic corpus/release acceptance. Exact refusals
must be captured if the condition recurs; do not weaken UNKNOWN or target-domain
checks to force these positives.

### MSC8 sub_319B0 countermodel replay + signature-chain cleanup (2026-09-30)

The frozen MSC8 changed-run ``observable_mismatch`` on ``sub_319B0`` was
previously a modeled counterexample without independent execution. The
comparator run was regenerated under ``.cache/sub319b0-changed/``; its solver
countermodel (eax=0x7ffbbfba, ebx=0x100) was then replayed concretely through
``tools/dosunit/flat32_replay.py`` on the exact extracted bytes — oracle 17
bytes at 0x319B0 (``mov ax,[esp+4]; and ax,0x8000; cmp ax,1; sbb eax,eax;
inc eax; ret``) versus candidate 21 bytes at 0x2B720 (``or [eax+1],bh; pop
esi; pop ebx; ret`` plus trailing fragments). Both runs RETURNED and
``compare_replays`` reports ``mismatched``: oracle eax=0/ebx=0x100/esp+4/no
writes, candidate eax=0x7ffbbfba/ebx=0/esp+12/write 0x01 at 0x7ffbbfbb —
matching every modeled difference. The verdict is a real behavioral
difference between the catalogued bodies, not a model artifact. Artifacts
under ``msc8-sub319b0-replay/``. This is replay evidence for one input
vector; it does not prove which catalog bound is authoritative and does not
change milestone status.

Dead-code cleanup in ``straightline_ssa.py``: the mapped layout-signature
equivalence reason was computed and threaded through
``_mapped_call_target_verdict``/``_unmapped_call_target_verdict`` /
``_call_target_verdict`` but never consumed after the signature-discharge
removal; the ``prefer_semantic_reason`` flag compared against a reason
string that no producer can emit. The parameter threading, the stale
comparison, and ``_call_target_layout_signature_equivalence_reason`` are
removed; signature/layout evidence remains attached to resolved targets as
discovery metadata only. Full ``test_dosunit_tool.py`` re-verified 210
passed, Ruff clean, Pyright count unchanged (197 pre-existing).

### Source-bound omitted-leaf intake in progress (2026-09-30)

Parent public binary regression now supplies exact near CALL/RET MZ callers
at0200 with fixed saved continuation0203 and omitted leaf targets0230/0260.
Equivalent MOV-AX/RET relocation must prove; changed AX and TEST-AX flag effects
must expose counterexamples. Independent initialized replay completes both
callers and agrees only for the equivalent pair; both corruptions mismatch.
Current symbolic route refuses all3 public controls (3failed/10.29s,-n3),
so these tests remain explicit unfinished acceptance work. Exact red log and
pre-run sources are saved under binary-leaf-intake/.
A bounded Devin batch owns only new binary_callee_intake.py and its focused
unit test, while parent owns public integration and acceptance controls.
Outer Bubblewrap verified rootRO/repoRW and4GiB before launch; session51730.
Intake must derive a unique full target from actual CALL bytes, prove terminal
near-RET body closure, retain full-state effects/source receipts and recheck
freshness. Signature/low16 lookup cannot supply semantic proof. Existing
saved-return/CS proof remains mandatory. No accepted capability is claimed yet.
Omitted-leaf parent refusal baselines:5 passed/23.84s (branch, nested CALL,
INT, far RET and potential saved-return aliasing store) and1 passed/17.18s
(physical low-word collision), each with exactly3workers. Collision image
places matching MOV-AX/RET bytes64KiB away from the actual near CALL target,
whose body loops forever. No low-word/signature redirection may discharge it.
The worker lifting probe confirms target.raw can be truncated16bit, far RET
shares Ijk_Ret and IN may still end in Ijk_Ret: receipts must check decoded
architectural target/return form and full typed effects, not jumpkind alone.
Implementation and public positive/counterexample controls remain pending.

### Decoded port-event admission (2026-09-30)

Parent independently reproduced a public false proof for actual MZ
IN-AL-immediate/RET code at an unregistered port: the lifter substitutes a
constant and leaves no Dirty or SSA port operator. Six public byte/word/dword
immediate IN/OUT controls reproduce3failed/3passed in19.19s with3workers;
all three reads were incorrectly PROVED under the environment-free contract.
`binary_environment` now additionally decodes original block bytes using
Capstone instruction IDs in the actual16/32/64 mode. Immediate, DX and string
IN/OUT (including width/repeat prefixes) require an environment contract;
port-looking immediate data in MOV does not. Missing/truncated bytes,
incomplete decoding or unsupported mode supply incomplete evidence, not
absence of events. Original Dirty and structured SSA checks remain intact.
This is an admission refusal, not a fabricated port/environment semantics model.

Initial corrected focused cohort21passed/26.50s; expanded decoder/public
cohort51passed/50.08s. A typed optional-byte boundary then adds explicit
incomplete evidence for missing Block.bytes, covered by three boundary controls.
Final configured owner gate95passed/39.52s with exactly3workers, including the
flat32 comparator lane, replay and conditional boundaries. Shared-config Ruff,
MyPy/type-ratchet/startup/context/ownership checks pass; separate changed-owner
Pyright has0errors. Existing unit/public files are already in routine default
and expanded lanes and ownership mapping. Pre-edit production/public sources
and exact logs are in `.cache/comparator-implementation/decoded-port-admission/`.
This closes the demonstrated folded-port admission hole; explicit environment
relations, initialized program/services, corpus and release acceptance remain
open. Omitted-leaf intake is still independently pending Devin review.

Parent diagnosis of the new public real16 call-obligation failures (all
``status=unknown``): ``binary_environment._scan_block`` decodes bytes with
``mode_bits=project.arch.bits``, but the ``86_16`` lifter arch reports
``bits=32``, so a 16-bit ``mov dx,imm16`` (``ba0100``) decodes as
``mov edx,imm32`` and overruns the block; ``decoded_port_effects`` returns
None, the scan stays ``complete=False``, and every obligation reports
``external_environment_contract_required`` even though the backend SSA
compare itself passes ``binary_equal``. Owner is the active
binary-leaf-intake slice; the fix is to derive the decoder mode from the
16-bit lowering context, not the arch word size. Recorded for handoff; the
module is in flight.

### Reviewed omitted-leaf public integration (2026-09-30)

Devin's bounded intake job is terminal and its owned delta has been reviewed.
Parent integration discovers missing direct-call near-RET leaf bodies before
provenance sealing, with a 16-request/60-second budget and explicit refusal
receipts. Receipts bind exact decoded bytes, loaded image, model/packages,
selector domain and shared evidence counters; publication rechecks identity.
Existing full-state call/return and fetched-code proofs remain mandatory.
The decoder now uses ISA mode16 for the 86_16 architecture despite its32-bit
VEX storage width. Candidate caller mappings select discovery work only.

Focused red controls exposed missing VEX evidence and stale receipt identity
(5 failures before correction), and mapped caller discovery (1 failure before
correction). Final public controls pass12/21.64s with3workers, including omitted
leaf relocation, loop composition, mapped callers, AX/flag counterexamples and
branch/nested-call/interrupt/far-return/store-alias/DIV/64KiB collision refusals.
The saved final test log records538passes/122.44s with3workers; its Make FILES
argument was empty, so it is not evidence of explicit changed-owner lint scope.
A corrected explicit-five-owner check is running in explicit-owner-gate.log.
That corrected check is now terminal exit0:538passes/240.40s with3workers;
explicit selected-owner Ruff/MyPy/type ratchet and startup/context/ownership
checks pass. Whole quality-dev remains a separate required checkpoint.
Separate changed-owner Pyright reports0errors. Artifacts and saved worker delta
remain under .cache/comparator-implementation/binary-leaf-intake/.
This is bounded real16 intake, not flat32 intake or initialized whole-program
acceptance. Original M0-M7 corpus, environment/fault and release exits remain open.

Whole quality-dev stops before tests at4MyPy errors in the near-pointer argument
owner: exact-class identity does not narrow its object annotation. A guarded
third-party AST cast preserves exact-class and receipt semantics. Before-edit
focused tests17pass/16.11s; scoped typing reproduces4errors. After-edit owner
check52pass/11.58s with3workers and scoped lint/type/startup/ownership checks.
Saved source and logs are under binary-leaf-intake/near-pointer-baseline and
near-pointer-*.log. quality-dev-retry.log is running; no broad acceptance yet.
A report-only bounded Devin audit now examines the initialized-MZ/DOS-termination
integration seam (dos-environment-audit/), with no source ownership or tests.

Current-source real16 frozen-corpus self refresh is terminal exit1/statusUNKNOWN:
SwapBars/InsertionSort/Sleep remain unproved. On each side discovery attempts15
omitted bodies, refuses6alternate-exit bodies and9nested-call bodies, and
publishes no guessed parts. Current leaf intake improves the public controls but
does not close these representative callers. The original2000ms solver/15000ms
function/1000ms lift budgets are retained. Exact report/log:
binary-leaf-intake/corpus-real16-self.json and corpus-real16-self.log. This is a
current source diagnostic, not a new frozen-source cold/warm acceptance run.

The report-only Devin audit is terminal exit0. Parent verified the key seams:
MzExe retains header entry/stack but Real16Image drops them; guest setup always
installs a CallerFrame; replay refuses software interrupts before execution.
Microsoft's MS-DOS4 Programmer's Reference confirms EXE DS/ES point to PSP,
CS:IP/SS:SP derive from executable load state, and INT21/AH4C terminates with
AL as exit code and does not return to the program:
https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/ .
Next integration must use a distinct initialized-program contract without a
synthetic return frame. Explicit initial state and admitted services remain
part of the declared execution environment; termination is not function return.
The audit's suggested RET-versus-termination mismatch is not accepted as written:
without a caller frame, RET has no established complete return outcome. Budget,
unknown services and undeclared accesses stay incomplete/refused. No initialized
program capability has been implemented by this diagnostic alone.
quality-dev retry has passed its296-test preliminary contract cohort/19.04s;
the full fast pipeline is active separately and has no final verdict yet.

### Initialized MZ program termination lane (2026-09-30)

The preceding quality-dev retry is terminal exit2:296preliminary contract
passes/19.04s, then8682passes/31failures/1skip in1139.82s. This remains a failed
project gate. One demonstrated enrollment failure was an exact expected-set
assertion missing the3new leaf-intake targets; the expected inventory now
includes them and the2actual initialized-program targets without weakening
the equality assertion. Other failures are not collectively classified as debt.

Bounded Devin boot-owner job is terminal exit0, limited to2new owned files.
Parent read the complete source/tests and retained its exact final delta under
real16-program-start/worker-final/. The boot owner derives image placement at
PSP+16 paragraphs, header entry/stack, allocation bounds and file/image/header/
initial-environment identity from actual MZ bytes. The environment declares every
pre-load allocation byte and integer register; no zero-fill, PSP field or return
frame is guessed. Header SP0 remains distinct from function-frame restrictions.

Parent implemented separate process statuses, named output denominator, fresh
guest initialization, typed DOS INT21/AH4C exit, fault/budget/environment refusals,
checked manifest, snapshot-bound report and public dosunit/z3func command
`replay-program16`. Exact allocation hooks prevent page padding from supplying
undeclared memory; shared decoded port admission retains all port forms.
Output projections never change guest execution. Equal exit/events and all
declared outputs can agree on the tested state; internal registers/writes remain
captured diagnostics. Termination vs captured CPU fault mismatches, while equal
faults, bare RET, unknown services and exhausted executions remain incomplete.
Symbolic proof status stays `not_established_by_execution`.

Initial parent draft controls expose4failures/57passes/4.53s at ordinary POP-DS
admission. The attempted frozen-source test invocation actually loaded current
owners, so red-baseline.log is draft-red evidence, not old-source isolation.
Shared real16 instruction admission now accepts typed MOV/PUSH/POP segment
transfers, retaining control/debug-register and other privilege refusals.
After correction90passes/11.16s; final public/old-replay/enrollment controls
92passes/8.65s. Final explicit9-owner gate exit0:292passes/38.46s,-n3, with
selected Ruff/MyPy/type/startup/context/ownership checks. Separate new-owner
Pyright0errors. Worker direct test exercise was only smoke evidence; parent
pytest and owner gates supply the acceptance evidence recorded here.
The dispatcher tools/dosunit/dosunit.py remains legacy-skipped by configured
Ruff/MyPy selection; its registration is covered by the public command tests
and changed-file type ratchet, not a claimed full dispatcher lint promotion.

Actual public shell runs return0/AGREED for equivalent changed instructions and
1/MISMATCHED for changed DOS exit code, with immutable input and boot identities
in public-smoke/*-report.json. Full artifacts/logs:
`.cache/comparator-implementation/real16-program-start/`.
Documentation/schema/scope: reference/real16-program-execution.md; command:
`PYTHON_JIT=1 .venv/bin/python dosunit.py replay-program16 --oracle-exe original.exe --candidate-exe changed.exe --environment environment.json --out program-comparison.json`.
Boot tests are enrolled in fast and actual program/replay/CLI controls in default
and expanded binary-relational lanes, with explicit QA and ownership mapping.
This completes the initialized-program termination-only implementation step.
Original M6 startup/files/output/device/service coverage, flat32 program parity,
representative corpus and original M0-M7 release acceptance remain open.
A fresh required quality-dev checkpoint is active with3pytest workers and the
owned source hashes retained in real16-program-start/quality-dev-source-manifest.json.
Its final result is not yet established; do not reuse the preceding failed
project run as acceptance of this new source checkpoint.

Current isolated public affine-loop diagnostic preserves the failing broad
case's exact bytes and default60000ms solver budget. It completes exit0/PROVED,
with paired_affine_region_transitions_proved and3raw/normalized/classified/
materialized facts,0failures, and no assumptions. Artifacts:
affine-public-diagnosis/report.json and immutable MZ/catalog inputs. This does
not explain the earlier broad-run UNKNOWN; no limits or proof gates were raised.
The public regression now prints its exact verdict row on failure rather than
pytest truncating a whole SSA/binary report. The broad discrepancy remains an
unresolved acceptance item pending captured missing-obligation evidence.

### Declared real16 output-stream step started (2026-09-30)

Parent owns initialized-program boot/model/replay/manifest/CLI integration and
new output integration controls; bounded Devin owns only new pure
real16_program_output.py and its focused tests. Other active worker retains
affine-loop regression ownership. Sandbox independently verified hostRO/repoRW
and 4GiB worker limit. Exact dirty integration baseline preserved in
.cache/comparator-implementation/real16-output-service/baseline/.
Graph coverage generation2026-09-30T06:26:53Z reports freshness not_tracked for
these new program owners; parent used exact source fallback.

Scope is explicitly enabled INT21/AH40 successful writes to declared independent
stdout/stderr byte streams, with per-call/total caps. This is a synthetic declared
environment, not universal DOS redirection/file behavior or symbolic proof.
Defaults retain termination-only admission. Pure service module is staged until
parent review; integration is in progress, not accepted. Initial integration
controls show3failures/2passes at absent output service; collection import error
was corrected before that behavioral baseline. Byte mutations must mismatch,
split writes must agree, unknown handles/memory/budgets must stay incomplete.
Original M6/M0-M7 release acceptance remains open.

### Reviewed declared real16 byte-stream integration (2026-09-30)

Devin terminal exit0: pure output owner and47focused controls, no existing-owner
edits. Parent reviewed complete source/tests, saved exact worker-final files and
dirty-baseline integration diffs. Worker HEAD-based baseline interpretation is
rejected because these existing owners are untracked; an empty git diff does not
establish restoration. Its integration-status statement was stale relative to
concurrent parent edits.

Parent reproduced1contract-review failure: accepted/refused result records allowed
bool/float handles and accepted AX wider than16bits. Result constructors now
require integer/u16 handles and AX. Explicit policy, capped service execution,
boot/environment identity, manifest/report and independent-stream comparison are
integrated. Zero-byte writes read no memory; unknown handles, buffers, wrap and
budgets refuse. Write chunk boundaries are diagnostic; each stream byte order
is observed, cross-stream interleaving is outside this explicitly declared
synthetic environment. No arbitrary DOS files/console/redirection behavior or
symbolic proof is claimed. Defaults retain termination-only services.

First integration67passes; expanded draft173passes/2failures at incorrect fixture
bytes and missing exact enrollment member, both corrected without weakening
assertions. Final175passes/14.89s,-n3. Six-owner linters-files passes Ruff/MyPy/type
ratchet; Pyright0errors. Startup/context/ownership checks pass. New modern typed
aliases and QA declarations placed before Make selection prevent legacy skips.
Final source hashes/logs/deltas under real16-output-service/. Review ledger:
reference/comparator-devin-review.md. This completes only the declared successful
output-stream step. Original M6 file/device/services/flat32 parity/corpus and
M0-M7 release acceptance remain open; separate broad gate/affine-loop work remains
active, not accepted by this scoped result.

### Current-tree broad-failure revalidation (2026-09-30)

The real16-program-start quality-dev gate is terminal: 8716 passed, 31 failed,
1 skipped in 1368.46s with three pytest workers. Source changes during the run
prevent using it as stable-tree acceptance. On the current tree, the complete
real16_loop_calls suite passes 34 tests in 35.14s, including its public positive
9043c3 and deliberately changed-leaf refusal. The return-witness address suite
passes all six tests in 22.98s. Its current source refuses duplicate witnesses
unless distinct retained source statements establish the instruction projection.
These checks do not establish the cause of the earlier broad failures, nor
discharge the other failures, flat32 parity, corpus, environmental or release
requirements. Original M0-M7 acceptance remains open.

### Flat32 declared-machine-input closure (2026-09-30)

The independent replay admission contract now refuses clock, CPU identity,
entropy and extended-control reads without explicit environment evidence:
RDTSC/RDTSCP, CPUID, RDRAND/RDSEED and XGETBV use the typed
undeclared_machine_input reason. Four actual function regressions failed before
the fix (14.15s, -n3). Shared admission protects function replay and the staged
PE32 initialized-program executor; final combined controls pass38/37.27s,-n3.
Ruff, scoped MyPy and type ratchet pass with the legacy test-owner MyPy exclusion
disclosed. The full-state test owner is already enrolled in routine pipelines.
The staged PE32 executor also needed a concurrent fresh-selector bootstrap
correction, independently exercised by the final controls; these results do not
establish a full Windows loader, flat32 public program acceptance, representative
corpus or original M6/M7 completion. quality-dev remains a separate checkpoint.

### Shared real16/flat32 machine-input admission follow-up (2026-09-30)

Reviewed bounded Devin audit and reproduced real16 admission defects using
actual MZ function/program controls:15failed/1passed in2.93s,-n3. A shared
replay_machine_inputs.py owner now supplies decoded IDs and typed instruction
reasons to both replay tracks, avoiding separate architectural truths. All six
instruction classes and real16 operand-size forms refuse before backend effects.
The final function/program/full-state/concrete replay cohort passes89/19.86s,-n3.
Scoped lint/type gates pass, with legacy test MyPy exclusions disclosed;
five production owners pass Pyright0errors. No symbolic evidence is promoted.

The first quality-dev attempt stopped before pytest at five exact-class-narrowing
MyPy errors in near_return_entry_selector. An explicit cast after the unchanged
exact-class guard corrects typing, with21selector tests passing both before and
after (18.82s/11.96s,-n3). The optional third-party boundary is documented where
the type ratchet consumes it. Development-gate retry and all remaining original
M0-M7 acceptance requirements remain open, including the separately staged PE32
review failures and ELF32 program parity.

### Original frozen-corpus checkpoint preparation (2026-09-30)

Reused .cache/comparator-implementation/three-track-corpus/manifest.json rather
than selecting easier examples. All10 frozen input files still match their
recorded hashes and sizes. Its20-function denominator remains real16:3, MSC8:2,
BC5:15. A stable2758-file Python/schema snapshot, with3 explicit deleted Python
paths, is retained at corpus-current-20260930-_ka3a2jo/sources with input/source/
package/interpreter identities in receipt.json. Post-copy inventory and content
checks passed. A partial earlier copy failed at a tracked deletion; it is not
accepted or used. Snapshot CLI --help exits0; comparator execution and dependency
isolation remain unvalidated. No compiled extensions were copied, so measured
conditions must be declared and cannot establish normal-build performance gains.

Bounded Devin work prepares only an ignored serial runner for this selection;
parent review, cold/warm evidence and complete per-entry publication are still
required. No historical report is promoted. The separate quality-dev retry has
296preliminary passes/14.65s,-n3 and a live fast-pipeline handle; neither whole-gate
nor original M0-M7 acceptance is established.

### PE32 Devin delivery review recorded (2026-09-30)

Parent-reviewed the two-file PE32 boot delivery against saved worker-final bytes;
found and corrected stale boot identity admission. Parent initialized replay,
manifest/CLI/schema integration retains explicit synthetic terminal/environment
scope and never promotes execution agreement to proof. Integrated cohort:269
passed/35.82s,-n3; scoped types/lint and39-module mypyc smoke pass. Latest separate
broad gate:28failed/8868passed/1skip/1409.06s; unresolved release acceptance.
See reference/comparator-devin-review.md for ownership, corrections and limits.
Original M0-M7 remains open; existing ELF support is retained without new features.

### Reviewed initialized real16 file-input integration (2026-09-30)

Devin delivered only the two pure input owner/test files with83controls; parent
review found and fixed three reproduced receipt/runtime admission defects.
Actual MZ baseline3failed/1passed; initialized read/seek, immutable input identity,
exact code/buffer admission, complete final cursor accounting and public schemas/
reports now integrated. Final354passed/26.79s,-n3; eight-owner lint/type ratchet
andPyright0errors; startup/context/ownership pass. Review evidence/source identities
under real16-file-input/; contract reference/real16-program-file-input.md and
parent ledger reference/comparator-devin-review.md. Opening/writing/closing files,
additional devices/services, representative initialized scenarios and M4/M5/M7
acceptance remain open. Latest separate broad gate28failed/8868passed remains
unresolved. Existing ELF is retained; no new ELF features. Original M0-M7 is
not complete, and concrete agreement remains separate from symbolic proof.

Final file-input review follow-up: one additional red regression demonstrates
that missing/foreign/malformed unused runtime handles were not checked before
service effects. The common boundary now validates the complete exact handle
set and every cursor, bounded to32items. Final authoritative integration cohort:
355passed/3warnings/21.29s,-n3; eight-owner Ruff/MyPy/type ratchet passes and
Pyright0errors. Earlier354test result precedes this final correction. Exact
worker-final versus parent-final deltas and source hashes refreshed under
real16-file-input/. Original M0-M7/release acceptance remains open.

### Frozen-corpus import isolation defect (2026-09-30)

The serial cold/warm runner is terminal: five command pairs executed, but its
MSC8 changed warm phase failed to seal evidence. The traceback identifies a
live-worktree tools/dosunit/flat32_proof_report.py import from a frozen driver.
Both flat32 adapters inserted a hardcoded /home/xor/vextest at sys.path[0],
overriding the snapshot PYTHONPATH. Consequently all flat32 phases from this
checkpoint lack established source isolation; their apparent verdicts and
timings are diagnostic only, not accepted frozen-source corpus evidence.
The runner correctly rejected the unsealed partial report; its missing requested
denominator is a downstream symptom, not the initiating defect.

A relocated-adapter regression reproduced the wrong root in both adapters
(two failing subcases/6.27s). Both now resolve their shared dependency root from
__file__, preserving the same ordinary-checkout root while permitting immutable
snapshots. Artifact: .cache/comparator-implementation/adapter-source-isolation/.
A new complete snapshot and actual adapter-import probes are required before
replacement corpus acceptance; the old snapshot is preserved unchanged.
The separate quality-dev retry ended with 8868passed/28failed/1skip,1409.06s.
Those failures remain unclassified; original M0-M7 acceptance remains open.

Isolation-fix verification: the normal-pipeline flat32 comparator lane now
includes relocated MSC8/BC5 adapter controls and passes32tests/12.13s with
three pytest workers. Ruff passes for both adapters and the test owner.
The independently retained pre-edit adapters reproduce two failing relocation
subcases; the post-edit artifact check passes both/10.79s. This fixes source
root selection only, not proof coverage or corpus acceptance. The regression
owner is already enrolled in default/expanded binary-relational lanes.

### Replacement isolated corpus checkpoint (2026-09-30, running)

Preserved the failed prior snapshot unchanged. Replacement checkpoint:
.cache/comparator-implementation/corpus-isolated-20260930-c66lqnl8/.
Current tracked/untracked Python inventory and retained schema files copied:
2763source/schema files. Exact live inventory/content recheck passed after copy;
all10 original input hashes/sizes and manifest identity match. The20-function
selection and budgets are unchanged. Actual imports of each flat32 adapter and
flat32_proof_report independently checked18 loaded owned modules per driver,
all inside the replacement snapshot. These probes cover loaded modules, not
every potential late import. Package/interpreter identities refreshed.
Serial cold/warm execution is active; no terminal corpus acceptance yet.
The snapshot remains source-only, with no normal-build performance claim.

Current-tree REP store revalidation (2026-09-30): the formerly failing forward
three-word case passes1/34.68s. The complete existing owner then passes19tests/
47.69s with3workers, including all10 generated-code variants and corruption
oracles. No REP owner edit was made in this investigation. Earlier broad gate
failures remain historical failures whose cause is unestablished; this current
cohort does not retroactively make that gate pass or settle other failures.
A separately owned broad test process was observed concurrently; these elapsed
results are functional checks, not controlled performance measurements.

Replacement corpus first phase terminal: real16 self/cold exits1 as expected,
parsed complete3-row denominator,155.122s. All3 remainUNKNOWN: InsertionSort
andSleep call_target_unmapped; SwapBars paired_region_admission_refused.
No assumptions or proof promotion. Serial remaining phases continue on the same
run; no replacement whole-corpus acceptance yet. Timings were collected amid
other owned test activity and do not support speedup claims.

### Complete saved-phase corpus aggregation (2026-09-30)

Replacement run process handle disappeared; saved harness is command_incomplete,
not an accepted uninterrupted run. Eight completed phase result files retained.
The unstarted BC5 changed pair was executed separately with the same frozen
source/input identities and600s/2048MiB bounds in a fresh cache namespace:
recovery report complete_missing_pair, no harness failures, cold16.776s and
warm11.771s. No completed phases were rerun or overwritten.

Parent aggregation reparses every raw report, matches its exact frozen selected
denominator and retained receipts, checks expected CLI exit codes and all
flat32 semantic-source hashes/paths against the actual snapshot. All10 phase
reports now available for all20 selected functions (37 mode-specific obligations
per cold/warm pass). Cold and warm verdict counts agree:

| Track/mode | Proved/passed | Mismatch/failed | Unknown/refused |
| --- | ---: | ---: | ---: |
| real16 self | 0 | 0 | 3 |
| MSC8 self | 2 | 0 | 0 |
| MSC8 changed | 0 | 1 | 1 |
| BC5 self | 0 | 0 | 15 |
| BC5 changed | 0 | 0 | 15 |

Current evidence: corpus-isolated-20260930-c66lqnl8/aggregate-evidence.json.
MSC8 source isolation now holds across1168 sealed owners per report; BC5 across
1167. Their source_escape_count is0 using resolved absolute snapshot paths.
Real16 callee closure remains missing. BC5 additional attempts include
indirect_jump and call_return_target_unproved:timeout; no budget increase or
assumption mode introduced. Equal refusal counts establish no equivalence.
The aggregate records original interruption and recovery explicitly; it does
not rewrite the original failed harness to complete or claim release acceptance.
Raw receipt differences include solver timing/witness changes: verdict-count
agreement is not identical dependency/cache evidence or a performance gain.

Bounded Devin region proposal now active under verified hostRO/repoRW and4GiB
sandbox, owning only ignored probe/report artifacts. Exact source baseline
hashes, prompt and CLI log retained in real16-callee-region-proposal/. The
proposal must retain both guard arms, indirect saved-return outcome and external
failure tail; it cannot admit a proof or weaken leaf/return/environment gates.

BC5 return-obligation diagnostic: captured the exact current frozen self proof
request at callsite0x401263,target0x4011ec,fallthrough0x401268. Instrumentation
stops before solving and claims no verdict. The retained JSON expression has
1636tree nodes/511360bytes, including33loadle and175storele occurrences.
It composes stack and absolute global stores over shared unconstrained memory;
possible aliases must remain obligations, not be optimized away. Existing
1000ms return-proof budget retained. Artifacts in corpus-isolated checkpoint:
bc5-return-obligation.json,capture_return_obligation.py,return-obligation.log.
This is exact formula evidence for the next bounded optimization/domain audit,
not a claim that the timeout is harmless or a proof result.

### Parent review: current gate disposition (2026-09-30)

The interrupted sixteen-node attempt is superseded only for current revalidation
by two process-helper passes (33.33s) and a terminal fourteen-node audit:
14failed/3warnings/278.00s, three workers, explicit exit1 receipt. These runs
do not retroactively change the full development gate's 28failed outcome.
Exact artifacts: rep-store-gate-review/process-helper-current-detail.log,
remaining-fourteen-current.log and remaining-fourteen-exit.json.

Current fourteen-case evidence: five cases explicitly report missing /dev/kvm
(drawtime, EnvSize, BIOS store, InBox long, SwapBars); seven report emitted-C or
validation failures (initmenu array assignment/pointer-or-integer, initbars
forbidden ss shift, runmenu unassigned stack local, percolateup, insertion sort,
DOS loadProgram wrapper and loadprog tail failures); setgear times out; monoprin
Fimemset exits1 without a sufficient classified cause. A KVM blocker does not
establish that a case would otherwise pass. None is waived or relabelled proved.

Parent identified a separate reporting defect: a final acceptance failure with
a passed semantic snapshot can still print a clean headline; another failure
branch assigns the truthy string "hold" to the Boolean merge_gate consumed by
milestone reporting. A bounded Devin worker is preparing ignored staged code
and controls only under acceptance-reporting/. No production patch from that
worker is accepted yet; exact baseline delta, focused red/green and consumer
review are required before integration. Preserve semantic snapshot provenance,
Boolean gate semantics and final refusal/exit behavior.

Plan disposition remains bounded deliveries rather than original milestone
acceptance: PE32 boot and declared real16 file reads/seeks are parent-reviewed
M6 steps; M4/M5 proof closure, representative M6 scenarios and M7 final gates
remain open. Frozen-corpus counts and source-isolation evidence are recorded in
the plan's complete saved-phase aggregation; refusals are not equivalence.

### Exact return-memory preprocessing checkpoint (2026-09-30)

The captured BC5 return formula is not merely expensive proof of equality.
Under the same1000ms budget, default and expand_select_store time out; exact
blast_select_store preprocessing findsSAT in407.13ms (+10.08ms preprocessing),
with no assumptions. This is a countermodel of saved-return equality under the
current shared unconstrained memory domain, not inequivalence of a self binary.

Typed ScalarPreprocessing policy now belongs to ssa_output_lemmas. STANDARD
remains the default for general SSA comparisons. Flat32 call-return checks
select READ_OVER_WRITE; exact Z3 expansion retains every alias and consumes the
original comparison deadline before solving. Return failure diagnostics retain
the selected policy. Existing mismatch/UNKNOWN gates remain unchanged.
On the captured actual request, production now yields call_return_target_mismatch
in344.98ms instead of timeout; caller composition still refuses. No stack/global
disjointness was assumed, no budgets enlarged and no false proof promoted.

Focused red2failed/12passed/3.19s; an initial green draft had one Z3 model-value
assertion defect (symbolic Boolean coercion), corrected to compare concrete
model values. Final complete shared lemma/flat32 lane47passed/8.26s,-n3.
Controls retain alias corruption, the actual return-check policy selection,
expired-deadline refusal and all prior lemma/call lane behavior. Direct Ruff
passes all4changed owners. Scoped Make lint/type/ratchet includes the explicit
flat32 contracts dependency; the first narrower scope returnedAny from that
skipped import, corrected by checking its owning typed contract rather than
adding a production cast. Make legacy-skips straightline_ssa and the test owner
for MyPy; this is not a full legacy SSA typing promotion. Broad quality-dev/
required pipeline/release acceptance still pending; no function-fixed claim.
Artifacts: .cache/comparator-implementation/return-preprocessing/.

### Reviewed binary callee-region diagnostic (2026-09-30)

Bounded Devin terminal0. Parent retained worker-final probe/report/JSON and
verified intake/discovery bytes still match their recorded dirty baseline.
Parent review corrected diagnostic identity admission: wrong binary/region
hashes now stop loudly before a candidate result. Source owner/probe hashes
are included in the fresh parent report. Parent rerun reproduces4blocks/6edges/
4SSA parts,11raw instructions,4normalized blocks,6classified edges,4materialized
parts,0failures. Both guard arms, indirect successor and external0x2062 retained.
Source path restrictions and leaf refusals remain unchanged. This artifact
uses an explicitly audited candidate span only; it is not a generic production
intake or proof. Existing whole-function expansion may extend into the external
tail, so generic region intake needs an explicit expansion boundary contract.
Saved-return/CS, guard-domain DS:02c2 and external-tail/environment closure remain
unproved. Diagnostic artifacts: real16-callee-region-proposal/.

### Acceptance reporting: reviewed and integrated (2026-09-30)

Devin exited0 with staged-only code, eight controls and handoff; exact source/test
copies retained in acceptance-reporting/worker-final/. Parent reviewed all three
source hunks and tests, then reproduced3failed/5passed on the saved baseline and
8passed on the staged source. Separate parent controls reproduce4failed/3passed
on baseline and7passed staged, including downstream bool conversion and cache
separation. No production edits from Devin occurred before parent integration.

Integrated terminal validation_failed now holds merge_gate as BooleanFalse,
including clean semantic snapshots. CLI surface severity uses an owned typed
acceptance outcome, with an explicit final-acceptance headline rather than a
semantic changed verdict. Actual semantic records, snapshots, summary and counts
are preserved. Both console/detail cache identities bind acceptance rejection.
Existing semantic-mismatch headlines remain intact; no proof/exit/retry/target
boundary changed. Parent found and repaired a consumer gap that the worker had
only documented: acceptance_scorecard must project rejection to its existing
failed outcome in both structured and text reports. Its2new controls were red
before correction. Worker token passthrough alone was not accepted integration.

New durable eight-case test owner enrolled in routine test pipeline and focused
ownership; existing typed-status/stale-status tests now require the corrected
Boolean and acceptance reporting contracts. Combined reporting/scorecard/COD
batch owner cohort57passed/3warnings/9.85s,-n3. Scoped Ruff clean; four selected
production/tooling owners pass MyPy/type ratchet via linters-files FILES=...
(the initial PY_FILES invocation selected nothing and is not gate evidence).
Two reporting-owner Pyright0errors, ownership manifest check exit0. Current-source
hashes and all red/green logs retained in acceptance-reporting/.

This closes a bounded M1/M7 reporting defect only. The full quality-dev gate
remains failed; current fourteen-node audit failures and original M4/M5/M6/M7
acceptance obligations remain open. No equivalence verdict is promoted by this
reporting change, and no controlled performance improvement is claimed.

### Declared candidate-region lowering boundary (2026-09-30)

Added the authoritative typed SuccessorRangePolicy in ssa_lowering_scope.
DISCOVER retains existing open function discovery; DECLARED_ONLY requires an
explicit positive size and prevents all dynamic range/epilogue extensions.
Source successors outside the declared region retain their original transfer
plus typed successor_outside_declared_scope refusal with exact source/target
coordinates. No successor is silently dropped as proof of completeness.
The lower context derives its legacy extension Boolean from this typed policy.
Public lower_straightline_ssa_document and internal function lowering expose the
policy; document parameters and each part source receipt retain it before IDs
are sealed. SSA schema documents both allowed values. This is a generic boundary
contract, not a new guessed callee range or automatic proof admission.

Focused red3failed/1passed/5.66s. Initial4controls green; explicit missing-size
control added. Final scope/lemma/flat32 lane plus both legacy extension controls:
54passed/11.38s,-n3. Cases retain external branch evidence, both in-range guard
arms, incomplete split-instruction refusal, mandatory explicit size and unchanged
default discovery/epilogue behavior. Ruff passes all5source/test/script owners.
Scoped Make lint/type ratchet passes after adding mandatory future annotations
to the new contract; existing SSA/test legacy MyPy exclusions remain explicit.
The new regression is enrolled in default/expanded binary-relational pipeline,
QA fast targets and source/test ownership mapping.

Actual retained corpus helper is independently lowered via the production API:
4parts at0x2222/0x2233/0x2229/0x222f, external0x2062 refusal and unchanged
indirect_successor at0x222f. The initial diagnostic call had malformed segment
metadata and refused before lifting; corrected segment_para projection supplies
the real production result. Its JSON passes the updated SSA schema. No external
tail code is consumed and no guard/return/domain obligation is discharged.
Artifacts: .cache/comparator-implementation/declared-callee-scope/.

Required make test-pipeline PYTHON=./.venv/bin/python is active. Its preliminary
contract cohort passes296/9.39s with3pytest workers; main pipeline has no final
verdict yet. No full gate, function-fixed or original M0-M7 acceptance claimed.
Next integration still needs generic source-bound region intake and caller-bound
return/guard/external-effect closure, using this boundary instead of automatic
range extension.

### KVM integration-test classification and InitMenu diagnosis (2026-09-30)

Five existing real DOS acceptance integrations lacked requires_kvm despite
terminal current logs explicitly naming unavailable MS C5.1 KVM execution:
SwapBars, drawtime, EnvSize, BIOS-store and InBox-long. Added only per-test
requires_kvm markers (plus the missing pytest import in EnvSize); bodies and
assertions unchanged. Fresh selected run terminal0:5explicit skipped/3warnings/
22.18s under pytest worker evidence missing,errno2. Parent-process probe reports
read_write, so device availability differs by execution context; no host-wide
availability claim is made. Missing backend remains non-acceptance, not passed.
The pure BIOS/InBox controls still execute:23passed/3warnings/13.20s,-n3.
Ruff clean on4test owners; ownership manifest check exits0. Saved pre-edit copies,
selection, actual skip reasons, receipt and source hashes: kvm-gate-markers/.

Parent independently recompiles the retained InitMenu failure C with gcc
-fsyntax-only: exact same array assignment and pointer-or-integer errors at
lines137/181. Saved artifacts and full dirty source hashes before delegation.
Bounded diagnostic-only Devin session launched under freshly verified hostRO,
repoRW,4GiB sandbox; ownership only ignored initmenu-gate-review/. Production
semantics/tests/config are outside its ownership. It must establish binary/IR/
alias storage facts and exact earliest-layer fix scope before any implementation;
original source/COD cannot supply semantics. Graph index_status is unavailable
under current approval policy, disclosed in its prompt; exact source fallback
required. Worker is live, no diagnostic report or semantic fix accepted yet.
Other active task retains callee-region/return-proof ownership. No project-wide
passing gate or original M0-M7 milestone acceptance is claimed.

### InitMenu independent binary storage evidence (2026-09-30)

Parent exact MZ-byte16bit decode confirms BP establishment, AX=0x12 stack-helper
call, then DI/SI pushes. On the helper's successful guarded path, savedDI is
BP-0x14..-0x13 and savedSI BP-0x16..-0x15; eight actual LEA buffer-address
instructions useBP-0x12. Source/COD names were not used to derive these offsets.
The generated-C array-assignment/pointer-or-integer symptom merges distinct
storage. Earliest-layer root cause remains under review; no patch/proof admitted.
Raw helper failure arm and indirect return retained as open obligations.

Artifacts: initmenu-gate-review/parent-binary-review.md, three exact-byte JSON
records and parent-review-receipt.json. Saved source hashes currently show zero
drift. Devin's cached IR dump remains provisional: its record exposes address/
payload checksum but this review has not established binary/source provenance.
Do not elevate newest mtime to current-source evidence. Production source is
unchanged while the separately owned full pipeline gate is active. Devin's
specific handle remains live; terminal diagnosis is not yet available.

### Independent concrete return-formula witness (2026-09-30)

The BC5 captured return obligation has a SAT witness even after constraining
initial data memory to all-zero and every non-ESP scalar input to zero. With
ESP0x4c2c8a, expected fallthrough0x401268 becomes0x1268. Exact expanded solver
query findsSAT in63.09ms under the unchanged1000ms limit. An independent Python
interpreter of the retained JSON bitvector/sub/add/little-endian byte-store/load
operations reproduces the same value and mismatch, using sparse zero memory
and32-bit address wrap. Unsupported operations fail loudly.

This witness belongs to the existing unrestricted shared-data-memory return
model; it is not whole-function/binary inequivalence, native replay, or proof of
a safe caller environment. It demonstrates that arbitrary initial array values
are unnecessary to trigger the corrupted return. A stack/global separation
contract or general control-exit treatment is a real prerequisite; increasing
Z3 budgets or deleting aliasing writes cannot supply that proof. Artifacts in
corpus-isolated-20260930-c66lqnl8/: verify_zero_memory_countermodel.py and
zero-memory-countermodel.json.

Live source remains unchanged while required test-pipeline is active. The main
suite has emitted a failure but has not yet published its identity/final result.
A bounded Devin scanner implementation is staged only under ignored
region-scan-staging/, with disjoint module/test/handoff ownership. No worker
pytest or live-source integration permitted during the active parent gate.
Parent source baseline/prompt/session log retained; generic scanner closure,
refusal, provenance and integration review remain pending.

### Required pipeline terminal checkpoint (2026-09-30)

Separately owned make test-pipeline is terminal failed; parent inspected actual
summary and final MakeError. Four lanes:1passed/3failed, no lane timeout. Main
unit cohort24failed/8971passed/5skipped/866.84s; binary-relational cohort306passed/
1skipped/189.62s. UltraQuickC fixtures and MS C6 tiny full-pipeline lanes failed
before successful build/decompilation. Their precise causes remain separately
owned classification work, not waived here. No faster-than-baseline claim:
cohort/source/cache scopes differ. Unit lane records over_budget against its
configured30s budget, not an execution timeout. Preliminary296pass controls
are distinct from these cohorts, not an overall passing gate.

Exact terminal summary copy/hash receipt under initmenu-gate-review/, original
log declared-callee-scope/test-pipeline.log. InitMenu diagnostic handle remains
live. Fresh runtime instrumentation reproduced the failure and records the
correct distinct physical projections: savedDI-low BP-20/entrySP-22 versus buffer
BP-18/entrySP-20, despite both third-party raw variable offsets being-20. The
initial proposed resolver-query explanation is not established: observed resolver
queries were only-2. Root cause therefore still needs the actual materialization/
unification consumer trace; do not patch the resolver on numeric resemblance.
Parent independently checked typed unset-seed semantic-cache refusal; actual
probe stages were observed, but final diagnostic/source-identity review remains
pending. No function-fixed or original M0-M7 milestone claim.

### Required pipeline terminal and DOS device intake (2026-09-30)

Required make test-pipeline is terminal exit2. Preserved original full report
as declared-callee-scope/terminal-summary.json before later runners can replace
the shared summary. Four selected lanes:1passed/3failed/0skipped/0timed_out.
Main unit cohort:8971passed/24failed/5skipped/866.84s; binary-relational cohort:
306passed/1skipped/189.62s (lane190.012s, within its300s budget). UltraQuickC
and MSC6 compiled-execution lanes failed. These are failed gates, not acceptance.

Three main failure tracebacks explicitly show missing/dev/kvm. Parent separately
read every one of the10REP failing CLI stdout artifacts: each includes the
missing/dev/kvm toolchain error. This explains those inspected environmental
refusals; it does not collectively classify every other test or erase failures.
Initial saved classification contains3direct-log KVM failures and21unresolved,
with retained artifact copies where available; original emitted evidence remains
authoritative. No REP semantic patch or weakened validation was introduced.

The documented scoped launcher --with-kvm succeeds on device-presence and API12
probes, but actual follow-up24-case/REP task launches fail before pytest because
the parent environment lacks/dev/kvm at open_verified_kvm. A repeated expanded
probe also failed at stat before child setup. Device availability is inconsistent
across observed invocations; a successful earlier probe does not establish a
usable validation run. No host-device substitution, sandbox weakening or
non-KVM acceptance fallback attempted. Recheck logs retained; no tests ran in
those failed task launches. Full DOS recompilation acceptance remains open.

The captured BC5 formula witness is now localized: return load starts0x4c2c76;
a later32-bit zero store at0x4c2c78 overwrites its upper two bytes, changing
0x401268 to0x1268. Source stack return push and later overlapping store both
retained in return-alias-witness.json. This is independent formula evidence,
not native replay or a whole-binary counterexample.

Devin region scanner staging remains active, with all4recorded parent source
baseline hashes unchanged. Generic scanner integration can continue independently
of the external-DOS validation limitation; original M0-M7 stays active/open.

### Staged independent clone-coordinate guard (2026-09-30)

Parent isolated reproduction shows exact scalarBP-20 and bufferBP-18 resolve
correctly, but a scalar clone with the same identity fields resolvesBP-18 through
entry-SP containment when raw offsets collide. This contradicts storage identity;
no original C/COD names supply proof. Baseline control1failed/2passed13.16s.
An ignored proposed guard refuses the competing exact raw-BP/entry-SP containment
rather than binding the scalar to the neighboring buffer:3passed5.92s; proposed
owner Ruffclean. Exact-object lookups remain unchanged. Retained baseline,
proposal, controls, logs/hashes: coordinate-clone-review/.

Staged only: broader containment/clone behavior and production cohorts have not
been audited. This is not yet demonstrated as InitMenu's actual substitution
path; its fresh exact scalar lookup was correct. Devin remains live tracing
unification/equality consumers, with no terminal report or semantic patch. Do
not attribute a function fix, refusal reduction or original milestone acceptance
to this independent guard. It is evidence for the next bounded review task.

### Declared-scope regression lane correction (2026-09-30)

Parent inspection found the declared-scope regression was enrolled only in
FOCUSED_PYTEST_TARGETS, despite the earlier relational-lane claim. Moved it to
RELATIONAL_BINARY_PYTEST_TARGETS and updated the exact inventory contract so
default/expanded execute it without duplicate focused-lane execution. Parent
verification: declared-scope 5 passed/12.66s; pipeline inventory 57 passed/1.33s,
each with exactly three pytest workers; scoped Ruff passes. No broad gate or
original M0-M7 acceptance is claimed. Devin scanner session remains live.

### Parent scanner review: flat-coordinate refusal correction (2026-09-30)

Devin staging session66625 exited0; parent verified all4 recorded live-source
baseline hashes unchanged and preserved the exact worker-final module/tests.
Independent staged pytest reproduces18/18 worker controls. Parent review found
16-bit target canonicalization wrongly applied to flat32/64 targets: a low
absolute external successor could be rebased inside a high-address window.
New control fails before correction (candidate incorrectly completed); scoped
coordinate handling preserves absolute flat targets and produces the external
edge refusal. Final staged cohort19passed/6.58s with exactly3workers; Ruff
passes. Scoped MyPy with skipped imports initially reports an Any-return at
the legacy SSA boundary; explicit integer boundary validation resolves it.
No live scanner integration or admission is claimed. Further parent review,
source-bound intake integration and required broad gates remain open.

### Reviewed scanner promoted to owned modules (2026-09-30)

Promoted the parent-corrected staged scanner into binary_callee_region_scan.py
and split its typed evidence/contracts into binary_callee_region_contracts.py.
Moved the19 exact-byte controls into the owned test suite; removed staging
path/import dependence. Enrolled the suite in default/expanded relational
pipeline, exact inventory contract, Make lint/type/test lists, and selective
test ownership. Parent final tracked cohort:76passed/3.59s, exactly3workers.
Scoped Ruff passes; MyPy with skipped legacy imports passes for both owners.
This provides a production candidate-scanning API, not discovery/composition
wiring or proof admission. Source CALL/domain verification, exact declared
region lowering, dedicated receipt and final return/control closure integration
remain next. Original M0-M7 completion and broad gate remain unaccepted.

Parent Pyright on the promoted scanner found4 optional-coordinate diagnostics
at dictionary boundaries. Added explicit typed refusal guards for missing
port-decoder address and terminal reference coordinates; final Pyright0errors,
Ruff passes, scanner19passed/4.82s with3workers. Discovery wiring remains open.

### Clone-coordinate guard integrated with bounded acceptance (2026-09-30)

Parent durable regression red1failed9.90s against actual pre-change owner.
Integrated exact competing raw-BP/entry-SP containment refusal; known exact
object projections retain their values. Existing coordinate test owner now
belongs to changed-source ownership so its regression cannot be silently omitted.
Full coordinate/frame/rebinding/identifier cohort50passed7.23s,-n3.
Selected source Ruff/MyPy/type ratchet pass (legacy test MyPy exclusion retained),
owner Pyright0errors. Four-line guard is a general Types/Lowering coordinate
boundary repair; no name/address/source-specific substitution or rewrite fix.

Ownership-driven check-files passes startup architecture, agent context,
ownership and selected lint/type; pytest result102passed/1failed44.20s. Failure
is SORTD Sleep final quality rejection unassigned-stack-local. One bounded
isolated baseline uses saved dirty pre-edit registry bytes, without altering
production source or checking out HEAD, and reproduces exit4/same refusal with
cache seed unset. Other dependencies are live dirty-tree files, not a complete
frozen tree. Thus Sleep is unresolved and no project gate is waived or called
passed. No function-fixed or original milestone acceptance is claimed.

Exact original/proposed/production identities, durable red,50control result,
check-files, Pyright, baseline driver/stdout/stderr and exit receipt retained in
coordinate-clone-review/. InitMenu diagnosis remains separately active with
Devin; its earlier fresh trace predates this guard. This guard's independent
clone reproduction is not proof that it resolves the actual InitMenu merge.
Full quality-dev/test-pipeline checkpoint remains pending after this delta.

### Source-bound multi-block region candidate intake (2026-09-30)

Added binary_callee_region_intake.py. It consumes the existing typed request
and authoritative caller CALL/domain verification; scans exact source intervals
using production lifter/loader callbacks; rechecks caller bytes, every scanned
span, loaded-image identity and lowering identity before publication. Typed
candidate status is distinct from admission; source and scan refusals retain
partial evidence. No guessed range or single-block leaf-complete claim.
Actual-MZ controls verify3block/2return candidate closure, fabricated target
refusal, external arm refusal and post-scan source mutation refusal. First
cohort2pass/1fail exposed an incorrect expected refusal enum in the new test;
verified TARGET_NOT_SOURCE_BOUND is the authoritative existing contract and
corrected the test, with production unchanged. Final80passed/13.23s with3workers
(scanner/intake/pipeline inventory); scoped Ruff/MyPy/Pyright pass. Test and
owner enrolled in relational default/expanded, Make and ownership projections.
Next: declared-only lowering, multi-block receipt and discovery/composition
admission wiring. Full M0-M7 and broad project gates remain open.

### Fresh InitMenu focused acceptance checkpoint (2026-09-30)

Parent current regression terminal1:1failed/67.34s, exactly3workers, semantic
cache hash seed unset. It reaches the SEG_U-not-in-body assertion: returncode0,
clean-output assertions, validation-passed-or-whole-tail-clean headline, expected
prototypes/signature and absence of vvar_ all passed first. Earlier retained
array-assignment syntax failure is not reproduced at this checkpoint. The full
function acceptance still fails on unrecovered segmented accesses; no assertion
was weakened and no function-fixed/binary-equivalence claim is made.

Registered source review checks1142paths: only recorded coordinate owner differs
from diagnostic launch baseline; original binary hash unchanged. Test-file hash
diff is accounted for: saved pre-KVM-marker file matches launch baseline and
the focused InitMenu AST is identical to current test (decorators/body). Receipt
and full short-traceback log under initmenu-gate-review/. Short failure output
does not retain full CLI streams, so no repeat solely to reconstruct output.
Sleep's11current snapshots:9registered production owners match baseline;2test/doc
files are unregistered, not established drift. All11match current bytes. Its
cached Sep20IR is historical evidence until source/binary binding is established.
Original M0-M7 full acceptance and project gates remain open.

### Multi-block source-bound callee discovery/composition checkpoint (2026-09-30)

Added binary_callee_region_lowering.py and wired it into discovery after typed
single-block branch/alternate-exit refusal. Candidate CALL identity is verified
again; exact consumed intervals are passed to declared-only SSA lowering; each
lowered block must match scanned bytes/size/jumpkind and the authoritative
full-state/successor grouping must accept the region. A source-derived enclosing
extent supplies existing whole-body identity; holes remain outside executable
intervals. New _lower_function declared_linear_ranges contract and a gap control
prove extent identity cannot authorize code in holes. Final bytes/identities
are rechecked before publication. Region receipts preserve original leaf
refusal, source scan, exact spans, part IDs and lowering decision counters; no
leaf_complete or whole-call proof is manufactured.

Public actual-MZ/replay controls now prove relocated jmp+equivalent leaf and
equivalent3block/2return callee; changed values and removed value-setting code
produce COUNTEREXAMPLE agreeing with concrete replay. Cyclic, nested, interrupt,
far-return, alias-corrupting and divide-fault cases remain UNKNOWN. The old
early-refusal eb00c3 case now has complete proof scope and a real mismatch; it
was moved to the counterexample controls, retaining an ebfe cycle refusal.
First public region controls exposed incorrectly rejecting the public zero
assignment-limit sentinel; preserving the existing uncapped SSA contract fixes
3failing controls. Resource defaults and proof/refusal gates were not weakened.

Final integration139passed/47.37s; after type-alias/VEX-attribute cleanup the
final runtime49passed/16.83s, each exactly3workers. Scoped Make linters-files
passes after fixing type aliases and replacing dynamic VEX dst access with dot
access; scoped Pyright0errors. Legacy SSA MyPy/Make-Ruff exclusions disclosed;
direct SSA Ruff passes. Startup architecture and ownership check pass. Moved
new Make enrollments before selected-file variable evaluation so scoped gates
include the owners. Parent exact source checkpoint hashes still match.

Fresh quality-dev and test-pipeline KVM-bound launcher attempts both exit1
before Make/test startup: missing/dev/kvm at open_verified_kvm. No broad green
gate, function-fixed, corpus or original M0-M7 completion claim. Evidence under
.cache/comparator-implementation/region-integration-checkpoint/. Graph coverage
refresh failed Transport closed; exact current source read fallback used.
Devin read-only saved24failure classification session62908 remains active;
prompt/baseline/log retained under pipeline-failure-triage and devin-prompts.
Next: review that classification; reproduce the frozen real corpus against this
new intake; close indirect-return/external-environment helper obligations and
remaining original M4-M7 exits, with final project gates once KVM is available.

### Reviewed combined initialized-MZ file-copy scenario (2026-09-30)

Devin session22939 exited0; parent verified all8baseline source hashes unchanged
and independently reproduced20staged controls in1.17s. Promoted to
angr_platforms/tests/test_real16_program_file_copy.py, removing staged sys.path
hacks/E402 exemptions. Added a parent control for independent input/output byte
budgets in one execution. Final cohort104passed/2.18s,3workers:21combined controls,
existing input/output integration and pipeline inventory. Actual MZ/Unicorn
checks cover deterministic seek/read/write/termination, equivalent chunking and
relocated buffer correspondence, stream-only/observation-only/exit mutations,
policy/handle refusals, receipts and immutable snapshots. Concrete evidence only.

Routine relational/default-expanded enrollment, exact inventory, QA and selective
ownership updated. Parent caught initial late Make registration causing scoped
Ruff selection to skip the new owner; moved it before projection evaluation.
Final scoped Ruff/type-ratchet/registered MyPy and ownership exit0; tests retain
explicit legacy MyPy exclusion. Before snapshots, worker-final, exact parent
diff, hashes and logs retained in real16-file-copy-scenario/. No production replay
semantics changed. This does not close representative applications/services or
whole M6/M7 acceptance; required project gates still have recorded failures.

Sleep static session88821 exited0; parent rejects causal proof from historical
IR/mtime/cleanHEAD and rejects CMP flag suppression without proved liveness.
One-run current diagnostic session79497 launched under freshly verified
hostRO/repoRW/4GiB sandbox, ignored sleep-current-probe/ ownership only. It must
identify actual first refusal with positive hooks and source-bound evidence,
without production edits, scratch reverts or extra runs. Original M0-M7 remains
active and unaccepted.

### Genuine PE32 branch public coverage integrated (2026-09-30)

Parent serialized actual PE32 pairs through InclusivePE and both MSC8/BC5
sealed z3cmp32 public drivers. Six controls prove exchanged distinct-effect
terminal arms and reject changed guard/arm effects with full GPR outputs;
initialized-image/startup relation remains UNKNOWN. Initial staged failure was
a test metadata expectation (PE vs actual InclusivePE), corrected without
changing any comparator semantics. Current singular baseline already proves
this pair, so it cannot support the proposed branch-search capability claim.

Promoted test_relational_branch_public32.py; enrolled binary-relational default/
expanded lane, exact inventory, QA and flat32 selective ownership before Make
projections. Final shared-tree test+inventory cohort63passed/6.94s/3workers.
Scoped Ruff/type-ratchet/ownership exit0. Before source snapshots and final hashes
in flat32-branch-staging/public-pe32-integration/. This is added durable real-PE
coverage of existing behavior, not new proof capability, M4 acceptance or a
whole-project green gate. Staged Devin74977 remains live investigating genuine
VEX successor-order differences; no production consumer patch promoted.

### Original M4 unequal-step intake (2026-09-30)

Parent independently decoded actual16/32bit machine fixtures for a zero-tested
loop and a two-step candidate retaining the odd-count intermediate zero exit.
Current actual-MZ region path returns UNKNOWN; MSC8/BC5 real-i386-byte consumers
refuse cfg_not_bijective. Bounded run2.191s,5000ms comparator deadlines; four
owner hashes unchanged before/after. This is a concrete refusal baseline, not
a proof of intended equivalence or public-PE acceptance. Fixture bytes, decoded
instructions and receipts retained m4-unequal-step-intake/. Existing pairing
source requires equal region cardinalities; finite chains stop at branches.

Fresh rootRO/repoRW/4GiB verified; static-only Devin62531 owns ignored design/
for exact composition reuse and bounded finite branching macroregion proposal
with initiation/preservation/exit/progress/relative-termination obligations on
both widths. No tests/runs or production edits by that worker. It must preserve
zero/odd exits, bitvector wraparound, complete state and UNKNOWN on exhaustion;
parent reviews design before assigning implementation. Graph unavailable,
bounded exact source fallback only. Branch staging74977 remains independently
live; no whole original milestone accepted.

### Unequal-step fixture independent replay (2026-09-30)

Parent replayed exact intake fixture bytes via existing Unicorn16/32backends:
32vectors (counts0,1,2,3,7,254,255,256; flags0x202/0x887; width16/32),160
executions,2000instruction cap,17.260s. Intended candidate agrees on all32;
stride corruption mismatches28nonzero vectors (zero correctly agrees); lost
intermediate zero guard is INCOMPLETE on16odd vectors and agrees on16even
ones; one-sided stutter INCOMPLETE on32. Full existing register/flag/control/
write replay comparison used, including high halves16. Exact reviewed rows
and hash saved m4-unequal-step-intake/parent-concrete-review.json. Replay-source
pre-run snapshots were not collected, so no frozen full-source checkpoint claim.

This corroborates fixture behavior and mutation sensitivity only; symbolic
UNKNOWN/refusal persists. No all-input, maximum-count or termination proof.
Static design62531 and branch staging74977 remain live with disjoint ownership.
Original M4/M6/M7 acceptance is not closed by finite replay.

Original M4 unequal-step design62531 terminal0, parent reviewed with explicit
endpoint/coverage/progress/type/freshness corrections (see comparator-devin-review
and m4-unequal-step-intake/parent-contract-review.json). Staged implementation
Devin3617 started under verified hostRO/repoRW/4GiB, ignored ownership only and
eight source baseline snapshots. Both-width solver/negative/resource acceptance
required; production integration and original M0-M7 closure remain pending.

Branch-search Devin74977 exited0, parent declined promotion: no demonstrated
new proof and no measured gain; sampled canonicalization is not universal
impossibility proof. Production consumer unchanged. Actual unequal-step3617
continues; original M4/M0-M7 acceptance remains open.

### M4 macro-step checkpoint (2026-09-30)

Reviewed Devin3617 delivery and parent corrections are now production dosunit primitives. Exact real16 MZ and both flat32 driver/PE controls plus adversarial admission/deadline/full-state controls: 52 passed in 20.70s. Shared flat32 retry now invokes complete macro-step proofs under one total deadline, preserving prior counterexamples and every attempt; retry/register cohort 20 passed in 7.02s, scoped Ruff and Pyright clean. Public real16 wiring, environment/provenance review, representative corpus and broader gates remain pending; original M0-M7 scope is unchanged and incomplete. Detailed evidence: reference/comparator-devin-review.md and .cache/comparator-implementation/m4-macro-step-stage/parent-review/.

### Public flat32 environment admission follow-up (2026-09-30)

Region report environment checks now execute after retry, and both matched-CFG
report paths check retained binary block coverage before publication. Parent
red controls identified both the original post-gate retry bypass and a missing
byte-size projection introduced by the new gate; both drivers now retain exact
IRSB block sizes. Production matched-CFG RET positives and real port-read
refusals are covered. Retry/admission suite15passed/4.76s; existing comparator
lane32passed/20.02s; scoped Ruff/Pyright clean. This does not close retry-owned
coverage when original lowering was incomplete or original M4-M7 acceptance.
Devin publication audit continues under verified repo-only 4GiB sandbox.

### Retry-owned environment coverage retained (2026-09-30)

Reblocked CFG, macro-step CFG and direct-call composition now retain exact
original member block ranges for independent final byte/IR environment scans.
Direct-call coverage includes every inlined callee. Initial lowering refusal
therefore no longer prevents final admission of a complete retry merely because
it lacks source ranges; omitted/empty retry coverage still refuses. Parent
retry/admission cohort19passed/11.50s; macro primitive cohort52passed/29.18s;
scoped Ruff/Pyright clean. New owner is enrolled in QA and selective ownership.
This adds no import/device semantics or recursive public proof capability;
original M4-M7 and representative release gates remain open.

### Real16 public unequal-step retry integration (2026-09-30)

Parent-reviewed Devin stage is promoted as separate real16_macro_retry owner,
retaining existing call/region orchestration and public environment/provenance
gates. Exact saved MZ pair baseline UNKNOWN now PROVED with macro-step method;
full-state mutations remain UNKNOWN. Parent repaired zero budget to visibly
refuse without entering either retry engine. Production public cohort12passed/
18.54s; strict zero-budget1passed/8.81s; scoped Ruff/Pyright and ownership clean.
Default/expanded relational, QA and selective test ownership enrolled. Required
post-macro test-pipeline is live, output retained; full M4/M0-M7 acceptance and
remaining M5-M7 requirements are still open.

### M5 staged address closure review checkpoint (2026-09-30)

Parent failure attribution: reproduced AIL CALL evaluator red (`None` instead
of4640); `_eval_call_return_op` now models bounded DWORD left shifts, with
saturation before allocation. Full AIL control cohort seven passes9.57s and
scoped Ruff clean. Independent separate-project counterfactual on the real
near-return expression fixture confirms a consumer regression: corrected
symbolic CALL yields PROVEN semantic artifact but candidate refuses
BASE_USE_UNPROVEN; historical process-local literal CALL accepts. Production
CALL remains corrected. Next obligation is source-bound frontend call-effect
recovery for symbolic direct destinations, not reverting truncation or treating
this regression as unrelated concurrent debt. Strict static joint admission
remains a separate evidence boundary.

Required quality-dev retry is terminal exit2: fast unit pipeline8711 passed /
284 failed /19 skipped in770.16s. Prior296-test regression group passed, but
this does not accept the integration. Failure inventory is saved under
`real16-address-production-integration/failed-nodes.txt`; many failures are
direct-call/near-return consumers and seven early joint-admission failures
report static control opaque. Attribution remains unresolved; the corrected
symbolic CALL target may expose frontend literal-target dependencies. Repair
those consumers before applying the isolated JMP experiment or claiming no
baseline loss. Preserve current dirty sources and do not waive these failures.

Isolated JMP producer experiment (no production activation): replacing only
the direct JMP path with the shared CS-relative WORD/full-DWORD continuation
owner proves all10 independent Unicorn vectors (short/word encodings across
low/high, forward/backward wrap and the first-MiB boundary). Current production
high controls previously countermodeled. Exact experiment and structured
results are under `real16-address-production-integration/jmp-coordinate-probe.*`.
This is process-local diagnostic evidence, not compiled-Cython acceptance;
production patch/rebuild, explicit positive regressions and branch/callee
consumer checks remain after the running source checkpoint gate.

Parent high-control audit distinguishes passing refusal tests from supported
semantics: independent Unicorn/native SSA matrix shows both short/word JMP
targets still mismatch at `0xffffd` and ordinary high head `0x84560`, while
the corrected near CALL proves in both cases. Exact terms and native targets
are saved in `real16-address-production-integration/high-control-matrix.json`.
These remain honest native-control refusals, not binary candidate mismatches
or completed branch support. Investigate the JMP/JCC producer coordinate seam
next without changing the source checkpoint under the live required gate.

Required quality-dev run is terminal exit2 at the changed-type ratchet:
`real16_macro_retry.MACRO_STEP_METHOD` lacked an explicit annotation. Parent
added `Final[str]`; focused changed-non-test type contract and Ruff pass.
Fetched-code prerequisite/refusal cohort passes seven controls in10.81s with
the updated complete obligation denominator. The subsequent quality-dev retry
is live in `real16-address-production-integration/quality-dev-retry.log`;
later phases of the failed run were not executed and are not acceptance.

Changed-surface acceptance gate started on the integrated checkpoint:
`make quality-dev PYTHON=./.venv/bin/python`, log under
`real16-address-production-integration/quality-dev.log`. Mandatory mypyc
compiled-import smoke passes39 modules; remaining gate phases are live, not
accepted. Updated fetched-code refusal accounting for the new required
address-closure row and corrected the production owner's integration docs.
Terminal-joint Devin run remains live with disjoint stage ownership. No
new milestone or whole-project acceptance is claimed while these run.

Private same-run integration checkpoint: parent-reviewed address compositor
is now `real16_address_model_closure.py`, consumed only by the joint run via
its private checker after fresh frames and domain dispatch. The report retains
the typed certificate; the joint model seal includes its owner; the exact
denominator includes `complete_address_model`. Only complete address closure
removes ADDRESS_MODEL; FAULT_DOMAIN/ENVIRONMENT remain conditional requirements.
Two focused positive/missing-entry controls pass43.64s. Integrated address,
joint and pipeline-enrollment cohort:117 passed/four failed in141.86s, all four
failures were obsolete denominator assertions (14 rather than15 fixed rows).
Corrected four refusal controls pass on rerun; original refusal assertions
remain intact. All58 adversarial compositor controls now live in the routine
pipeline and ownership manifest. Scoped production Ruff/Pyright clean.
Independent terminal-boundary fixture and project gates remain pending;
this integration does not establish full M5 or original M0-M7 acceptance.
Evidence: `.cache/comparator-implementation/real16-address-production-integration/`.

Independent terminal edge: exact near CALL at CS:IP `ffff:000d`
(`e8f0ff`) reaches `0xffff0`; RET (`c3`) restores word `0x0010`,
producing terminal `0x100000` outside the first-MiB contract. Two-instruction
Unicorn execution and composed full-state CALL/RET SSA agree (focused
regression passes, 11.44s; scoped Ruff clean). This demonstrates why a valid
CALL target cannot discharge terminal scope; it does not yet prove whole
joint closure rejection. Devin terminal-joint staging task launched with
disjoint ignored-stage ownership after live rootRO/repoRW/4GiB sandbox
verification; parent owns integration and acceptance. Task requires actual
source-bound MZ recursive evidence, a nearby positive companion and explicit
terminal rejection, or an exact earliest refusal. No production promotion.

Final focused producer/consumer follow-up: native control/edge/shift cohort
passes 32 controls in 8.82s; symbolic-call, entry-domain and bound-control
cohort passes 42 controls in 13.37s. A further high-address CALL with symbolic
CS consumes the exact declared selector domain and proves the full `0xffff0`
destination (one control, 5.76s). Parent-reviewed staged compositor Ruff is
clean and scoped Pyright reports zero errors. No frame receipt is promoted
as independently source-bound; private same-run integration and explicit
terminal-out-of-first-MiB closure rejection remain next requirements.

Parent control/dispatch review follow-up: preserved Devin's terminal stage,
reviewed its exact delta against parent-v2, and tested a separate parent copy.
The corrected actual-MZ cohort passes 58 controls in 96.91s with three workers
and immutable shared-fixture guards. Corrected stale strict-static-dispatch
admission in the staged frame stage: structural layout is derived there and
the retained domain-dispatch certificate remains a mandatory separate stage.
The corrected CALL producer also exposed two consumers: admission fixture
now invokes the authoritative universal-selector target solver under the same
deadline (1000ms per query); native control checks opaque singleton targets
against full DWORD native effects under the proved cutpoint, without retrying
resource-limit refusals. Scoped native-control Pyright has zero errors.
Final production regression rerun, private fresh-run integration, terminal-wrap
controls, fault/environment closure and public promotion remain pending.
Artifacts: `.cache/comparator-implementation/real16-address-control-parent-review/`.

Parent near-CALL producer repair: independent Unicorn regression reproduced
`0xffff0` becoming `0xfff0` in the compiled lifter. Direct near CALL now uses
the shared CS-relative WORD continuation owner and retains full DWORD loader
control. Rebuilt mandatory Cython extension; native control/wrap/edge cohort
passes 27 tests. Bounded static-control intake now evaluates constant left
shifts with count-width independence and pre-shift saturation; five dedicated
scalar/refusal controls pass and are enrolled in the routine pipeline/ownership
manifest. Scoped resolver Pyright has zero errors; scoped Ruff passes. This
repairs a producer/consumer prerequisite, not full M5 or M0-M7 acceptance.
Devin control/dispatch staging session is terminal; parent semantic review,
staged tests and fresh-run frame integration remain pending.

Devin's address compositor remains staged. Parent corrected exact operand proof-fact accounting and operand source/domain provenance, and corrected test refusal ordering/nonempty mutation selection. Independent corrected actual-MZ cohort:39 passed in79.70s with3 workers and reusable setup guarded against evidence mutation. This is restricted no-wrap address-domain evidence, not fault/environment closure or public recursive promotion. A bounded static-only Devin follow-up adds authoritative native-control/domain-dispatch intake; production integration, terminal-wrap coverage and frame provenance remain required. Full release gate remains failed; detailed receipts in comparator-devin-review.md. Original M0-M7 scope unchanged and incomplete.

### Recursive deadline controller regression repair (2026-09-30)

Parent reproduced seven failures in test_recursive_joint_deadlines.py after
full-width selector-dependent CALL lowering. Controller fixtures had requested
strict dispatch admission merely to construct frame layouts. They now consume
only derive_joint_frame_layout; the explicit unproved-dispatch rejection remains
unchanged. Focused red:7 failed/1 passed; green:8 passed in11.11s with3 workers;
scoped Ruff passes. No production admission gate was relaxed. The earlier broad
284-failure gate remains unresolved; this focused repair is not full acceptance.
Devin symbolic-call-effect session91883 remains live; terminal-joint session95330
exited0 and its staged diagnostic still requires parent review.

### Terminal-coordinate diagnostic independently verified (2026-09-30)

Devin terminal-joint session95330 exited0 with stage-only fixtures/diagnostics.
Parent independently constructed the same high-address blob loader: Arch86_16
reports bits16; CLEError rejects base0xFFFF0. Source inspection confirms the
native-effect, code-prefix and operand-access relift producers use the capped
architecture, whereas load_dos_mz and load_dos_ne explicitly widen loader bits
for linear mappings. This validates the loader blocker, not the worker entire
joint proof claim. Next repair must apply the existing loader-coordinate contract
coherently to all three producers, preserve 16-bit instruction semantics, and
verify high/low address and corrupted controls before public promotion. No proof
verdict has been upgraded and no full milestone acceptance is established.

### High-address relift loader repair in progress (2026-09-30)

Parent added real16_loader_arch, matching the production MZ loader address-width
setup without changing register offsets or instruction defaults. Native-effect,
code-prefix and operand-access relifting now consume it. Native-binding and
code-prefix model identities include helper source bytes. Scoped Ruff passes.
Actual terminal-joint diagnostic session20804 is running against this patch;
scoped typing and boundary/control validation remain pending. This is not proof
promotion, full M5 acceptance or a passing release gate. Symbolic-call-effect
Devin session91883 remains live, with disjoint staging ownership.

### High-address boundary diagnostic terminal result (2026-09-30)

Parent diagnostic20804 exited0 after loader repair. Both actual MZ fixtures now
bind native effects and discharge image-bound entry prerequisites. Terminal
0x100000 yields UNKNOWN/address_model_root_or_terminal_coordinate_out_of_scope;
nearby terminal0xFFFFF yields PROVED address closure but only CONDITIONAL joint
status/joint_physical_model_not_closed. Fault/environment obligations are not
waived. New loader regressions:4 passed in14.32s with3 workers, covering low/high
linear addresses, word MOV decoding and architecture isolation. Enrolled in
routine pipeline/ownership manifest. Changed production owners pass Pyright
with0 errors and Ruff. Full broad gate remains unresolved; staged terminal
fixtures need durable production regression integration before M5 acceptance.

### Durable recursive terminal-boundary controls (2026-09-30)

Parent promoted the reviewed binary-only fixture builder to
recursive_proof_fixtures/terminal_boundary_inputs.py and added two production
regressions in test_recursive_terminal_address_boundary.py. Both pass in50.49s
with3 workers. Tests assert complete address closure at0xFFFFF, UNKNOWN at
0x100000, and retained fault/environment requirements on both sides; neither
claims binary equivalence. Enrolled in relational routine pipeline and ownership
manifest with matching enrollment expectation. Fixture typing fixes make the
pair arity explicit and isolate the dynamic angr attribute boundary. Scoped
Ruff passes; final typing/enrollment receipts are being collected. This closes
a bounded high-address loader regression, not full M5/M0-M7 acceptance. Broad
284-failure gate and symbolic-CALL source-binding repair remain open.

### Boundary-control typing and enrollment receipt (2026-09-30)

Final fixture/test Pyright:0 errors. Routine enrollment expectation passes1 in
2.62s; scoped Ruff remains clean. The two durable boundary tests passed2 in
50.49s before an equivalent explicit-pair typing cleanup. Integrated loader,
address compositor, actual recursive joint and terminal-boundary regression
cohort is now running; this supplies the next checkpoint rather than replacing
the failed full release gate. Operand-scope model identity already inherits the
native-binding model hash, which now includes the loader helper source.

### Follow-up verification state (2026-09-30)

Integrated70-test loader/address/actual-joint/boundary cohort65051 is confirmed
live and has advanced through52 outcomes without a reported failure; no terminal
acceptance count yet. Symbolic-call-effect Devin91883 remains live. Parent source
review confirms direct JMP still uses constant-target lowering, unlike the
corrected selector-dependent CALL path. The earlier isolated10-vector JMP
experiment stays staged; production lifter changes are deferred until the CALL
consumer repair and this integrated checkpoint are stable. No release gate or
original milestone is promoted by these observations.

### Fresh direct-JMP countermodel replay (2026-09-30)

Parent standalone12720 exited0 on the current compiled lifter. Ten independent
Unicorn/SSA JMP comparisons: ordinary-low rel8/rel16 PROVED; first-MiB boundary,
forward wrap, backward wrap and ordinary-high rel8/rel16 all COUNTEREXAMPLE.
Thus8 of10 vectors reproduce the high-coordinate/wrap defect; this is a real
producer mismatch, not an unsupported/refusal result. No production lifter
change was made during integrated loader cohort65051, which remains confirmed
live at69 outcomes without reported failure. The staged shared-coordinate JMP
repair is the next producer change after that fixed-source checkpoint.

### Integrated loader/address checkpoint terminal (2026-09-30)

Integrated cohort65051 exited0:70 passed,3 warnings in276.33s with3 workers.
Includes58 adversarial address-closure controls, actual recursive joint controls,
loader isolation/word-decode tests and both actual-MZ terminal boundary cases.
This supports the bounded loader repair and preserved refusal behavior only;
fault/environment closure, symbolic-CALL regressions, full broad gates and
original M0-M7 acceptance remain open. Full log retained under
real16-terminal-joint-stage/integrated-loader-cohort.log.

### Word-JMP coordinate repair started (2026-09-30)

Following fresh8/10 countermodels, parent changed only direct word JMP lowering
to the shared relative_continuation arithmetic already used for CALL. Operand
size is checked from decoded native operands; other forms keep existing handling.
The WORD architectural offset wraps before full selector-base reconstruction.
Ten independent Unicorn/SSA equality regressions added and enrolled in routine
relational pipeline. Scoped Ruff passes. Mandatory Cython rebuild11959 is live;
compiled tests and broader consumer checks remain pending. No binary equivalence
or milestone acceptance follows from source edits alone. Devin91883 remains live
and owns only the staged symbolic-CALL binding work.

### Compiled JMP first regression checkpoint (2026-09-30)

Mandatory Cython rebuild11959 exited0. First compiled cohort92010:38 passed/
2 failed in33.76s. All10 independent JMP equality controls passed; failures were
two old nonzero-CS JMP expectations of COUNTEREXAMPLE that now return PROVED.
Parent updated those expectations and added exact native/expected successor
assertions for all successful zero-displacement JMP controls, retaining missing/
wrong coordinate/deadline refusals. Corrected40-control cohort76023 running;
Ruff clean. No whole-project or original milestone acceptance claimed.

### Symbolic CALL candidate domain review caveat (2026-09-30)

Devin91883 is still writing staged artifacts. Parent preliminary source review
finds its target-binding PROVEN currently relies on exact IR relative-continuation
shape plus linear next+signed displacement and mapped E8 bytes. Those facts alone
do not prove a literal target across all valid CS windows. Concrete arithmetic:
callsite0x10020, CS3, IP0xFFF0, displacement0x100 gives native WORD target0x123,
but linear summary0x10123. The entry IP is valid; a wrap actually occurs. Saved
counterexample under call-binding-domain-counterexample.json. Before acceptance,
require an authoritative admitted selector/window premise or prove all allowed
selectors target the same callee; do not admit summaries through shape alone.
This is preliminary review evidence, not a claim of executed staged false proof.
Compiled JMP cohort40 passed; final test Pyright0 errors. Full M0-M7 stays open.

### CALL selector-wrap independent execution and safe-domain proposal (2026-09-30)

Parent Unicorn replay21038 exited0: exact E8 0001 at physical0x10020 with CS3/
IP0xFFF0 reaches0x123 and saves return0xFFF3; linear summary predicts0x10123.
This validates the candidate-domain caveat with native execution. No staged
binding was executed, so do not label this an observed candidate false proof.
Conservative source-bound proposal: selectors that can fetch head h range from
max(0,ceil((h-65535)/16)) to min(65535,floor(h/16)). A literal callee t is equal
under every such selector only if max-selector base <= t <= min-selector base+
65535. Parent checked this interval criterion against exhaustive selector
execution arithmetic for the original0x10F7 forward fixture, wrap counterexample
and a low backward case: exact agreement; forward fixture admits, wrap/backward
refuse. This is a proposal under valid-fetch premise, not production proof; an
authoritative narrower selector domain can admit further cases. Evidence saved
in call-binding-domain-native.json and call-binding-selector-window-check.json.

### Compiled word-JMP checkpoint identity verified (2026-09-30)

Parent independently verified active.json source_sha256 against current lifter
source and extension_sha256 against the activated compiled artifact:both match.
Corrected compiled cohort76023 exited0:40 passed in14.84s with3 workers. Final
Pyright for new JMP/edge controls reports0 errors. This is a closed producer
regression checkpoint, not frontend consumer/full-project or milestone acceptance.
Devin symbolic-CALL stage continues writing provenance/binding artifacts; parent
selector-wrap review caveat remains an integration blocker for that candidate.

### Compiled JMP consumer regression checkpoint (2026-09-30)

Nearby symbolic-successor, symbolic-CALL-control, bound-control-scope and relative
control-edge cohort88991 exited0:68 passed in28.70s with3 workers. This checks
shared arithmetic and typed control consumers after the compiled JMP repair;
it does not rerun or clear the broad284-failure frontend gate. Preliminary
Devin binding review also finds no check of origin.statement_index or the
project control-address domain in the staged checker. Those provenance/domain
checks and the native-confirmed selector-wrap caveat remain acceptance questions
for parent review after the worker finishes. No staged candidate promoted.

### Devin staged CALL delivery preliminary review (2026-09-30)

Worker91883 reports21 standalone checks passing and has written DESIGN.md,
candidate.patch and patched modules. Job is still confirmed live; parent has
not accepted it. Independent hash comparison confirms all four original saved
baselines and current production files match pre-run hashes, so isolation is
preserved. Parent review requires selector-window proof, exact terminal position,
explicit control-domain binding and real patched-importer e2e evidence. Worker
checks manually stamp origin on IR for green; that does not verify importer
integration. Staged constant fast path also retains low16 target matching and
its exact-equality docstring is inaccurate. Review requirements retained in
symbolic-call-parent-review/requirements.md. No staged result clears the broad
frontend failures or promotes a milestone.

### Parent staged CALL reproduction and correction copy (2026-09-30)

Parent reproduction14288 exited0:21 original standalone checks pass. Original
Devin delivery preserved byte-for-byte; independent symbolic-call-parent-fixed
copy created. Added SELECTOR_WINDOW_UNPROVED arithmetic guard there, with
explicit documentation that valid native fetch is a required premise, not a
manufactured selector receipt. No production integration. Scoped candidate Ruff
finds two complexity defects:register-leaf resolver12, binding checker22 (limit10).
These need structural refactoring, not suppressions. Exact terminal/domain and
real importer checks plus removal/proof of low16 target path remain pending.

### Parent importer/constant-path correction staged (2026-09-30)

Independent correction copy now overlays actual patched vex_control_flow and
vex_import modules. Positive fixture and downstream green use their unmodified
imported IR, not post-hoc origin stamping; red uses saved original importer.
Constant target fast path now requires full exact equality; added a high-summary/
truncated-constant refusal control (old low16 case below64KiB was not a negative
control because low16 equaled the full target). Parent diagnostic83758 running.
All changes stay in symbolic-call-parent-fixed; original Devin delivery and
production sources remain untouched. Domain/provenance gates and complexity
refactoring are still required before integration or broad acceptance.

### Parent terminal-provenance binding correction (2026-09-30)

Independent corrected stage now requires a real Arch86_16 angr project under
LOADER_LINEAR control and freshly re-lifts a bounded block ending at the exact
E8 continuation. It checks native Ijk_Call, terminal statement count and next
TMP identity against retained origin. Missing/unmodeled domains and corrupted
terminal position refuse with typed reasons. Corrected diagnostic56235 exited0:
22 checks pass, including actual patched importer e2e and tampered terminal
position. Added explicit ARCHITECTURAL_OFFSET-domain refusal; diagnostic running.
No production promotion; selector valid-fetch premise acceptance and complexity
refactoring still remain.

### Bounded Devin correction refactor launched (2026-09-30)

Corrected standalone39674 exited0:23 checks pass, including explicit wrong
control-domain refusal. Parent verified outer sandbox rootRO/repoRW/4GiB and
launched Devin2085 with ownership ONLY corrected staged binding module. Saved
pre-run module/hash under symbolic-call-parent-review. Task preserves refusal
ordering/counters/domain guards and fixes complexity without suppressions;
no tests/proof reruns/production edits permitted. Parent owns tests and added
an actual high-address E8 importer-derived selector-wrap negative control;
it will run after worker terminal state to avoid mixed-source acceptance.

### Retained CALL binding contract review (2026-09-30)

Parent reviewed saved pre-refactor complete property:it currently checks only
PROVEN/failure-none/shape-present/exact aggregate counts, not consistency of
retained CS/width/callsite/target fields; boolean counts can equal integer1.
Added adversarial corrected-stage controls for replaced segment, target, control
width and boolean counter. These are pending red/green execution after worker
refactor2085 exits, not claimed passing. Worker owns only binding refactor;
parent owns disjoint test changes. Required integration must preserve retained
proof validity as well as fresh producer checks, not trust an enum alone.

### Devin refactor preliminary source review (2026-09-30)

Worker2085 remains confirmed live; scoped Ruff on its current binding file passes.
Parent read the staged validators/orchestrator and compared saved source:the
refactor splits CALL identity, summary/operand, origin/native provenance and
shape-coordinate validation into typed helpers, retaining selector-window and
native-byte gates. Delta currently135 additions/41 removals. This is preliminary
review only; final exact delta and pending adversarial red/green checks remain
required after terminal worker state. No production integration or accepted
proof result follows from lint or source reading alone.

### Retained binding corruption reproduced and repaired in staging (2026-09-30)

Devin refactor2085 exited0; parent reviewed typed helper splits and preserved
gates, scoped Ruff clean. Parent74428 red:actual high-selector-wrap control
reached expected refusal, then replacing a PROVEN binding segment with ES still
left complete=True. This is an observed retained-contract defect. Parent corrected
complete to recheck CS/width/next/displacement/target/window consistency and added
exact integer/nonnegative counter validation so bool1 cannot stand in for a fact.
Ruff clean; corrected diagnostic10442 running. Original delivery remains preserved;
no production integration or milestone acceptance yet.

### Corrected CALL binding production intake checkpoint (2026-09-30)

Parent verified all seven saved/current pre-run sources match their baselines,
then integrated six reviewed modules:terminal origin contract, control importer,
VEX importer, call-effect contracts/consumer and corrected binding. Corrected
standalone10442 passed25 checks before integration; original Devin delivery remains
preserved. Production near-return cohort75383 exited0:47 passed in11.75s with3
workers, restoring the affected focused source-bound caller intake without
reverting full-width CALL control. Six-module Ruff clean. Scoped Pyright results
being collected; adversarial checks still need durable routine-test promotion
and broader gates. This is not a function-fixed/tail-validation claim or original
M0-M7 acceptance; selector-fetch premise applies only to native source execution.

### CALL adversarial routine-test promotion (2026-09-30)

Added production-only test_direct_near_call_target_binding.py, deriving immutable
CALL evidence via actual importer and summaries without overlay/manual stamping.
Initial13 controls passed in9.51s. Expanded to changed operand/summary/native-byte
controls and enrolled in relational routine pipeline/ownership manifest with
matching enrollment expectation. Expanded pytest86475 running. Ruff clean.
Pyright found one test architecture-narrowing issue; explicit Arch86_16 instance
assert added and recheck running. Production six-module Pyright already passed0
errors. No whole-project gate or original milestone acceptance claimed.

### CALL adversarial production checkpoint and failure replay (2026-09-30)

Expanded production adversarial/enrollment cohort86475 exited0:24 passed in
22.46s with3 workers. Test Pyright0 errors and Ruff clean; six production modules
already passed scoped typing/lint. Parent saved selected-node list and test-source
hashes before starting an exact replay of the earlier284 failed nodes (no expanded
full gate or overlapping pytest pool). Results remain pending; this replay will
measure fixes versus unresolved caller/prototype/environment failures without
claiming that focused green clears broad acceptance. Original M0-M7 stays open.

Failure replay preparation correction:the saved284 rows contain one duplicate,
so the first strict uniqueness assertion stopped preparation and pytest exited4
without running tests (missing argument file). Parent saved283 distinct nodes
from34 files and their current hashes, then started the actual replay. This
preserves the original failure ledger; no failure was removed from selection.
Also fixed import sorting after the last test architecture-narrowing edit;
final scoped Ruff passes. Prior pending-run wording is superseded by this receipt.

Replay invocation correction:pytest argument-file invocation52792 exited5 with
0 collected items, so it supplied no test evidence. Parent switched to explicit
pytest.main node arguments read from the same saved283-node list; no selection
was dropped and no proof result inferred from the empty run. Exact current
replay handle/log is retained; investigation must preserve full accounting.

Exact-node replay investigation:explicit283-node pytest.main invocation96379 also
exited5 with0 items. A two-node direct CLI control ran and passed2 in15.72s, so
these empty selections are invocation/collection limitations, not passing tests.
No selected test-source drift detected. Parent started a34-module affected-surface
replay instead, retaining a controller-side report journal for every executed
node and explicit missing-prior-node accounting. This broadens scope to exercise
all previous nodes and catches additional regressions; it does not silently
claim coverage if any saved node lacks a report. No overlapping pytest pool.

### Replay liveness and independent CALL soundness audit (2026-09-30)

Affected-surface replay26247 confirmed live, 1095 collected tests across34 modules; failures remain visible, no terminal accounting yet. Source fallback confirms native_binding_model_hash consumes ssa_provenance._semantic_hash, which freshly hashes all frontend Python owners including the new direct_near_call_target_binding module. Graph index_status is approval-denied; graph completeness is unknown. Parent verified sandbox rootRO/repoRW and4GiB limit, saved six-file source hashes, and launched read-only Devin58544 to audit the production CALL binding and consumer use of the valid-native-fetch premise. No edits/test pool delegated; independent audit report and parent review remain pending. Original M0-M7 acceptance remains open.

### Remaining segment-CALL consumer intake (2026-09-30)

Source inspection establishes ir/segment_call_preservation.py still requires a CONST CALL operand and accepts callee_addr&0xffff. This is incompatible with retained full-width symbolic near-CALL control; truncation also lacks selector proof. Historical failed gate contains39 target_mismatch result assertions, not a newly measured current count. Saved exact source/hash and bounded acceptance obligations in .cache/comparator-implementation/segment-call-binding-intake/. Required repair consumes shared Semantics binding with decoded coordinate evidence, never fabricated ABI facts or rewritten SSA. Live replay sources remain unchanged. Replay26247 and independent audit58544 remain live; final failure accounting and parent audit review pending.

### Segment-CALL staged repair and standalone producer probe (2026-09-30)

Verified sandbox rootRO/repoRW/4GiB again, saved exact two-module baselines and launched Devin83244 with ownership limited to .cache/comparator-implementation/segment-call-binding-stage/ copies. Worker must preserve the summary-facing API, extract shared typed decoded-coordinate binding rather than fabricate ABI summaries, remove truncated target admission and revalidate retained evidence. No production edits or pytest delegated while replay26247 is live. Independent soundness audit58544 remains live. Parent standalone scaled-return fixture probe49052 confirms exact CALL binding PROVEN and complete BP-preserving stack effect; probe72891 confirms Semantics SSA and near scaled-return candidate PROVEN/complete. Receipts in symbolic-call-parent-review/scaled-return-{call-effects,standalone-receipt}.json. This isolates one repaired producer fixture, not replay or milestone acceptance. Await terminal replay accounting before classifying its current failures.

### Second stale symbolic-CALL consumer identified (2026-09-30)

Source fallback identifies direct_call_segment_entry._call_target_refusal_8616 as a second CONST-only/low16-alias consumer, alongside segment_call_preservation. Saved its exact source/hash and existing authentic binary integrity regression obligations under segment-call-binding-intake/. The shared typed coordinate-binding repair must be consumed by both owners while preserving decoded-entry, raw-IR registration, Alias/contextual-entry and retained-result gates. Current replay and both Devin jobs are confirmed live; no production edits or milestone promotion.

### Authentic direct-entry refusal reproduced (2026-09-30)

Parent production probe20468 uses existing real-byte PUSH SS/POP DS/E8/RET fixture, actual raw IR, registered artifact, Alias restore and exact decoded index. Result UNKNOWN_REFUSE/call_not_direct_near; CALL operand is dword TMP Iop_Add32/source_tmp76, establishing the CONST-only consumer refusal without invented evidence. Before-fix receipt:segment-call-binding-intake/direct-entry-red.json. Initial diagnostic import62677 failed before execution because its dynamically loaded dataclass module was not registered in sys.modules; diagnostic setup corrected only, no production exception changes. This is a standalone production reproducer, not a passing pytest gate or function-fixed claim. Replay26247, audit58544 and stage83244 remain live.

### Terminal affected-module replay and complete reconciliation (2026-09-30)

Replay26247 terminal exit1:761 passed/282 failed/52 skipped,1095 items,1711.58s (28m31s). Initial journal reported11 missing prior IDs; parent established selection-parser truncation at parameter spaces and one xdist_group @sortd-initmenu scheduler suffix. Reparsed complete original FAILED lines:284 rows/284 distinct, superseding earlier283 distinct/duplicate interpretation. Exact283 node matches plus one source-backed xdist-group alias account for all284:108 now pass,176 remain failed, none missing. Expanded module scope adds106 failed tests (CLI70,SORTDEMO29,COD7); these are additional-scope findings, not proven newly introduced regressions. Several CLI captures show unavailable /dev/kvm and incomplete mock attributes; classification remains open. Receipt: symbolic-call-parent-review/reconciled-failure-replay.json; original journal preserved. Full gate remains failed. Started focused before-fix segment consumers pytest67504 after replay terminal, no overlapping pool. Independent Devin audit58544 and staged repair83244 remain live.

Focused before-fix consumer pytest67504 terminal exit1:5 failed/14 passed in16.82s. Failed authentic direct-entry positive and four catalog-free contextual-callee controls; retained/malformed controls otherwise pass. Log:segment-call-binding-intake/focused-red.log. Production has not yet incorporated staged coordinate-binding repair; independent audit and worker delivery still pending.

### Devin soundness audit parent review and D1 repair (2026-09-30)

Read-only audit58544 terminal0 reports D1 decorated-register reduction and D2 alleged fetch wrapping. Parent reproduced D1 (85239):offset0x1000 CS leaves falsely PROVEN; CS0 altered target0x115bc versus native0x15bc. Parent tightens both leaf reduction paths and adds eight routine-enrolled adversarial controls. Standalone31185:authentic positive complete, decorated mutant refuses SHAPE_MISMATCH; Ruff clean and Pyright61847 zeroerrors. Focused pytest pending CLI worker coordination; no acceptance promotion. D2 remains unaccepted pending architectural/policy review. Parent rejects audit claim that downstream byte checks automatically rescue bad operand bindings. Full receipts/review under call-binding-independent-audit/. Stage83244 must be rebased while preserving this parent correction. Also launched bounded test-only CLI loader-mock stage22467 after sandboxverification/sourcebaseline; no production edits delegated, at most one3worker focused pool, no blanket validation bypass.

D2 parent disposition:Intel80386 PRM14.7 item8/exception table confirms past-FFFF instruction execution raises exception13, not8086-style fetch wrapping (manual mirror https://www.ardent-tool.com/CPU/docs/Intel/386/manuals/prref386/s14_07.htm). Segment-limit violations are explicitly excluded by project practical-real-mode policy; no opcode-address-modulo16 blanket refusal introduced. Original M5 arbitrary fault/environment closure stays open. D1 durable controls also being exercised in an isolated direct-invocation diagnostic while CLI worker owns the bounded pytest slot; no pytest gate acceptance claimed.

### Staged coordinate-binding source review (2026-09-30)

Both stage83244 and CLI test-only worker22467 confirmed live. Parent provisionally reviewed coordinate contract/adapters/shared core and segment-preservation delta:original domain/origin/relift/selector/byte gates retained, exact CONST matching, revalidation and deferred import. Final worker delivery required before integration; parent D1 correction must be preserved. Draft regression bounds/high-address setup have flagged fixture defects requiring final-version review; no production catch/fallback permitted. Review receipt:segment-call-binding-intake/parent-stage-review.md. CLI worker owns bounded pytest pool, parent starts no overlapping tests.

### Reviewed shared coordinate binding integrated (2026-09-30)

Stage83244 terminal0; parent reviewed final typed coordinate/summary/decoded adapters and shared proof core, compared untouched consumer/second-consumer hashes and exact AST of all D1 leaf guards, saved pre-integration sources, then integrated binding plus segment preservation and parent direct-entry consumer. Initial staged authentic-positive25682 refused DECODED_INSTRUCTION_MISSING:actual owned DirectCapstoneInstruction8616 retained raw insn.bytes but lacked projected bytes. Parent fixes frontend projection (immutable bytes) and adds assertion to existing decoder-detail regression. Corrected staged85264 proves; fresh production79184 runs four durable binary/restore assertions successfully. Ruff clean. Initial scoped Pyright79924 finds optional return coordinate in worker wrapper; parent adds exact-int narrowing, recheck running. CLI worker22467 still owns bounded pytest slot; full pytest/consumer acceptance and regression proposal promotion pending. No function-fixed or milestone acceptance.

### Shared binding regression proposal promoted with parent fixture fixes (2026-09-30)

Parent promotes worker test_segment_call_binding_regression.py to routine-owned source, corrects ES-callee end from100b to byte-derived100c, optional program assertion, wide image input typing and architecture narrowing. Enrolled relational pipeline/ownership and expected enrollment set. New test Ruff clean, Pyright41818 zeroerrors. Production integrated four-module Pyright86184 zeroerrors after exact-int return narrowing. CLI worker22467 still owns bounded pytest slot; its intermediate report11pass22fail on33 missing-memory cases is not accepted final evidence (now triaging deadline doubles/remaining KVM and loader-level failures). All binding pytest and full acceptance remain pending, no overlapping parent pool.

### CONST call-binding regression fixture repair (2026-09-30)

Parent reproduced both proposed CONST controls failing before their intended target check: synthetic boundary census included0x1000 absent from IR. Replaced those fixtures with actual high-address decoded CALL bytes, retained native index/CFG/instruction census, and substituted only the CONST operand before first publication (registry conflict protection preserved). Independent direct invocation:2 passed, proving truncated high target refuses TARGET_MISMATCH and exact full-width target binds. Ruff clean; focused pytest remains pending the existing Devin22467 test slot. This repairs test evidence, changes no production gate, and establishes no milestone/project acceptance. Receipt:segment-call-binding-intake/const-fixture-repair-receipt.json.

### Provenance controls and staged CLI parent review (2026-09-30)

Parent found origin_missing/origin_tmp controls republishing conflicting artifacts, refusing coverage before target binding. Saved pre-fix direct invocation confirms2 failures. Corrected first-publication ordering and added explicit complete-coverage prerequisite; all18 binary-binding controls now pass under independent direct invocation (not pytest/project gate acceptance), Ruff clean and Pyright0 errors. Receipts:segment-call-binding-intake/{provenance-controls-before,all-binding-controls-direct-receipt}.json. CLI stage parent AST audit: original source hash still matches saved baseline,51 test functions changed, zero assertion changes, one shared loader helper added. Mock extent agrees with production relative-memory/absolute-inclusive-max_addr owner. Staged changes remain unintegrated; Devin22467 handle repeatedly confirms running with no terminal report. Additional-scope failures do not prove newly introduced regressions; parent rejects that intermediate attribution without baseline evidence. Full original-plan acceptance remains open.

### Shared-worker collector ownership repair (2026-09-30)

Devin22467 diagnosed a production lane mismatch; parent independently reproduced TypeError in shared completed-future collection because item_by_future is initialized only in isolated-worker execution. Saved pre-change cli_core source and failure trace in shared-future-collector/. Parent collector now consumes shared future_map, preserves worker exceptions as explicit error results, and uses existing late-emission/accounting boundary with abort propagation. Two new direct-invocation controls pass (success and worker failure), routine fast pipeline/ownership enrolled; touched-file Ruff clean and new-test Pyright0 errors. Production type ratchet, focused pytest and budget-sweep sibling remain pending. No acceptance bypass introduced. Devin remains staging-only/live; intermediate infinite repeat clock caused a hang and was rejected, worker correcting it to advancing count. Full project/original M0-M7 acceptance remains open.

### Shared-worker budget-expiry closure (2026-09-30)

Parent independently reproduced budget-sweep TypeError when expiry precedes first wait (done=None). Sweep now inspects actual pending-future completion, reuses shared task-map collector without blocking unfinished work, and returns exhaustion plus emission exit code; caller propagates that code. Four routine-enrolled direct controls pass:success, explicit worker error, mixed ready/unfinished budget expiry, and targeted emission abort. Ruff clean and new-test Pyright0 errors. Initial production Pyright reports50 errors across cli_core; one adjacent optional-result handoff corrected to use the key just assigned, remaining diagnostics not yet baseline-classified. New production typing run74919 pending. Existing Devin22467 remains live; intermediate bounded CLI run12 pass, remaining21 failures and thin arch.capstone mock under investigation. No full gate or milestone acceptance. Saved pre-fix sweep failure and green receipt in shared-future-collector/.

### Collector caller-loop checks and scoped type gate (2026-10-01)

Parent adds enclosing-wait-loop variants to budget controls:6 independent direct-invocation controls pass, including propagation of emission exit2 through actual caller; Ruff and test Pyright clean. Required scoped type-ratchet-files completed exit0 for cli_core.py,test_pipeline.py,test_ownership_manifest.py (receipt shared-future-collector/type-ratchet.log). Whole cli_core Pyright49 errors, none in changed collector range; broader baseline classification still open. Devin22467 repeatedly verified live. Parent independently probes staged relative/absolute memory helpers:4 equivalent backed boundary reads and6 unbacked reads correctly reject; declared entry0x11423 lies outside helper image0x10000..0x103ff and must be classified before accepting fixture completeness. CLI stage remains unintegrated. No full original-plan milestone or release acceptance.

### Existing direct-entry consumer controls (2026-10-01)

Parent independently invoked21 no-fixture existing direct-entry controls:17 passed/4 failed (receipt existing-entry-controls-direct.json). Three fixtures lacked required native decoded CALL evidence. Parent replaced DS-write and missing-Alias indexes with authentic boundary indexes, and unrelated-caller case with two real decoded byte-backed CALLs to one callee. Original assertions preserved; focused3 direct controls pass, Ruff/Pyright clean. Fourth target-disagreement refusal classification remains unresolved; no broadened assertion or production proof bypass. Saved exact pre-repair test source. Devin22467 remains live; formal pytest/project acceptance pending.

### Native target disagreement classification closed (2026-10-01)

Parent replaced remaining mismatch fixture with authentic decoded CALL instruction and actual byte-backed callee boundary, mutating only the indexed target. Focused pre-fix assertion fails with generic CALL_NOT_DIRECT_NEAR. Consumer now preserves Semantics DECODED_TARGET_MISMATCH/DISPLACEMENT_MISMATCH as typed TARGET_MISMATCH; all failures remain UNKNOWN_REFUSE, no admission change. All21 existing no-fixture direct-entry controls now pass under independent direct invocation, including three prior native-index repairs; scoped Ruff/Pyright clean. Receipt existing-entry-controls-final-direct.json and native-target-classification-before.txt, saved exact production baseline. Formal pytest/full gates remain pending Devin22467 test-slot handoff; original M0-M7 acceptance unchanged.

### Integrated binding/collector pytest checkpoint (2026-10-01)

Parent verifies no running pytest pool visible before launch; focused4-module pytest with3 workers completes51 pass/3 fail in22.01s. Remaining3 failures are SS-write parametrizations with address-only decoded doubles, refusing before intended Alias/segment guards. Replaced only index with native boundary decoder; unchanged assertions. Same cohort now54 pass/0 fail in22.72s, Ruff/Pyright clean. First handle confirmed terminal before starting distinct5-module consumer-closure cohort54875 (repeated callee, entry integrity/provenance/context and shared binding controls). Devin22467 remains verified live with no terminal report. No full release or original milestone acceptance. Receipts:focused-pytest-receipt.json and integrated-focused-pytest{-final}.log.

### Nested segment-context binding consumer closed (2026-10-01)

Consumer cohort terminal54875:72 passed/5 failed in27.09s; all5 failures are production propagated-context caller missing new project/call_block/decoded_entry keyword arguments. Parent saved exact source and wired already validated caller project, unique CALL block and decoded index entry into shared binding owner; no fabricated evidence or changed refusal gate. Same cohort terminal63742:77 passed/0 failed in19.09s with3 workers. Ruff/Pyright clean and scoped type-ratchet exit0. Combined separate focused runs cover131 passing tests (54 binding/collector/frontend plus77 consumer integrity/provenance/context/repeated-call/binding controls); this remains scoped evidence, not project/M0-M7 acceptance. Devin22467 still verified live and CLI stage remains unintegrated. Receipt consumer-closure-receipt.json and exact red/green logs.

### Ranked queue accounting and higher consumer intake (2026-10-01)

Pipeline enrollment pytest81724 terminal:57 passed in1.79s. Higher near-return selector cohort57297 terminal:21 failed in13.08s, all at shared upstream _definition asserting CallOutputDefinitionResult.complete; selector expectations unchanged and root cause pending. Parent independently reproduces a separate limited-ranked-queue defect matching Devin diagnostic: _phase_build_tasks...o1 appended new items to original function_tasks then replaced it with empty replacement_tasks. Corrected both appends to owned replacement list; existing task/recovery identity and ranked placeholders retained without mutation of prior list. New focused red control captured, enrolled in fast pipeline/ownership. Ranked queue+collector+enrollment pytest31956 terminal:64 passed in23.42s; Ruff and new-test Pyright clean. Scoped type ratchet50094 result tracked separately. Devin22467 remains verified live, staged CLI patch not accepted. Scope remains full original M0-M7; broad gates and21 upstream near-return failures unresolved.

### Symbolic call-output definition seam staged (2026-10-01)

Source fallback locates common near-return blocker in resolve_storage_call_output_definitions_8616:still requires CONST although native lifter preserves symbolic TMP target. Existing callers supply optional project but project-less shared fixture cannot prove native binding. Parent reverified sandbox rootRO/repoRW/4GiB, saved exact lowerer baseline and launched bounded staged Devin84945 (disjoint from CLI22467; no pytest or production edits) to consume shared native target binder with independent SSA-to-registered-raw provenance closure. Missing project/provenance must still refuse; no reconstruction or fabricated ABI. Parent retains fixture ownership and will review precise delta plus native corruption controls. New task must report blocker rather than force proof if SSA/raw binding lacks a sound bounded contract. Full original plan stays open.

### CLI stage parent integration and native fixture project supply (2026-10-01)

Devin22467 terminal exit0. Parent verifies exact dirty-source baseline,51 changed test functions, zero assertion changes and only two memory helpers plus bounded loader/Arch/advancing-clock conversions. Saved original before integrating. Ruff clean; independent integrated8 prior positives+2 timeout cases pytest60973 terminal:10 passed in52.10s with3 workers. Parent does not accept report assumptions that unreadable memory is the intended fallback contract or all20 remaining failures resolve with KVM; incomplete original aggregate fixture and entry outside helper backing remain recorded. No acceptance bypass added. Parent-owned near-return fixture _definition now forwards optional project and _receipt supplies its actual retained project; source-backed SYMBOLIC TMP/CALL_TARGET_UNKNOWN evidence retained. This prerequisite alone does not support symbolic calls; Devin84945 remains staged/live and21 near-return failures require production review/integration plus rerun. Other production resolver callers audited:three supply project; memory-live-out caller omits it and needs follow-up. Full M0-M7 stays incomplete.

### Memory live-out project evidence route closed (2026-10-01)

Source audit confirms memory live-out source caller_project was lost between function collection, callsite collection and candidate materialization. Baseline module16 passed in14.20s; strengthened existing integration test observes real definition resolver without replacing verdict, reproducing missing-project assertion. Parent forwards exact caller_project through optional keyword interfaces to resolver; same module16 passed in16.01s, Ruff/Pyright clean, scoped type-ratchet exit0. Existing constant-only compatibility retained. This is a native-evidence prerequisite, not new symbolic target proof admission. Devin84945 remains staged/live; parent must verify producer-closure integrity (mutated SSA producer with unchanged CALL operand/origin must not bind) and no repeated VEX lowering before integration. Full original plan remains open.

### Symbolic CALL adapter parent corruption review (2026-10-01)

Parent independently exercised real E8 caller/callee fixture from staged Devin84945. Authentic SSA binds complete/proven. Changing only caller block0x1000 target-producing instruction t30 to MOV constant0, while retaining CALL operand/origin, registered raw IR and native bytes, also binds complete/proven. This verifies a producer-integrity defect in the staged adapter, not production. Receipt: `.cache/comparator-implementation/call-output-symbolic-review/producer-mutation-probe.json`. Patch remains unintegrated; require exact SSA/raw target-producer closure with version integrity and a durable mutation refusal before acceptance. Devin84945 is confirmed running by process handle; await terminal report before a bounded revision. Full M0-M7 acceptance remains open.

### Symbolic CALL revision launched after terminal review (2026-10-01)

Devin84945 terminal exit0 reports25 staged controls passing and scoped Ruff/Pyright clean; parent rejects producer-closure claim using two independent corruptions (direct t30 and transitive t26), both incorrectly complete/proven. Existing cached block-local SSA projection detects both changed instruction streams; authentic35-instruction caller projection/bindings match. Receipts: call-output-symbolic-review/{producer-closure-controls,local-projection-probe}.json. Verified fresh sandbox rootRO/repoRW/address limit4294967296; launched bounded revision37114 with no overlapping worker ownership, prompt/log `.cache/devin-prompts/call-output-symbolic-revision.{md,log}`. Original adapter remains staged only. No milestone acceptance.

### Production Semantics projection compatibility review (2026-10-01)

Parent real binary probe builds Semantics-enriched SSA from the same registered raw E8 caller. Effects/output accounting closes, but staged adapter refuses conflict/ssa_raw_operand_mismatch because Semantics adds CALL stack_effect absent from raw CALL. Production call_outputs also inserts CALL_OUTPUT prefixes into return blocks, invalidating general positional1:1 assumptions. Receipts: call-output-symbolic-review/semantic-{projection,adapter}-probe.json. Production return-trial and live-out routes currently provide artifact/project, not decoded index. Existing CallSemanticProjection retains source/effects/outputs/final SSA on codegen but not via project SSA resolution. Launched separate bounded staging-only Devin20947 to establish this coherent retained evidence route, disjoint from active producer-integrity revision37114. Same verified rootRO/repoRW/4GiB launcher, no pytest pools or production worker edits. Prompt/log call-semantic-projection-intake.{md,log}. Integration and full original-plan acceptance remain open.

### Input/return consumer baseline for shared symbolic-target integration (2026-10-01)

Parent focused two-module baseline terminal14579:6 passed/24 failed/3 warnings in15.15s with3 workers. Fifteen return-pointer failures stop at constant-only output target resolution; nine input trial failures stop at reaching-definition CALL_TARGET_CONFLICT. Independent signed-immediate replay confirms typed input failure REACHING_DEFINITION_CONFLICT/CALL_TARGET_CONFLICT. Source interprocedural_storage_reaching_defs.py also demands a constant CALL target. Shared symbolic binding must serve both input and output gates; do not fork target semantics or loosen refusal. Receipts: call-output-symbolic-review/production-consumer-baseline.{log,json}. Existing return fixture also loses actual project/backed callee ownership; repair that evidence prerequisite after adapter interface settles, retaining semantic assertions. Both staged workers37114/20947 remain confirmed live; no production target-proof integration or milestone acceptance.

### Return-pointer native fixture ownership repaired (2026-10-01)

Parent repairs test fixture prerequisite independently of staged adapter: _lift_ssa retains exact angr.Project alongside SSA, maps actual callee RET at0x1013, builds exact caller/callee boundaries and publishes both raw artifacts. Existing16 test functions retain assertion counts; definition and materialization callers now receive actual project rather than losing it/using empty SimpleNamespace. Direct receipt verifies registered caller/callee and callee bytec3; resolver still honestly refuses call_target_unknown. Scoped Ruff/Pyright clean. Formal module terminal30088 still fails at unresolved target seam; exact log return-pointer-after-project-fixture.log (no function-fixed claim). Before-source/ownership/assertion receipts retained in call-output-symbolic-review/. Both staged Devin workers remain handle-confirmed live. Full M0-M7 acceptance open.

### Input-trial native project surface retained (2026-10-01)

Parent adds actual lifted arch/loader to existing input-trial project surface (factory/census unchanged), preserving native-byte/architecture prerequisites for shared symbolic target integration. Formal module terminal28436:9 failed/5 passed/3 warnings in14.64s, same target-gate blockers as baseline. Ruff clean. Scoped Pyright initially found legacy optional storage.address access; parent strengthens existing test with explicit non-null assertion, retaining segment expectation. Final module Pyright96732:0 errors. Scoped type-ratchet-files on both repaired fixture modules exits0 (fixture-type-ratchet.log). Independent reusable parent mutation harness saved as call-output-symbolic-review/review_producer_mutations.py for terminal revised adapter review. Before-source/log receipts retained. Both staged Devin tasks remain live; integration/acceptance open.

### Preliminary producer revision passes independent parent mutations (2026-10-01)

Parent freezes staged producer revision sources (hash manifest in call-output-symbolic-review/revision-parent-snapshot/) while worker37114 continues its own checks. Independent parent harness terminal27134 confirms authentic binding complete and rejects direct t30 mutation, transitive t26 mutation and CALL operand SSA-version corruption; all three typed conflicts at ssa_raw_producer_mismatch. This closes the demonstrated original counterexamples on this snapshot, not final adapter acceptance. Source review confirms cached owned projection, closure instruction/version checks and bindings/refusal ledger comparison; Semantics compatibility remains separate/open. Parent frozen legacy controls terminal68441 exits0:all emitted controls pass, runner reports0 failures/0.2s (excludes import/startup); no production integration. Devin20947 confirms two-call real fixture call2 is SSA index37 versus raw36 due CALL_OUTPUT prefix; retained effect target_binding complete. Both workers still active; full plan incomplete.

### Parent explicit binding-provenance comparison control (2026-10-01)

Deeper frozen revision audit changes only target binding record source_tmp to999. Dataclass equality still declares bindings equal because IRValue provenance is compare-exempt; adapter returns complete/proven. This contradicts its claimed complete-ledger provenance contract, without changing the already-correct target-instruction rejection controls. Parent frozen-only patch reuses _value_matches_projection_8616 for each binding target, with exact version/instr_index and cardinality. Independent terminal71840 now refuses conflict/ssa_raw_projection_mismatch. Red/green receipts and exact before-source remain in revision-parent-snapshot/{binding-provenance-probe,binding-provenance-after-parent-fix}.json and before-parent-binding-provenance.py. Live worker files untouched; apply reviewed narrow delta only after terminal handoff, then durable regression/scoped gates. Parent recheck60194 pending. Both workers remain handle-confirmed live; no production integration or milestone acceptance.

### Terminal producer stage reviewed and parent fixes verified (2026-10-01)

Devin37114 terminal exit0. Parent compares every staged code file against saved current worker hashes (both exact), preserves original terminal sources, applies explicit binding provenance comparison and repairs deliberately unbound raw/SSA fixture coherence while retaining its verdict/reason assertions. Adds durable producer_binding_provenance corruption control. Final staged control run60115:33 emitted passes/0 failures/exit0; Ruff clean and Pyright15144:0 errors. Receipts: call-output-symbolic-review/terminal-producer-stage-parent-{controls.log,receipt.json}; before-parent sources retained in stage. Demonstrated direct/transitive/version and binding-provenance gaps are closed on staged raw-to-SSA path. This remains staged only: Semantics projection worker20947 is confirmed live; coherent Semantics/decoded-coordinate route, shared input/output production integration, focused regression cohorts and final project gates remain required. Full original M0-M7 incomplete.

### Semantics SSA-version parent control and shared closure route (2026-10-01)

Parent verifies existing cached build_x86_16_block_local_ssa over outputs.function matches all three blocks and bindings of real two-call Semantics SSA, including second CALL raw36/SSA37 prefix shift (enriched-local-projection-probe.json). Frozen worker semantic candidate (with diagnostic IRAtom import corrected to owning ir.core only) accepts authentic and target-version7-corrupted SSA after coherent raw/SEMANTIC registrations; receipt semantic-parent-snapshot/call-version-probe-backed.json. This verifies its modulo-version comparison does not establish the claimed SSA projection. Parent frozen-only reuse of reviewed _producer_closure_failure_8616 against outputs.function block keeps authentic complete/proven and refuses mutant conflict/ssa_enriched_operand_mismatch; terminal69242, receipt call-version-after-shared-closure.json. No VEX relift or competing version evaluator introduced. Live worker20947 untouched and confirmed running/refactoring scoped lint failures; integration must retain this exact version/provenance obligation and add durable control after terminal handoff. Full original plan remains incomplete.

### Semantics worker terminal handoff and shared integration task launched (2026-10-01)

Devin20947 terminal exit0 reports35 controls/Ruff/Pyright green, supports real CALL_OUTPUT prefix raw36/SSA37, and documents projection/index plumbing absent from production consumers. Parent baseline audit: all recorded production source hashes unchanged; only sibling staged binder changed by reviewed parent provenance fix. Parent does not accept modulo-version proof claim: verified version7 corruption receipt remains an integration blocker; shared enriched-block closure fix is independently green. Fresh sandbox verification rootRO/repoRW/4GiB succeeds. Launched disjoint staging-only consolidation72972 to produce concrete small shared IR integrity owner, retained Semantics evidence route and copies wiring existing input/output gates (no duplicate materializer or VEX model). Prompt/log call-target-consolidation.{md,log}; scope preserves all M0-M7 requirements and typed refusals. Worker35 controls still require independent terminal-source review/reproduction, production integration and final acceptance gates.

### Terminal Semantics controls independently reproduced; version rejection remains required (2026-10-01)

Parent terminal-source direct control run26284:35 emitted passes/0 failures/exit0, receipt terminal-semantic-parent-controls.{log,json}. Separate reusable parent review_semantic_versions.py terminal41156:authentic complete/proven and coherently rebound target-version7 mutant also complete/proven, so assertion correctly fails; receipt terminal-semantic-version-review.json. This confirms the terminal refactor did not close the demonstrated version-integrity gap. Worker reported green controls are local coverage, not acceptance. Consolidation72972 remains live and explicitly incorporates exact cached enriched-block producer closure; its log acknowledges parent fix. No production target proof integration, no milestone acceptance, full M0-M7 scope preserved.


Parent consolidation follow-up (2026-10-01): live process handle72972 polled successfully; worker remains active. Current staged binder reconstructs each CALL_OUTPUT prefix from retained typed output facts and compares exact instructions including compare-exempt provenance, rather than accepting prefix cardinality alone. Source review confirms this change; mutation controls and terminal parent acceptance remain pending. Public call_operand_producer_integrity_8616 still lacks strict index/type/CALL-op admission in the live staging source. Existing frozen parent red/green receipt consolidation-index-review/after-index-guard.json accepts authentic index34 and refuses negative, MOV index0, bool False and out-of-range999. Apply that reviewed narrow guard after terminal handoff and enroll durable controls; do not modify worker-owned live files. MCP index_status returned approval-required under never policy; source fallback used, graph completeness unknown. No production promotion or M0-M7 acceptance claimed.


Independent frozen consolidation controls (2026-10-01): parent snapshot of shared producer/binder owners proves authentic two-call binary fixture and rejects coherently rebound target SSA-version mutation with conflict/producer_mismatch. Separately, parent changes injected CALL_OUTPUT address to0xDEAD in enriched IR, rebuilds SSA, and coherently rebinds outputs/SSA registry; exact fact-derived prefix accounting refuses conflict/outputs_prefix_mismatch while authentic proof remains complete. Reusable harnesses review_consolidation_versions.py and review_consolidation_prefix.py, frozen sources consolidation-parent-snapshot/, receipts consolidation-{semantic-version,output-prefix}-review.json under call-output-symbolic-review/. These are staged soundness controls, not production consumer/project acceptance; strict public-index guard and terminal worker review still required.


Parent frozen input/output consumer review (2026-10-01): staged copies preserve existing constant-target/materialization behavior and delegate symbolic target proof to one shared binder. Independent real push5/near-CALL binary fixture resolves input definitions (two byte pieces) with complete accounting and AX CALL_OUTPUT with complete provenance. Coherently rebound target-version7 corruption causes both consumers to refuse atomically: input call_target_conflict; output callsite_conflict; neither emits definitions. Harness review_consolidation_consumers.py under call-output-symbolic-review/, frozen consumer copies under consolidation-parent-snapshot/copies/. Parent run42353 exit0. Production orchestration still needs retained semantic projection and once-built decoded index plumbing; consumer optional parameters alone do not close existing24 regressions. Devin handle72972 verified live again. No production promotion/full milestone acceptance.


Parent consolidation broad-control audit (2026-10-01): frozen39-control runner initially35 pass/4 fail. Three gate checks compare copied module enums by identity against production enum classes; parent confirms this is a staged harness identity error, not a change in typed gate behavior. Remaining alleged CONST compatibility fixture e80000 lifts to MemSpace.TMP, const=None, expr:Iop_Add32, version0: production refusal versus new shared-binder proof is intended symbolic coverage. Preserve true constant-target compatibility using actual immediate far CALL, not weaker expectations on this symbolic fixture. Frozen corrected intermediate runner still has2 failures (one parent broad text replacement accidentally changed production baseline enum reference; one mislabeled symbolic compatibility test), so no39-green claim. Live worker independently reports same root causes and is revising its own runner; handle72972 remains active. Production integration needs both semantic-projection retention at SSA construction and decoded boundary index transport/cache for raw-stage consumers; current optional consumer parameters alone are insufficient.


Parent frozen full staged runner now independently passes39 controls (run14833 exit0; consolidation-parent-controls-final.log). Exact log accounting corrects earlier worker-derived count: original frozen run was35 pass/4 fail,39 total, not43. Terminal runner comparison preserves all controls; three copied-enum assertions repaired and alleged near-CONST fixture replaced with actual far-CONST binary while requiring identical production/staged definitions and stats. Worker72972 still live running scoped checks. Strict public-index guard, terminal delta audit, production retention/plumbing and broad gates remain required.


Parent public-index repair now has durable staged controls: frozen shared producer helper requires exact int index, in-range source position and source opCALL before any projection lookup. Extended independent runner keeps all39 worker controls and adds authentic/negative/non-CALL/bool/out-of-range cases. Run80379 exit0:44 controls pass/0 fail; receipt consolidation-parent-index-controls.log, reviewed sources consolidation-parent-snapshot/. This is the narrow parent delta to apply after worker terminal, not an edit to its live ownership. Full M0-M7 and production retention/plumbing remain open.


Retained evidence transport started (2026-10-01): verified fresh sandbox rootRO/repoRW/exact4GiB limit, recorded source baselines, and launched disjoint staged Devin73258 for typed semantic-projection/decoded-index retention and construction/publication/consumer transport copies. Prompt/log call-target-retention.{md,log}; ownership only call-target-retention/; no production edits, pytest pools or binder changes. Parent remains responsible for exact identity/invalidation checks, scope review, integration and acceptance. Existing consolidation72972 continues focused module split with39 runner controls previously independently green (parent frozen guard extends44). Both handles polled live. Full original M0-M7 objective preserved; no acceptance claim.


Production symbolic CALL-target checkpoint (2026-10-01): Devin72972 terminal exit0, delivered13 hashes verified, all20 recorded production/staged baseline files unchanged before parent promotion. Parent AST audit confirms26 moved definitions unchanged across module split. Reviewed strict public-index guard applied after terminal and44 staged controls independently green. Integrated six shared target owners plus minimal input/output resolver deltas; exact pre-integration gate sources retained under consolidation-production-before/. New routine-enrolled test_x86_16_call_target_ssa_binding.py independently passes12 controls with3 workers (12.16s), covering both artifact routes, both native calls, output definitions, coherently rebound target versions, forged CALL_OUTPUT plus rebuilt SSA, and invalid public indices. Ruff and scoped Pyright clean; scoped type-ratchet-files exit0. Existing input/output target-gate cohort20fail/5pass is exactly reproduced by isolated saved dirty-source baseline (same20 IDs, zero introduced/resolved); production still needs retained projection/decoded-index transport. Enrollment cohort118pass/1fail; same legacy CLI selector mismatch independently persists after removing this one enrollment entry, so not attributable to this delta. Full project gates remain open; no function validation or M0-M7 acceptance claim. Devin73258 remains active on disjoint retained evidence route, baseline transport files preserved. Artifacts under call-output-symbolic-review/{production-target-binding-*,production-target-constant-compatibility.log,preintegration-target-gate-baseline.log,production-target-gate-baseline-comparison.json,ownership-enrollment-baseline.log}. Parent owns subsequent integration, actual24-consumer baseline conversion, near-return regressions and final gates.


Target-alias applicability repair (2026-10-01): parent binary regression reproduces decoded_entry_missing on both raw and semantic routes when native E8 target0x1010 is admitted as image-relative0x10. Existing full-width target-identity owner already proves that relation, but decoded-index lookup queried only the unnormalized address. Binder now expands lookup with normalize_x86_16_call_target_addr_8616(project,address), preserving original keys, exact caller/callsite filtering, immutable native proof and final admitted-relation check. No new address arithmetic/semantic model or resource limits. New refused controls cover high-address low-word collision0x11010, different same-caller target0x12 and unrelated0xDEAD. Focused red2fail; final enrolled production module17pass/3warnings16.27s with3 workers. Ruff/Pyright clean and type-ratchet-files exit0; receipts production-target-alias-{red,green,pyright,type-ratchet}.log under call-output-symbolic-review/. Previous tool handles64648/73258 unavailable after environment change; completed pytest log proves terminal17pass, retained-evidence stage has no patch yet. Discovered saved Devin session trite-pump using structured session metadata and resumed that SAME conversation after fresh rootRO/repoRW/exact4GiB sandbox check. New handle59046 verified live; prompt/log call-target-retention-resume.{md,log}. No session lock removed or host permissions broadened. Full original M0-M7 remains incomplete; retained evidence transport, consumer regression closure and project/corpus acceptance remain required.


Routine input-gate coverage checkpoint (2026-10-01): enrolled shared-binding cohort extended to exercise real push5/E8 input definitions on both raw and semantic artifacts, with native0x1010 and image-relative0x10 admitted coordinates. All four cases preserve two exact byte definitions, native push/call coordinates, complete accounting and value5; wrong-callee0x1012 refuses atomically without definitions. Full module21pass/3warnings11.22s with3 workers; scoped Ruff/Pyright clean. Receipt production-target-input-gate-{tests,pyright}.log under call-output-symbolic-review/. Fixture review identifies existing20-failure modules discard their native Project and raw registry after lift, pass symbolic E8 operands as though constant, and use SimpleNamespace loader-only evidence in linked-coordinate checks. Future fixture repair must preserve actual project/boundaries/raw/index and every semantic assertion, rather than weaken refusal. No such original fixture edits made here. Resumed Devin handle59046 remains live; no retention patch yet, so production automatic transport and24-consumer conversion remain open. Full original M0-M7 and project/corpus acceptance preserved.


Existing input-fixture closure (2026-10-01): parent repaired test_x86_16_interprocedural_storage_reaching_defs.py to retain actual Project, registered raw IR, closed binary boundary and decoded index, explicitly transporting evidence to the integrated binder. Includes a real terminal RET in the caller census; does not manufacture constant CALL operands. Rebased-target control now uses the byte-backed original image's full-width loader coordinates while native decoding/proof remains in its Arch86_16 active slice; no loader-only SimpleNamespace proof. Exact AST audit preserves all105 assertions across17 original test functions. Saved baseline had15 failures in this module; final17pass/3warnings10.37s with3 workers, Ruff/Pyright clean, scoped type-ratchet-files exit0. Intermediate failure16 was the fixture's excluded terminal RET, then one CLE address-width setup error; both repaired at fixture evidence boundary without production exception catches or weakened assertions. Receipts reaching-fixture-{native-evidence,complete-boundary,green,final-pyright,final-type-ratchet}.log and reaching-fixture-assertion-review.json under call-output-symbolic-review/. The snapshot before caller edits is reaching-fixture-after-helper-before-callers.py (not a full pre-helper source snapshot). Existing output fixtures, automatic production retention transport and consumer acceptance remain open. Devin59046 verified live and has now produced the first staged retention owner/copies; review/integration still required. Full original M0-M7 acceptance remains unproven.


Existing output-fixture closure (2026-10-01): parent preserves byte-for-byte pre-edit source return-defs-fixture-before.py, repairs test_x86_16_interprocedural_storage_return_defs.py to retain actual Project/raw registry/closed boundary/decoded index and transport them explicitly, with byte-backed original-image coordinate metadata for the rebased case. All original test-body assertions are AST-identical (receipt return-defs-fixture-assertion-review.json); no target-operand fabrication, lowered refusal gate or production exception catch. Standalone8pass/3warnings14.40s; Ruff/Pyright clean; type-ratchet-files exit0. Combined shared-binding/input/output cohort46pass/3warnings14.58s with3 workers (run64080); includes all25 legacy gate tests which formerly had20 failures and21 enrolled shared-binder controls. Receipts return-defs-fixture-{native-evidence,pyright,type-ratchet}.log and shared-target-gates-combined.log under call-output-symbolic-review/. This closes those exact gate regressions, not the separate24 consumer failures, automatic evidence transport, near-return cohort, project gates or original M0-M7 acceptance. Devin59046 remains active building retention owner plus frontend/pipeline/consumer copies; source review has begun but cache invalidation/result completeness still needs frozen adversarial controls before promotion.


Parent retained-evidence soundness review (2026-10-01): independently frozen staged sources expose two admission defects before production promotion. Publication/resolution complete predicates admit PROVEN results with an explicit failure; resolution also admits missing source IR. Frozen predicate guards preserve authentic publication/resolution and reject all three mutations (retention-completeness-before.json vs retention-completeness-after.json). Separately, replacing one authentic project's retained decoded-index record with another project's record makes resolve without an explicit boundary return complete/PROVEN with a foreign boundary. Frozen project/caller identity guard rejects that mutation as CONFLICT/CALLER_BOUNDARY_CONFLICT while the original resolves complete; receipts retention-foreign-cache-before.json, retention-foreign-cache-review.json and retention-foreign-cache-green.log. Reusable review_retention_complete_contract.py and review_retention_foreign_cache.py plus exact frozen sources are under call-output-symbolic-review/. These are staged red/green controls only; worker-owned live files were not changed, durable enrollment and terminal-source parent integration remain required. Devin59046 confirmed live by successful handle poll; worker is investigating the remaining staged input-consumer STORAGE_PIECE_CONFLICT after correcting class-reload and fixture-boundary issues. Full original M0-M7 acceptance remains open.


Extended frozen completeness review (2026-10-01): reusable parent harness now includes eight mutation controls: explicit publication/resolution failures, missing source, empty accounting on either result, missing resolution boundary and wrong caller identity on either result. Saved original predicates wrongly accept every mutation; reviewed predicates refuse all eight while both authentic positives remain complete. Independently rerun green exit0 and original-source red exit1; updated retention-completeness-{before,after}.json. This extends staged evidence only, not production acceptance.


Parent semantic-publication propagation review (2026-10-01): independent frozen real raw-stage fixture has its registered raw artifact replaced with a conflicting caller address before requesting semantic SSA. Original staged pipeline ignores publish_function_ir_artifact_8616's refusal and returns SSA PROVEN while the raw registry remains UNKNOWN_REFUSE/ARTIFACT_CONFLICT. Frozen narrow propagation guard, following existing IR-registry behavior, returns SSA UNKNOWN_REFUSE/ARTIFACT_CONFLICT and does not publish the new SSA. Parent harness review_retention_publication_failure.py preserves an authentic semantic fixture positive and rejects the corrupted raw-registry path; final rerun exit0. Original red receipt retention-publication-failure-before.json and reviewed green retention-publication-failure-review.json are under call-output-symbolic-review/. Worker-owned live files untouched; require this guard and durable production regression during terminal integration. Independent hash check verifies all8 production baseline files unchanged (retention-production-baseline-review.json). Full original M0-M7 remains open.


Fresh raw-route mutation review (2026-10-01): independent frozen parent binary control first admits the authentic two-call raw fixture, then replaces its raw registry entry with a same-address push/call fixture and resolves evidence again. Fresh accessor remains complete because it inventories the registered raw artifact; the required shared binding rejects the mutation with SSA_RAW_INDEX_MISMATCH, while original binding is complete. Harness review_retention_raw_fresh_binding.py and receipt retention-raw-fresh-binding-review.json are under call-output-symbolic-review/. This verifies binder refusal even after fresh resolution, rather than relying only on a stale pre-mutation accessor result. Accessor completeness is transport availability, not authentication or equivalence proof; preserve that boundary in documentation and durable consumer tests. Devin59046 confirmed live; terminal review/promotion still pending.


Parent routine-regression draft checkpoint (2026-10-01): created11 explicit binary/result-contract pytest controls under call-output-symbolic-review/test_retention_parent_contracts.py for eight invalid complete-result mutations, implicit foreign cached census, raw publication conflict propagation and fresh raw mutation followed by binding. Isolated frozen-source run before completeness guards:8fail/3pass1.60s. Same assertions after merging proven parent completeness guards into frozen owner:11pass1.88s; Ruff clean after adding useful test docs. Receipts retention-parent-contract-tests-{red,green}.log; runner run_retention_parent_pytest.py uses one isolated interpreter (-n0) because staged import overrides do not propagate into xdist workers; no overlapping pool or production mutations. This is a draft for durable test enrollment after terminal-source integration, not an already enrolled production acceptance. Devin59046 verified live and is closing staged scoped Pyright findings in a merged preview. Full original M0-M7 acceptance remains open.


Preintegration consumer baseline refreshed (2026-10-01): actual shared-tree two-module consumer cohort independently reproduces24fail/6pass/3warnings13.67s with3 workers before retention promotion; receipt retention-preintegration-consumer-tests.log. Exact source snapshots saved in retention-consumer-fixtures-before/. Existing return-pointer helper retains native Project/raw IR but omits decoded-index transport into the standalone resolver; input-census helper wraps the native lifter in SimpleNamespace and needs a byte-backed caller/callee boundary review. Preserve every original semantic assertion when repairing fixture evidence. Graph index_status retried and explicitly denied approval under never policy; source fallback used, completeness unknown. Devin59046 remains live preparing terminal REPORT.md; production counterpart hashes still match the8-file recorded baseline. Full M0-M7 acceptance remains open.


Retained CALL-target transport production checkpoint (2026-10-01): Devin59046 terminal exit0; parent verifies all7 delivered hashes and all8 original production baseline hashes, reviews all owned deltas, independently reproduces42 staged controls, then applies proven completeness/project-cache/raw-publication guards in a separate delivered snapshot. Final guarded worker controls42pass0fail1.4s. Parent13-control draft passes2.46s; codegen controls explicitly reproduce2fail/11pass1.44s against pre-guard sources and pass after publication is checked before codegen mutation. Semantic resolver now inspects raw publication and projection retention before admitting new SSA; codegen checks both before exposing publication fields. Promoted six reviewed files plus new routine-enrolled test_x86_16_call_target_evidence_retention.py (Makefile/test_pipeline/ownership/architecture registries coherent). Exact pre-promotion source copies retained under retention-production-before/. Production four-module gate cohort59pass/3warnings20.30s with3 workers. Ruff clean on all six owners/new tests/enrollment sources; scoped production Pyright initially flags only the new SimpleNamespace codegen mock. Parent replaces it with a fully initialized typed codegen double preserving prior raw-stage state; isolated test Pyright0errors. All six production owners have no scoped type errors. Final13-test rerun tracked in retention-production-final-contract-tests.log. Postintegration consumer cohort still24fail/19pass/3warnings11.12s (includes13 new controls); same original24 consumer failures remain, not claimed fixed. Next: repair native fixture evidence and production consumer census transport without changing semantic assertions, run near-return/enrollment/type ratchet and project gates. Full original M0-M7 acceptance remains open. Receipts under call-output-symbolic-review/retention-delivered-parent-{controls,final-controls,contract-tests}.log, retention-codegen-parent-red.log, retention-production-{gates,consumers,pyright,test-pyright}.log. No claim of function-fixed or full binary acceptance.


Pointer-return consumer fixture closure (2026-10-01): parent repairs only native fixture helpers in test_x86_16_interprocedural_storage_return_pointer.py: retain the exact reachable decoded caller index and forward resolved project-scoped evidence into the standalone output-definition gate. Actual caller/callee byte images and native proof remain intact. AST audit verifies all64 assertions across16 original tests unchanged. Before15 failures; final16pass/3warnings10.35s with3 workers; Ruff and scoped Pyright clean. Receipts retention-pointer-fixture-{green,pyright}.log and retention-pointer-fixture-assertion-review.json; source before repair retained in retention-consumer-fixtures-before/. This closes15 of the24 consumer failures; nine input-census failures remain. Fresh sandbox probe confirms rootRO/repoRW/exact4GiB. Started Devin21945 on disjoint staging-only input-consumer-fixture/ helper repair; prompt/log input-consumer-fixture.{md,log}, original source/hash saved. Worker serial pytest only; parent reserves broad/enrollment/near-return pytest until terminal. Parent source review confirms higher near-return selector fixtures consume this same _definition helper and already retain decoded indices; independently verify receipts before broader acceptance. Full original M0-M7 remains open; no function-fixed or global-gate claim.


Retention checkpoint follow-up (2026-10-01): scoped type-ratchet-files for all six promoted production owners exits0 (retention-production-type-ratchet.log). Parent direct native near-return receipt checks now all succeed for DS, SS, ES and retained stack-entry selectors, including complete segment preservation and correct pointer-address spaces; receipt retention-near-return-native-receipts.json. These are four direct native controls, not the complete higher selector pytest cohort. The original21 upstream failures may be relieved by the shared helper repair, but require the actual cohort after the input worker's serial tests finish. Devin21945 confirmed live and independently reproduces the remaining9 input failures; no parent pytest pool overlaps its work. Full project/corpus/M0-M7 acceptance remains open.


Retention integration static acceptance (2026-10-01): production make architecture-check-fast test-ownership-check exits0; startup architecture checks passed and ownership manifest check completed successfully. Receipt retention-production-static-gates.log. This validates new routine test enrollment/startup constraints, not full architecture/quality/pipeline acceptance. Current-follow-up ledger now reflects integrated transport,59 gate controls,15 pointer-return failures closed and9 input failures still staged, replacing the stale under-review transport wording. Devin21945 remains verified live investigating exact SSA/native input target binding; no overlapping parent pytest pool. Full original M0-M7 remains active and incomplete.


Independent input native-coordinate review (2026-10-01): parent verifies six actual byte patterns used by the remaining input fixtures (signed PUSH, two PUSHes, no PUSH, BP address PUSH, global word PUSH, numeric PUSH). Original CALL bytes remain unchanged; append a real C3 RET at the fixture's existing target/fallthrough, construct an exact reachable caller census, register raw IR and build its decoded index. All six shared raw SSA bindings prove, each decoded callsite/target matches the existing summary exactly and each index has one decoded call fact. No target rebasing, constant IR fabrication, expectation edits or production changes. Receipt input-fixture-native-call-receipts.json under call-output-symbolic-review/. This changes the parent review criterion for Devin's fixture repair: keep original CALL coordinates and close the native terminal census, rather than rewrite call targets. Devin21945 confirmed live and independently diagnoses CALLER_BOUNDARY_MISSING from the fake caller object. Full nine-test consumer closure and broader gates remain pending; native-target receipt proof is not trial materialization or full M0-M7 acceptance.


Current frozen-corpus identity preflight (2026-10-01): all10 existing frozen input files still match recorded byte size/SHA256; original20-function selection remains unchanged. All three recorded extant comparator proof sources now differ from the historical manifest (straightline_ssa.py and both flat32 drivers), and recorded tools/dosunit/real16_repeat_contracts.py no longer exists. Fresh report retention-corpus-identity-preflight.json records hashes, exact unchanged selection, changed/missing sources and identity-preflight-only status. Initial preflight attempted to read the missing legacy path and raised FileNotFoundError; corrected reporting preserves missing identity explicitly instead of hiding it or rewriting the historical manifest. No current corpus comparisons executed and no old reports promoted. Next corpus checkpoint must seal current semantic owners/source dependencies, preserve the original input denominator and declare normal Cython/cache/resource conditions. Devin21945 remains verified live on staged input fixture repair; parent broad pytest remains reserved until terminal. Full original M0-M7 remains incomplete.


Near-return exact-control replay (2026-10-01): isolated direct invocation of the existing declared parameter cases (no second pytest pool) now passes all21 entry-selector controls plus two SS/ES controls, then stops honestly at test_stack_selector_consumes_only_retained_caller_entry_context. Complete retained caller/callee coverage and one Alias restore source are present; context refuses ENTRY_UNPROVEN/CALL_NOT_DIRECT_NEAR. Parent native binding diagnostic identifies the actual lower refusal SELECTOR_WINDOW_UNPROVED for the backward E8CBFF at0x1032 to0x1000 (next0x1035; displacement bit pattern65483; retained dword control composition). Existing direct-call entry owner already calls the shared native binder, so this is not a missing symbolic-target adapter. Its all-admitted-fetch-window obligation is undisclosed by the blob fixture; do not weaken it or change the positive expectation to hide the requirement. Need an explicit proved selector-window/domain premise or an independently justified fixture domain, with negative window controls. Evidence retention-near-return-direct-controls.{json,log}, retention-stack-{context,native-binding}-review.json and replay_near_return_controls.py. Initial direct script failed only because repository root was missing from its import bootstrap; corrected in the diagnostic runner, no production catch added. Remaining7 cases were not executed after the first failure; no whole-cohort acceptance claimed. Devin21945 verified live; it reports candidate14pass and102 original assertions preserved, still awaiting terminal-source review/lint. Full M0-M7 remains open.


Input consumer parent acceptance checkpoint (2026-10-01): Devin21945 terminal exit0, delivered candidate hash7a6eac1f9479bbaff3b08e14f3841cb4aad1dc09c6ba9eb2bdc342a616d429cd verified; production baseline9d5f8a25986d20b1381f91cb6b36820d7e40e533b9a33adba3611e12fc4ebde5 unchanged before promotion. Parent independently reproduces14pass/3warnings11.73s with3 workers, reads entire delta, verifies every original test-function AST unchanged and all102 module asserts identical (97 in14 tests,5 in unchanged helpers; worker's wording conflated the counts). Real native Project and exact caller census retain original CALL bytes, append one C3 terminal, publish decoded index and preserve all summary/census facts; remove unused fake function manager. Parent promotes helper repair, replaces test-boundary cast(Any, project) with documented vars(project) extension installation, and removes staging-only doc wording. Production combined input14/pointer16/retention13 cohort43pass/3warnings10.97s. Scoped Ruff and two-fixture Pyright0errors. Exact source before promotion saved retention-input-fixture-production-before.py; receipts retention-input-fixture-parent-{review.json,tests.log}, retention-input-fixture-production-tests.log, retention-consumer-fixtures-final-pyright.log. All original24 consumer failures now closed; no broad acceptance inferred. Actual near-return entry/segment cohort1fail/30pass/3warnings14.07s; sole failure is the proved missing selector-window prerequisite, not the shared output gate.

Selector-window independent execution checkpoint (2026-10-01): Unicorn UC_MODE_16 replays exactly one E8CBFF at physical0x1032 with hook-verified initial CS:IP, same mapped bytes and fresh state per vector. CS0/IP0x1032 and CS0x100/IP0x32 reach physical0x1000; CS0x103/IP2 reaches0x11000 (IP0xFFD0); each pushes one near word return, SP0x800->0x7FE. Native instruction hook confirms all three fetched the same physical callsite, so this is a realizable counterexample to an unconditional fixed physical target under the current admitted selector set. Receipt retention-selector-window-native-replay.json. Do not relax _target_in_all_fetch_windows_8616 or silently assume CS0. Next M5 closure must admit an explicit proven narrower selector/fetch-window domain (or corresponding caller-established premise) with immutable provenance, propagated domain/conditional status and negative countercontrols. Current near-return positive fixture must supply that missing premise instead of replacing backward CALL with an easier forward sample. Full original M0-M7 remains active/incomplete.


Current comparator interface/selector review (2026-10-01): isolated serial runs remove the combined-run top-level z3cmp32 import collision: BC5 adapter19pass3.02s, MSC8 adapter17pass3.70s; shared dosunit202pass/3fail/5skip56.03s. Remaining failures are shifted-region-proven-callee and mapped-direct-call control outputs (observable_mismatch), plus bounded-loop ABI composition (control_flow_unproved); not classified as pre-existing or fixed. Original assertions unchanged. Captured current lowered documents and compare results under call-output-symbolic-review/. Parent Z3 checks original shifted-call terms: word ip equals decoded target for all inputs, full control_ip equals it only under the actual callsite valid-fetch CS domain [0,0x120]; two negated full-control lemmas unsat under that domain, sat unconstrained. Receipt symbolic-call-fetch-domain-review.json. A domain-aware proof boundary is required; neither force CS0 nor erase full control outputs.

Devin selector-window-premise terminal review (2026-10-01): independently reproduce original11 controls, but reject production integration: replacing retained instruction_entry_states[0x1032].cs with an unproved CONST_WRITE/PROVEN source0 retains exact artifact identity and yields complete=True with singleton[0,0] on the native counterexample-containing isolated backward-CALL fixture. Receipt selector-premise-parent-forged-state.json. Original production owners untouched; claim that supplied numeric states cannot grant admission is false for that staged version. Frozen all3 worker deliverables under selector-window-premise/parent-review-before/ with SHA256 manifest. Verified fresh rootRO/repoRW/exact4GiB sandbox. Started bounded Devin27572 repair, staging-only, no production edits/pytest pool; require solver recomputation from retained bound dependencies or honest refusal, singleton fetch membership and authentic/corrupted controls. Prompt/log selector-window-state-repair.{md,log}. Full M0-M7 remains incomplete; corpus and release acceptance still open.


Current retained-evidence regression refresh (2026-10-01): final shared-tree pointer-return, retained-call-evidence and SSA-call-input modules46pass/3warnings9.12s with3 workers; receipt current-retention-regression.log. This is the current cohort count, not the earlier43-test frozen denominator. Initial invocation used a nonexistent input-module filename and collected0 tests/exit5; corrected to test_x86_16_ssa_call_target_inputs.py before reporting success. No production edits in this review turn; shared-suite3 failures and near-return domain refusal remain open. Devin27572 independently reproduced the exact forged-state red and is repairing staged recomputation/dependency validation.


Bounded-loop control diagnosis (2026-10-01): independently translate the three current countdown nonterminal SSA parts to Z3 and negate membership in their retained direct-successor sets under each terminal instruction's valid-fetch CS interval. All three checks unsat with1000ms solver caps, total diagnostic process0.094s; receipt symbolic-loop-successor-domain-review.json. Composition currently consumes symbolic full control via literal-only _target_key, so it cannot follow these physically invariant successors. Membership alone does not prove branch-arm correspondence or discharge an unbounded loop: preserve predicates, exact successor-domain proof, loop/status/resource contracts during any adapter repair. Initial diagnostic accidentally called .get on terminal transfer=None; corrected explicit terminal handling in diagnostic only, no production catch.


Selector-state repair parent checkpoint (2026-10-01): Devin27572 terminal exit0. Parent reads exact module+runner delta against parent-review-before/, verifies all5 production baseline hashes unchanged and final staged hashes against revision2-manifest.json. Independent full final controls13/13pass; exact supplied-CS forgery now STATE_PROVENANCE_UNREPRODUCED, authentic domain[0,0x100] remains complete, native counterexample domain[0,0x103] remains retained. Parent scoped Ruff clean/Pyright0errors on final staged files. Receipts selector-premise-parent-final-controls.log and selector-premise-parent-repaired-state.json under call-output-symbolic-review/. Solver replay consumes bound IR plus complete same-artifact retained call-preservation/entry-context dependencies; checks singleton callsite fetch membership. Important limitation: SegmentStateArtifact does not retain original function_ssa/restore_sources, so CS facts requiring those unreplayed inputs refuse. Still staging-only, no production integration or full M5/M0-M7 acceptance. Next integration obligation: authoritative bound selector-domain dependency transport and domain-aware symbolic-control/successor proof, with backward-wrap negatives, exact branch predicates, loop/resource/status gates preserved. Shared dosunit3 failures remain open; both flat32 adapter suites and46-test retention cohort green as above.


Required Cython startup checkpoint (2026-10-01): live source inspection found normal lifter startup still defaulted to interpreted Python, contrary to the user's earlier requirement. Parent changes lifter_backend default to CYTHON, preserves explicit python diagnostic/auto compatibility modes, updates selection docs/README and enrolls backend checks in Make, fast pipeline and a specific ownership rule. New two default-mode controls red before patch; final14 backend/parity checks green. Actual default import verified extension/source hashes against active.json. Compiled-default retained-evidence cohort46pass7.46s with2 workers; no speedup claim against earlier different-worker run. Scoped Make linters-files/type ratchet and startup architecture/context/ownership gates exit0. Final backend/enrollment/tooling cohort142pass25.57s with2 workers. Initial9 failures:8 Make stdin-oracle failures because /tmp is read-only (all9 inventory tests pass after TMPDIR=.cache), plus stale CLI ownership expected list omitting two already-enrolled controls. Saved dirty pre-run ownership source selects exactly the same20 CLI targets as current source; parent preserves all18 original expectations and adds the two omitted future-collection/ranked-queue controls, no production CLI changes. Reports under required-cython-default/. No decompiler function-fixed claim or full release acceptance.

Fresh compiled corpus baseline started (2026-10-01): original20-function selection and all10 frozen inputs retained, with matching hashes/sizes. Sealed2997 Python/schema/config/build files and the exact current Cython active manifest+extension in corpus-compiled-20261001-5p88ef7_/sources; source copy checked against live content and later immutable inventory. Runtime probe confirms both comparator and compiled lifter import from snapshot, with CYTHON selected. Initial probe incorrectly resolved the venv interpreter symlink and lost installed packages; corrected to absolute venv entry path, no weaker environment fallback. Existing reviewed serial runner reused, plan-only integrity passes. Execution61571 currently live,5 self/changed commands in cold/warm pairs, original flags/budgets unchanged except explicit120s outer process cap; no assumption/normalization modes added. Actual reports pending, historical reports not promoted.

Shared control-domain intake started (2026-10-01): Devin31560 owns only real16-ssa-control-domain/ staging. Prompt/log real16-ssa-control-domain.{md,log}; saved main comparator/control owner/test sources, fresh rootRO/repoRW/exact4GiB probe verified. Worker reproduces all3 shared-suite failures and stages source-/native-/domain-bound control normalization/routing, preserving full control, predicates, backward-wrap negatives and bounded solver budgets. Parent owns integration and corpus/release acceptance. New AGENTS instructions applied; codebase-memory skill read. index_status denied but subsequent search/trace/coverage calls succeed: home-xor-vextest generation2026-10-01T01:36:29Z, coverage exact8 paths/no pages outstanding; comparator/shared coordinate files metadata_match, touched backend and enrollment files metadata_changed and read directly. Graph direct traces confirm _prepare_call_normalized_functions -> _with_call_bound_control_outputs and _compose_abi_state -> _abi_control_term. Full M0-M7 remains incomplete.


Fresh compiled frozen-corpus terminal checkpoint (2026-10-01): execution61571 exit0; harness complete, all5 commands/10 cold-warm phases parsed with complete selected-row accounting. Original20 functions and10 frozen inputs unchanged; sealed2997 source/schema/config/build files and exact active Cython extension. Receipt corpus-compiled-20261001-5p88ef7_/runs/20261001T034601Z-run-4-000/run-report.json. Real16 self3unknown (InsertionSort call_target_unmapped; SwapBars macro_unsupported_boundary; Sleep cold macro_admission_refused/warm call_target_unmapped). MSC8 self2pass; changed sub_2B0D0 region_lowering_incomplete, sub_319B0 observable_mismatch. BC5 self/changed15refused call_or_exception_boundary. Top verdicts agree cold/warm, but refusal detail and bounded proof outcomes can differ (BC5 sub401234 call-return cold timeout vs warm counterexample). This is a current compiled baseline, not cache acceptance, performance gain or whole-plan proof.

ABI bounded-loop soundness defect reproduced and fixed (2026-10-01, parent delta): compare_ssa_abi_documents previously admitted summaries with loop_cuts>0, dropping live cut branches. Synthetic legacy SSA negative with mutation on iteration7 returned passed at unroll2; independent native16 Unicorn witness count7 returns7 vs9. ABI now requires complete paths and enables only literal composed-predicate pruning; live cut paths refuse loop_bound_incomplete. New negative and complete-constant-loop positive both red before; focused region/ABI controls4pass7.38s after. Two old partial-loop passed expectations corrected because they asserted unsound whole-function proof, not renamed/filtered to hide failure. Saved evidence abi-loop-cut-audit/{oracle,candidate,manifest,before,native-witness}.json and red/green logs. Full212-test dosunit suite running; worker31560 remains staging only. No induction claim from finite unrolling; original M0-M7 remains incomplete.


ABI parent-review correction and final focused checkpoint (2026-10-01): full212-test dosunit run initially204pass/3fail/5skip40.62s. Two failures are the existing symbolic shifted/mapped-call cases owned by Devin31560. Third was a parent expectation error: literal pruning completely closes the stack-argument loop (zero cuts), so it must keep passing. Restored that original positive and strengthened it to require oracle/candidate loop_cuts==0 plus branch pruning. Final ABI/region28pass20.01s3workers; Ruff both touched files clean. Only the unbounded native countdown positive was corrected to honest refusal (routing or incomplete path); the delayed-mutation negative proves the unsafe prior behavior independently. No additional full-suite run until new production semantic changes justify it.


Staged control helper parent negative (2026-10-01, not promoted): independent probe changes only control_domain.terminal_linear from native0x1000 to0x10ff0 and recomputes its selector lower bound0x100; instruction bytes/hash/address remain E80000 at0x1000. A term that equals0x1003 only for CS0x100 and equals0x1004 otherwise honestly refuses with the true terminal, but the staged helper claims PROVEN after marker tampering. Terminal metadata is not cross-checked with the actual last native instruction, allowing an artificially narrowed theorem domain. Receipt abi-loop-cut-audit/control-terminal-binding-review.json binds tested helper SHA and both outcomes. Reject current staged integration until native terminal identity is enforced and this negative remains refusal. Worker31560 is still running; no production control-domain patch accepted.


ABI soundness scoped gate closure (2026-10-01): explicit Ruff both touched files clean; make linters-files exit0, with existing promotion rules skipping these legacy modules for Ruff/MyPy (not claimed as typing success). Startup architecture/context/ownership checks exit0. Saved after.json rejects the exact prior false-proof pair as loop_bound_incomplete,0 solver_ms,~2ms diagnostic elapsed. This is no corpus throughput claim. Plan remains active; next action review terminal Devin31560 delivery, reject terminal-marker narrowing, stage a bounded followup with exact disjoint ownership, then reproduce negatives and integrate only sound native-domain routing.


Control-domain parent-review continuation (2026-10-01): previous goal turn classified progress (ABI complete-path source fix and red/native evidence), not blocked. Devin31560 remains confirmed live via the same exec handle; no restart from observation timeout. Parent saves an executable independent red negative at abi-loop-cut-audit/test_control_terminal_binding_review.py:1failed18.74s, exact forged terminal marker yields false PROVEN while genuine domain refuses. Prepared bounded followup prompt real16-control-terminal-binding-review.md; launch only after current worker is terminal and exact staged pre-run sources are saved. A parent note in its staging directory explains the complete-path ABI correction and forbids restoring passed with loop cuts.

Flat32 preservation check after ABI complete-path change: MSC8 adapter17pass in the attempted combined collection; BC5 collection cannot share that process because both standalone suites are named test_z3cmp32 and use same top-level module names. BC5 isolated run19pass5.27s, two workers while staged worker retains at most one serial pytest; aggregate3 maximum. Initial combined collection error explicitly retained, not promoted to whole-suite success. No ELF tuning or production flat32 edits. Graph Tier2 refreshed home-xor-vextest generation2026-10-01T01:36:29Z: _abi_control_term/_record_lowered_part/_with_call_bound_control_outputs and allfetch guard discovered4/fullpage; comparator/test metadata_changed, source read; coordinate/arch/binder metadata_match. Wrong initial semantics/control_coordinates.py path was corrected to X86_16/control_coordinates.py and separately coverage-checked/read. Scope and M0-M7 completion remain unchanged/incomplete.


Shared control intake terminal review (2026-10-01): Devin31560 terminal exit0. Saved its exact helper/tests/proposal/handoff plus current core/test/FactCounters sources as7 immutable baselines under real16-control-integration/before/. Parent independent staged+forged-terminal negative13pass23.42s3workers; initial forged terminal marker attack is fixed (native terminal must match contiguous hashed instruction list). Helper stays staged: proposal has illustrative @@ function headers, not an applicable unified patch; adapters omit aggregate encoding/deadline and closed fact accounting. Reviewed positive caller examples are conditional staging evidence, not public production acceptance. Fresh rootRO/repoRW4GiB probe verified, new bounded Devin86571 launched at2026-10-01 04:32:04UTC with prompt/log real16-control-integration.{md,log}. Ownership only new candidate/report/tests area; no production, old staging or baseline edits. Task supplies bounded memoized DAG encoding/cycle/width checks, aggregate/caller budgets, authoritative FactCounters/report propagation, typed transfer kind, actual minimal3-seam unified diff. Current worker confirmed live via same handle; no duplicate terminal-forgery job launched.

Current adapter/execution retention: isolated MSC8 adapter17pass12.65s,BC5 adapter19pass5.27s (2 workers; earlier combined collection collision retained). PE32 boot/replay/CLI and real16 initialized file-copy cohort93pass14.83s2workers, with real self/equivalent/mutation/refusal/snapshot controls. These focused cohorts do not establish arbitrary Windows services, native DOS backend availability or whole M6/release gates.

ABI entry-register false-proof correction (M0,2026-10-01): native mov ax,bx;ret (89D8C3) vs xor ax,ax;ret (31C0C3) falsely passed because _initial_abi_state silently zero-filled unspecified BX. Saved source/test/SSA/image/manifest before baseline at abi-entry-register-audit/. New actual-MZ negative red1fail; alternative MOV encoding8BC3C3 positive already green1pass. Parent changes only entry initialization: registers without existing explicit scaffold defaults now symbolic rather than zero; includes CS. Existing FLAGS/DS/ES/SS model defaults retained and documented, SP symbolic. All30 ABI/region controls pass7.79s2workers, including unbounded-loop refusal and complete constant-loop positives. Freshly lowered after.json returns observable_mismatch,69 solver_ms for the same corrupt binaries. Independent Unicorn9 vectors (BX0/7/65535 across original/corrupt/equivalent) execute actual complete near RET to declared continuation, allSPff02/IP1300; two nonzero mutation vectors differ, equivalents preserveBX. Arena0x40000,SS3000,SPff00,FLAGS202 explicitly recorded. Ruff direct both touched files clean; startup/context/ownership exit0; linters-files exit0 but excludes these legacy modules from promoted MyPy/Ruff scope, not typing acceptance. Parent informs staged worker to preserve/rebase this concurrent correction; no whole-file production replacement. Execution spec updated with honest symbolic-entry and complete-path contracts. Full M0-M7 still incomplete; two public mapped-call failures remain until reviewed production integration.


Real16 control integration parent review (2026-10-01): Devin86571 finished the isolated candidate; no production promotion yet. Parent independently reproduced all27 staged controls in9.53s/3workers, including the two public caller regressions through the candidate adapter. Review found the advertised250ms attempt limit was not aggregate outside the main thread: the fallback deadline was checked only during encoding and each solver query reused the full timeout. Parent added two deterministic deadline controls (red2fail), then staged an absolute monotonic deadline in ControlProofBudget, per-query remaining-time timeouts, rejection of late solver results, and a final boundary deadline check. Signal timer remains an additional guard, not the only bound. Final verification recorded separately below. Remaining review obligations: closed FactCounters enforcement on all success paths, preserve concurrent symbolic ABI entry-register and complete-loop fixes, production enrollment and independent public regression/gates. No M0-M7 completion or function validation=passed claim.

Parent deadline revision verification: all29 candidate integration/staged controls pass9.79s with3workers; scoped Ruff on both helpers and integration tests clean. Two new deterministic controls reject a late unsat and verify shrinking query timeouts/expired-deadline early exit without signal alarms. This remains staging evidence; production promotion and original M0-M7 acceptance remain open.


Real16 control-target production checkpoint (2026-10-01): parent promoted Devin86571's reviewed helper through a minimal patch, preserving concurrent symbolic ABI entry-register and complete-loop-path guards. New native-bound control-domain producer and real16_control_targets/real16_control_boundary owners are enrolled in routine tests, typing and ownership gates. Proof attempts retain predicates, reject backward fetch-window wrapping and validate contiguous native bytes/hash/terminal; no flat32/ELF tuning. Encoding is memoized and bounded to8192 unique nodes,250ms aggregate attempt and8 shared solver queries, additionally respecting the caller deadline.

Independent Devin68870 review terminal exit0 reproduced relocation-normalization false proof, premature product consumption and unenforced evidence accounting. Parent reproduced the native relocation exploit before correction and retained permanent actual-lowered negatives. Raw native routing proofs now exclude pair relocation normalization; consume products only after successful replacement/route selection; failed/pending accounting refuses. Parent additionally fixed a preclassification expired-proof fallthrough into modeled mismatch: failed proof attempts now propagate typed control_proof_refused. Absolute deadlines shrink each solver query and reject late unsat/results even without signal timers. Exact source baselines and review/replay evidence retained under .cache/comparator-implementation/real16-control-integration/ and real16-control-parent-review/.

Final production cohort:243passed5skipped19.29s,3workers, no overlapping heavy job (production-tests-accepted.log). Earlier overlapping240pass1fail5skip run remains recorded; its intermittent positive failure is not independently attributed to the deterministic expired-proof bug. Isolated MSC8 adapter17pass24.20s and BC5 adapter19pass11.46s retain flat32 coverage before the final real16-only failure-accounting correction. Final four-helper/test Pyright0errors1.699s; touched Ruff, scoped linters/type ratchet and startup/context/ownership pass. These focused checks do not establish arbitrary-binary proof or full milestone acceptance.

Broad quality-dev stopped in linters-dev (exit2); downstream test/decompiler lanes did not run. Actual blockers: return_defs.py:362 Any return from mypyc and reaching_defs.py:129/130 Any return from dev MyPy. Not classified as unrelated/pre-existing without baseline evidence. Bounded Devin39885 is staging a typed dependency/config repair under call-binder-type-gate/candidate only, with immutable7-file baseline and verified rootRO/repoRW4GiB sandbox. Parent review/integration, broad gates and a fresh unchanged-denominator20-function real16/MSC8/BC5 corpus checkpoint remain required. Original M0-M7 remains active and incomplete.


Fresh frozen corpus production checkpoint (2026-10-01): corpus-control-20261001-cnr4ashm snapshot seals3027 source files, unchanged original20-function selection/10 inputs, retained interpreter/packages and byte-verified Cython lifter source+extension. Plan integrity passes; serial2GiB runner terminal exit0, all5 commands/all10 cold-warm phases parsed with complete accounting and no harness failures. Real16 self3unknown (macro_admission_refused/macro_unsupported_boundary); MSC8 self2passed, changed1refused+1failed (the retained concrete sub_319B0 observable mismatch); BC5 self15refused and changed15refused. No representative coverage gain established by this control-domain change. Recorded cold/warm seconds: real16 86.241/53.795, MSC8self9.257/9.507, MSC8changed10.008/11.010, BC5self11.508/11.008, BC5changed12.009/14.265. Shared-host load and separate per-function limits preclude an isolated throughput claim.

Parent semantic-field receipt comparison excludes timing only and retains statuses/reasons/dependencies/assumptions: all statuses retained, but BC5sub_401234 alternates region_lowering_incomplete versus call_or_exception_boundary because one phase hits its unchanged5000ms lower limit. Thus harness completion is not M7 cache/dependency-parity acceptance; timeout variability remains visible. Raw receipts also differ on solver timings. Original runner carries a historical generic live-extension caveat; this snapshot in fact includes the extension and parent independently verifies its byte hash against the receipt, without changing the frozen runner. Full report under runs/20261001T063005Z-run-4-000/run-report.json and bounded parent-summary.json. Broad typing fix remains live/unreviewed in Devin39885; original M0-M7 stays incomplete.


Typed dependency gate parent integration (2026-10-01): Devin39885 terminal exit0 delivers4entry config-only normal-follow override for analysis_helpers/call_target_identity/call_target_ssa_binder/call_target_ssa_contracts. Parent reads full report/diff, verifies all7pre-run production hashes unchanged, independently reproduces3errors red versus0green with isolated MyPy caches, then applies the exact minimal pyproject.toml delta. No runtime source, suppression or compiled-target change. Worker full364file dev cohort green; QA1350file saved-baseline set comparison removes exactly2errors with zero additions (655other error-lines remain). Parent corrects earlier parallel-log attribution: all3consumer diagnostics reproduce in MyPy; do not claim that the previous :362 error came from mypyc.

Fresh parent quality-dev terminal68786 exit2 in linters-dev, now at actual GCC mypyc compile error: acceptance_scorecard _validation_verdict_from_output emits missing CPyDef_work_items___TailValidationDisplayOutcome constructor reference while header offers CPyType. Subsequent type/decompiler/regression lanes did not run. No blanket pre-existing classification. Fresh rootRO/repoRW4GiB verified; bounded Devin81123 launched with immutable4file baseline, ownership only scorecard-mypyc-enum/candidate and new report/logs. Task requires one isolated baseline native reproduction, minimal compile-safe typed status fix, unchanged scorecard status/metadata-priority controls and retained compile target coverage; no production writes/broad gates. Parent review remains pending. Corpus sum10 serial phase times228.608s; largest recorded direct-child RSS409144KiB, shared-load measurement not throughput acceptance. Full original M0-M7 remains active.


Mypyc enum cache-boundary parent acceptance (2026-10-01): previous turn is progress, not blocked/wait-only. Devin81123 terminal exit0; parent reads full minimal2file diff/report, verifies4immutable production baseline hashes, confirms sole private normalizer caller by graph/source scope and preserves final-report regex domain. Parent independently primes isolated2module baseline and changes only a staging comment (AST identical): baseline prime0 then exact cached-provider GCC missing-symbol red1, with provider Cgen mtime/hash unchanged. Candidate same topology prime0/warmfresh-consumer0, same provider-retention check. Timings4.876/1.018/5.126/0.918s;2GiB child limit and<=2compile jobs. Native matrix checks explicitly verify both work_items/acceptance_scorecard .so origins under parent-owned compiled tree; all16status cases byte-identical across saved-baseline Python/candidate Python/candidate native. This corrects the worker's initial cwd/source-shadowing matrix attempt rather than accepting it. Parent preparation initially copied one staging directory level too high and failed before native execution; corrected isolated parent-native-2 is the accepted receipt, original failed setup retained.

Parent promotes minimal status-owner conversion: public normalize_tail_validation_status preserves old body; scorecard uses exported typed function instead of cross-module enum constructor. Invalid/missing remain UNCOLLECTED, declared UNKNOWN remains UNKNOWN, published changed remains failed and metadata priority unchanged. No mypyc target removed, no dependency patched, no semantics or validation relaxed. Eleven public contract controls added beside15existing scorecard tests and enrolled in Make QA_RUFF/QA_PYTEST, fast pipeline and reporting ownership. Production26pass3warnings6.63s/3workers; scoped linters/type ratchet exit0, explicit Ruff clean, threefile Pyright0errors1.104s. Native red/green/matrix receipts and logs under scorecard-mypyc-enum/.

Parent broad quality-dev66451 terminal exit2: enum GCC stage is now green, but mandatory Cython VEX fails in isolated mypyc import smoke. Pipeline/decompiler/regression lanes did not execute. Independent neutral-cwd corrected two-package receipt: original source loads CYTHON and the canonical .so; isolated .cache/mypyc/lib fails missing/stale ImportError. Initial source-only PYTHONPATH omitted sibling inertia_decompiler and failed before the positive could run; corrected receipt includes root after selected package source/lib, pins CYTHON and records actual origins. No Python fallback enabled. Actual source binding cause: lifter_backend parents[3] computes .cache/mypyc for flat isolated package while verifier expects original source layout and .cache/cython-vex there; source sync excludes native/Cython cache. New bounded Devin92927 staging job owns only mypyc-cython-package-binding/candidate and new report/logs,8immutable source baselines, verified rootRO/repoRW4GiB. Requires genuine isolated native startup/lift, canonical origins, strict source/ABI/artifact/path confinement, negative controls and manifest/extension attestation invalidation. Parent review remains pending; no broad green/M7 acceptance. Graph coverage generation2026-10-01T07:13:07Z metadata_match source/build/cache owners; no complete-impact claim.

Current near-return recheck: original test_stack_selector_consumes_only_retained_caller_entry_context still fails at context.complete/ENTRY_UNPROVEN,1fail3warnings4.66s/3workers. Existing backward-CALL native selector counterexample remains valid; no assertion changed, CS domain narrowed or forged numeric state accepted. Its explicit proven invocation-domain prerequisite remains separate M5 work after the build/package gate. Full original M0-M7 remains active/incomplete.


Initialized-MZ boot provenance native audit (2026-10-01): while Devin92927 continues mandatory Cython package repair, parent independently probes the M5 bootstrap prerequisite. Actual13byte two-exit MZ payload under complete declared512byte arena/register environment: header CS0110:IP0 executes movax4c00/int21 and terminates exit0; dataclasses.replace(boot,entry=CS0110:IP8) retains producer boot_sha256, passes construction and replay, executes movax4c07/int21 and terminates exit7. Both ProgramResult.boot_identity values equal23e5d7a70b7885b250c3182baee63b9474c429c326e55415ad8de324345002ac. File/source receipt and actual EXE at boot-identity-audit/replay.json,two-exits.exe. This proves stale initial-state provenance is consumed, not a formal comparator false-equivalence verdict. Initial diagnostic mistakenly accessed nonexistent result.boot_sha256; corrected runner uses owned result.boot_identity, no production catch/workaround.

PE32 countercontrol uses existing genuine serialized-PE factory fixture: changing only entry by+1 while retaining key raises ValueError("PE boot identity is stale for its entry, bytes or environment"). Receipt pe32-constructor-negative.json. No PE32/ELF patch justified for this demonstrated stale-key defect. Source inspection confirms real16 ProgramBoot __post_init__ checks type/nonemptykey only, and replay initializes directly from supplied entry/stack. Header-derived fields cannot be trusted for M5 proof until provenance closes.

Bounded independent Devin56665 launched on real16-boot-provenance/candidate only,6immutable source/test baselines, verified rootRO/repoRW4GiB. It independently reproduces original mutation and object.__setattr__ bypass native red, now stages retained-source header/image validation at construction and consumption. No production changes, broad gates or pytest grant; it may run only bounded serial direct native probes/static checks while Cython92927 has the single granted3worker pytest pool. Work ownership disjoint. Parent must review delta, original IDs/semantics, genuine header mutation/native outputs, forged/stale controls and resource cost before promotion. Original M0-M7 remains active/incomplete; source audit is concrete progress, no blocking status. GraphTier2 generation2026-10-01T07:13:07Z, full30row boot search paginated, exact factory both-direction trace and8relevant source/test coverage metadata_match; initial guessed dos_mz_loader.py absent, actual owner load_dos_mz.py coverage/source corrected.

Parent review checkpoint (2026-10-01): both bounded Devin staging jobs completed and their owned deltas were compared against immutable pre-run SHA256 baselines before promotion. Cython bundle verifier retains source/ABI/digest/path binding in isolated mypyc packages; native smoke pins Cython and requires canonical lib-confined extension origins. Parent removed new Protocol-parameter Vulture findings without suppression. Real16 ProgramBoot now retains actual MZ bytes, rederives header/image/arena/identity at construction and replay, rejects stale replace/setattr state, preserves genuine IDs and admits genuine changed headers. Actual two-exit MZ parent replay independently confirms exit0 with unchanged ID, forged-IP rejection, and genuine IP8 exit7 with distinct ID. Original red receipt remains logs/red.log; a production-green probe used the worker default red.json output name, then was moved to parent-production-green.json (do not treat it as baseline red).

Final shared-tree focused gate: 158 passed/2 dependency warnings in70.83s,3workers; includes bundle, backend equivalence, boot/replay and program input/output/file/CLI integrations. Native mypyc smoke:39 compiled modules passed with mandatory Cython. Scoped Ruff clean;4production-file Pyright0errors. New regressions enrolled in Make QA, fast pipeline and ownership manifest. Receipts: .cache/comparator-implementation/parent-review-focused.log,parent-mypyc-smoke.log,parent-review-types.log. Broader quality-dev started with3pytest workers/4pipeline workers/2lint jobs/2mypyc jobs; terminal outcome pending at this checkpoint. These repairs do not complete M4-M7 or representative corpus acceptance.

Additional parent receipts: frozen-before real16 native replay independently reproduces same-ID exit0/exit7 and setattr bypass in real16-boot-provenance/logs/parent-baseline-red.json; promoted production rejects both forgeries in parent-production-green.json. Isolated .cache/mypyc/lib native Cython lift independently executes four sequences (Ret, conditional Boring, INT21 Call, operand-size override Ret), with actual .so origin confined to that lib. Broader gate has advanced through linters/type ratchet to architecture-check startup; final outcome still pending.

Gate checkpoint: linters-dev and type-ratchet-changed advanced successfully; startup architecture and agent-context checks passed; test-ownership check296passed/3dependency warnings18.31s. quality-dev is now in test-pipeline-fast (--require-external,4MSC workers), session87355 remains live and no terminal pass is claimed.

M5 invocation-domain stage started (2026-10-01): previous turn was concrete progress (two reviewed production repairs,158focused tests+39module native smoke+296ownership controls); current broad gate87355 confirmed live, no restart. Parent rechecked selector-window revision2 report and native counterexample: intra-function refinement cannot establish isolated backward-CALL invocation. Fresh exact rootRO/repoRW4GiB sandbox verified. Devin22510 staging only under real16-invocation-domain/candidate,6immutable production baselines, no pytest grant/no production writes. Task requires real retained MZ source/header/domain evidence bound to project/native registered artifacts and propagated through current call context, retains default full-window refusal and original backward-CALL effects/assertions. GraphTier2 generation2026-10-01T07:13:07Z, selector search3complete, bothtrace binder and context, actual ir owner coverage metadata_match; boot owner metadata_changed read current patch. Initial guessed non-ir paths missing and corrected before delegation. Parent continues broader acceptance/corpus review independently.

PE32 relational acceptance staging checkpoint (2026-10-01): parent found existing public rotation/saved-register controls were actual ELF32, not requested PE32 format. New staged test_relational_pe32_public.py runs genuine serialized PE32-to-PE32 through both unchanged production drivers, all modeled REG32 outputs, real CLE/VEX/Z3, exact optional boundary labels. Both rotation positives prove; rotated stride negatives honestly refuse cfg_shape_mismatch. Same-shape stride produces failed modeled transition but public refusal, retained without promoting to whole-function counterexample; independent initialized actual-PE Unicorn execution establishes concrete corruption. Four vectors0/1/3/255 include zero case, modular EBX wrap, complete register/event equality for rotated equivalents, identical declared environment IDs, different boot IDs and deterministic snapshots. Six public controls+four native vector controls pass serially under2GiB; no pytest/production edits while broad gate87355 is live. Ten durable parametrized tests staged at pe32-relational-acceptance/candidate/angr_platforms/tests/test_relational_pe32_public.py; Ruff clean; native-controls.json/native-execution.json/same-shape-final.log and */out/compare.json retained. Initial draft demanding public counterexample from a failed induction candidate was rejected (same-shape.log); final preserves independent proof/execution statuses. Must promote/enroll and pytest-n3 after gate ends; not representative compiler corpus/M4 acceptance. Devin22510 invocation-domain remains verified live, baseline-only staging ownership, no pytest grant. Broad gate currently main cohort41percent with failures; no final tracebacks/classification/acceptance claimed.

Parent native-control checkpoint (2026-10-01): broad quality-dev terminal outcome was136failed/8989passed/19skipped in1591.56s; subsequent regression lane did not run. Reviewed/promoted genuine PE32 relational/native controls (10pytest pass12.11s, routine enrollment). Parent repaired input fixtures with real native project/raw IR/SSA/census and existing shared target binder (14pass); AST audit retains all79 original input assertions. Pass-through production CONST-only gate now consumes retained call-target evidence/shared binder, preserving symbolic operands, admitted relation and independent semantic-target check. Before repair20fail/2pass; after22pass11.62s. Two new missing-census/unrelated-callee controls refuse. All29 original pass-through assertions unchanged. Reviewed/promoted Devin terminal-JMP retention after checking five frozen baseline hashes and independent native red replay; real unconditional transfers survive coordinate arithmetic, NOP fallthrough does not gain JMP, ambiguous selector windows retain symbolic operands and typed refusal. Final combined cohort133pass/3dependencywarnings13.63s; scoped Ruff clean, Pyright on pass-through/helper0errors. New helper has routine lint/type/ownership enrollment. Evidence native-call-fixture-repair/{REPORT.md,final-focused.log,assertion-preservation.json,pyright.log}, real16-terminal-ir-retention/{HANDOFF.md,parent-red.log}. No updated whole-suite total or compiler-corpus acceptance claimed.

Devin invocation-domain22510 terminated exit1 at provider free-model rate limit (reset reported47min); partial candidate stays staged/unaccepted. Parent flagged caller-supplied boot_recompute authentication for review: identity callback cannot authenticate a fabricated boot. Preserve original E8CBFF CS103/IP2→physical11000 counterexample and full-selector guard. Five separate dosunit SSA region/macro controls remain unresolved; invocation-domain, remaining broad failures, representative corpus/cold-warm parity and original M0-M7 acceptance remain open.

Native return evidence checkpoint (2026-10-01): remaining return-collection/split focused baseline13failed/27passed10.23s. Parent native fixtures retain real project identity, source blocks and decoded census; no original machine bytes or assertions changed (83original assertions AST-identical). Shared CALL output binder is now supplied retained census/projection by memory live-out flow. Split-condition graph accepts preceding same-instruction TMP calculations only under authoritative CLOSED_DESTINATION/NONE effect proof, typed scalar operands, exact TMP identity and literal successor. Eight new corruption/positive controls; no guessed selector or effect-table fork. Native original cohort40pass14.92s; final combined owner/regression cohort184pass/3dependencywarnings17.20s. Scoped Ruff clean, both production owners Pyright0errors, diff whitespace clean. Evidence native-return-fixtures/{REPORT.md,red.log,final-shared-cohort.log,assertion-preservation.json,pyright.log}. No new full-suite total, corpus acceptance or milestone completion.

Unfinished invocation-domain review: parent isolated `_recompute_boot_8616(object(), lambda value:value)` returns None (no refusal), showing caller-controlled callback equality cannot authenticate source provenance. Whole-domain acceptance was not tested; candidate remains unpromoted. Need independently source-derived MZ header/relocated-image/entry proof bound to native project, registered raw artifact, root-to-callsite path and local scope. Loader owners MZHeaderView/DOSMZHeader already exist and were live-read with exact-path metadata_match; no frontend→dosunit dependency or independent third MZ semantics implementation. Devin provider rate-limit remains terminal job22510; do not invent a live wait. Review receipts real16-invocation-domain/{PARENT_REVIEW.md,parent-authentication-probe.json}. Original M0-M7 goal remains active and incomplete.

Source-derived MZ authority checkpoint (2026-10-01): original MzExe/parser/relocation implementation extracted unchanged into Frontend mz_load_source.py; replay exports/private relocation alias retain identical functions, with AST preservation receipt. New mz_invocation_source.py rederives entry/stack/module from immutable source+declared load paragraph. ProgramBoot uses shared typed coordinate projection on its already parsed source, adding no parse/relocation/image-copy pass. Owned projection rejects stale fields, mutation/Boolean values and subclass equality forgery (focused red reproduced then fixed). Durable native source-header controls retain realizable E8CBFF physical1032 CS100/IP32→1000 vsCS103/IP2→11000. Final integrated cohort210pass/3dependencywarnings17.79s; production Ruff clean, integrated scoped Pyright/annotation receipts retained. Owners/test enrolled in Make/pipeline/ownership. Evidence mz-source-authority/{REPORT.md,integrated-source-cohort.log,parser-preservation.json,subclass-red.log,native-source-replay.json}.

Parent staged invocation authentication repair now requires independently source-derived header/module/fingerprint before caller callback replay; genuine object retained and five fake/missing-source controls rejected (staged-authentication-red-green.json). Full invocation patch remains unpromoted:7staged Ruff findings, broad decode catch, unknown-effect/fetched-code-write closure and local assumption propagation still require review. Current indexed-loop cohort15fail/4pass10.99s, unchanged tests; raw101b→100b backward JMP selector-window refusal prevents proven predecessor/natural-loop (indexed-loop-root.json). No guessed selector/backedge, no new full-suite/corpus/milestone acceptance. Devin prior job terminal at provider limit; original M0-M7 remains active.


Reviewed region/macro control checkpoint (2026-10-01): five unchanged positive/progress controls reproduced failing (5failed/17passed), then repaired by reusing the existing full-width real16 control-destination theorem in graph admission and continuing composition. Every entry selector remains admitted; legacy IP projection is separately proved, and data/stored addresses/return state are untouched. Wrap/unknown/IP-mutation/budget controls refuse. Final shared-tree16module cohort136passed/3warnings203.26s with3workers, including both public PE32 drivers; scoped lint/type checks pass. No performance, corpus, full-gate or original-M0-M7 acceptance claimed. Receipt region-control-rewire/REPORT.md. Late Make QA enrollment was moved before file selection so focused linters consume the new owners/tests. The15Frontend indexed-loop failures remain distinct/open.

Devin retry36052 is terminal exit1 at provider quota, not live. Parent independently verified its genuine-MZ positive domain/context/near-return chain. Exact snapshot review finds only the staged IRBlock instruction membership correction. Invocation candidate remains unpromoted: actual initialized stackSS100/SP34 makes pushSS overwrite future CALL1032 bytes E8CBFF→0001FF, independently captured in Unicorn write hooks, while the candidate still reports complete=True. This is a missing code-write/scope gate, not a whole-equivalence counterexample; unsupported self-modifying execution must refuse explicitly. Receipt real16-invocation-domain/parent-code-write-review.json and parent-worker-delta.diff. Unknown-effect, environment identity and invocation-scope closure remain required. Full plan stays active.


Parent invocation-prefix review (2026-10-02): Devin prefix-closure staging remains unpromoted. Genuine MZ loop bytes 16 75fd e8caff c3 with initialized SS100/SP3A receive staged proven, while independent Unicorn hooks capture stores1038,1036,1034; the last overwrites future CALL1033..1035. Root-head simulation reseeds instead of joining backedges. Parent records native receipt and bounded revision task under real16-invocation-domain/PARENT_PREFIX_REVIEW.md; outer sandbox rootRO/repoRW/4GiB reverified. Additional alias/address-width/operator/budget/environment obligations remain review-pending. Production unchanged.

Failure refresh: discarded-return module17passed/3warnings15.04s. Two exact-node replay attempts ran zero tests (exit5), not validation. Independent serial collection identifies xdist group suffix @sortd-initmenu in saved node ID; source marker verified. Module-based34-file replay is live with3workers; no new broad total claimed. Disk recovered; test-inclusive region Pyright recovery receipt remains green. Original M0-M7 remains active and incomplete.


Parent entry-JMP theorem checkpoint (2026-10-02): native EBEE at101b reaches100b forCS100 and1100b for isolatedCS101. Bounded Z3 negation under root1000 fetch and unchangedCS is unsat; this proves only conditional coordinate arithmetic, not path/CS/source prerequisites. Receipt selector-window-premise/parent_jump_entry_theorem.json. Parent exact-source graph audit identifies terminal_direct_jump_evidence -> vex_import._block_to_ir and metadata_match for three owners; file-pattern graph misses were followed by source reads. New bounded disjoint Devin real16-entry-jump staging snapshots nine current files; owns only that task, no production/pytest, requests generic native path-domain discharge while retaining isolated/body-entry/wrap/mutation refusals. Existing invocation-loop worker remains separate. Parent34module replay still live; no terminal totals or project acceptance.


Parent stack-word symbolic CALL staging (2026-10-02): saved native6control baseline4pass/2fail; candidate6pass/0fail preserves all original test bodies/bytes and corruption controls. Alias consumer delegates symbolic operands to existing Semantics full-width coordinate/native-provenance binder, retains strict literal path and original frame/lifetime/source gates. No guessedCS/rewrittenCALL. Candidate Ruff clean; production/test saved sources hash-identical, held until active34module replay ends; normal pytest/package-aware types still pending. Receipt stack-word-symbolic/REPORT.md. A diagnostic filename collision overwrote baseline manifest with results; results preserved and manifest restored solely from untouched before copies, probe paths corrected, no source changes.


Stack-word staged final review:8/8 serial native controls pass (six originals plus two operand offset/width mutations retaining positive). Four original function ASTs preserved exactly; candidate_test.py appends permanent seam controls. Ruff and production-path MyPy shadow exit0; normal pytest/Pyright/promotion remain pending the still-live module replay. No full-gate or milestone acceptance claimed.


Parent invocation opaque-effect review: revised loop candidate still admits an injected unused DIRTY/TMP effect as proven (87raw/87normalized/87classified/87materialized/0fail). This is an effect-admission corruption control, not a native whole-function counterexample. Destination presence cannot establish absence of hidden effects; must consume authoritative scalar_instruction_effects typed UNKNOWN refusal. Worker module remains unedited by parent while live; parent_opaque_tmp_review.json and PARENT_OPAQUE_EFFECT_REVIEW.md retain evidence. Candidate stays unpromoted.


## Parent checkpoint 2026-10-02T01:24:03.941412+00:00

The saved 34-module replay is terminal: **141 failed / 883 passed / 59 skipped**, 88 warnings, 3781.38 seconds, exit1. This is a module-expanded replay of the old136 failures, not a full gate. Normalized-ID comparison finds78 old IDs still failing,58 absent from failure summaries,63 additional module failures; absent is not proof of pass versus skip. Receipts: `.cache/comparator-implementation/current-broad-failure-replay/module-replay.log`, `module-failed-current.json`, `module-comparison.json`. Two workers were idle; final worker was waiting for a bounded SORTDEMO decompiler subprocess, confirmed independently with py-spy. No timeout/test coverage was reduced.

Parent symbolic CALL Alias consumer fix is integrated after both saved hashes matched. Original tests preserved, two corruption controls appended. Focused CALL-binding cohort:39passed/3warnings in32.18s (three workers); scoped Ruff/Pyright and type-ratchet-files pass. Files are pre-existing untracked shared-tree owners, so git diff alone does not represent the parent delta; saved before/ copies remain authoritative. No function or M0-M7 acceptance claimed.

Devin loop revision finished and remains staged. Parent reproduces opaque TMP DIRTY admission as proven87/87/87/87/0; bounded followup62998 owns only staged invocation task and consumes authoritative scalar effects. Entry-jump worker96601 remains live. Independent parent controls additionally show its current staged entry-domain proof accepts both unknown TMP/REG effects and an out-of-census successor0x2000; all three still admit edge101b->100b with1/1/1/1/0. These are IR corruption/closure controls, not native whole-function counterexamples. See staged `parent_effect_review.py/json/log`. Must repair effect/path closure before promotion. Original-plan completion remains unproven.


Parent follow-up: staged invocation opaque-effect repair independently reproduces PATH_EFFECT_UNPROVEN on the original TMP corruption, retaining frozen red receipt. Native loop still refuses and concretely overwrites future CALL bytes under Unicorn. Parent fixed stale row materialization on later fixpoint refusal; new staged regression red5/6 ->green6/6, ledger122/122/122/121/1. No production promotion or milestone acceptance. Entry-jump initial worker terminal0; parent rejection remains, bounded review followup7432 now owns only that staging task. Refreshed condition cohort15failed/14passed42.34s; native diagnostic identifies missing CFGFast comparison block after symbolic JMP, with complete direct/cached inventory for only the supplied first block. See task reports for source-backed evidence.


Parent native-effect review: initialized MZ SS100/SP34 writes1032,size2 into subsequent CALL bytes under Unicorn. Authentic staged invocation refuses CODE_WRITE_VIOLATION; fabricated known MOV sp,100 inserted at same native address changes verdict to proven with coverage complete. Address/CFG coverage is explicitly not effect binding. Native source-bound effect projection is now a required staging prerequisite; no production promotion. Receipts real16-invocation-domain/parent_scalar_origin_review.py/json/log and PARENT_NATIVE_EFFECT_REVIEW.md.


Native CFG adapter focused checkpoint (2026-10-02): production frontend_cfg_direct_jump.py consumes the shared exact-byte/full-width terminal JMP theorem through angr default resolver registration; execution VEX remains symbolic. New adapter cohort7passed/3warnings28.60s; scoped Ruff clean and Pyright0errors. Initial combined cohort31passed/7failed67.13s: five new-test fixture/CFG ownership assertions corrected without altering original controls, two original condition-binding refusals remain open. Native diagnostics now locate the remaining gap in function membership: CFG discovers some direct-jump targets as separate functions, leaving caller register inventory incomplete for the comparison; this is not established as overlapping block decoding. Preserve strict source/path gates pending ownership review. Devin native-effect staging63276 remains live; claimed fabricated-MOV refusal awaits independent parent replay/review. No corpus, performance, broad-gate or original M0-M7 acceptance. Receipts cfg-native-direct-jump/adapter-tests.log and production-pyright.log.


Parent staged source-binding audit (2026-10-02): entry-stage42controls and separate original-red/candidate-green probes independently pass, but a new in-window native transfer corruption is falsely admitted. Same native EBEE/IR at101B with supplied pending EB00 is admitted101D rather than authentic100B, both ledgers1/1/1/1/0. Existing EB80 control only exercised window refusal. Staging remains unpromoted; bounded disjoint Devin30769 repairs actual byte/expression binding, verified outer rootRO/repoRW/4GiB. Receipts real16-entry-jump/parent_transfer_binding_review.py/json/log. Invocation parent replay confirms fabricated MOV now refuses NATIVE_EFFECT_UNPROVEN, but final87classified/87materialized/1failure violates accounting. Independent capture mutation also establishes ordinary IRBlock equality ignores simulation-consumed source_tmp (capture0->10000; equality true while complete serialized fields differ). Invocation63276 remains live; exact-binding/ledger followup prepared and held until ownership is free. No project/corpus/milestone acceptance.

Independent native transfer replay: parent_transfer_native_replay.py exits0; selectors0 and100 both execute retained EBEE at101B to100B, while the staged forged-evidence proof admits101D. This is a native transfer binding defect, not whole-function equivalence evidence. Receipts real16-entry-jump/parent_transfer_native_replay.json/log. Original M0-M7 acceptance remains open.


Native direct CFG job checkpoint (2026-10-02): source review identified angr CFGFast classifying a resolved symbolic native JMP as an indirect jump and creating a separate function at its target. New Frontend frontend_cfg_direct_jobs.py projects only a source-proved default native JMP target into the existing direct-job path; original execution IRSB is unchanged, calls/selector-dependent/indirect/flat32 cases retain their paths. Frozen29originalcondition controls27/29 before ->29/29 staged without assertion edits; final production four-module cohort39passed/3warnings45.09s. Ruff, scoped Pyright, scoped type-ratchet and ownership gate pass. New owner enrolled in shared typing/lint/ownership/docs; original tests already routine-pipeline enrolled. Exact dirty-source before snapshot/hashes retained. Required quality-dev91390 now live with3pytest/3pipeline workers; no broad outcome yet, no function/tail/corpus/performance or M0-M7 acceptance. Invocation worker63276 terminal0; reviewed report still has ignored-capture/exact-binding and ledger defects; bounded followup74724 live. Entry native-binding30769 remains separate/live. Receipts cfg-native-direct-jump/direct-jobs-production-tests-final.log, direct-jobs-pyright-final.log, direct-jobs-contract-gates.log, direct-jobs-before/manifest.json.


Entry native-binding parent checkpoint: Devin30769 terminal0; new explicit source/project and bounded native byte/next-expression checks reject in-window forged transfers. Parent independently reproduces50/50 controls. New parent RuntimeError injection revealed catch-all converted programming defect into NATIVE_SOURCE_UNPROVED; frozen red retained, parent narrowed to named SimEngineError/SimTranslationError/PyVEXError boundary exceptions. RuntimeError now propagates, named decode failure still refuses with cause and closed ledger;2/2 exception controls plus original50/50 remain green. Ruff clean; final package-aware Pyright live. Entry stage still unpromoted pending durable routine tests/review/integration. Native CFG quality-dev91390 stopped at own unused callback parameter; explicit intentional discard added, required retry90642 live, completed296contract tests before fast-pipeline stage. No full broad result or M0-M7 acceptance. Invocation followup74724 remains live/disjoint.


Parent review update (2026-10-02): the opaque goto identity is NOT accepted.
The saved parent-opaque-lifetime.json demonstrates object-id reuse after target
release on iteration 1. A detached identity tuple can therefore alias a later
unknown node. Typed incomplete/refusal propagation or rigorously scoped lifetime
anchoring is required before this projection may certify equality. Earlier
focused green controls do not discharge this defect.


Flat32 stack-domain CLI parent checkpoint (2026-10-02): both staged PE32
drivers now expose --entry-esp-range MIN:MAX and retain conditional assumptions
in sealed proof evidence. Parent restored the keyword-only API/fixed mocks and
replaced MZ-only admission with bounded i386 PE32 header checks (4 frozen red
controls now green). 61 initial focused controls passed; final CLI/retry/ownership
cohort 113 passed with one stale enrollment assertion, subsequently updated.
Scoped Ruff/Pyright and manifest checks pass. Ownership rerun receipt and exact
delta: .cache/comparator-implementation/flat32-stack-domain-cli/. No actual
corpus conversion or original milestone acceptance claimed.

Final ownership rerun: 60 passed in 4.81s; scoped assertion-file Ruff passed.


Reviewed checkpoint (2026-10-02): goto typed-refusal cohort338passed; DAG/stack
proof/CLI/retry cohort80passed; ownership60passed; scopedRuff/Pyright pass.
Parent found and fixed two stage-admission corruption failures and a DAG-depth
ordering corruption failure; comparison version17 and suffix-height memoization
preserve those controls. Node/solver/lift/composition budgets remain bounded.
BC5 sub_401234 public before/after cold/warm runs stay refused; the guard now
exposes outside-function edge0x49f780 rather than counting shared expressions
repeatedly. Warmwall19.21->18.96s, RSS315272->315756KiB; coldafter24.33s vs
before20.39s, so no overall speed or proof-conversion claim. Requiredquality-dev
first stopped at three doc/type-ratchet findings; all corrected, standalone
type-ratchet exits0, and retry27832 is live after compiled smoke39passed.
No refreshed broad total or original milestone exit yet. Exact parent reviews:
.cache/comparator-implementation/{goto-unknown-refusal,flat32-dag-budget}/
PARENT_REVIEW.md. Gate receipts:parent-reviewed-checkpoint/.


Gate scheduling correction: retry27832 was intentionally stopped after296
contract tests because Make selected7external pipeline workers. Replacement
quality-dev44475 explicitly uses PIPELINE_WORKERS=3; earlier interruptedrun is
incomplete, not a broad pass. Currentstartup and ownership contracts are green;
full fast pipeline/release outcome remains pending. Source bytes at BC5 boundary
0x49f780 are file-backed executable CODE; optional listing labels it ___close
and shows a CloseHandle call. Labels are diagnostic metadata, not a callee or
environment proof. Source-byte receipt:flat32-dag-budget/parent-boundary-bytes.json.

Current gate terminal checkpoint (2026-10-02): bounded quality-dev44475 exited2;
startup/ownership296passed, main fast pytest9308passed/38failed/64warnings in
1710.92s. Make did not run the subsequent optimization suite. Saved full log and
structured pipeline summary under parent-reviewed-checkpoint/. Failures are not
collectively classified as unrelated/baseline debt. Parent focused21case rerun
reproduced native pointer/callback fixture, boundary and enrollment failures.
Boundary semantics now use the retained native CALL target theorem instead of
expecting literalized IR; routine DAG-test enrollment expectation is coherent.
Parent boundary/binding/enrollment42passed10.60s, scopedRuff clean; logical-memory
presence is explicit. Devin58148 owns only3fixture test modules with frozen dirty
baselines and original assertion preservation required. Required optimization
lane75550 is live; no broad acceptance or original M0-M7 exit follows.

Parent-reviewed flat32 tail checkpoint (2026-10-02): direct acyclic transfers
to declared foreign entries now compose destination effects without a CALL
push, preserving the return slot, control, memory and environment coverage.
Parent review reproduced positional-budget incompatibility and nested call/tail
cap overshoot; the accepted implementation preserves positional arguments and
reserves work before descending. The production tail/composition/domain cohort
passed 55 tests in 38.03s; scoped Ruff and Pyright passed. Ownership and pipeline
enrollment passed 59 tests in 5.26s. Tail-only retry publication and conditional
environment gates now recognize explicit dependency counts. Saved-source red
controls reproduce three failures; malformed-count controls reproduce eight
more. The existing/new retry cohort passed 71 tests, and the final projection
cohort passed 25. Declared domain assumptions remain conditional.

The controlled frozen BC5 single-function probe advances from an outside edge
to an indirect-jump refusal. Warm CPU time was 22.71s before and 22.80s after;
peak RSS stayed around 300 MiB. No proof conversion or speed gain is claimed.
This checkpoint closes no original M0–M7 exit. Python and pytest now run at
nice 10 as requested. CMP16 Clinic transport remains under parent corruption
review; native CALL CFG and total composition-budget jobs are staged only.
Receipts: `.cache/comparator-implementation/flat32-tail-compose/PARENT_REVIEW.md`
and `flat32-tail-retry-projection/PARENT_REVIEW.md` in the same artifact root.


Parent-reviewed total flat32 composition-budget checkpoint (2026-10-02):
one absolute deadline now covers both sides, lifting, substitution, return
proofs and final solving. Parent red controls reproduced post-materialization
publication and zero RET timeout escaping as unlimited; both are corrected.
Public retry forwards its existing deadline rather than restarting after adapter
setup. Production composition/term/tail/retry cohort: 99 passed in 39.32s;
scoped Ruff, Pyright and the selected type/doc ratchet pass. New controls are
routinely enrolled. Uninterruptible single lift/materialization/solver calls
remain documented; their late completion cannot publish success. No original
M0-M7 exit or new corpus/performance result follows. Review and red/green
receipts: `.cache/comparator-implementation/flat32-compose-total-budget/`.


Parent-reviewed native near-CALL CFG checkpoint (2026-10-02): the Frontend
adapter now uses the existing source-bound near-call theorem to publish direct
CFG edges while leaving symbolic execution VEX unchanged. Parent independently
reproduced and repaired supplied-VEX/producer substitution holes in CALL/JMP,
and corrected two boundary typing errors. Integrated focused run: 36 passed,
including the four previously failing compiled-C segment-call-effect controls.
Final routine-enrollment/CFG cohort: 145 passed, one remaining authentic
PercolateUp failure (interior_leader source 0x10f46 -> edge 0x10f52). This is a
separate blocker, delegated in isolated staging; the refusal is retained.
Scoped Ruff, Pyright and four-owner type/doc ratchet pass. Positive discovery
and corruption/refusal controls are enrolled in Make, pipeline and ownership.
A refusal control previously spent 118.96s scanning unrelated 64 KiB padding;
its production version now checks early refusal without a CFG scan. This is a
test-work reduction, not a comparator or corpus speed claim.
Receipts: `.cache/comparator-implementation/native-call-cfg-parent-review/`.

Parallel M6 execution audit produced deterministic original/original fixture
replays, corrupt mismatches and visible unsupported outcomes for real16 and
PE32; reports explicitly say execution does not establish proof. Representative
compiled DOS program replay remains incomplete at INT21/AH30 during startup.
Authentic InitBars diagnosis also corrects the earlier far-call hypothesis:
linked bytes use near calls; the first entry-domain blocker is CALL_ON_PATH,
with later unknown IDIV effects. Neither audit closes an original M0-M7 exit.

Final CALL-only routine cohort: 19 passed in 41.13s with three workers;
each test call is under one second, including the previously 118.96s selector
refusal. Constant and temporary discovery-operand/producer corruptions are
both enrolled. Scoped mypy also passes.


Optimization checkpoint after native-CALL integration (2026-10-02): CMP16
single-function guard now exits0, main0x101a7 generated with validation=passed,
158.149s under the unchanged180s limit. Earlier Clinic checkpoint timed out.
Both configured modes share one active import surface; the guard ran once and
reused that artifact for parity, so this is neither a speedup measurement nor
independent dual-backend validation. LOOPS/FPTR suite inputs are pending.
Receipt: native-call-cfg-parent-review/cmp16-after-call.json and .log under
.cache/comparator-implementation/. Full M0-M7 completion remains open.

Remaining optimization inputs completed after CALL integration: LOOPS44.937s
and FPTR42.082s, each exit0 / one generated function / validation=passed under
the180s cap. All three configured single-function optimization inputs pass.
This is the quality guard scope only, not broad pipeline or M0-M7 acceptance;
shared active import surface means no independent backend timing comparison.
Receipts: native-call-cfg-parent-review/opt-{LOOPS,FPTR}-after-call.json and logs.
CFG and callee-scanner workers encountered retryable service connection errors;
confirmed terminal1 jobs were resumed by their saved session IDs, preserving
baselines and task scope. DOS version-service worker continues separately.

Parent review of the first staged CFG extent repair reproduced a capability
regression: a new source-size guard silently removes a decoded successor before
the existing extent owner can repair its short cached source node. Independent
control passes the saved dirty baseline (1pass/11.86s) and fails the staged
worker copy (1fail/16.68s). Production unchanged; that guard is not accepted.
Making this already-repairable path a typed refusal would still lose baseline
capability. Review receipts and exact worker snapshot are under
.cache/comparator-implementation/interior-leader-parent-review/.

Parent integration checkpoint (2026-10-02): reviewed CFG leader clipping and
explicit DOS version-query service are in production. The CFG patch retains
undercovered-source edges for the authoritative extent repair (worker's silent
skip rejected), stops at the earliest instruction-aligned leader and propagates
unexpected edge-registration errors. Routine controls include malformed leaders
and the repaired retention path. Version policy is explicit, bounded and bound
to environment/boot identity; parent added strict receipt validation plus CLI
policy/schema projections. Combined production cohort138passed/1warning64.74s;
scoped Make lint/mypy/type-ratchet/ownership exit0 and version Pyright0errors.
CLI discovery Pyright reports4 inherited Never-iteration errors (worker baseline5);
no new errors. Public compiled original/original replay independently reaches
instruction20, then honestly refuses code_write; schema validates. Original
SORTD test remains unresolved: parent run timed out158.57s call/177.35s total;
worker's native probe cleared interior_leader but reached uninitialized-read.
No function fix, corpus acceptance, overall speed gain or M0-M7 exit claimed.
Artifacts: interior-leader-parent-review/ and real16-version-parent-review/ under
.cache/comparator-implementation/. Devin callee-region-leader-split remains staged
and under review; resumed protective-hawthorn separately investigates evidence-
derived code scope for the compiled MZ startup, with at most two replay probes.

Reviewed callee-region split checkpoint (2026-10-02): bounded prefix re-lift
normalizes reachable instruction-head targets for both real16 and flat32;
mid-instruction targets, changed bytes, ignored bounds, cycles and exhausted
budgets still refuse. Parent native9-byte probes: before MID_BLOCK_TARGET on
both tracks; after completed scans,4blocks and5lift calls, unchanged budgets.
Counters raw9/normalized4/classified5/materialized4/failures0; completion is
candidate boundary evidence, not semantic equality. Stock32 probe uses opt1
constant-propagated control (opt0 remains indirect-control refusal). Final
production scanner/intake cohort43passed/2warnings43.77s; prior shared16/PE32
program cohort127passed/2warnings47.85s. Version/CFG cohort138passed64.74s.
Worker late exit-subset guard reviewed/integrated; parent corrected its docs:
matching target/kind multiplicity does not prove guard or dropped-exit semantics.
Real native probes, extra invented-edge control and all owners/tests enrolled.
Startup code-scope follow-up: retained linker map and binary hashes reviewed;
parent public replay equals worker's report exactly,39instructions, five data
writes, next explicit refusal INT21/AH4A at11111. Declared code ranges are not
symbolic proof; embedded CODE data need not fail decoding (worker overclaim
rejected). New requiredquality-dev started with nice10/3pytest/3pipeline workers;
no refreshed broad outcome yet. Original M0-M7 acceptance remains OPEN.
Receipts: callee-leader-parent-review/ and real16-startup-code-scope/ under
.cache/comparator-implementation/.

Required quality-dev first attempt exited2 at linters-dev: one imported-evidence
no-any-return in clinic_terminal_control._decoded_target_8616 and isolated mypyc
smoke lacked a writable temp directory outside the repository. Saved exact
clinic dirty baseline; added int local annotation only, scoped mypy passes.
Retry launched with TMPDIR=/home/xor/vextest/.cache, nice10,3pytest/3pipeline
workers. First attempt never ran the broad pytest/optimization phases. Final
scanner scoped lint/mypy/type-ratchet/ownership and Pyright all pass.

Continuation checkpoint (2026-10-02): parent replayed the actual retained MZ
callee0x23d4 under identical default32block/32instruction/256byte limits.
Frozen-before scan refuses MID_BLOCK_TARGET23f4 in[23f2,23f6) at0.190s;
production discovers8blocks/26instruction-work facts then honestly refuses
CYCLE at0.295s. No selected-function proof conversion; full20function denominator
unchanged. Exact receipts callee-leader-parent-review/corpus-scan.json/log.
Current quality-dev retry passes linters/compiled39module smoke, startup
architecture/context/ownership and296contract tests43.05s; broader fast pipeline
still running. Native DOS audit sandbox independently verified KVM API12/nice10/
4GiB and now probes unmodified MZ, with host-time reproducibility caveat pending
parent final review. A separate bounded Devin audit maps cyclic-callee intake to
existing loop-proof consumers; no production change or CYCLE bypass authorized.

Native backend audit parent correction (2026-10-02): installed kvikdos is
available, but both default CLI and dosunit wrapper are PERMISSIVE. Parent
strict replay of exact retained original returns252 at unsupported INT10/AH1B
(cs0110/ip33eb),0stdout/no dump in0.041s; therefore permissive cleanDOSexit25
is NOT whole-program acceptance. Existing wrapper also conflates nonzero guest
exit withFAULT and snapshots memory only; those remain explicit limitations.
New bounded Devin stage native-dos-strict-policy addresses generic strictpolicy
at both backend launch seams, with isolated native redgreen and no production
edits. Broad gate still owns3pytestworkers. Real16 cyclic-callee audit remains
read-only/staged; no cycle gate removed.

Broad gate result (2026-10-02): quality-dev retry exited2 after the fast
pipeline: 9419passed/14failed/19skipped,1968.73s. Earlier lint, compiled smoke,
architecture, ownership and296contract checks passed; this is NOT a green
quality-dev result. Parent isolated rerun of countdown-head boundary passed
unchanged (14.17s call/21.20s total); the broad failure was BUDGET_EXHAUSTED,
so load-sensitive budget behavior remains unresolved rather than “fixed”.
Other failures include bootstrap registration expectation drift, retained raw-IR
conflicts, selector-window refusals, output-shape assertions and timeouts.
Their attribution to current deltas is not established. Full failure receipts:
callee-leader-parent-review/quality-dev-retry.log and countdown-recheck.log.
Both bounded Devin processes exited1 on retryable service-unavailable errors;
parent verified terminal handles and resumed existing flint-thyme and
organized-lodge sessions under the same sandbox/ownership/budgets. Original
M0-M7 acceptance remains open; no corpus denominator or proof gate changed.

REP intake boundary review (2026-10-02): parent independently reproduced the
retained0x23d4 diagnostic: source scan CYCLE; declared lowering8parts/0refusals;
grouped graph has no residual back-edge; summarize returns; same-document
paired proof reports PROVED over8cutpoints (1.715s). This is private diagnostic
consumability, not caller-bound admission or corpus conversion. Existing REP
summary owner removes instruction-internal iteration; general inter-block
cycles still require a single-side inductive summary. Devin flint-thyme now
stages a bounded typed pending-REP-summary intake route, with exact source and
caller checks, unsupported/nonREP cycle refusals and unchanged budgets.
Native strict-policy stage remains under review: embedded kvikdos fatal path
can exit the hosting process; parent must preserve failure accounting before
accepting that route. No strict backend production change yet.
Broad-gate cleanup: bootstrap description regression omitted the already
installed native direct-CALL resolver. Parent verified bootstrap imports,
installation and description, then restored the exact ordered test expectation.
Focused regression1passed/2warnings21.84s; Ruff clean. No production semantic
change and no claim that the remaining broad failures have been resolved.
Receipts: callee-leader-parent-review/cyclic-consumer-recheck.log,
bootstrap-recheck.log and package-exports-before.py.

Native CLI strict-policy checkpoint (2026-10-02): parent reviewed Devin's
exact saved-before delta and integrated ONLY --strict at the subprocess CLI
seam, preserving KvikdosBackendError diagnostics and vector accounting.
Independent argv/diagnostic regression: red1failed/3skipped; green1passed/
3skipped (exact duration in retained log). Native tests are requires_kvm and
separately enrolled in default/expanded binary lane; fast ownership includes
only the nonnative contract. Ruff and ownership checks pass. Parent launcher
cannot stat /dev/kvm in current shell, so native acceptance remains pending;
worker's earlier four bounded native CLI probes show unsupported INTf0 false
success before / explicit status252 after, supported exit0 unchanged.
Embedded strict1 was NOT integrated: run_dos_prog exits the host on unsupported
services, bypassing runner's per-vector error handler. Parent verified actual
call chain runner→execute_vector→KvikdosSession. Resumed organized-lodge stages
persistent subprocess containment preserving snapshots/read/write and explicit
failure state; no native acceptance claimed. flint-thyme separately continues
typed pending-REP-summary intake. Original M0-M7 and broad gate remain open.
Artifacts: native-dos-strict-policy/parent-{red-no-kvm,green-final,ownership}.log;
new stages rep-callee-intake-stage/ and native-dos-process-stage/.

Native accounting control (2026-10-02): parent added a two-vector regression
through the real record_oracle→execute_vector→CLI error boundary with only
harness construction, process execution and observation decoding substituted.
First process status252 retains a refused backend_failure with no expected
observation; second success remains recorded; both vectors/results survive.
This is a harness-accounting contract, not native or symbolic proof. Focused
strict CLI controls2passed4.66s; Ruff clean. Native cases still require KVM.
Both staged Devin processes re-polled live: pending-REP intake now has typed
contracts/scan/intake/lowering/helper edits and is adding native-byte controls;
embedded isolation is reading the parent-integrated baseline. No staged changes
accepted yet, and no original M0-M7 completion claimed.

REP intake integration checkpoint (2026-10-02): parent reproduced a genuine
same-assertion red baseline (real MZ caller→CYCLE,0parts) and frozen green
(pending candidate→LOWERED,2parts). Frozen staged17controls passed; existing
scanner/intake27passed. Reviewed/integrated source-bound pending REP self-edge
route; retained raw edges, source/caller checks and ordinary loop refusals.
Parent added typed discharge failures, incomplete/duplicate/dangling graph
refusals, corrected pending-termination wording and promoted tests without
stage imports, variant-dependent assertions or .cache corpus dependency.
Production REP cohort24passed35.37s; existing scanner/intake/leader cohort
43passed65.16s (that run also exposed a new-test import error, subsequently
corrected). Scoped lint/mypy/type-ratchet, Pyright and ownership pass. Native
16/32 REP tests are lifter/scan controls, not KVM execution or flat32 whole-call
proof. Test fixture materializes VEX before Capstone to use actual block bounds.
No fixed-manifest proof conversion or M0-M7 completion claimed.

Staging incident: Devin's typecheck overlay symlinks caused four unreviewed
production overwrites. Parent verified exact stage-byte identity, preserved
hash receipts, detached symlinks and restored only exact saved baselines before
intentional reviewed integration. Worker attribution to parent integration was
incorrect. No unrelated dirty edits reset. Receipts:
rep-callee-parent-review/overlay-repair/ and REVIEW.md. Future writable overlays
must use regular private copies, never symlink targets.

User now authorizes six aggregate test workers; reference/agent-execution.md
updated, nice10 retained. Parent used five while Devin retained one slot.
Embedded native-process containment remains staged/running; KVM unavailable
in current shell. Remaining broad gate and original-plan acceptance stay open.

Native process parent review continuation (2026-10-02): initial Devin stage
confirmed terminal, exit 0; frozen stage retained under
native-dos-process-stage/parent-review-before/. Independent repeated-close
regression fails with EBADF (1 failed, 3.97s). Source review additionally finds
blocking request writes outside deadline enforcement, unchecked handshake
version, oversized newline reply admission, and one-shot VM reuse that changes
the original fresh-VM-per-run behavior. Bounded correction worker launched
after rechecking read-only-host/repository-writable/4GiB sandbox; report/log
under native-dos-process-stage/PARENT_REVIEW.md and devin-review.log.
Snapshot token ownership also requires review before native pointer conversion.
No production integration, native acceptance, refreshed broad gate, or original
M0-M7 exit follows from this review checkpoint.

Fresh focused gate replay (2026-10-02): all 14 previous failing nodes selected,
five workers at nice10/PYTHON_JIT=1; terminal result **12 failed, 2 passed,
8 warnings in 560.49s**. Bootstrap-description and COD procedure-name controls
now pass; countdown budget exhaustion remains under concurrent load. This
is a failure replay, not a refreshed full-suite total. Receipts:
gate-failure-refresh/nodes.txt and replay.log.

Native InitBars diagnostic completed: all 10 pending terminal jumps remain
refused because reachable call 0x1056f lacks a bound preservation proof;
29 blocks enumerated, 0 jumps materialized, 10 failures. Exact evidence in
gate-failure-refresh/initbars-refusals.json. A separate read-only Devin job
examines this first call and reusable proof owners, with no production edit
authority (entry-call-preservation-review/). Do not infer CS preservation
from near-call encoding. Native-process parent review also reproduces three
missing address-domain rejections before ctypes narrowing (3 failed, 1.58s);
staged correction/integration review remains open. Original M0-M7 is incomplete.

Native worker private parent candidate checkpoint: independently replayed
Devin containment stage and added pre-ctypes guest-range validation using one
shared memory-limit constant. Expanded boundary controls were 7 failed/7 passed
before parent correction. Four further red controls caught untyped spawn
failure, invalid hexadecimal reply data, and wrong-length memory replies;
parent now preserves typed causes and rejects malformed observations.
Private candidate cohort **36 passed, 1 requires_kvm deselected in 6.49s**;
scoped Ruff clean. Receipts in native-dos-process-stage/parent-candidate/.
This is reviewed staging evidence only: no production integration, real native
execution, broad-gate refresh, or M0-M7 exit. Separate call-preservation
diagnostic worker remains active.

Native worker production integration (2026-10-02): Devin correction batch
confirmed terminal exit0; final backend sources matched the parent-reviewed
candidate byte-for-byte, and the saved production baseline hash matched before
promotion. Integrated isolated worker/facade, ordinary-import protocol tests,
memory/protocol/registry controls, routine ownership/fast-test enrollment and
separate native test enrollment. No global test-module injection promoted.

Environment changed during validation: /dev/kvm is now present (character
10:232). First production cohort: 40passed/1failed; the native snapshot fixture
incorrectly wrote memory before loading a program. Corrected fixture to match
the existing native lifecycle, then native cohort **4passed/3warnings/55.22s**:
real strict abort plus fresh-session recovery, both snapshot controls, and
segmented DS observation. Receipt native-dos-process-stage/native-production-tests.log.
General snapshots still cover memory only; CPU/service/file-state snapshot
acceptance remains open and is explicit in dosunit-execution-spec.md.
Final nonnative cohort and scoped types are running after production test-import
and typing corrections; no refreshed broad-gate or M0-M7 acceptance claimed.

Native integration verification completed: production protocol cohort39passed
in96.76s; scoped Ruff/Pyright clean, MyPy passes with model.py included as the
owned import provider, ownership and type-ratchet pass after annotating new
constants. General paused-program snapshots remain explicitly unsupported by
the memory-only wrapper. Required quality-dev launched with six test workers;
no broad result yet. Read-only call-preservation Devin batch is terminal; its
REPORT.md describes non-leaf/environment and in-flight-artifact binding gaps.
These are a handoff for parent verification, not discharged proof obligations.

Parent source review of call-preservation handoff: local effect closure checks
the validity of supplied call proofs but does not require a proof for every
CALL. The earlier worker's wording overstated that closure. Keeping the leaf
gate is necessary until a complete bounded acyclic dependency census is proved.
New staged Devin job owns nonleaf-segment-preservation-stage/ only; missing,
cyclic, stale, ambiguous, cross-project and budget-limited dependencies must
remain typed refusals. No DOS environment or importer admission is changed by
this task. Parent review receipt: entry-call-preservation-review/PARENT_REVIEW.md.

Integration gate is still live: linter phase and startup architecture passed;
296 contract tests passed (6 warnings,54.81s), then fast pipeline launched.
Worker test permission depends on the parent's explicit terminal marker because
private PID-namespace process absence is not host-process completion evidence.
No final broad-gate result or original M0-M7 exit claimed.

Pipeline-worker configuration correction: host process inspection proves the
current fast pipeline is actually running pytest with3 workers, despite Make
receiving PYTEST_WORKERS=6 (the earlier296-contract cohort used6). The runner
hard-coded3 independently of --msc6-workers. Added bounded --pytest-workers
1..6 (direct default3), routed it through both pytest lanes and Make's pipeline
recipes, and documented the distinct compiler-construct pool. The live gate
was not restarted; its eventual result must retain the actual3-worker setting.
Frozen pre-edit runner rejects all4 new CLI-forwarding controls; final runner
module63passed/2.97s. Three stale expected lane-inventory entries were reconciled
with the already-enrolled REP/native suites; no tests removed. Ruff clean;
receipts pipeline-worker-setting/. This configuration repair is not a measured
six-worker end-to-end speedup or a whole-plan acceptance result.

Fresh gate/corpus checkpoint (2026-10-02): native-process quality-dev is terminal
exit2. Main fast cohort:9476passed/21failed/63warnings,2126.09s with actual3workers;
earlier296contracts used6. Full failure inventory is retained in
native-dos-process-stage/quality-dev-failures.json. Six Make default-concurrency
tests inherited outer MAKEFLAGS PYTEST_WORKERS=6. Parent reproduced all6 failures,
isolated default probing from inherited Make overrides, and added explicit6-worker
controls across all6 recipe targets. Combined runner/Make controls81passed7.36s,
Ruff clean. The lane-inventory failure also passes in this current scoped run
after its prior enrollment correction. The other14 broad failures remain open;
this focused result does not retroactively pass the broad gate.

Unchanged-manifest corpus refresh: real16 self3unknown/no proofs172.69s;
MSC8 self2passed24.69s; MSC8 rebuilt comparison1failed/1refused21.99s;
BC5 self15refused32.08s and rebuilt15refused27.76s. MSC8 sub_319B0 retains
observable_mismatch; sub_2B0D0 has oracle lowering timeout and candidate incomplete
block at0x24e9d. BC5 each has14call-boundary refusals and1incomplete lowering.
Owned source/input hashes stayed unchanged during each run. Selection/budgets
were not enlarged. Receipts: corpus-refresh-20261002/refresh-summary.json plus
per-run reports. This is not a complete native-dependency seal or cold/warm
acceptance, and real16 still lacks a rebuilt candidate in the frozen manifest.

Nonleaf stage parent review found exponential validation re-entry: linear chains
of depth1..8 trigger1,3,7,15,31,63,127,255 local-closure evaluations, despite staged
memoization. callee.complete re-enters child proof.complete with fresh budgets.
Staged patch remains unpromoted; shared-context bounded validation and independent
counted regressions required. Review receipt nonleaf-parent-review.md and
nonleaf-traversal-review.json. Devin's test slot was released only after the
actual broad-gate handle returned terminal2. Original M0-M7 remains incomplete.

Pointer-output gate diagnosis (2026-10-02): independent serial actual-SORTD
regression still fails caller-target completeness after its callee output/alias/
materialization assertions pass. The semantic SSA builder retains selector-window
refusals for caller0x108d0. Separate raw importer evidence:15blocks,7pending jump
records,0materialized,7failures; each is CALL_ON_PATH at0x10929. Native bytes
e868fe decode to near call0x10794, but no callee preservation is inferred from
that encoding. This is another integration case for entry-domain source-bound
call preservation, not a pointer-output rewrite defect. Receipts:
pointer-caller-refusal-review/REVIEW.md and caller-refusals.json. No production
gate or whole-function proof was relaxed; original M0-M7 remains incomplete.

Native no-op census blocker (2026-10-02): caller108d0's callee10794 begins36NOPs.
Its imported body has no refusals but exact coverage refuses instruction census,
so segment-effect closure is incomplete. Minimal independent native control:
RET(c3)coverage passes; NOP;RET(90c3)coverage refuses because frontend heads1000,
1001 become emitted IR addresses1001 only. New bounded Devin stage nop-census-stage/
owns private importer/coverage evidence changes, disjoint from nonleaf stage.
Require typed source-bound no-effect evidence, preserved stateful/unknown/fault
refusals and mutation controls; no production edit or corpus conversion yet.
Sandbox rechecked rootRO/repoRW/4GiB/nice10; one serial worker allocated.

Nonleaf parent frozen-candidate checkpoint:12controls pass15.19s; unchanged
positive-chain assertion fails old implementation16.65s. Corrected shared traversal
checks8closures at depth8 (previous255); forged-empty-census cyclic evidence stays
refused. Actual native caller->callee->leaf bytes now yield complete segment
preservation forCS/DS/SS/FS/GS and exclude changedES; same assertion/bytes refuse
CALLEE_NOT_LEAF on frozen before. This is segment-projection evidence, not whole-
function equivalence. Parent initial assertion omittedFS/GS; corrected fixture/log
retained. Worker final tests/review still pending; production unpromoted. Receipts:
nonleaf-parent-current/ and nonleaf-parent-review.md. Original M0-M7 remains open.

Nonleaf compatibility review continued: existing segment-preservation/native
binding cohorts31passed6.07s against the frozen staged candidate. Parent prepared
ordinary-import native tests for ES-only and ES+DS mutations;2passed4.78s, Ruff
clean. Tests remain private until production integration, with normal gate
enrollment still required. Worker now extends shared traversal to standalone
closure validation and adds counted regressions; the final changed delta must
be independently rerun. NOP census worker remains separate/staged. No new
production capability or milestone acceptance follows from these checks.

Nonleaf production integration (2026-10-02): worker1988 terminal0 and final
two-owner delta reconciled against unchanged saved production hashes. Parent
reproduced/fixed constructor-vs-revalidation root-budget mismatch, unbounded
pre-traversal tuple lookup preparation, and misplaced malformed-leaf guards
(3budget failures/1pass;2AttributeError controls before repair). Root proof now
consumes the same budget at construction/revalidation; oversized retained tuples
refuse before lookup allocation. Shared traversal covers local closure and
preservation entry points; cycles/dependency gaps remain typed refusals.
Production60controls pass61.10s with5workers, including native ES/DS mutation
propagation. Ordinary imports only; fixtures split out; fast contracts and native
default/expanded controls routinely enrolled. Enrollment123passed5.93s; scoped
Ruff/MyPy/Pyright/type-ratchet/ownership pass. New quality-dev started5workers,
one slot reserved for staged NOP worker. No corpus conversion or complete
function/termination/environment proof claimed. Receipts nonleaf-parent-final/,
nonleaf-parent-review.md. Original M0-M7 remains incomplete.

2026-10-03 — Provenance cost / M1 gate checkpoint: removed two unused real16
freshness reads while preserving both lowering seals and both admission checks
per side. Small-fixture ABBA median7.85s→5.48s with identical verdicts/counters;
no source cache or budget relaxation. Seven reviewed real-MZ accounting controls
now cover conditional normalization, corruption, ambiguous mapping and missing
counterpart refusals; mapping is correspondence, not executable reachability.
Parent sabotage checks fail when assumptions/accounting are bypassed. Final
early gate296contracts+339comparators passes, enrollment155 and PE32 adapters
19/17pass; scoped lint/types/startup/ownership gates pass. Exact receipts in
provenance-cost/REVIEW.md and m1-real16-boundaries/PARENT_REVIEW.md. Broad25failure
result and original acceptance ledger remain open; this is not M7 completion.


2026-10-03 — Parent independently reproduced Devin's libdosbox INT10/AH1B
capture using checksum/complete-RAM/return-cutpoint guards. Three transport
controls pass; capture6.2s, two786432-byte snapshots,27changed bytes accounted
for by output table and INT stack frame. First bounded attempt timed out;
no speedup inferred from retry. Exact identities/receipt retained under
.cache/comparator-implementation/libdosbox-video-intake/parent-review/.
Native observation only: not model agreement or whole-program acceptance.
AH1B replay refusal and original M0-M7/broad-gate obligations remain open.

2026-10-03 — Selected real16 lowering now follows binary-derived catalogued
call closure independently on both sides, with alias/ambiguity retention and
unknown-control fallback. Parent65controls pass; PE32 adapter19/17pass.
Early/normal gates and scoped linters include the owner and counted-work,
recursion, corruption-accounting and environment controls. Frozen SORTDEMO
plain retry now accounts for all3requested functions inside the same120-second
watchdog: allUNKNOWN (region admission or macro boundary), no missing report.
Catalog lowering10entries versus40previously; no solver budgets increased.
Profiled attempt crashed during candidate discovery; retained as unresolved,
not hidden by the plain retry. No M0-M7 acceptance claim. Receipt:
.cache/comparator-implementation/real16-selection-budget/PARENT_REVIEW.md.

### Parent staged review checkpoint — 2026-10-03

Real16 public suite92690 completed12passed/2failed843.94s. Failures are
unbound-premise and equivalent-changed-body component results returning unknown;
the earlier stale-assertion-only diagnosis was incomplete. Detailed same-budget
two-case retry16374 is live; do not accept M5 from the partial suite. After
source freeze ended, merged the independently red/green-tested missing-call-site
typed refusal and disabled-outer-deadline repair into staging. Original synthetic
controls2passed5.09s, scoped lint clean; backups and logs in
`.cache/comparator-implementation/m5-real16-public-review/`.

Terminal i386 lowering seam extracted unchanged into staged flat32_lifting.py;
59existing controls passed24.97s, scoped Ruff/ratchet clean. Shared driver
adoption, production/public integration and enrollment remain pending. Devin
M7 enclosed-entry-domain task90485 remains live and confined to staging.
No M5/M7 acceptance, no broad-gate or corpus-performance completion claimed.

Real16 public integration checkpoint: four reviewed owners and actual-MZ public
tests copied from stage to production, plus ordinary-import admission controls.
Saved pre-integration sources are m5-real16-public-review/production-before/.
Both prior public failures pass in focused same-budget retry:2passed202.34s;
original failing suite receipt remains visible. Scoped MyPy4owners and
lint-iteration pass; intake/pipeline cohort66passed10.31s. Routine relational
and cheap admission enrollment and execution-spec7.8 updated. Production public
+existing comparator+ownership suite28113 is live serially at unchanged budgets.
No M5/M7 acceptance follows until final evidence is reviewed.

Terminal/public-schema integration checkpoint (2026-10-03): shared flat32
lowering and complete-memory terminal proof owners now ordinary imports; both
function adapters reuse them. Restored exported ARCH after original MSC8 CFG
regressions caught its omission. Final full driver selections:MSC8 17pass10.23s,
BC5 19pass4.18s. Terminal/schema/pipeline/ownership194pass25.69s; public terminal
CLI+original replay/pipeline/ownership156pass29.57s; final CLI12pass38.54s includes
zero-budget unknown and unsupported named-projection rejection. Scoped MyPy and
lint pass. New compare-terminal16/32 reports remain conditional with explicit
premises and execution_status=not_run; schemas/spec/guides/routine tests updated.
Real16 production recursive/public+existing comparator+ownership94pass657.34s.
Integration receipt:m5-symbolic-terminal-review/integration-receipt.json. Required
quality-dev79472 is live (six test workers,one comparator admission worker).
No original M5/M7 acceptance or final corpus/performance claim.

Both Devin jobs stopped on provider quota,reset17:01UTC. Retained sessions:
super-debt (M7 enclosed-entry partial domain patch;resolver/tests incomplete),
miniature-quart (PE32 public task,source exploration only). Exact state in
.cache/comparator-implementation/devin-rate-limit-checkpoint.json. Resume rather
than duplicate after availability; parent continues useful integration/review.

2026-10-03 — Updated parent checkpoint: quality-dev79472 ended with
10483passed/13failed/23skipped (1008.86s); later decomp-opt phase did not run.
Three stale fetched-code ledger assertions were repaired and their seven-test
module passes. SetGear's30s subprocess timeout reproduces in isolation; the
remaining failures are not dismissed as contention. Matrix self controls now
have16passed76.30s; evidence map51supported/1unverified/4missing is not a plan
completion percentage. M5/M7 remain open.

PE32 public Devin38920 completed its staged implementation. Parent independently
found and repaired early-refusal selection loss and a test-helper error, retained
invalid-range refusals, and prevented premise-bearing unconditional projection.
Reviewed adapter scoped lint/MyPy pass; worker contract tests7passed and actual-PE
missing-domain/zero-budget driver controls4passed11.11s. Fourteen native joint
proof controls and production integration remain pending. Exact staged hashes,
red/green logs and review copies are in m5-pe32-public-review/. Real16 Devin4289
continues the bounded SORTD replay: current refusals require interior-call
preservation before RunMenu can supply an enclosing-entry premise. No corpus
conversion, M5 acceptance, or final gate completion follows from this checkpoint.

2026-10-03 — PE32 public recursive integration: reviewed adapter and both drivers
now expose an explicit-access-domain recursive_joint component without changing
ordinary member verdicts. Parent repaired selection loss on refusals, invalid
ranges, premise-bearing PROVED projection, and test-helper provenance forwarding.
Production32tests pass205.44s; pipeline/ownership126pass10.62s after correcting
the exact enrollment expectation (red retained). Scoped lint/MyPy green;18saved
production reports/16components schema-validated and retained with hashes in
m5-pe32-public-review/integration-receipt.json. Schema/spec7.10 and routine
enrollment integrated. Full M5/M7 acceptance and broad gates remain open.

Real16 enclosed worker4289 completed; parent checked actual replay remains7/5
refusals,0domain admissions. Resumed super-debt as58339 for exact retained-callee
proof reuse at unchanged64-resolution/depth16caps, staging only, baseline saved.
Native worker release granted after production PE32 proof cohort finished.

2026-10-04 — Ordered-I/O integration and Devin review:31 production files
integrated; combined focused native run171passed/1failed210.82s. The remaining
DX-port regression was a test-helper Const-only assumption. Devin85523 supplied
a resolver; parent rejected and repaired delayed register-read evaluation and
overlapping-write tracking, with two red controls against the submitted helper.
Final port module21passed; scoped lint-iteration passes and1252 frozen semantic
sources remain unchanged. Receipts: m5-parent-integration/ and
m5-dx-port-review/PARENT_REVIEW.md. Nested-invocation scope repair remains staged;
conditional dependencies must not escape into universal closure/cache consumers.
Original M5/M7 and broad final gates remain open; no corpus conversion claimed.

### Reviewed modular unary-use integration

Integrated authenticated active-unary dependency traversal in the IR modular-use
census, preserving signed-extension refusal and requiring exact producer evidence
for captured one-bit values. Added 17 positive/corruption controls to the routine
QA inventory. Parent baseline: 4 failed / 13 passed; final combined near-return and
modular-use cohort: 102 passed in 23.02s. Scoped lint-iteration and MyPy passed.
Evidence: `.cache/comparator-implementation/m7-unary-return-review/parent-*.log`.

Devin carry proposal remains unintegrated: parent review reproduced a pinned-wrapper
validation bypass and a lossy narrowing/widening chain receiving a PROVEN carry link.
A bounded correction is being staged; passing original tests alone was insufficient.
M5/M7 and the final broad gate remain open; no new corpus acceptance claimed.

### Integrated copy and PUSH consumer repairs

Parent integrated exact low-byte copy projection and eight routine corruption
controls after reproducing two baseline failures; scoped lint/MyPy passed.
Frozen saved-failure replay plus new controls:330passed/68failed in248.73s,
versus357failures in the prior full run (different total selection). Remaining
failures are saved verbatim in m7-control-refusal-review/remaining-failed-nodes.txt.

Parent then reviewed/integrated physical PUSH capture identity repair with14
controls:45passed14.00s. Differing capture versions require identical exact prior
producer, width/projection checks and all other metadata; no generic unary
identity substitution. Scoped lint/MyPy pass after explicit bool typing. Final
63remaining-fast-failure +14control replay is running; five carry/SORTD/COD
cases remain explicitly deferred to their owning followups, not accepted.
Evidence under m7-indexed-copy-unary/ and m7-physical-push-review/.
M5/M7 final gates and current performance reconciliation remain open.

Physical-PUSH followup terminal:53passed/24failed25.16s (63previous failures plus14controls). With the five explicitly deferred cases,29previous failures remain outstanding; this is not a fresh full-suite count. Exact nodes/log: m7-physical-push-review/{remaining-failed-nodes.txt,parent-followup.log}. Final-source controls pass; no M5/M7 acceptance claim.

### Stack-coordinate integration and remaining13cases

Parent source trace showed SP writes consuming captured Sub16/Add16 results,
while extent collection required a folded register descriptor. IR extent owner
now records prior exact word captures in one pass, authenticates producer/read
projection, and retains unwrapped literal arithmetic coordinates. Missing, duplicate,
wrong-width/op/decoration, active-unary and wrap-sized producer controls refuse.
Native extent tests now pass; no private-write permission is inferred by this owner.

Reviewed/integrated worker entry-prefix snapshot repair: scalar TMP affine reads
require earned recorded producer operation, exact width and zero displacement;
16permanent corruption controls enrolled. Repaired incomplete scoped-resolution
mock by supplying declared_services; no production fallback added. Final combined
130tests pass9.68s, scoped lint/MyPy pass (test modules excluded by existing typing
policy). Evidence: m7-stack-window-review/parent-{green,lint}.log and
m7-stack-extent-review/.

Saved failure set now has13outstanding cases:7address-escape/private-write,2carry,
and4pipeline/SORTD cases. This is focused reconciliation, not a new full gate.
Address-escape staging is delegated; Devin carry correction remains live58522
(revalidated handle this turn), with original rejected proposal retained. Original
M5/M7 and corpus/final release evidence remain open.

### Carry/escape final consumer integration

Parent reviewed and integrated address-escape dependency repair:34passed6.19s,
scoped lint/MyPy pass. Capture identities now precede live-register fallback;
widths and pending conversions remain authenticated, derived-address taint
survives narrowing and outgoing/store controls.

Devin carry correction terminal0 (session58522). Parent rejected residual
missing-definition storage-width fallback with an executed red control, added
explicit refusal, and integrated identity-only definition lookup plus explicit
conversion consumption. Broader96test audit found3store-destination regressions
(also reproduced in Devin's staged version). Parent repaired the Alias byte-lane
consumer with exact16to8 traversal, preserved captured producer/read widths,
operation/projection and register-version checks;9new refusal/positive controls.
Final combined carry/ALU/destination/boundary cohort:110passed29.04s.
Evidence: m7-carry-unary-review/parent-final/ and m7-carry-destination-review/.

Reviewed/integrated retained decoded-boundary reuse at invocation lookup. It
removes the concrete conflicting-census exception without weakening retention
guards. Five boundary controls pass in final cohort; SWAPS still has honest
IR_BUILD_REFUSED, not accepted. Scoped MyPy reports34identical saved-before
diagnostics (0added/removed); no clean typing claim for that restricted import
scope. Startup architecture passed.

Remaining four previously recorded pipeline cases are still open:LoadProgram
pointer publication (binary dereference facts exist but DS physical-source
evidence missing),SWAPS caller IR refusal,InitBars caller-domain transport and
SORTD inventory timeout. Current focused fixes are not final broad/M5/M7
acceptance. No source or proof budget relaxed.
