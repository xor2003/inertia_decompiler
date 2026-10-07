# Comparator Devin review — 2026-09-30

Scope: parent source/test review of the current declared-output worker, plus an
acceptance-ledger review of recent recorded Devin deliveries against the original
M0–M7 plan. Earlier checkpoint test totals below are historical evidence from the
plan; they were not all rerun during this review. No original milestone is fully
accepted. Conditional/executed agreement is never promoted to symbolic proof.

| Delivery | Parent review / disposition | Plan relevance / remaining work |
| --- | --- | --- |
| Signature discovery/refusal controls | Recorded exact dirty-baseline review: four owned test functions; corrected the claim that INT16 was explicitly environment-refused. Historical parent red4 / green9. | M1/M2 guardrails; names/signatures cannot prove callees. |
| Omitted real16 near-RET leaf intake | Recorded source-bound receipt review and public integration, 16-request/60-second cap; historical explicit-owner538 passing controls and lint/type checks. | M2/M5 partial: frozen SwapBars/InsertionSort/Sleep still UNKNOWN; alternate exits/nested calls refused. |
| Initialized-program seam audit | Diagnostic accepted; rejected suggested bare-RET-versus-exit mismatch because no complete callerless return was established. | M6 groundwork; an audit itself added no execution capability. |
| MZ boot owner | Recorded parent review of two exact owned files; initialized arena, header entry/stack and identities integrated without a synthetic caller. Historical292 owner checks /92 public controls. | M6 partial: DOS termination-only lane; no flat32 whole-program parity. |
| Declared output streams (current worker) | Terminal exit0; two new owned files,47 worker tests. Parent independently integrated opt-in policy, identity, execution, report and stream comparison; found/fixed malformed result handles and AX-width admission. | M6 bounded step: INT21/AH40 successful independent stdout/stderr streams only; real files, partial writes/errors, console/device behavior and general services remain open. |

## Current-worker review

The pure service checks handle scope, per-call/total caps, 16-bit buffer wrap and
exact allocation bounds before its single memory read. Zero count reads nothing;
short reads refuse and callback exceptions propagate. Parent checked every owned
source/test file and preserved worker-final copies and exact review/integration
diffs under `.cache/comparator-implementation/real16-output-service/`.

The worker handoff's HEAD-based baseline interpretation is rejected: existing
program owners are untracked in this shared tree, so an empty `git diff` against
HEAD cannot establish restoration or authorship. The saved byte baseline and
parent diffs establish the integration changes. Its statement that integration
still admitted only termination was stale relative to concurrent parent edits.

Parent review adds integer/u16 validation to accepted/refused handles and AX;
one focused regression fails on the saved worker contract, then passes after the
fix. Type aliases now use the project-required annotated modern syntax. Routine
pipeline, ownership and QA lists include both pure and execution controls; the
QA entries precede Make's immediate selection so the new module is actually
checked, rather than silently classified as legacy.

Output-service policy is explicit, defaults off, and binds environment/boot
identities. Reports keep all write receipts and enabled handles. Stream comparison
uses the pure owner's concatenation, admits different chunking, and detects byte
or destination mutations. Independent stdout/stderr interleaving is deliberately
outside the declared contract. Symbolic status remains
`not_established_by_execution`.

## Acceptance still open

M0–M3 bounded implementation steps have recorded evidence, but representative
binary acceptance and final gates remain open. M4 differing-shape/termination
proofs, M5 recursion/indirect/environment closure, M6 initialized scenarios on
both architectures, and M7 cold/warm performance/cache/release evidence remain
partial. The separate affine-loop worker and broad quality gate are active;
this review neither claims their acceptance nor reruns their overlapping work.

## Current parent validation

Final six program owners, pure/actual-output controls and pipeline enrollment
cohort:175passed/14.89s with3pytest workers. Separate owner Pyright:0errors.
Six-owner `make linters-files` passes selected Ruff/MyPy/type ratchet; architecture
startup, agent-context and test-ownership checks pass. Earlier failures in the
new public-report fixture and exact enrollment inventory were corrected; no
assertion or refusal boundary was weakened. Full shared-tree quality-dev remains
a separate active gate, so these results are scoped acceptance only.

## PE32 boot delivery: parent review (2026-09-30)

Devin delivered only `tools/dosunit/runtime/pe32_program_boot.py` and its boot test
owner: 43 worker controls. Exact worker-final copies are retained under
`.cache/comparator-implementation/pe32-program-start/worker-final/`.
Parent rechecked the complete worker-to-current delta: the boot test owner is
unchanged; production changes add actual-byte entry backing, image/environment
compatibility and recomputed boot identity checks, plus a bounded input-file
size check before parsing. Two parent regressions were red before correction:
stale boot entry/bytes and excessive observation work. Observation budgeting
belongs to the parent replay integration rather than Devin's boot owner.

The parent supplied replay, manifest, CLI, schemas and enrollment. This supports
initialized, import-free i386 PE32 executables with exact caller-declared memory
and registers and an explicit synthetic terminal gateway. Imports, TLS, runtime
loader dependencies, undeclared machine inputs, unsupported segment behavior and
x87 remain outside the admitted contract. No Windows execution environment is
claimed. Concrete agreement remains `not_established_by_execution` as a proof
status; it cannot discharge symbolic equivalence.

Recorded integrated evidence: 269 passed / 3 warnings / 35.82 seconds with three
workers; scoped Ruff/MyPy/type ratchet pass, Pyright zero errors, startup/context/
ownership checks pass and cached mypyc import smoke passes for 39 modules.
These are scoped results, not final release acceptance. The latest separate
broad development gate is terminal: 28 failed / 8868 passed / 1 skipped in
1409.06 seconds. Those failures have not been collectively classified or waived.
The earlier PE32 development-gate attempt stopped at a temporary-directory
failure; it is not a passing gate. Original M0-M7 acceptance remains open.

Current priorities remain frozen-corpus per-entry/dependency evidence, resolution
of broad gate failures, M4/M5 proof closure and M6 additional declared services
and representative initialized scenarios. Preserve existing ELF support; the
user has asked for PE32 improvement, not new ELF capability.

Fresh parent recheck after this ledger review: all three PE32 boot/replay/CLI
test owners pass72tests/3warnings/8.45seconds with three workers. The broader
269-test result above is recorded prior integration evidence, not this rerun.

Standalone module-entry PE32 smoke also checks equal and deliberately changed
serialized programs: exit0/agreed versus exit1/mismatched, fullu32 exit values
305419896/305419897 retained; proof_status remains not_established_by_execution.
Artifacts and current-source hashes: pe32-program-start/public-smoke/ and
review-current-source-manifest.json. Direct tools/dosunit/dosunit.py invocation
without a package path failed import; the supported module entry succeeded.

## Declared read-only input files: reviewed delivery (2026-09-30)

Devin terminal exit0; two exact owned new files,83pure read/seek controls.
Parent independently read all code/tests and saved worker-final copies. Parent
red controls expose three admission gaps: corrupt served-byte budgets accepted
by seek, predefined handles accepted by successful receipts, and bool segment
coordinates accepted by read receipts. Corrected at the pure service boundary;
no assertions or refusal gates weakened. Worker claim that all corrupt runtime
state is caught at each service boundary was broader than its implementation.

Parent integration adds explicit bounded input manifest/identity, fresh per-run
file cursors, staged guest write/cursor commits, exact code/buffer protection,
complete cursor receipts, public reports/schemas, routine pipeline and ownership.
Actual MZ baseline3failed/1passed6.45s; first integration10passed3.03s. Combined
draft307passed/1failed at the stale exact pipeline inventory; final354passed/
3warnings/26.79s,-n3 after enrolling the new binary controls. Eight-owner scoped
Ruff/MyPy/type ratchet passes and Pyright0errors. Startup/context/ownership gates
pass. Evidence/diffs/source hashes under real16-file-input/.

Accepted scope: successful AH3F reads and AH42 seeks on explicitly preopened
immutable regular files; max32handles,4MiB supplied/served caps, no host file
access. EOF preserves unreturned bytes, actual seek returns fullDX:AX, split
reads compare by complete named outputs and final cursors. Missing/foreign/
discontinuous cursor evidence cannot agree. Unknown DOS handles/services remain
refused. Opening/closing/creating/writing regular files, devices, Windows services
and representative program acceptance are still open. Concrete agreement never
establishes symbolic proof. This is a bounded M6 step, not original M0-M7 closure.

Final file-input review follow-up: one additional red regression demonstrates
that missing/foreign/malformed unused runtime handles were not checked before
service effects. The common boundary now validates the complete exact handle
set and every cursor, bounded to32items. Final authoritative integration cohort:
355passed/3warnings/21.29s,-n3; eight-owner Ruff/MyPy/type ratchet passes and
Pyright0errors. Earlier354test result precedes this final correction. Exact
worker-final versus parent-final deltas and source hashes refreshed under
real16-file-input/. Original M0-M7/release acceptance remains open.

## REP-store gate diagnostic review: qualified findings (2026-09-30)

Read-only Devin report: rep-store-gate-review/devin-diagnosis.md. Accepted the
source mechanism: final C acceptance requires both compilation targets; direct
failure diagnostics can be suppressed while the original clean tail snapshot
is printed. Rejected its categorical ten-case KVM attribution: none of the ten
retained REP failure sections contains the KVM blocker, and their referenced
stdout artifacts are no longer available. Sibling failures establish missing
KVM for those siblings, not every REP case. Also rejected log/file mtime and
three current-file hashes as proof of unchanged source throughout the broad
run, and a cache-record timestamp as proof of fresh native compilation rather
than reuse of a compilation receipt.

Parent current owner recheck:19passed/116.04s,-n3 including all ten REP binary
variants and corruption controls; independent prior one-case pass32.72s.
Current COD CLI case passes1/45.99s. The MSC fixed-width actual-target test now
has its missing requires_kvm marker; its focused run passes1/16.06s, Ruff clean.
These are current scoped test outcomes; no controlled performance comparison,
retroactive broad-gate pass or fresh-backend-execution claim is made.

The attempted remaining16node audit initially collected zero due to xdist's
reported @sortd-initmenu suffix. Explicit normalization then verified exactly16
collected nodes. Its execution log ends atFFF without a terminal summary and
the execution handle is now missing; this is incomplete evidence, not a sixteen-
case result. Narrow diagnostic revalidation is ongoing. Original M0-M7 remains
active with unresolved gate and proof/corpus acceptance.

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

Parent baseline reporting probe now reproduces both defects with terminal exit1:
rejected acceptance plus an incomplete snapshot emits merge_gate="hold", whose
consumer Boolean conversion isTrue; rejected acceptance plus stable semantic
stages emits severity=clean and merge_gate=True. Artifact:
acceptance-reporting/parent-baseline-probe.json. The failing assertion explicitly
requires BooleanFalse for rejected acceptance. This is focused reporting-boundary
evidence, not a semantic equivalence result. The existing typed-status test and
stale-failed-status test encode the old behavior and require corrected contracts
with preservation checks; no semantic snapshots may be rewritten to pass them.

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

### Parent diagnostic provenance checkpoint (2026-09-30)

InitMenu Devin session56125 polled live; terminal diagnosis still pending. Parent
verified41 retained inspected-source copies:40 match launch baseline; all41 match
current source. The sole baseline drift is the already recorded parent coordinate
guard. Late snapshots establish byte identity, not runtime causal coverage or
exhaustive inspected-source coverage. Receipt: initmenu-gate-review/parent-snapshot-review.json.
No InitMenu root-cause/function acceptance is inferred from the clone reproduction.

Independent read-only Sleep diagnostic session88821 launched with current dirty
source hash baseline under freshly checked rootRO/repoRW/privateproc/dev/4GiB
sandbox. Ownership only ignored sleep-gate-diagnosis/; no production edits,
new decompiler runs, DOS execution or broad tests authorized. It must trace
binary/typed-IR call-return and stack-storage evidence behind the retained
unassigned-stack-local refusal; printed C is only a symptom. Other task retains
callee-region admission ownership. No gate waiver or original M0-M7 acceptance.

### InitMenu unification hypothesis parent controls (2026-09-30)

Parent inspected installed angr VariableManagerInternal.unify_variables and
retained exact source hash/excerpt. Same-offset stack grouping occurs only when
interference is not None and the variables pass its noninterference check.
Independent real-manager synthetic controls: no interference argument keeps
scalar/array unified identities distinct; empty interference graph merges them.
These controls verify a third-party boundary possibility, not the actual failing
InitMenu mapping, invocation arguments or variable insertion timing. Devin's
raw-offset-conflation hypothesis remains unestablished without that causal trace.
Artifacts: initmenu-gate-review/parent-unification-review.json and
parent-unification-controls.json. Initial probe used an incomplete None manager
and failed its constructor; corrected probe uses real KnowledgeBase/VariableManager
and exits0. No production fallback was introduced. Both diagnostic sessions
polled live; no terminal report, function-fixed or original M0-M7 acceptance.

### Terminal InitMenu diagnostic parent review (2026-09-30)

Devin session56125 exited0; diagnosis.md retained with SHA256 in
initmenu-gate-review/parent-diagnosis-review.json. Accepted only partial diagnosis:
the independent clone boundary defect was already repaired by the parent guard.
Report actual substitution hop remains unobserved; cached IR source binding
remains unsealed. Its epilogue addresses101c5/101c6 disagree with exact binary
101d5/101d6. Current fallback description omits the integrated refusal guard,
and its baseline owner is in fact retained in coordinate-clone-review/.
Alias-clean and unconditional helper-success assertions are not accepted.
Unification remains conditional on interference evidence, with parent synthetic
controls recorded. No new production patch/function acceptance from this report.
Parent fresh focused InitMenu regression session73082 launched after checking
no active pytest pool, with3workers and unset semantic-cache hash seed. Sleep
diagnostic session88821 remains live; parent independently decoded actual
BP-4 AX/BP-2 DX stores and signed-high/unsigned-low comparisons, retaining
allocator-success and callee-output contract limitations in its exact-byte JSON.

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

### Combined input/output M6 scenario staging (2026-09-30)

After parent inspection found existing initialized-MZ input and output controls
exercise their policies separately, delegated one disjoint staged combined-policy
scenario to Devin session22939. Ownership only ignored real16-file-copy-scenario/;
no production/config/docs edits. Eight-source baseline retained, graph access
unavailable under never disclosed, sandbox freshly checked hostRO/repoRW/4GiB.
Task requires real Unicorn on compact actual MZ bytes: deterministic original,
equivalent chunking, output/destination/exit mutations and incomplete-policy
controls, plus immutable state and exact stream/cursor receipts. No invented
file opens or real-DOS completeness, no proof promotion; parent review/enrollment
remain mandatory. Synthetic scenario does not close representative whole-program
M6 scope. Sleep session88821 remains live with static-only ownership.

### Reviewed combined initialized-MZ file-copy scenario (2026-09-30)

Devin session22939 exited0; parent verified all8baseline source hashes unchanged
and independently reproduced20staged controls in1.17s. Promoted to
tools/dosunit/tests/test_real16_program_file_copy.py, removing staged sys.path
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

### Saved pipeline failure-triage parent verification (2026-09-30)

Parent verified pipeline-failure-triage/report.json against exact retained
source-log SHA256 and counted all24rows:13unresolved,3explicitKVM,6assertion
mismatch,2timeout. This is saved-log classification, not current rerun status
or proof of deeper causes; fixture-build lanes still lack independently checked
per-node causes. Group-suffixed labels must not be treated as runnable nodeids.
KVM evidence remains execution-context-specific. New parent InitMenu regression
supersedes its old syntax symptom only for that selected current run. Exact
review receipt retained as pipeline-failure-triage/parent-review.json. Other
task is currently idle after interruption; its callee-region ownership preserved.
Sleep current diagnostic session79497 polled live, no terminal report or
production changes accepted. No original M0-M7 milestone closure.

### Original M4 acceptance audit delegation (2026-09-30)

Parent refreshed graph index_status:approval-blocked under never, so bounded
source fallback retained without graph coverage claims. Independent read-only
Devin session55214 launched for original M4 requirements, not later-roadmap
substitution. Fourteen-path current baseline includes authoritative plan and
register/affine/paired-region/memory owners plus real16/flat32 public controls.
Ownership only ignored m4-acceptance-audit/; no tests, corpus execution or edits
outside artifacts. It must distinguish actual-byte production proof controls,
conditional/UNKNOWN evidence, initiation/preservation/exit/progress/termination,
and propose one concrete missing acceptance slice with exact ownership/budgets.
Non-exhaustive inspected scope must be disclosed; no completion claim from
historical test totals. Fresh sandbox rootRO/repoRW/4GiB checked. Sleep current
probe79497 remains live preparing hooks; parallel callee-region ownership stays
preserved. No broad gate or original milestone acceptance.

### Current Sleep probe parent observation (2026-09-30)

The single authorized runtime probe completed exit4 in27.918s (not timeout).
Parent verified positive wide-condition and topology hook observations and
zero registered source drift against its launch baseline. All3wide-lowering
returns record raw1/normalized0/classified0/materialized0/failure1; all3loop
topology returns areNone. Summarizer error count0. Typed SLE/SGE/ULE facts reach
the lowerer, but its IR-pair and C-expression prerequisites refuse; terminal
classifier is not reached through the observed path. This narrows the missing
evidence without proving which producer is defective.

Important coverage limit: IRValue summaries omit version/expr/index/call_output
and other dataclass equality fields. Apparently matching summaries do not prove
the operands compare equal. Absence of downstream calls does not prove a broken
call ABI. Parent retains actual receipt/records hash in
sleep-current-probe/parent-runtime-review.json. No flag suppression, production
patch, extra diagnostic run or function acceptance. Worker final report and
original-M4 audit remain pending.

### Original M4 branch-pairing audit reviewed (2026-09-30)

Read-only Devin session55214 exited0 with matrix/report. Parent inspected exact
flat32_cfg_regions.compare_reblocked_cfg, region_pairing proposal contracts and
real16/flat32 actual-byte controls: flat32 uses the singular ordered proposal;
existing shared API enumerates bounded ordered/permuted proposals. This supports
one concrete original-M4 equivalent-condition gap, not an exhaustive gap audit.
All14baseline paths rehashed; only authoritative plan changed by parent ledger/
M6 edits, with original M4 projection previously checked unchanged. Worker report
incorrectly says15baseline paths; parent receipt records14. Test status is source
inspection only, no new acceptance claim. Graph list_projects transport closed;
bounded exact source fallback, no graph freshness/coverage assertion.

Fresh sandbox verified rootRO/repoRW/4GiB. Devin session74977 owns only ignored
flat32-branch-staging/: preserve baseline consumer, build staged multi-proposal
consumer and actual-i386-byte red/green/mutation controls for MSC8/BC5. Cap64,
one shared proposal/lowering/solver/invariant deadline, retain failed mappings,
full-state observables and scoped UNKNOWN. No production edits, broad gates,
corpus/decompiler runs or commit authorized for this worker. Parent must review,
reproduce and integrate before any capability claim. Callee-region ownership
remains with other task. Sleep diagnostic79497 still live; no extra runtime run.
Original M0-M7 scope remains active and unaccepted.

### Sleep current diagnostic terminal review (2026-09-30)

Devin79497 exited0; single diagnostic execution remains exit4/27.918s, no
extra run or production patch. Parent accepts bounded observations:11/11DX
condition lowering expressions absent,3topologyNone, terminal classifier not
reached. Internal operand/orientation/topology causes remain unproved. Parent
rejects report causal linkage from failed C predicates to topology absence:
collect_loop_break_topology consumes CFG inventory/SSA independently. Likewise
absence of lowered-expression does not identify a particular orientation helper;
printed IR summaries omit equality fields. Rendered-C symptoms corroborate only.
Report/hash and precise acceptance limits saved parent-final-review.json. No
flag suppression or function-fixed claim; original scope/gates remain open.

### Flat32 pairing staged review caveat (2026-09-30)

Parent provisional code review recorded reporting blockers: no-candidate
FactCounters claim materialization never produced, enum-to-string regression in
exception attempt rows, and incomplete deadline reporting. Stage remains
worker-owned; no production promotion. Devin smoke then reported first swapped
loop fixture PASSED under saved singular baseline. Consequently source-level
API difference is a prospective gap only; require actual-byte baseline refusal
and staged solver proof (plus mutants) before acceptance. Parent public PE32
fixtures remain unrun and may need stronger ambiguity controls. No capability
or original-M4 acceptance claim. Session74977 remains live.

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

### Narrow Sleep operand/topology diagnostic started (2026-09-30)

Parent inspected exact operand dispatch and corrected earlier prospective
owner: condition_register_expression_8616 lives in Structuring, whereas Alias
resolve_condition_register_definition owns reaching storage identity. Current
None operands still cannot distinguish those layers. Independent loop topology
uses physical classifier, optional SSA-backed connector normalization and final
classifier; predicate-materialization failure alone does not determine it.

Fresh rootRO/repoRW/4GiB verified; Devin45482 owns only ignored
sleep-operand-topology-probe/. This separate task authorizes one<=150s direct
in-process run, exact operand builder/view returns and topology classifier/SSA/
connector results, positive binding-site observations, source snapshots and drift.
No retry, production edits, flag suppression, tests or DOS tools. Parent review
required; prior run remains untouched. Branch74977 and static unequal-step62531
are still live with disjoint artifact ownership. Original scope remains active.

### Unequal-step design reviewed; staged implementation assigned (2026-09-30)

Static Devin62531 exited0. Parent accepts bounded finite frontier/concatK2
proposals as an implementation direction, not proof. Rejects unpaired-head
common -2 normalization, owned string statuses and implied signedness/wraparound
coverage. Require closed endpoint relation, actual return identity, complete
feasible-path coverage, full-state guarded solver discharge, and checked positive
finite instruction progress on both sides. Parent also rejects universal pre-read
hash claim: worker log admits post-hoc hashes on some additional paths; four
parent baseline anchors are independently verified, not every cited source.

Fresh rootRO/repoRW/4GiB checked. Devin3617 owns only ignored m4-macro-step-stage/
for corrected typed proposal/term/adapters and actual-MZ/both-flat32/PE controls,
one deadline and explicit path/term limits. Eight current owner snapshots/hashes
saved before launch. No production edits, broad gates, corpus runs or commit.
Positive controls must actually solver-prove; negative guards/width/memory/
endpoint/coverage/stutter controls must refuse or mismatch honestly. Parent
reproduction/integration pending; no original milestone acceptance.

### Sleep forked-record integrity and positive evidence (2026-09-30)

Single narrow diagnostic run exit4/25.201s. Parent-local status lists only3
hook names; records instead contain forked worker observations, so that status
is not hook-coverage evidence. Parent parsed1994JSON records, found24duplicate
(hook,event,seq) keys and a per-hook400cap ONLY on Alias _transfer_kind. No
global cap inferred. All42registered snapshots rehash unchanged. Receipt
parent-record-integrity-review.json retains exact counts/caps/hash caveats.

Direct operand builder records have17DXcalls (4sle,13sge), each uniquely
paired within that hook to a None return. Exact builder source short-circuits
on missing LHS before RHS; this is positive missing-DX-expression evidence,
not proof that high-stack lane lookup refused. Eight physical/final topology
classifier returns record non-unique-exit-target; four transparent-topology
returns retain resolutions=[] (first independently inspected). Worker final
report pending. PID-less cross-hook causal associations still need scrutiny;
no extra run, semantic patch, empty-connector proof or function-fixed claim.

### Branch-search delivery declined (2026-09-30)

Devin74977 terminal0. Parent verified production consumer remains byte-identical
to saved baseline. Declined staged search promotion: no baseline-red/new-proof-
green result; worker substituted parity/enumeration/refusal controls (reports
30pass, parent did not rerun rejected stage). Independent parent6realPE controls
already showed existing ordered capability. Finite canonicalization battery
cannot support universal PERMUTED-impossibility claim; retain bounded observations
only. Fake no-candidate counts and enum attempt regression were corrected in
stage, but that does not establish applicability/performance gain. Receipt
flat32-branch-staging/parent-final-review.json. No production delta accepted;
unequal-step3617 continues as demonstrated original-M4 refusal work.

### Narrow Sleep diagnostic terminal review (2026-09-30)

Devin45482 terminal0, no production patch. Parent accepts observed missing-DX
operand expression/empty candidate source refusal and present-SSA/nonunique-exit
normalization failure. Rejects two incorrect claims:70distinct hooks fired,
not116; Alias calls are REPLACE when represented_definition/is_call are true,
not unconditionalKILL. Missing candidates therefore must not be repaired by
bypassing the source join. PID-less fork sequence collisions and transfer-kind
cap limit cross-hook causal claims; uniquely matched directDXreturns remain
positive evidence. Per-block transparency conjunct and upstreamDXcandidate
producer remain unobserved; no speculative fix or extra run. Exact receipt
sleep-operand-topology-probe/parent-final-review.json. Macro3617 remains live.

### Live macro-step boundary review (2026-09-30)

Parent independently polled handle3617 twice: live, no terminal result. Exact
staged-source review plus parent probe reproduces three boundary behaviors:
return frontier expansion returns2 paths with max_paths_per_cut=1; malformed
scalar width defaults to32; malformed memory entry is omitted by masked_state.
These must be closed by typed rejection/admission before production promotion.
This is not a demonstrated end-to-end false proof. Concatenation allocation
budget and actual both-width unequal-step positives/mutants remain review
requirements. Evidence and reproduction live under
m4-macro-step-stage/parent-review/. Worker-owned stage and production sources
are untouched; no original milestone is promoted.

Parent boundary corrections are now isolated in
m4-macro-step-stage/parent-review/boundary-correction/ with prepatch hashes.
Seven independent rejection checks went red on worker helpers, green on this
copy; corrected two helper modules pass scoped Ruff after extracting the
common charged-path append. No overlapping pytest pool or worker-owned edit.
All eight production baseline-owner hashes independently match baseline.json.
Devin3617 remains live: fixed an inverted slow-concat side after KeyError14;
latest log investigates positive-case observable mismatch and explicit versus
lazy flag-state outputs. This diagnostic is not yet parent-verified. Keep all
flags observable; no proof promotion or fixture substitution is authorized.

### Parent flag-lookahead repair (2026-09-30)

Independent immutable-intake lift found first unrolled16 body writes12/4 but
omitsFLAGS36, whereas the second writes12/36/52/4. Production local liveness
proved jcxz;dec dead incorrectly. Parent isolated correction stops local decoded
lookahead at transfers; exact same first body now writes12/36/52/4. This is a
verified Python semantic-owner defect, not the worker's proposed pyvex-C FDA
explanation. Integrated generic control-boundary keep-unknown decision; preserves
straight-line overwrite elimination and full flag observables. Added routine
flag-boundary regressions and lift-cache v5->v6 invalidation, with persistent
old-cache rejection test. Worker staging is untouched; straightline_ssa baseline
intentionally differs only in cache version/comment at this checkpoint.

Parent pytest3worker cohort:71passed/17.76s across new flag boundaries, existing
status-flag liveness, CFG liveness and lift context. Touched semantic/test and
manifest/pipeline sources Ruff clean. Stale-cache regression added afterward;
separate direct assertion passed. Full project gates remain outstanding; KVM
still absent. No function-fixed, macro-proof acceptance or original milestone
completion claim. Devin3617 remains live; reported both flat32 positives prove
after bookkeeping fixes, pending independent final review.

Parent routine-projection audit confirms new flag-lookahead test is selected
by FOCUSED_PYTEST_TARGETS and selective flag semantic ownership. Also enrolled
in QA Ruff/pytest inventories; default/expanded Make cohorts contain it. Latest
Devin log reports real16 positive now proves on current sources and launches
its full staged suite; handle3617 independently remains live. Worker's earlier
backend-change explanation is rejected: parent recorded the exact Python
liveness repair and cache-version delta in PARENT_UPDATE.md and flag receipts.
No macro-stage proof is accepted until parent reproduction and all boundary
corrections pass. No whole-tree gate or original milestone completion claimed.

Latest independent macro review distinguishes narrow ABI PASS from required
full-state proof: adding STC;RET to original unroll2 passes with OUTPUT_REGS,
refuses when allREG32names are supplied. Return-observation receipt records
exact bytes; new parent controls cover carry/ECX changes in both drivers. Also
expired flat32 endpoint currently invokes solver after deadline; independent
red test and isolated green correction retained. Deadline test follows helper
extraction into flat32_macro_terms, preserving its original rejection contract.
Devin3617 independently polled live; now reads parent corrections and applies
full-state return changes. Reported37green before corrections remains historical,
not parent acceptance. Boundary malformed-state/path limits and deadline checks
must pass with actual16/both32positives before integration.

Flag semantic owner also passes scoped Pyright (0errors/0warnings). Parent
macro search regression now independently demonstrates empty-frontier rounds
continue after no extension can exist; bounded test fails immediately rather
than consuming a large stress budget. Correction handoff requires early break
and charged initial work. Worker3617 remains live and actively ports parent
malformed-term, path-limit, deadline and full-state corrections. No corrected
macro-stage suite has yet been accepted by parent.

### Macro-stage independent reproduction (2026-09-30)

Devin3617 independently terminal0. Final report:38staged tests/21.5s and8parent
boundary checks passed, scoped Ruff/compile clean. Parent saved all8worker-final
Python sources and SHA256 manifest before further changes. Parent then fixed
the two independently red remaining resource controls: check outer deadline
before/between discovery calls and proposal timing; stop empty-frontier concat
iterations and charge initial concat work. No weakening of state, flags,
coverage, endpoints or progress.

Independent parent combined suite on corrected stage:52passed/22.32s with
3workers. Includes exact original-MZ/both-flat32/actualPE positives, semantic
mutants, parent malformed-width/memory/path controls, expired endpoint/public
entry, exhausted search, carry/ECX return mutations in both drivers. All these
results are staged; production macro integration and relevant project gates
remain pending. Full original M0-M7 is still unaccepted. Evidence under
m4-macro-step-stage/parent-review/combined-acceptance.log and worker-final-snapshot/.

### Macro primitives promoted, orchestration pending (2026-09-30)

Parent promoted seven reviewed modules into tools/dosunit with package imports;
owned real16 reason/scope fields now use enums. Five migrated production test
files retain staged positives and independent parent controls. Production suite:
52passed/20.70s,3workers. Initial migration missed three local test imports;
corrected and independently reran the failed dropped-coverage regression before
the complete52green run. No test weakened. Production modules/scoped tests Ruff
clean; typing review corrected test-helper object annotations and deliberate
malformed-input cast boundaries. Relational default/expanded lane, selective
ownership and QA inventories now enroll the production surface.

These are directly callable proof primitives only. Automatic/public retry
integration, full observation/provenance admission at those consumers, broader
regressions and project gates remain next. Existing call/recursive owner's
files untouched. Original M4 and M0-M7 remain partial; no whole-program equality
claim. Evidence: production-combined.log and production-macro-pyright.log.

### Flat32 automatic retry wired (2026-09-30)

Shared flat32_proof_retry now attempts full-state macro-step induction after
unproved direct-call and reblocked-CFG attempts. Existing counterexamples stay
unchanged. One deadline spans all retries; CFG and macro receive remaining time
and the same outer deadline. Proof scope stays CUTPOINT_SIMULATION, and every
preceding attempt is retained. Strict memory comparison only, no relocation
assumption discharge by token/name matching.

Both driver retry positives prove exact unequal-step bytes; return-only carry
mutations cannot pass. Counterexample/zero-budget skip controls use nonempty
contexts so they do not pass merely because context is absent. Focused retry
and existing register-region cohort:20passed/7.02s with3workers; Ruff clean and
Pyright0errors. Test enrolled in relational pipeline, QA and selective ownership.
Production macro primitive cohort previously52passed/20.70s. Public real16
retry owner remains untouched; its integration, public environment/provenance
review, representative corpus and project gates remain open. No full original
M0-M7 milestone acceptance. Evidence: retry-tests.log and retry-pyright.log.

Actual PE32-to-PE32 automatic retry controls now load immutable synthetic PE
images through each native driver loader and prove the original unequal-step
family with CUTPOINT_SIMULATION scope. Updated retry suite8passed/7.39s. No ELF
candidate added or improved. Repository test-ownership-check exits0 on the
current registered surface. Full public report/environment-provenance review,
real16 retry integration, representative corpus and broader project gates are
still outstanding; these PE controls establish loader/retry reachability only.

### Parent final-environment ordering regression (2026-09-30)

Parent reproduced both region-report consumers publishing a newly successful
retry after their environment gate had already returned the original refusal.
Two report-level regressions went red (unexpected PASSED), then green after
moving the existing environment admission after retry in both drivers. These
are orchestration controls with injected environment evidence, not whole-binary
environment acceptance. Complete retry suite:10passed/6.18s,3workers; scoped
test Ruff clean. Matched-CFG publication and retry-model scan provenance remain
open; original M0-M7 remains incomplete. No concurrent owner sources changed.

### Matched-CFG final environment admission (2026-09-30)

Both public matched-CFG consumers now call shared checked_cfg_environment_verdict
after retry and before serialization. Retained original block lowering receipts
are independently byte/IR scanned; missing receipts refuse rather than authorize
a retry proof. This conservative admission may keep a valid retry refused when
its initial lowering was incomplete; retry-owned sealed scan receipts are still
needed to recover that capability safely. No scope enlargement or environment
assumption discharge. Real RET coverage passes; real IN AL,DX needs a contract.
Parent retry suite13passed/7.57s; existing flat32 comparator lane32passed/20.02s.
Scoped Ruff clean; retry owner/tests Pyright0errors before final two added
binary controls. Devin publication-audit process58749 remains live, report
pending; no recursive production claim accepted. Original M0-M7 still open.

### Parent corrected missing CFG scan metadata (2026-09-30)

Independent real matched-CFG RET controls exposed a regression in the previous
final-admission checkpoint: both driver lower_blocks owners omitted
machine_code_size, causing every ordinary matched-CFG proof to fail byte-scan
admission. Parent two controls red, then green after retaining block.irsb.size
in each source record. Complete retry/admission suite15passed/4.76s,3workers;
touched CFG/test Ruff clean. Prior injected scan controls alone were insufficient
for this production metadata obligation. Retry-owned coverage for proofs whose
original lowering failed remains pending. Devin audit58749 still live; worker
observes concurrent wiring and must use current source, not initial snapshots.

### Retry-owned binary environment coverage (2026-09-30)

Parent added shared flat32_environment_coverage owner. Reblocked and macro CFG
proofs retain every original discovered member address/IRSB byte size, separately
from composed transition SSA. Final admission independently scans those member
ranges in the corresponding loaded projects; omitted/empty coverage refuses.
Both real unequal-step retries now pass final admission even when the initial
CFG result lacked lowering documents. Controls also deliberately remove coverage
and empty the candidate set, both refusing. Suite17passed/6.98s; scoped
Pyright0errors after narrowing coverage values explicitly; Ruff clean. New owner
enrolled in QA/selective macro ownership. Direct-call retry coverage, source
identity sealing beyond immutable in-process contexts, real16 public integration
and full original M0-M7 gates remain open. Devin audit58749 remains live and
must not accept stale conclusions from the concurrently changing source.

Post-change original macro primitives cohort52passed/29.18s,3workers; terminal
exit0. Test-ownership-check exit0. These scoped gates preserve real16/both32
positive and adversarial behavior, not complete release acceptance.

### Direct-call retry binary coverage (2026-09-30)

Parent two production controls red with missing environment_coverage.
Composition now derives exact ranges from every cached lifted block, including
unselected inlined callees, using the shared coverage owner. Summaries retain
those ranges separately from composed outputs; compare publishes both sides.
Identical caller/callee positives now survive final admission after an initial
call-boundary refusal; controls verify caller CALL, continuation RET and callee
MOV/RET ranges are present. Suite19passed/11.50s,3workers; Ruff clean and
scoped Pyright0errors. This is bounded function-environment byte/IR coverage,
not environment semantics, recursive acceptance, or complete M0-M7 acceptance.
Devin audit58749 remains live and sees the concurrent changes.

### Publication audit terminal parent review (2026-09-30)

Devin58749 terminal0; report in publication-audit/REPORT.md. Parent confirms
current real16 consumer lacks per-attempt coverage and macro invocation; flat32
producer/gate findings match parent controls. No demonstrated current real16
environment hole: existing retries consume sealed document parts. Future
recursive fresh lifting needs additional admission before publication. Accept
this prerequisite, not a false-proof or milestone claim. Reject patch sketch
that records only selected function parts: coverage must include consumed
callees/dependencies as well. Broad negative assertion of no production
recursive consumers has unverified graph coverage; treat as bounded source
audit rather than exhaustive acceptance. Worker report's test-count15 is
historical; current parent19green governs. New stage-only real16 macro job
preserves reserved production retry/consumer ownership.

### Independent public real16 macro baseline (2026-09-30)

Parent independently executed compare_binary16 on exact original
ORACLE16/CANDIDATE16 unequal-step MZ bytes with 60000ms solver timeout:
UNKNOWN/paired_region_graph_unproved in3.92s. Immutable images, SHA256 receipt
and full public report retained in parent-real16-public-baseline/. This proves
the production public integration obligation remains open despite direct macro
primitive positives. Devin stage-only job96672 is live; production retry and
consumer snapshots preserved, no edits to reserved ownership. Acceptance must
show public scope/accounting, all-state mutations, deadline and provenance/
environment closure, not merely repeat direct helper tests.

### Current comparator gate and historical-node accounting (2026-09-30)

Parent current test_dosunit_tool.py + test_real16_region_proof.py cohort
terminal0:214passed/5skipped/42.64s,3workers. Log and receipt retained as
current-dosunit-gate.log/json. AST node audit finds19of27historical failed nodes
still present;8old names absent. Thus do not report all27old failures fixed from
this green result alone. Exact current source/graph (generation15:39:04Z,
no recorded gap for test file) identifies replacement refusal controls for
unproved SCC, indirect calls, renamed/decorated targets and normalized binary
signature immediates, plus complete-call memory/store controls. Parent inspected
SCC/indirect assertions: zero passed, zero semantic facts, explicit missing-proof
reasons. Remaining old-to-new exact lineage still requires acceptance audit.
Five skipped controls are KVM-dependent; no native-DOS acceptance inferred.
Original full pipeline/release gates remain unaccepted. Devin96672 live,
stage-only public real16 macro integration not yet delivered.

### Renamed comparator regression obligations reconciled (2026-09-30)

Parent inspected current assertions and read committed HEAD assertions without
checkout/reset. HEAD is historical reference, not the dirty pre-run baseline.
Eight absent historical names map to these current obligations in the same
214green cohort:

| Old expectation / obligation | Current inspected control | Disposition |
| --- | --- | --- |
| SCC stubs passed without joint evidence | refuses_call_scc_without_joint_evidence | Corrected missing recursive proof; zero semantic facts. |
| Equal unresolved indirect call shapes passed | refuses_matching_unproved_indirect_calls | Corrected missing target coverage; zero semantic facts. |
| Call-boundary memory mismatch remains observable | real16_complete_calls_preserve_memory_outputs | Complete real-byte call evidence; changed memory fails. |
| Equivalent call stack addresses pass | real16_complete_calls_prove_equivalent_stack_addresses | Complete real-byte call positive retains address equivalence. |
| Call stack store value stays observable | real16_complete_calls_keep_stack_store_value_observable | Changed value fails with memory mismatch. |
| Compact-entry renamed target match passed | refuses_renamed_call_targets_without_callee_proof | Discovery alone refuses; zero semantic facts. |
| Decorated name match passed | resolves_decorated_call_names_without_callee_proof | Discovery retained, unproved callee refuses. |
| Masked signature immediate differences passed | refuses_normalized_binary_signature_immediate_differences | Changed AX immediate hidden by signature masking no longer proves equality. |

Current memory controls were independently source-read; signature immediate
control explicitly requires different raw/layout hashes and zero semantic facts.
This reconciles required behavior locally, not equivalence of historical fixture
coverage or a fresh full-suite acceptance. Historical broad failures are not
retroactively green; M5 recursion/target coverage still needs actual proof.

### Live real16 macro staged boundary review (2026-09-30)

Devin96672 remains live, staged tests running. Parent read staged wrapper: it
reuses production retry then attempts macro on UNKNOWN/remaining budget,
retains macro scope and diagnostics. Independent boundary probe shows zero
timeout still invokes the original retry chain with timeout_ms0; macro-only
skip controls are insufficient to establish no new proof work. Red receipt
in parent-real16-macro-review/zero-budget-red.json. An isolated parent copy
skips the chain for zero budget and passes the same probe; worker-owned stage
and production files remain untouched. Production-quality correction must also
retain visible exhaustion and use real typed obligations in regression fixtures.
No stage acceptance or original milestone completion claimed.

Parent independent public replay on immutable saved original MZ images now
PROVED/ssa_z3_macro_step_induction in12.85s with the isolated corrected staged
wrapper; baseline same images UNKNOWN/3.92s. Full report retained as
parent-real16-macro-review/public-positive-report.json. Production three-file
baseline hashes still match; no promotion/owner overwrite. Worker96672 live,
reported9staged tests before a helper typing/order correction and now reruns;
worker claim is not final parent acceptance. Zero-budget visibility, independent
mutation and final scope/dependency review remain pending.

### Real16 macro public retry promoted (2026-09-30)

Devin96672 terminal0, staged9tests/31.29s, Ruff/Pyright clean; immutable final
worker sources/report/hashes retained in parent-real16-macro-review/worker-final/.
Parent independently reviewed complete wrapper/tests and corrected zero-budget
entry: emit explicit UNKNOWN/compose_budget_exceeded evidence without invoking
prior or macro engines. Strict public control monkeypatches both engines to fail
if called and passes. Existing production call/region retry owner remains
byte-identical; separate tools/dosunit/compare/real16_macro_retry.py wraps it, and public
consumer changes only its retry import. One shared remaining-time budget,
existing attempts preserved, scoped SAT never COUNTEREXAMPLE, all modeled state
retained. No additional binary lifting or environment bypass.

Public production cohort12passed/18.54s includes original unequal-step proof,
STC-return/hidden-store/stride/stutter refusals, matched-region neighbors and
scope control; strengthened zero-budget control separately1passed/8.81s.
Scoped Ruff and three touched proof/test Pyright0errors, ownership-check exit0.
New owner/test enrolled relational default/expanded pipeline, QA and selective
ownership. Required make test-pipeline now running (handle12059), log
post-macro-test-pipeline.log; no broad gate acceptance yet. Original M0-M7
remains incomplete, especially recursive/indirect/environment closure and
representative release coverage.

### Required post-macro pipeline verified wait (2026-09-30)

Parent re-polled handle12059 live; preliminary cohort296passed/28.64s. Main
pipeline command is behind the recorded flock and captures lane output until
completion; no terminal result or fresh aggregate yet. Host-style lslocks PID
is not visible in this exec namespace, so PID absence is not evidence of
termination; the live tool handle remains authoritative. Do not restart or
accept the gate from its preliminary cohort. Further production deadline edits
deferred until the current semantic checkpoint run completes. Original M0-M7
remains open; no blocked/complete transition justified.

### M5 address-model staging launched during gate (2026-09-30)

Parent exact-source/graph Verify audit (generation16:16:25Z; checked three
recursive owner paths, no recorded gaps) confirms address prerequisite child
proofs exist but joint remaining_requirements closes only entry/code. Bound
access certificate deliberately grants no final binary/fault/environment
closure. Devin79158 launched under verified repo-only/4GiB sandbox, staging
only real16-address-closure-stage/, no pytest or execution while pipeline12059
runs. Required theorem must bind complete source/domain/raw-access witnesses
to exact segmented/effective/physical address semantics; child PROVED status
alone cannot erase ADDRESS_MODEL. Fault/environment remain separate. Production
ownership and source stay untouched during main gate; no acceptance claim.

### Parent shared-deadline resolution boundary (2026-09-30)

While main pipeline12059 remains live (>53%observed), parent lightweight
mock-clock probe on production wrapper shows candidate-resolution exhaustion
still invokes macro with stale100ms: resolution-deadline-red.json. No solver
or pytest launched. Isolated correction rechecks immediately before macro and
retains visible UNKNOWN/compose_budget_exceeded with unattempted-stage
diagnostics. Candidate in parent-real16-macro-review/resolution_deadline_candidate.py;
production source unchanged pending gate terminal. This is resource admission,
not a demonstrated false equivalence proof. Devin79158 address stage remains
live and static-only; fault/environment requirements unchanged.

### Interrupted checkpoint and resolution deadline corrected (2026-09-30)

Pipeline12059 handle missing; process/lock checks find no live pipeline, log
ends76%without terminal result. Existing summary predates run. Record as
interrupted, never accepted/restarted from an observation timeout. Parent
production resolution-deadline regression red1 then green; wrapper rechecks
remaining time after candidate resolution and records explicit unattempted
UNKNOWN/compose_budget_exceeded. Full public suite9passed/17.01s,3workers;
Ruff clean, scoped Pyright0errors. Existing positive/mutations remain covered.
Devin79158 process also absent; CLI session inventory identifies saved
flying-celery/address closure session, stage contains only baseline.json.
Resume that saved conversation under reverified hostRO/repoRW/4GiB sandbox;
static-only/no production edits remains required. No full-plan acceptance.

### Promoted macro source-seal coverage verified (2026-09-30)

Parent observed the real ssa_provenance._semantic_hash chunk inputs while
retaining every original read:1171source keys; real16_macro_retry, macro_proof,
macro_step_pairing and public consumer all hashed. Fresh observation0.1189s;
receipt parent-real16-macro-review/source-seal-coverage.json. Thus these new
source owners are covered by the existing invocation source seal; no separate
source-cache optimization justified by this single observation. This does not
claim compiled-artifact, dependency-cache, whole-corpus or release acceptance.
Gate90513 live (preliminary296pass/15.05s, main pending); resumed Devin99497
live, only baseline stage artifact so far. No source edits during gate.

### Address-model staged audit: parent revision requested (2026-09-30)

Devin handle99497 completed successfully with a staged draft, report, source hashes and unrun test recipe. Parent saved the immutable delivery under `.cache/comparator-implementation/real16-address-closure-review-baseline/`; scoped Pyright on the draft reports0 errors. No production promotion. Parent review found insufficient exact child manifest/source-domain identity consumption, an inconsistent request denominator, and overstrong unrestricted-selector/no-missing-theorem claims. Candidate static target coordinate reuse is consistent with current equal-coordinate joint admission, not a present defect. Existing source-bound control-scope and domain-dispatch children must remain authoritative prerequisites; static target evaluation cannot replace them.

A bounded static-only revision is live as handle90289, with ownership restricted to `.cache/comparator-implementation/real16-address-closure-stage/` and adversarial test implementation requested without pytest execution. Outer sandbox independently verified rootRO/repoRW and4GiB. Full post-deadline pipeline90513 remains live past82 percent with failures, no final classification yet. Fault/environment and original M0-M7 acceptance remain open.

### Post-deadline pipeline unit result and enrollment correction

Pipeline90513 unit lane completed:8984 passed,23 failed,7 skipped in883.99s. Overall gate remains live in binary-relational; this is not final acceptance. Exact failures saved in `.cache/comparator-implementation/post-deadline-gate/unit-failure-inventory.json`. One failure is attributable to macro-suite enrollment: the exact expected list in test_test_pipeline.py omitted the six deliberately promoted macro suites. Parent saved that pre-fix file and added all six explicit paths, preserving exact-set/disjoint-lane assertions. Ruff passes; focused runtime verification deferred until the current test pool ends. Remaining22 failures are unclassified and not waived as baseline debt. Comparator semantic-owner hashes match pre-run snapshots.

### Completed post-deadline pipeline and focused enrollment verification

Handle90513 is terminal(exit2): selected4 lanes,1 passed/3 failed. Unit8984 passed/23 failed/7 skipped in883.99s; binary-relational441 passed/1 skipped in226.70s. QuickC and MSC6 fixture lanes failed; saved fixture reports identify unavailable /dev/kvm at compile/link before executable production, so no external round-trip acceptance. Full final summary preserved as post-deadline-gate/final-summary.json.

The parent enrollment correction is independently verified: all57 test_test_pipeline.py tests passed with3 workers in1.47s (handle15010 exit0), Ruff clean. The unit run still retains its original23-failure history; no full gate rerun or acceptance is claimed. Three SORTD diagnostic artifacts are sealed separately: runmenu/initbars have def-use and control-flow refusals, insertionsort a missing branch-condition surface. Remaining defects require earliest-layer investigation; validation gates are unchanged. Devin revision90289 remains live, staged only. Original M4-M7 exits remain incomplete.

### Process-helper gate classification

Both DOSFUNC process-helper failures reproduce in isolation:2 failed in20.34s. A direct CLI replay for _dos_getProcessId(exit4) retains the expected empty return body and clean semantic tail snapshot, but explicitly reports MS C5.1 msc-dos toolchain unavailable because /dev/kvm is absent. This is an external recompilation acceptance blocker, not evidence to waive acceptance or change the empty-body semantics. Exact stdout/stderr and focused test log retained under post-deadline-gate/process-helper*. Next inspect KVM test markers/requirements so unsupported execution remains visible without presenting a successful round trip.

### Confirmed process-helper external-runtime marker

After isolated failure reproduction and explicit CLI toolchain diagnostics, the parametrized DOSFUNC process-helper test now carries the existing requires_kvm marker. All assertions remain unchanged; writable KVM runs still execute them. Focused verification(handle91380 exit0):2 visible skips, reason requires writable /dev/kvm(missing,errno2); Ruff clean. This records external environment limitation, not a function fix or round-trip acceptance. Saved pre-marker source and original red log permit independent review. Other failures remain separately open.

### REP-store execution dependency classification

A representative portable-flat CLI REP-store failure was independently reproduced(handle2733 exit1); its saved stdout explicitly identifies MS C5.1 validation unavailable due to missing /dev/kvm. Only the ten CLI round-trip parameter cases now carry requires_kvm. Native generated-C execution and corrupted-effect oracle controls remain active. Whole-file verification(handle63903 exit0):9 passed/10 explicitly skipped in11.12s, Ruff clean. Skips do not establish round-trip acceptance; original unit failure history and release obligations remain retained. Devin revision90289 is still live; revised draft now uses authoritative receipt consumption and exact manifests but awaits terminal review.

### Devin address revision terminal; parent staged execution started

Revision handle90289 completed exit0. Terminal delivery retained independently under `.cache/comparator-implementation/real16-address-closure-terminal-review/` with file hashes, draft/report/recipe/tests. Parent Ruff on owner and tests is clean. Independent adversarial suite runs as98712 with3 workers against the saved draft loaded only in the test process under its expected module name; no production promotion or source wiring. Scope includes actual-MZ positive and receipt/request/fetch/operand/physical/frame/terminal/model/deadline mutations. Existing control-scope/domain-dispatch prerequisites, terminal-wrap dedicated fixture and failure-boundary reason ordering still require parent review. No new ADDRESS_MODEL/M5/full-plan acceptance.

### Independent staged address suite terminal

Handle98712 exit1:32 passed/5 failed in508.24s. Four request-mutation tests expected MANIFEST but received the correct earlier RECEIPT refusal. The collected-fact mutation got CLOSED; inspect first-block denominator before attributing this to production, since deleting facts[:-1] on an empty ledger is a no-op. Positive actual-MZ closure passed in this restricted standalone context, not joint public promotion. Slowest cases42–56s each, so repeated full evidence construction must be reduced before routine enrollment. Separate parent-fix retains exact operand proof-ledger and source/domain checks; focused positive/new-corruption controls run68861 with3 workers, baseline pool now terminal. Frame provenance remains an integration risk: StackInvariantProof carries layout/clause/continuation but no input-state identity; current joint producer creates it fresh per state internally. Do not treat arbitrary retained frames as independently source-bound receipts.

### Parent address corrections independently green

Focused handle68861 exit0:3 passed in56.62s. Actual-MZ positive remains closed in standalone restricted scope, and missing/duplicate/counterexample/expired operand proof ledgers plus stale source-domain variants refuse. No production promotion. Parent-v2 separately corrects the four expected request-refusal reasons to RECEIPT and selects a nonempty collected ledger before dropping a fact, removing the no-op corruption from Devin's test. These five corrected controls are running; Ruff clean. Original delivery and failed suite are retained unchanged.

### Corrected address-control cohort green; next bounded Devin slice

Handle6172 exit0:five corrected request/nonempty-collected mutation controls passed in89.64s. Combined with prior three parent controls, targeted corrections are verified; this does not replace full final shared-tree integration. New static-only Devin task owns exclusively real16-address-control-stage/, copied from sealed parent-v2 with baseline hashes. It must consume native control-scope and domain-dispatch children with exact denominator/proposal/domain/model identity and preserve parent operand checks. No production edits or pytest authorized; parent reviews and executes. Sandbox reverified rootRO/repoRW4GiB before launch. Frame input-state provenance remains explicit integration obligation.

### Address regression setup reuse experiment started

Earlier independent37-case suite took508.24s with per-test real-MZ proof construction; slowest42–56s. Separate fixture-reuse copy retains all corrected tests plus two parent corruption controls. One actual-MZ evidence setup per worker, module-scoped, with per-test complete evidence repr and joint-proposal nonmutation assertions. No proof/timeouts/corruption checks removed. Ruff clean. Full suite runs7806 with3 workers; comparator production unchanged. Comparison is a corrected39-case superset, not an identical37-case speed benchmark; report measured scope explicitly. Devin control-stage76489 remains live/static only.

### Corrected full staged address suite and setup reuse verified

Handle7806 exit0:39 passed in79.70s with3 workers, all per-test evidence/proposal nonmutation checks passing. Earlier original37-case run took508.24s with5 failures; corrected superset adds two parent controls and fixes refusal-order/no-op mutations, so this is not an identical-suite speed benchmark. Reusing actual-MZ setup once per worker preserves every corruption check and accounts for three measured28–29s setup costs. Standalone actual-MZ restricted-address closure remains locally green; native control/domain dispatch intake, saved-frame provenance, terminal-wrap dedicated coverage and joint production integration remain open. No original M5/M0-M7 acceptance. Reusable fixture owner retained under real16-address-closure-fixture-reuse/ for parent adoption after Devin control-stage review.

### Concrete terminal-coordinate boundary fixture

Parent constructed an actual4KiB MZ image and verified bind_real16_mz/load.verify at load_segment0xFF00. Header entryCS0xFF resolves toCS0xFFFF; entryIP0xD gives physical0xFFFFD. Actual bytes e8f0ff call0xFFFF0 and save word0x10, whose CS-relative terminal coordinate is0x100000. The instruction bytes fit below firstMiB while exit leaves the restricted model. Fixture and receipt under real16-terminal-boundary/. This establishes a realizable loader/binary arithmetic edge for the terminal obligation, not an admitted full joint/whole-program proof; integration refusal regression remains required. Devin control-stage76489 still live.

### Boundary native-control mismatch independently confirmed

Actual terminal-boundary fixture was checked through prove_native_control_scope using authoritative loaded entry state: COUNTEREXAMPLE, expected target0xFFFF0 versus native lifted0xFFF0. This is an abstraction/lifting defect evidence, not a candidate binary difference. Independent Unicorn one-CALL replay of exact e8f0ff atCSFFFF:IP000D retainsCSFFFF,IP0000, physical0xFFFF0; saves word0010, terminal coordinate0x100000. Receipts native-control.json/unicorn-call.json retained. Existing control gate correctly withholds closure on this fixture before terminal-bound discharge; do not claim the fixture reaches complete joint induction. Need generic coordinate/lifter repair and regression, preserving refusals until then.
