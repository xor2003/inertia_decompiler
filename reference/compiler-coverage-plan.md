# Small DOS C Programs: Decompiler Round Trips

## Acceptance and current work

**0/16 starter round trips; 0/118 matrix cells accepted.** The complete
MS C5.1/Borland3.1 corpus and final Watcom11.0b phase below remain required.
Original-only builds, generated diagnostic C and passing unit tests do not
complete a round trip. Do not run SORTDEMO for this plan.

Each completed change must increase the number of genuinely decompiled
functions on the fixed corpus. Record before/after function identities and
validation outcomes on the same inputs. Unit tests, lower work counts, fewer
refusals and generated diagnostic C are intermediate evidence, not delivery.
Keep a coherent repair open until it produces that increase; do not substitute
an optimization-only milestone for the required decompiler result.

### Current verification

Current concrete blocker (2026-11-11): the normal SIMPLE MAIN run now
materializes all five jump-domain edges: counts **18/5/5/5/0**. Application
then refuses because CALL dependencies cannot be freshly closed
(`APPLICATION_REFUSED`, `STALE_INPUT`/`STALE_SOURCE`):
`simple-snapshot-final60.log`, exit 4. The unchanged-producer observer confirms
that the first selector batch succeeds at work 118207, while application's
fresh selector batch reaches **128302/128000**, with about 31 seconds remaining
(`call-consumer-final-observations.jsonl`). No function C is emitted; actual
acceptance remains **0/16 and 0/118**. All time/work/cache limits are unchanged.

The open repair authenticates an offered root without repeating its resolver,
snapshots each shared CALL index once per fresh proof graph, and shares only
the beginning scoped-record snapshot within a synchronous selector batch.
Fresh closure authentication, ending snapshots and late-mutation refusals
remain mandatory. The two-CALL resource regression now fits 6500 work
(previously 7529). Final scoped cohort: **51 passed, 7 skipped** (canonical
BITNBR not staged); scoped lint and MyPy pass. Earlier actual attempts sometimes
stopped at the selector deadline under host load; they are not acceptance.
Next: combine compatible collection obligations into one fresh native seal,
without weakening target or CS requirements, then repeat normal SIMPLE and
the required full acceptance gates. This coherent repair remains open until
actual generated-C acceptance increases.

Declared scoped CALL-target follow-up (2026-11-11): a native two-CALL
regression reproduced `UNPROVED` admission for valid original scoped callee
records. The view producer had omitted their explicitly supplied root scope,
and declared target admission only consumed selector-projection records.
The producer now retains the conditional root; application consumes the full
canonical CALL dependencies and native continuations while preserving original
records and raw operands. Scoped lint passed; focused native tests passed,
including native corruption, foreign scope, altered target and late-mutation
controls. Evidence and preimages are in `parent-declared-scoped-target/`.
The actual SIMPLE retry still exited 4 with `APPLICATION_EMPTY`; a subsequent
observed run stopped earlier at `scope_unbound`. No corpus acceptance follows.
The full architecture check remains failed on files outside this change:
`render_compat.py`, `cli_access_profiles.py`, `cli_storage_objects.py`, and
`hotspot_import.py`; retain `scoped-target-architecture.log` for diagnostics.
Declared-entry errors now retain typed selector verdict and per-CALL refusal
states to make the normal CLI's next failure actionable without an observer.

Allocation fingerprint follow-up (2026-11-11): an observed actual CLI run
refused `fingerprint: unsupported expression form NoneType/None`. The installed
native AIL contract permits absent incoming Phi values, and a focused native
regression independently reproduced that exact fingerprint refusal. The
frontend adapter now records an explicit absent-Phi-input structural key while
retaining the predecessor and still refusing missing required expressions.
Scoped lint passed; all 32 tests in the native allocation restart and Lowering
convergence modules passed. Preimages, diff and review are retained in
`parent-phi-fingerprint/`. The original CLI exception's parent expression was
not captured: a later observer run stopped earlier at `scope_unbound`. This
fix therefore remains a component result, not a claim that SIMPLE is fixed.
The uninstrumented post-fix CLI retry (`simple-phi-fingerprint60.log`)
finished with exit 4 and `scope_unbound`, before allocation; tail validation is
uncollected and no function C was written. It neither validates the full function
nor exercises the new Phi handling end to end. All probes are terminal.

Latest standalone selector evidence (2026-11-11): the unchanged-limit
`selector-native-binding-counts` probe completed with `proven_conditional`,
all five CALL edges preserved, and a successful `ScopedIndirectTargetView8616`
projection for `switch_fold` at `0x225a`. It used 19836 local/55598 shared work,
22.01 seconds elapsed and 21.56 seconds CPU. The observer only recorded native
callee sizes and did not replace proof producers. This is component evidence,
not generated C, tail validation, or round-trip acceptance. The subsequent
actual SIMPLE retry is recorded in `simple-selector-indirect-proven60.log`.
That actual retry is terminal, exit 4: `APPLICATION_EMPTY`, tail validation
uncollected, and no output C directory. It does not establish that the actual
CLI selector succeeded merely because the separate standalone probe did.
Subsequent standalone preparation observations instead refused `scope_unbound`.
The stage trace (`simple-entry-stages-result.json`) records the selector refusing
at 26.83 seconds elapsed, with 33044 shared work and 23.44 seconds remaining in
the shared request. Later scope authentication exhausted the original shared
50-second deadline at 61842 work, below the 128000 cap. These are distinct runs;
the exact CALL-target admission reason in the actual `APPLICATION_EMPTY` run
is still unobserved. Neither guard relaxation nor budget expansion is justified.

Bounded follow-up (2026-11-11): the selector recheck again refused
`DEADLINE_EXCEEDED` before reaching the indirect-control consumer (27.38 seconds
elapsed, 18.09 seconds CPU; 1249 local/20741 shared work). A separate diagnostic
cProfile run identified 153183 native term comparisons and 73252 sequence
comparisons; profiling perturbs timing and does not establish acceptance.
Raw data is retained as `selector-indirect-proof.pstats` and
`selector-indirect-profile-summary.json` in the resume directory. The native
comparator already memoizes within each comparison; do not add redundant caches
or bypass fresh source binding. No production edits resulted from this profile.
The root filesystem subsequently reported no free space, causing intermittent
sandbox startup failures. `/home` retained 13 GiB free, and the existing plan
was checked intact after failed writes. This environmental issue is separate
from the previously observed proof deadline. Acceptance remains unchanged.

Provisional indirect-control consumer (2026-11-11): selector CFG induction and
control binding now consume `ScopedIndirectTargetView8616` through fresh scoped
projection, exact native-byte/instruction binding and target geometry. Pending
marker discharge is restricted to the proved block. Scoped lint and startup
architecture passed. The focused run completed with 70 passed and one
`DEADLINE_EXCEEDED` failure in the existing conditional near-return test; all
eight new binding tests passed. Both exact preimage and candidate controls later
passed at unchanged limits, although an earlier isolated candidate retry failed
the deadline. The optional timing observer captured no calls and is not CPU evidence.
A further native-marker regression caught a wrong `IRRefusal.addr` access;
the consumer now uses the authoritative `block_addr`. Marker/corruption and
near-return controls passed together (two tests). Final scoped lint passed;
explicit MyPy on both consumers reports only the two existing baseline errors.
No new corpus acceptance is claimed. Candidate/preimages/review and the unresolved exploratory caller-fixture
diagnostic are retained in `parent-selector-indirect-control/`; the live test
results and continuation steps are recorded in the resume `CONTINUE.md`.

The actual indirect-consumer SIMPLE retry reached the unchanged outer supervisor
limit (exit 124), without a function verdict or accepted C. Its recovery banner
appeared about 80 seconds after log creation, leaving about 40 seconds of the
120-second process envelope. The standalone probe also stopped before reaching
the indirect consumer: `DEADLINE_EXCEEDED`, no call edges, 33.61 wall / 15.53 CPU
seconds and 6,427 shared work units. Integration correctness remains unverified.
Separate `--help` import profiling found 38.10 seconds cumulative beneath
`direct_request_fast_path`, including 18.71 seconds for `default_signature_catalog`
and 17.19 seconds for `cache_source_manifest`. These overlapping times must not
be summed. Inspect eager imports and preserve all cache source fingerprints and
the original acceptance limits; faster help alone is not completion.

Selector loop-entry correction (2026-11-11): two real native loop layouts
reproduced `cs_unbound`. The solver now distinguishes unvisited predecessor
edges from visited states with unknown registers and propagates only from
reached predecessors. Bounded convergence, full equation replay, native checks
and source seals remain mandatory. The focused suite passed **59 tests**, with
14 BITNBR-dependent tests skipped because their corpus fixture is not staged;
scoped lint passed. Scoped MyPy still reports the same two baseline errors.

The ordinary SIMPLE retry exits 4 with **`APPLICATION_EMPTY`**, rather than the
earlier `SCOPE_UNBOUND`; tail validation remains uncollected and no C is accepted.
A separate one-function observer completed in 22.12 wall / 20.70 CPU seconds:
all five calls retain segment effects, and only switch-fold remains refused.
Its authenticated callee carries `ScopedIndirectTargetView8616`, unsupported by
the selector's near-return-only conditional projection/control consumers.
Sum-to's loop and classify no longer produce selector obligations in that probe.
The next repair must consume the existing invocation-scoped indirect-target
authority without bypassing native control binding or guessing a target.
Evidence: `parent-selector-loop-entry/`, `selector-loop-corrected-records-result.json`
under the resume directory; logs `selector-loop-entry-focused.log` and
`simple-selector-loop-entry60.log` under `.cache/agent-tool-output/`.
Acceptance remains **0/16 round trips and 0/118 matrix cells**.

Retained native-callee correction (2026-11-11): selector induction previously
required a conditional near-return CFG view even for authenticated raw-native
callee records. A real `MOV AX,7; RET` regression failed for that reason while
failed-record and foreign-artifact controls refused correctly. Native records
now retain authentication and use the ordinary closed-native-CFG path; conditional
near-return records retain their projection requirements. The focused suite
passed 55 tests, including changed-native-byte refusal, and scoped lint passed.
Scoped MyPy reports two `no-any-return` errors also reproduced with exact
pre-change source through MyPy's shadow-file facility.

The ordinary SIMPLE retry still exits 4 with `SCOPE_UNBOUND` and no accepted C.
The subsequent unchanged-limit standalone selector probe completed in 19.42
wall / 18.64 CPU seconds with all five call effects preserved. The old three
generic callee refusals narrowed to an unsupported conditional view for
switch-fold and `FETCH_OUT_OF_WINDOW` / `cs_unbound` at sum-to's loop join.
This is a repaired regression and more precise evidence, not corpus acceptance.
Candidate/preimages/review: `parent-native-selector-callee/`; probe receipt:
`selector-native-callee-result.json` in the resume evidence directory. Logs:
`.cache/agent-tool-output/selector-native-callee-focused.log` and
`.cache/agent-tool-output/simple-native-selector-callee60.log`.

Nested selector deadline follow-up (2026-11-11): nested callsite collection
now receives the earliest selector, request and project deadline. The local
cap restores on exit, including exceptions, without renewing the request or
resetting charged work. All deadline consumers use the effective cap.
Six new baseline cases failed before this change; all eight new cases pass
within the focused candidate run (155 passed, 14 skipped, five failures).
The same five nonleaf-budget integration failures reproduce with the exact
pre-change owner modules (23 passed); they remain open baseline failures.
Additional selector controls passed 78 tests, and scoped lint passed.

The ordinary SIMPLE retry still fails acceptance: exit 4, `SCOPE_UNBOUND`,
tail validation uncollected, no generated C. Its 60-second function and
120-second supervisor limits were unchanged. This is a resource-contract
correction, not an accepted semantic improvement. Acceptance remains
**0/16 round trips and 0/118 matrix cells**. Evidence and four-question review:
`.cache/compiler-coverage-resume-20261110/parent-selector-nested-deadline/`;
runtime log: `.cache/agent-tool-output/simple-nested-deadline60.log`.

The separate selector diagnostic completed in 19.91 wall / 19.65 CPU seconds
with 35,801 shared work units. All five call edges retained segment effects,
but selector induction refused all three callee heads with `CFG_INCOMPLETE`
(unproved scoped callee). This is diagnostic evidence, not full CLI acceptance.
Two subsequent return-observer runs exhausted the selector deadline before
reaching that final check (27.01/15.25 and 31.81/23.96 wall/CPU seconds).
A later host snapshot showed load 22.81 on eight CPUs; contention is plausible,
but these runs do not establish the cause of the earlier CFG refusal.
The next diagnostic must distinguish the retained scoped-view type from
record reauthentication failure without adding proof calls or loosening limits.
Receipts: `selected-call-nested-deadline-result.json`,
`selector-authentication-observer-result.json`, and
`selector-scoped-records-result.json` under the resume evidence directory.

Current cost evidence (2026-11-11): baseline logs also contain normalization
and callee-stub registration; the candidate's core timeout is not evidence of
progress beyond the earlier scope refusal. Worker-thread samples remain in
native lifting, source authentication and invocation/selector proof work.
The first sampler only saw the waiting parent; its data must not be treated
as worker profiling. The all-thread sampler reached the unchanged120s outer
supervisor (exit124), so it provides sampled stacks, not a function verdict.

A separate nine-operation cost observer completed with the ordinary core
timeout (exit3). Its last cumulative snapshot reports **inclusive** CPU/wall
seconds: declared preparation39.12/50.97; selector proof35.79/46.95; scoped
call collection25.94/32.98; five invocation derivations16.03/20.82. Native
surface requests consumed8.88CPU across16 calls. Entry-source digest58 calls
consumed5.50CPU; artifact-body digest41 calls consumed4.84CPU. These nested
totals must not be added. Evidence: `proof-cost-summary.json`,
`proof-cost-observer/`, `simple-proof-cost-observation.log` under the existing
resume/output directories. The candidate's three code/test/doc files still
match their tested hashes.

No optional prefix was selected in a separate residency observation, which
exited4/SCOPE_UNBOUND. Do not implement cache-residency advice on the basis of
that run. Earlier encoder/serialization experiments also did not establish a
safe pipeline improvement. The current concrete target is deadline
propagation: the selector defaults to25s, but nested scoped collection inherits
the enclosing declared census deadline (50s) through `_census_deadline_8616`.
`_Budget.charge` observes the tighter selector deadline only after nested work
returns. A repair must bound the nested work while preserving/restoring the
parent allowance, rather than permanently shrinking or renewing the outer
request. Native/source/call guards and acceptance limits remain mandatory.
No accepted function or round trip is established.

Current scoped-selector prerequisite candidate (2026-11-11): the standalone
SIMPLE selector refuses `CALLEE_MISSING` for `switch_fold` at MAIN callsite
`0x22b1`. A narrow native observation shows ordinary surfaces for `classify`
and `sum_to`, but no closed boundary for `switch_fold`. Scoped collection then
selects only `0x22b1` and accepts no record. Its ordinary invocation census
still requires preceding CALLs; the restricted collection omitted those
prerequisite proofs. Restored-source baseline: selector refused in8.20s wall,
8.01s CPU, work1299/shared2743, with the same obligation. This diagnostic is
not whole-function acceptance (`selected-call-baseline.log`).

`declared_selector_scoped_callee.py` now expands missing-callee requests to
CALLs in the canonical invocation predecessor cone, bounded by instruction
order in the terminal block. It does not demand later calls in that block,
assume address order, grant call effects, or change resource limits. Two
regressions fail on the preimage; scoped lint and126 native/selector controls
pass. The same selector probe now attempts the prerequisite proofs but refuses
`DEADLINE_EXCEEDED`:51.69s wall/44.30s CPU, shared work33475. This does not
increase acceptance. The normal60s SIMPLE retry exits3 with a **core** timeout,
after function normalization and direct-callee stub registration. The earlier
normal retry stopped at SCOPE_UNBOUND, but inspection confirms those earlier
runs also normalized and registered stubs. Therefore the changed terminal
status does **not** establish progress to a later stage. A subsequent run
with a parent-only stack sampler again exits4/SCOPE_UNBOUND. No accepted
function gain is established; tail validation remains uncollected. Evidence:
`simple-prerequisites60.log` and
`parent-selected-call-prerequisites/runtime-result.json`. The next diagnostic
must sample the actual forked CLI worker, not the parent waiting for its
result. The narrower selector probe does not reproduce all CLI discovery
and context state. Evidence and review:
`.cache/compiler-coverage-resume-20261110/parent-selected-call-prerequisites/`.

The prior scratch-source isolation experiment is **withdrawn**, despite104
focused passes: `_PrefixSourceBindings8616` explicitly requires shared
invalidation so scratch scopes cannot hide missing authority. Independent
source records had not been shown to preserve that contract and produced no
accepted corpus gain. Its three files were restored from hash-checked exact
preimages; candidate code and results remain in
`parent-scratch-source-isolation/withdrawn-candidate/` and `withdrawal.json`.
Earlier budget-reservation work and unrelated edits were preserved. The normal
SIMPLE retry for that withdrawn experiment exited4/SCOPE_UNBOUND; a candidate
observer timed out. Do not treat either as an accepted repair.

Earlier SIMPLE work-allocation observation (2026-11-11; superseded next steps): the context-identity
observer completed with exit 4. Its three successful `sum_to` simulations and
one exhausted simulation belonged to four distinct proof contexts, although
they shared an artifact identity. This does not support a context-local cache
as a remedy for the observed repetition. Evidence:
`.cache/compiler-coverage-resume-20261110/simple-loop-context-analysis.json`;
full run: `.cache/agent-tool-output/simple-loop-context-observation.log`.

A separate production observation, without producer replacement, recorded 35
completed callee/scope operations. Successful `sum_to` calls charged 1,469 units
for optional feasibility and 2,574 for mandatory simulation. A later proof
context entered MAIN simulation already at 17,346 units; its first `classify`
simulation returned a typed failure at 18,922 units. This run alone does not
identify that typed failure's reason: the observer retained the result type,
not its fields. The command exited 4 with `SCOPE_UNBOUND` and CLI
`validation=failed`, not semantic equivalence. The next diagnostic must locate
work charged before MAIN simulation and retain typed failure reasons, rather
than assume optional loop feasibility is the remaining cause. Evidence:
`.cache/compiler-coverage-resume-20261110/context-cost-analysis.json` and
`.cache/agent-tool-output/simple-context-cost-observation.log`. Both observer
runs are terminal; acceptance remains **0/16 and 0/118**.

Native build recovery: dangling `.cache/mypyc` and `.cache/cython-vex` links
were preserved before replacing them with local build directories. The VEX
build exited 0, and the strict mypyc import smoke passed for all 39 modules
without forcing a Python-backend fallback. Evidence: `cython-vex-build-after-cache-repair.log`
and `mypyc-after-vex-repair.log` under `.cache/agent-tool-output/`. The full
`quality-fast` rerun passed groups of 309, 1,509 and 26 tests, but its large
pipeline group was interrupted after reported failures, deadline exhaustion
and memory-allocation failures under contention. In particular,
`test_loop_constant_scratch_register[msc8-none]` passed alone but failed after
20 tests in its containing module; the proof refusal remains unresolved.
Full gate evidence is `quality-fast-after-native-cache-repair.log`; no clean
gate or compiler round-trip acceptance is claimed.

A separate per-case diagnostic run, `first16-individual-current/` under the
evidence root, completed all 16 frozen starters with unchanged budgets:
15 decompile timeouts and one original-build failure; **0 accepted**. Original
build and execution passed for 15 cases. All 1,353 tracked source/input hashes
were unchanged across that run. It overlapped the gate, so these contended
timings cannot establish a performance improvement. See `parent-summary.json`
and the retained per-case logs in that directory.

The Microsoft comparison build produced a fresh, nonempty executable that the
harness rejected because DOS write timestamps have two-second granularity.
The reviewed repair is now integrated: clear and verify removal of prior
artifacts before each stage, require completion evidence, and allow strictly
less than two seconds of timestamp quantization. Missing, empty and genuinely
stale artifacts remain failures. Scoped lint and production-file type checking passed. The first canonical
regression run passed 144 tests; two pre-existing default-registry controls
expected KvikDOS drift instead of the earlier missing-DOSBox refusal. Their
helper now checks both configured runners. The final run passed 145 tests;
the process-cleanup timing control failed at 1.80 seconds against its unchanged
1.50-second ceiling under host contention (it passed in the earlier run).
Both registry controls now pass. See `canonical-ts-tests-final.log`; this is
not a clean module or full-gate result.
All four fresh native compiler probes passed and their new registry was admitted
by the normal loader (`timestamp-profile-admission.json`,
`toolchains-dosbox-timestamp-fixed.json`). The affected Microsoft comparison
case now builds and runs successfully (exit 255) with unchanged budgets,
then times out during decompilation: `case000-timestamp-fixed/case-000/coverage-result.json`.
The rebuilt executable is byte-identical to the previously rejected artifact
(`timestamp-affected-case-receipt.json`). The artifact rejection is repaired;
the round trip remains unaccepted. The isolated
native build/run and 18 independent timestamp controls also passed; none of
these results constitutes a decompiler round trip.

A provisional universal-closure trial now occupies the canonical
`inertia/ir/entry_domain_call_preservation.py`, with a hash-checked preimage
and `tests/ir/test_fresh_universal_closure.py`. It skips only the immediate
repeat of a fresh universal closure verdict; scoped and retained consumption
keep their evidence revalidation. The isolated candidate passed 23 tests;
the independent baseline reproduced the extra replay. The isolated MAIN
attempt was refused by startup architecture checks because the copied
package did not have canonical repository paths; it supplied no decompilation
evidence. Canonical lint and startup architecture checks passed. Scoped
type checking now reports the same 38 errors as the independent preimage,
with no added errors; it is not a clean typing gate. The new regression is
registered in the authoritative `reference/components/decompiler.json` and
its compatibility catalog. All 62 canonical freshness, mutation, scoped-consumption and budget controls
passed (`universal-canonical-controls-v3.log`). Normal-CLI MAIN verification
still timed out at 60 seconds and generated no C
(`universal-canonical-main60-result.json`). A separate isolated encoder trial
now tests avoiding unused record-factory allocation on operation-local memo
hits. Both native variants built and passed all 98 graph controls. Canonical
encoder source and its matching native bundle remain unchanged. Paired compiled
CPU ratios were 1.033, 1.031, 1.094 and 0.970 across four synthetic cases;
the candidate is rejected as a general optimization. Evidence: `parent-encoder-factory-trial/native-benchmark.json`.
A second isolated variant moves the memo lookup without repeating it on misses;
its native build and all 98 graph controls passed. Paired compiled CPU ratios
were 1.004, 0.974, 0.893 and 1.124: mixed results, not a general improvement
(`native-benchmark-single_lookup.json`). A real-MAIN artifact benchmark exhausted
its unchanged 120-second bound before reaching encoder timing; it supplies no
real-artifact speed result. The lower-load normal-CLI MAIN retry also exhausted
its unchanged 60-second bound (`universal-main60-lower-load.log`). These trials
remain unaccepted.

An isolated scalar-dispatch shortcut passed 16 differential controls but
duplicated the existing scalar path in `_native_sequence_equal_8616`: lookup
counts were unchanged and CPU ratios were 0.971, 1.035 and 1.067. It is rejected
(`parent-native-leaf-dispatch-trial/measurement.json`). A separate immutable
registry index trial passed 16 differential controls and 23 focused native
binding regressions; its independent baseline also passed those 23 regressions.
After adding fallback on replacement of the derived index, 17 differential
controls passed. Initial synthetic CPU ratios were 1.006, 1.011 and 0.904;
with the extra guard they were 1.168, 0.945 and 0.954. These mixed results do
not establish a real workflow gain. The latest guarded variant still needs
its focused regression rerun if pursued. Its source remains isolated in
`parent-native-indexed-dispatch-trial/`; canonical comparator bytes still match
the pinned preimage. No production comparator change or additional accepted
function is claimed.


A direct raw-MAIN diagnostic completed import in 4.82 seconds: 59 blocks,
3,957 instructions, with 4,182 raw temporary facts and 225 classified/materialized
removals (zero normalization failures). This is a raw surface, not a finished
artifact or accepted function. An isolated native build of the unchanged whole
invocation-domain module was rejected by Cython's parser at its Python type
alias. A generated subset containing the exact 16 comparator definitions built
and passed 16 differential controls; its real raw-MAIN comparison CPU ratio was
0.904. It is not integrated. Evidence: `parent-native-comparator-subset/`.

Selected-stage monitoring of direct artifact construction then narrowed the
cost to repeated target binding. The 120-second diagnostic ended with exit124;
35 completed `_bind_direct_call_target_8616` calls accumulated 80.35 seconds of
inclusive time, versus 10.00 seconds across 11 `_callee_closure_8616` calls.
Individual MAIN callsites 0x1dfd, 0x1e13, 0x1e2a and 0x1e58 took 12.91–18.10
seconds in binding. Inclusive timings overlap enclosing stages and are not a
baseline speed comparison. Producers were not replaced. The earlier normal-CLI
monitor emitted no selected-stage events and provides no stage-cost evidence.
See `callsite-stage-events.jsonl` and `callsite-stage-analysis.json`. The next
investigation is caller-premise construction versus its consumption in direct
near-call binding; scalar/encoder microbenchmarks do not address this evidence.


A narrower trace attributes 69.87 inclusive seconds across ten completed requests
to caller-premise construction, versus 11.01 seconds in 45 binding-core calls.
Normal CLI route observation confirms the direct indexed-Alias preflight asks
for universal SSA before declared-entry preparation
(`cli-route-observer/route-1961268.txt`). A provisional orchestration repair now
selects authenticated exact-head declarations through the IR owner and returns
`DECLARED_ENTRY_DEFERRED` from that optional preflight, without publishing scoped
IR or asserting any global-object requirement. Its new regression failed before
the change on the unwanted universal probe. Focused controls then produced
62 passes and one existing cache-reuse failure; that failure also reproduces
with both changed production files restored to their independent preimages.
Scoped lint passes. The normal MAIN run now reaches decompilation but still
exhausts the unchanged 60-second limit with uncollected tail validation and no
accepted function. This is not delivery. Preimages, hashes and the four-question
review are in `parent-declared-probe-deferral/`; `declared-probe-main60.log` holds
the real run. Post-change observation confirms declared-entry preparation now
runs first (`declared-probe-route-observer/route-1997401.txt`).

A second provisional repair changes bounded native-surface cache eviction to
prefer retaining surfaces with more blocks, using oldest insertion for ties;
the four-record/256-block caps and all source/proof checks remain unchanged.
The new final-rebind regression failed before the change; 73 focused cache,
native-rebind, census and scoped-view tests pass afterward, as does scoped lint.
Inside actual preparation, the selector now returns `proven_conditional` with
zero obligations (`retention-main-selector-result.json`, 11.959 seconds including
construction), versus refusal with five obligations before the change. Its
25-second/20,000-work limits are unchanged. This subproof is not acceptance:
the normal MAIN run still times out at 60 seconds with uncollected tail validation
(`native-retention-main60.log`). A subsequent unmodified-stage observation
reaches CALL collection but refuses the scoped CFG: retained dependencies do not
close over the source CALL census (`retention-declared-stage-error.json`).
A following unchanged-producer observation completes scoped preparation in
44.374 seconds with all 20 source CALL dependencies matched
(`census-declared-observation.log` and `census-declared-stage-events.jsonl`).
The refusal is therefore intermittent in current observations, rather than
evidence that a CALL record is always absent. Scoped-view proof takes 26.588
inclusive seconds, including 12.814 seconds reconstructing the CALL census.
Batch-consumption cost and deadline behavior remain under investigation; no
proof check has been relaxed. A subsequent typed observer explicitly returns
`UnprovedDeclaredEntry8616` with `unknown_refuse` / `scope_absent`, following a
refused selector (`typed-batch-outcomes.jsonl`). An ordinary producer return
must therefore not be counted as scoped proof success. This observation took
54.808 seconds in preparation, including 26.479 in the refusing selector;
contemporaneous host load was roughly 23 on eight CPUs. Timing variability is
not permission to raise proof limits or claim acceptance. Another normal
60-second MAIN run (`typed-outcome-main60.log`) still times out; its worker
observer produced no outcome receipt, so it does not localize the timeout.
A CPU/wall observer then measured 24.226 CPU seconds in the selector's 25.233
wall seconds (`cpu-batch-costs.json`): scheduler waiting alone does not explain
that refusal. The subsequent ordinary CALL collection consumed another 25.587
CPU seconds and ended with `scope_unbound` (`cpu-batch-declared-stage-error.json`).
Native import and artifact-digest reuse remain the investigation target; high
host load is not established as the blocker. A separate-process capacity experiment returned a proven scoped entry with
16 records/256 blocks (41.251 wall seconds,39.257 CPU seconds,227600KiB peak RSS),
versus a CALL-census refusal at four records (50.617 wall seconds,44.859 CPU
seconds,226640KiB peak RSS). This does not establish a function gain. The normal
CLI candidate hit its120-second outer supervisor without a terminal function
result (`capacity16-main60.log`), so the exact four-record preimage was restored
under hash guards (`parent-capacity-trial/result.json`). No capacity change is
integrated and no proof limits are changed.

A fresh normal-CLI boundary observer confirms declared preparation starts in
an angr `Clinic` for MAIN, but records no return before the normal function
request times out (`cli-preparation-observer/`, `cli-preparation-observation.log`).
This does not establish repeated preparation or a successful scoped result.
The smaller SIMPLE starter is the next affected-case check: current declaration
`declared-main-fresh.json` matches the retained Borland SIMPLE binary SHA256
`db648516dff460be1d1c631a492bb010975dd21cf4b197d2496644a50d5b86ab` and its
capture-authentication receipt, selecting entry0x2291 with the table-memory
premise. Older `.cache/simple-main-capture/` paths are absent in this workspace;
`simple-current-identity.json` records the current matches. Its normal60-second MAIN check finishes with `scope_unbound`, not acceptance
(`simple-main-current60.log`). Replay observation also produces
`application_empty`; the earlier derivation refuses with
`census_work_exceeded` at the sum_to call0x22a6 (539 raw/normalized/classified
facts,538 materialized,one failure). The budget observer locates the local
20,007/20,000 exhaustion inside optional callee feasibility before mandatory
simulation; shared work is56,638/128,000, so the local limit is decisive.
Evidence: `simple-auth-observer/`, `simple-budget-observer/`.

An unconditional full-scope cyclic bypass was rejected despite89 passing
focused controls: a native cyclic guard with an unreachable self-modifying
write passes the pre-edit orchestrator but the candidate refuses
`code_write_violation`. Its normal SIMPLE run still failed. Exact preimages,
including the attempted geometry-advice changes, were restored; retained
comparison is `cyclic-pruning-preservation-result.json` and rejected source is
under `parent-cyclic-feasibility/`.

The replacement candidate preserves optional pruning but offers an unordered
refinement only half of the remaining local work, leaving room for required
simulation. Ordered refinement keeps its original allowance; actual work and
all original limits remain accounted. Native live/dead code-write controls
pass before this change, while a new optional-exhaustion regression fails as
expected. Scoped lint and all91 focused controls pass (`callee-reservation-controls.log`).
Scoped MyPy passes for both the exact pre-edit shadow and current owner.
The normal SIMPLE retry still exits4 with `scope_unbound`
(`simple-main-reservation60.log`), so no function or matrix gain is claimed.
Post-change observation shows exhaustion has moved into mandatory simulation:
20,001 units at instruction simulation and20,026 at block rebinding, against
the unchanged20,000 local limit (`simple-reservation-observer/`).
The next trace finds five successful sum_to simulations that converge in at
most five visits per block (0.113–0.340CPU seconds), plus two attempts that
exhaust work after only three/one block visits. All seven have the same recorded
register/known-memory/unknown-memory input hash. Thus nonconvergence or lost
argument transport is not established; repeated attempts with depleted work
are the next target (`simple-loop-analysis.json`, `simple-loop-observer/`).
Context identity and complete source/input freshness still need checking before
any reuse is considered. Preimages, hashes and review are in
`parent-callee-budget-reservation/`.

Preimages and review are in `parent-native-cache-retention/`.
Acceptance remains **0/16 starter round trips and 0/118 matrix cells**.

Supporting WIP: the pure Python-code encoding candidate passed 14 independent
baseline-equivalence, depth, mutable-constant/default/closure and deep-refusal
controls. Only successful encodings of proved-immutable code-value graphs are
retained, with code identity/depth keys, strong references and a 4,096-entry cap;
source/native/artifact verdicts remain freshly observed. This is not delivered
compiler coverage: the real MAIN run still times out and emits no C. Review:
`.cache/compiler-coverage-resume-20261110/devin-closure-observation/followup-code-fingerprint/PARENT_REVIEW.md`.
The recursive timing sums are inclusive and do not prove a whole-pipeline gain;
normal admission completed at unchanged 101,873 work units, 49.42 wall/48.93 CPU
seconds. The cause of timing variation has not been isolated. The canonical-body
serialization follow-up finished without a patch: all six owned files match
its baseline hashes. Parent foreign-payload codec controls pass (23 tests),
but this adds no accepted functions. Worker stage measurements identify graph
canonicalization as the dominant digest cost; those timings remain diagnostic,
not independently established pipeline savings. Evidence:
`.cache/compiler-coverage-resume-20261110/devin-closure-observation/followup-body-serialization/PARENT_REVIEW.md`.
Current parent CLI verification of helper0x1ce2 on the declared BC31 binary
exits0 with statusOK, validation=passed and emitted C, at ordinary60s timeout.
Receipt: `.cache/compiler-coverage-resume-20261110/cmp-helper-full-route-baseline/parent-receipt.json`.
The separate near-call intake rejects its three incoming edges as
`entry_ambiguous`, but the normal pipeline succeeds; this narrow refusal does
not justify changing multi-caller authority. Legacy0x102c2 maps to0x1ce2 when
the load base changes from0x10000 to0x1a20. Work returns to repeated boundary
coverage authentication in MAIN, with the original worker deadline and all
freshness/cardinality gates preserved. The helper baseline is not a new
accepted round trip or evidence of an improvement.
The boundary-local memo experiment was not retained: real MAIN still timed
out with validation uncollected, and measured bindings remained153/51blocks.
Its two owned files were restored to verified dirty preimages;16focused tests
pass. Candidate and parent review remain under
`.cache/compiler-coverage-resume-20261110/devin-closure-observation/followup-boundary-observation/`.
The immediate producer/caller repeat was in `_caller_premise_surface_8616`.
It now consumes the freshly produced typed failure; retained/public coverage
checks still reauthenticate. Parent native-byte and registry-republication
controls within one traversal both pass, and the supported catalog checker
passes. Worker reports3focused and67neighbor tests plus lint passed.
Admission work fell101873→101715 at unchanged128000 limit, but MAIN still
times out60s with validation uncollected and no C. This remains supporting
WIP, not a function gain. Parent review and hashes:
`.cache/compiler-coverage-resume-20261110/devin-closure-observation/followup-fresh-caller-observation/PARENT_REVIEW.md`.
The graph profiling follow-up identified no safe local encoder repair and
left all four owned files byte-identical. Its interpreted profile includes
Cython-Shadow costs absent from the compiled backend; no production gain was
claimed. Next work measures whether fresh live-to-existing-snapshot comparison
can avoid table reconstruction in the scoped native seal while preserving
all current-field, snapshot-canonicality and refusal checks. This is an
investigated hypothesis, with no patch retained: the current-source capture
subset measured22calls/3.21s, but a generic matcher would duplicate schemas
and miss computed observation callbacks. All four owned files remained
baseline-identical. No cross-request verdict cache or budget increase is
authorized.

The traversal-wide closure-verdict cache from Devin `married-cormorant` was
rejected and removed after independent review. Its final code accepted changed
native bytes and changed segment-state facts between queries in the same
ambient traversal; both parent controls failed. The final MAIN run also still
timed out with validation uncollected. Exact dirty pre-worker closure source
was restored after the session exited, with final source hashes checked before
restoration. Two permanent same-traversal freshness controls were retained;
scoped lint and 49 closure/preservation/nonleaf tests pass. Candidate archives,
review and logs are under
`.cache/compiler-coverage-resume-20261110/devin-closure-observation/` and
`.cache/agent-tool-output/closure-final-candidate-parent-controls.log`.
Reduced observation counts are not proof that a whole traversal is immutable.

Fresh BC31 comparison MAIN entry admission now has a successful bounded probe
under the authenticated native declaration: `DeclaredEntryPipeline8616`, exit 0,
101,873/128,000 ambient work units, 21.64 seconds (unchanged local proof limits).
This is admission evidence only. Full direct decompilation at `0x1dc3` still
expires after the unchanged 60-second recovery budget and emits no C. Evidence:
`.cache/agent-tool-output/compare-main-budget-baseline.log` and
`compare-main-declared-decompile.log` in the same directory.

The diagnostic MS worker run confirms that cold imports alone do not explain
the timeouts. Five-second stack sampling catches repeated SSA canonicalization
from source-readiness fingerprints/registry admission and postprocess activity
in `0x101b3`; that function still times out. These are samples, not exclusive CPU
costs or permission to weaken source authentication. The profiled case remains
`decompile_failed`; its only `ok` record is the `astart` helper model. Full stacks
and per-function sample chains are retained in
`.cache/compiler-coverage-resume-20261110/worker-profile-final-analysis.json`.

Local gate checkpoint: `quality-fast` exposed four optional read-trace list
errors in the replay helper. The already-admitted collection is now passed
explicitly; scoped lint, MyPy and 58 replay tests pass. The repeated full gate
previously failed on dangling `.cache/locks` and `.cache/npm-cache` symlinks.
Those links are now preserved under
`.cache/agent-tool-output/gate-symlinks-20261110T220533Z/` and replaced by
writable local directories; external targets were untouched. The fresh
`quality-fast` now reaches MyPy and fails at
`function_readiness_contracts.py:520`: an exact-type-guarded container remains
`object` to the type checker. This retained CodeType optimization now uses
an explicit guarded container union; direct MyPy/Ruff,46owned tests and
14independent controls pass. The full rerun then failed on another dangling
cache link, `.cache/mypyc` (the typing error was gone). That link was also
preserved and replaced by a local directory; the isolated mypyc target is now
building successfully past directory creation. Completion remains pending.
No broad gate pass is claimed. Full rerun log:
`.cache/agent-tool-output/quality-fast-after-readiness-typing.log` (exit2);
active build: `.cache/agent-tool-output/mypyc-after-cache-repair.log`.

The current full-batch invocation (`first16-dosbox-current/` under the evidence
root below) stopped after the first MS C comparison case exceeded the unchanged
120-second decompiler stage limit. Original compilation/execution passed;
all 1,408 recorded source hashes stayed unchanged. Schema-2 runner policy stops
on a timeout, so the remaining fifteen cases are **not attempted**, not failed
or passed. Two serialized function results timed out (`0x101b3`, `0x100d6`);
the latter reports 82.46 seconds in the clean-process path. The next diagnostic
must separate worker startup from decompilation work without extending frozen
budgets. Raw cases and source stability are recorded in
`.cache/compiler-coverage-resume-20261110/first16-current-progress.json`.

The Devin callee-transcript experiment was rejected after independent review.
Its native-cache/identity guard accepted cached exits after the live IR block
inventory changed; the new negative regression failed. It also still refused
MAIN within the unchanged local budget. The exact worker delta was removed,
restoring the recorded dirty pre-worker invocation source. Candidate sources,
failed control and review are retained under
`.cache/compiler-coverage-resume-20261110/rejected-callee-transcript/`.
This is not an accepted optimization or function improvement.

The fresh MS C5.1 `word_comparisons` baseline ends `decompile_failed`:
one passed and four failed function records are serialized before a CLI
`AttributeError` aborts the sweep at `0x10402`. The receiving process tries to
export a new scalar interface from a `SimpleNamespace` function identity that
has no prototype. Transport now uses typed execution origin: new interfaces
come only from live in-process function authority; cache/clean-worker results
with no receipt keep that optional evidence absent. Retained receipts still
undergo source/generation authentication. Both cache and fresh-worker
identity regressions failed before their guards; 22 related tests and scoped
lint pass afterward (`scalar-cache-before.log`, `scalar-clean-before.log`,
`scalar-clean-after.log`, `scalar-clean-lint.log`). The frozen-tree rerun completed its sweep without that exception and serialized
all eight selected function records, including `0x10402`. Binary SHA-256 is
unchanged and all five recorded source hashes remained stable. This repairs
result transport, not semantic acceptance: seven records failed or timed out;
the sole `ok` result is the existing `astart` helper model. Previously passing
`0x101b3` timed out in this sweep, but the same-binary focused rerun completed
with `status=ok`, `validation=passed` and exit 0
(`.cache/agent-tool-output/msc-101b3-focused.log`). The sweep timeout remains
unresolved; this focused success does not accept the whole case. The case
still ends `decompile_failed`; no starter or matrix cell is accepted. Evidence:
`.cache/compiler-coverage-resume-20261110/msc-transport-review.json` and
`compare16-msc51-after-worker-transport/` in that same evidence directory.

Current-host toolchain prerequisite: all four MS C5.1/Borland3.1
small/large profiles now have successful explicit DOSBox compile/link/run
probes (exit255, int2/long4, data/function pointers2 for small and4 for large,
arithmetic checks PASS). Canonical admission of
`.cache/compiler-coverage-resume-20261110/toolchains-dosbox-all.json`
accepts all four profiles; its evidence registry pins current runner bytes,
compiler dependencies and complete probe artifacts. A copied registry with an
altered runner hash is refused (`dosbox-profile-negative-control.json`).
The repository's default KVM registry is unchanged. These are environment
prerequisites only; all round-trip and matrix acceptance counts remain zero.

The latest follow-up keeps **0/16 and 0/118** unchanged. The absorbing
prefix now performs one structural row census; 108 related tests passed, but
the uninstrumented MAIN probe still refuses (101,415 ambient charged work,
18.26 seconds). Reversed cyclic scheduling was measured and rejected: it did
not improve acceptance and increased the loop's work. Its implementation was
removed. Scoped indirect-view diagnostics now reauthenticate their retained
entry before publishing edges; stale or absent authority emits no accepted
edges. The regression failed before the repair; 22 indirect-view/segment
closure tests and the three-owner MyPy check pass afterward (logs
`view-serialization-before.log`, `view-diagnostics-after-fixed.log`, and
`view-diagnostics-types.log` under `.cache/agent-tool-output/`).

A fresh frozen `word_comparisons@bc31-small` round trip using the measured
DOSBox registry finished `decompile_failed`; no feature witness was accepted.
The raw report is in
`.cache/compiler-coverage-resume-20261110/compare16-bc31-roundtrip/`.
Observed failures include `entry_ambiguous`. Native entry capture and converter
source authentication subsequently passed in `compare16-native-entry-current/`.
The current native debugger build requires a different dispatch coordinate;
the diagnostic adapter records the binary/source/script hashes and retains the
live CS:IP and linear-IP guards. Failed capture attempts remain preserved.
The binary-bound declared-input rerun in `compare16-bc31-bound-roundtrip/`
finished `timed_out`. `cmp_i16` (module offset `0x2c2`) validates under the
measured entry, whereas the undeclared baseline refused it. This is a change
of explicit premises, not a same-input before/after code acceptance claim.
The undeclared baseline contains two passed and eight failed function verdicts;
the declared attempt times out before completing the same function set.
Limits and frozen corpus hashes remain unchanged.

**2026-11-10 continuation — MAIN still unaccepted.** On the authenticated
Borland small-model `simple_control` input, local invocation censuses for CALLs
at `0x22bc` and `0x22cd` exhaust the unchanged 20,000-work limit. The ambient
128,000-work budget and wall deadline are not the initial cause. Two generic
repairs remain intermediate evidence: absorbing prefix cuts now exclude only
exact mirrored refusals in blocks outside their absorbing region, and a separately
authorized snapshot walk can omit a confined terminal CALL effect after fresh
pre-CALL capture. Raw refusals and full-function refusal remain intact.
The latter reduced the uninstrumented MAIN probe's charged work from 109,822
to 100,713, but it still exits with `declared entry scoped CFG is unproved`.
The initial failure was source reauthentication of the retained prefix.
Mapped callee discovery had retained the image suffix as its extent (3,226
bytes for `classify`, 3,186 for `sum_to`). Native freshness already reads only
decoded blocks; no accounting discount was introduced. The frontend now
independently reproves a tighter upper bound for owned native blocks, retains
backward reachability, and checks live bytes against cached decode records.
Twenty boundary/context regressions pass. Prefix source authentication now
passes with 468 charged operations, but the subsequent terminal CALL transfer
still exhausts the local budget at 20,004. No function or round-trip acceptance
count increased. Focused evidence is in
`.cache/agent-tool-output/prefix-suffix-before.log`,
`prefix-suffix-after.log`, `captured-call-before.log`,
`captured-call-related-after.log` (151 passed), and
`captured-final-guard-tests.log` (36 passed after the fresh-capture guard).
These checks do not replace the required pipeline and semantic gates.

**2026-11-10 environment recovery — not round-trip acceptance.** The earlier
cache artifacts referenced below are absent in the current workspace. All46
source/runtime/signature references of the frozen16-case manifest still match
their recorded hashes. The default registry currently refuses because its
`/usr/bin/dosbox` path is missing; `/dev/kvm` is also unavailable. A fresh
Borland3.1 small-model probe compiled, linked and executed under the installed
`/usr/local/bin/dosbox`: observed exit255, expected width/arithmetic/indirect-call
output and `PASS failures=0`, with stable runner hash and seven dependency hashes
verified. The first Boolean of the runtime helper denotes exit0, so its false
value for the expected255 is not an execution failure. Exact native observations
and the separately checked explicit DOSBox registry are retained under
`.cache/compiler-coverage-resume-20261110/`. The canonical
`branches_loops@bc31-small` PTY run completed with `timed_out`: original
build/run succeeded (exit255, empty stdout), but decompilation emitted zero
functions before the unchanged120-second stage budget (120.49s observed).
Binary discovery queued seven functions. Evidence is in
`simple-dosbox-pty/summary.json` and `case-000/runner.log` beneath that directory.
The earlier non-PTY run ended with SIGTERM143; its initial summary is not a final
result. A separate same-budget diagnostic records periodic process stacks to
locate the delay. Both canonical and stack-instrumented runs timed out.
The retained worker results additionally refuse CLASSIFY because multiple
incoming CALL rows are ambiguous to the current single-entry owner. A focused
MAIN diagnostic (exit4) preserves the deeper typed failure:
`native_near_call_entry_selector_window_unproved`, caused by
`near_call_selector_target_not_window_invariant` at callsite0x10158 to0x10341.
This requires authenticated selector context; choosing a convenient CS or
weakening the universal selector-window check would be unsound. Fresh capture
recovery succeeded for the executable entry using the installed debug DOSBox
and its current loader/interpreter ABI: CS0x1f5, IP0, a full1MiB memory snapshot,
and full-width registers. The canonical capture converter returned exit0 and
`status=captured`; its report explicitly retains
`proof_status=not_established_by_execution`. See `native-entry-v2/` and
`native-entry-verified/`. A fresh two-stop MAIN capture
now also exists in `native-main-raw-flags/`. The temporary guest INT3 byte was
restored before the MAIN memory snapshot, and the full115-byte function and
eight-byte table match the relocated source. The caller E8 target and captured
return slot agree. `declared-main-authentication.json` records canonical
declaration admission (exit0), source/tool/script hashes and exact premises.
`declared-main-fresh.json` fixes the observed word registers, two return-slot
bytes and eight table bytes; environment-memory reuse is disabled. Lazy flags
type23 is retained as raw evidence and flags are omitted from the declaration.
The external DOS-vector coordinate comes from the authenticated IVT as an
explicit conditional policy; no service sites or handler semantics are inferred.
The focused MAIN check at0x2291 with that declaration completed exit4:
`declared entry scoped CFG is unproved`, typed `application_empty` because the
retained application did not satisfy the unchanged-surface acceptance contract.
Evidence: `.cache/agent-tool-output/latest-main-declared-baseline.log`. The
underlying application is `empty`, with no application refusals and
CALL-target status `not_requested`. Per-check observation localizes the failed
identity check to five retained `terminal_jump_selector_window_unproved`
refusals in the raw MAIN artifact (blocks0x22d5,0x22e0,0x22eb,0x22f6,0x22fb).
They must be discharged by the scoped jump owner, not erased by the view.
See `main-scope-applications.jsonl` and `main-scope-checks.jsonl`; both diagnostic
runs returned exit4. Further observation confirms all five pending jumps reach the proof owner:
its ledger retains five `entry_jump_domain_call_on_path` refusals because
CALL0x22a6 to sum_to0x223a lacks preservation evidence. The first CALL0x229b
to classify0x2212 has a complete retained callee closure. sum_to and later
calls return `entry_domain_call_callee_incomplete`, not budget exhaustion.
Evidence: `main-domain-proof.jsonl`, `main-domain-preservations.jsonl` and
`main-raw-callee-receipts.jsonl`. A focused check of the authenticated32-byte sum_to body at0x223a passes
canonical IR publication, boundary coverage and segment-effect closure:
no refusals, closure counts[1,1,1,1,0], complete=true (0.79s owner work).
Evidence: `sum-to-leaf-published.json`; native body SHA-256
`7d074076942bf457ab7c778b195875f7a5df68ad0cde9fabf90cf8bb3ef0a459`.
This proves isolated closure, not generated-C equivalence or caller acceptance.
Fresh direct MAIN preparation both with and without preimporting sum_to still
refuses. A later instrumented direct run binds sum_to successfully (21.94s),
so its earlier missing closure is not a context-independent leaf defect.
The next CALL, 0x22b1 to switch_fold0x225a, has a valid near-return frame premise
but no mapped callee boundary. Both ordinary and deferred scoped boundary
lookups refuse before importing the CS-indexed indirect jump at0x2269.
Evidence: `direct-factory-refusals.jsonl` and `switch-scope-refusals.jsonl`.
These direct owner runs do not establish exact equivalence with CLI recovery.

A separate producer-to-consumer regression confirms an integration gap:
`ScopedIndirectTargetView8616` produces an authenticated CFG projection, but
scoped boundary coverage refuses it with `scoped_view_refused`. The existing
indirect theorem is not admitted by that consumer. The baseline regression
failed1/1 in49.54s; retained log:
`.cache/agent-tool-output/indirect-coverage-gap-before.log`.
The provisional repair now admits the exact owned view through scoped
coverage and segment-state analysis. Its producer→coverage→segment-effect
regression passes1/1 (115.90s), including foreign-project/stale-native coverage
refusal and context-free incompleteness. Scoped lint, startup architecture and
MyPy pass for the three changed owners. Evidence:
`.cache/agent-tool-output/indirect-effects-after.log`.
On-demand theorem selection, source-bound conditional callee boundaries and
deferred exact-caller construction are now connected. Known-input intake
succeeds conditionally; unknown inputs refuse without universal publication.
The five related regression files pass62tests (42.43s), including mutation
controls and existing nested-call behavior. Retained log:
`.cache/agent-tool-output/indirect-callee-related-regressions.log`.
Combined MyPy retains the same38 pre-existing call-owner diagnostics at the
same original lines/error codes; the other changed owners pass. No new type
errors are hidden. The subsequent canonical MAIN run still times out during
function recovery at the unchanged60s diagnostic limit, with tail validation
`uncollected` (exit3), so this is not a decompiled-function gain. Evidence:
`.cache/agent-tool-output/main-declared-after-indirect-intake.log`.
Separate direct MAIN preparation is being rechecked before attributing that
CLI timeout to this repaired proof path. The repair remains open until canonical function and corpus
acceptance improves; admitting a view alone is not delivery. Later broad diagnostic runs
were inconclusive under host load around24 on8CPUs and hit recovery/watchdog
limits; their timeouts are not new semantic defects. Capture authentication is not semantic
equivalence. KVM absence does not block this DOSBox capture path. Evidence: `main-binding-refusals.jsonl`,
`retained-worker-results/`, and `diagnostic-site/` in the same recovery directory.
No new accepted function or round trip is claimed.
The following paragraphs describe earlier retained reports, not reverified
current artifacts.

The fresh run in `.cache/bc31-seven-word-casts/` validates all six helpers and
emits conditional MAIN (340.22s). All seven exact generated bodies rebuild with
Borland3.1; fresh original/rebuilt executions both return255 with empty stdout
under the same frozen compiler/runtime context. GCC syntax checking also passes.
Evidence: `rebuild-fixed/comparison.json` beneath that directory. MAIN retains
its declared-entry premise and diagnostic480s function timeout; this is concrete
whole-program execution evidence, not unconditional or formal corpus acceptance.

The Widening repair recomposes Alias-owned byte lanes before Structuring checks
shared return arms (54 focused tests; native clamp validation passed). The rebuild
boundary now includes its existing fixed-width/Boolean compatibility headers
without changing authenticated function bodies (97 builder tests, lint/MyPy).
The next frozen starter is `branches_loops@bc31-small` (SIMPLE, four functions),
tested through the canonical manifest command with the explicit verified
DOSBox registry `.cache/bc31-first-acceptance/toolchains.json` in
`.cache/compiler-coverage/simple-bc31-dosbox-next/`. The initial kvikdos profile
attempt is retained as build-failed because `/dev/kvm` is unavailable.
The DOSBox original builds and returns255; decompilation remains failed.
For sum_to0x102ea, loop-topology collection incorrectly consulted the default
angr KB instead of codegen's authenticated private function. It now uses the
canonical function resolver. Three new owner regressions failed before the
repair;49 focused tests, scoped lint/MyPy and startup architecture checks pass.
The subsequent shared-storage Alias proof admits DX initialization and its
loop increment as writes to the same authenticated runtime lane, while the
unique-value-definition API remains strict. Missing/partial writes, calls,
foreign storage and register changes between CMP and JCC refuse.32 focused
tests pass. The final native run `.cache/simple-sum-storage-final/` emits
sum_to0x102ea with statusOK and validation=passed (34.56s,774MiB, unchanged
sources); GCC C99 syntax checking passes. Its signed loop guard now compares
`(short)(inertia_edx & 0xffff)` against `arg_4`; accumulator/update behavior
and the source's absence of calls are preserved. This adds one validated
SIMPLE application function, not a completed four-function program.
The default pipeline was interrupted (exit130), not passed; log
`.cache/simple-sum-pipeline.log`. The GNU Make oracle subset passes43 tests
with writable TMPDIR. Scoped fixture and comparator failures remain unresolved.
Scoped MyPy still reports two pre-existing no-any-return findings in
condition_lowering.py, outside the new shared-storage implementation.
A fresh two-stop native capture for SIMPLE main is authenticated in
`.cache/simple-main-capture/declared-main.json` (observed entry0x1d61,
module offset0x341,115 native bytes). This supplies explicit input premises only;
execution did not establish semantic equivalence. No CMP16 entry state is reused.
MAIN currently refuses because switch_fold0x1d2a has no closed native boundary:
the reachability census leaves its table dispatch at0x1d39 unresolved
(`jmp word ptr cs:[bx+0x339]`, after an unsigned BX<=3 guard and SHL BX,1).
The declared selector invariant consequently reports CALLEE_MISSING at call0x1d81;
the later missing sum_to preservation is downstream, not a diagnosed loop defect.
Evidence: `.cache/simple-main-surface-diagnosis/` (unchanged sources,13.28s).
Next is bounded, authenticated indirect-table reachability using the caller's
CS premise and proven index domain, with invalid-table/index/CS controls.
Do not admit incomplete boundaries or silently promote declared CS to universal.
The scoped callee-boundary retry is the integration point: transport the
authenticated caller-prefix register state and path-memory overlay before
closing the callee census. Selector preservation alone does not prove table
contents. The frontend reachability tests now retain the actual guarded-table
bytes at three load addresses and require refusal without those premises
(28 tests pass); they are safety controls, not switch support or corpus acceptance.
The CS-address prerequisite is implemented in typed IR, VEX address recovery,
path-memory segment resolution and segment contracts. Focused verification:
43 passed; the separate direct-byte logical-capture failure reproduces against
the exact pre-edit owners. Iteration lint passes. Scoped MyPy still reports
four findings in existing persistent-memory/scalar-effect code, outside this
change. Conditional table-edge proof and its consumer integration remain open;
this prerequisite adds no accepted SIMPLE function by itself.
Caller-prefix recovery now succeeds after fixing an independent native-binding
defect: universally normalized leaf jump rows were compared to raw VEX rows.
The census independently reproves that same universal normalization and retains
full row/operand equality; changed native bytes, targets and proof producers
still refuse.35 focused tests and iteration lint pass; scoped MyPy diagnostics
match the exact pre-edit baseline. Evidence: `.cache/simple-callee-normalization/`.
The uninstrumented MAIN retry completes in40.58s, with unchanged sources and
exit4 (`APPLICATION_EMPTY`), not validation success. The separate authenticated
prefix diagnostic now reaches switch_fold with CS=0x1a2 and retained stack/memory
evidence (`.cache/simple-switch-prefix-normalized/events.jsonl`); previously
this prefix refused. Next, consume that invocation evidence to prove the
indirect target without treating conditional table contents as universal.
The original declaration supplies only its return-slot memory and explicitly
disables environment-memory reuse. A separate declaration now includes the
eight table bytes observed in the authenticated MAIN capture:
`.cache/simple-main-capture/declared-main-table.json`. Its conversion validates
capture/source/tool identities and the full captured-memory hash; canonical
declaration intake passes. The original declaration is unchanged. These are
explicit input premises, not a claim that loader bytes remain immutable or that
the function has passed validation. Unknown or overwritten table memory still
requires proof before an indirect edge can be admitted.
The bounded invocation discovery now evaluates the actual native callee prefix
with the shared scalar/path-memory engine and returns target0x1d43 for this
call. Evidence: `.cache/simple-indirect-singleton/` (26.42s,292MB, unchanged
sources, diagnostic exit0). This is a conditional discovery result only;
scoped CFG consumption and complete MAIN validation remain open. The existing
entry-jump owner handles decoded relative jumps, so indirect discharge must
retain its own evidence rather than inventing a relative-jump record.

### Retained generated-only Borland 3.1 CMP16 evidence

Historical evidence below is not currently available at its recorded
`.cache/bc31-prototype-integration/` path. It must be reproduced or recovered
before it can support present acceptance; the fresh helper receipt above
proves only that one function.

All seven application functions now compose into one generated C translation
unit. GCC accepts it; the pinned original Borland toolchain compiles/links it;
the resulting DOS EXE returns255 with empty guest stdout, matching a fresh run
of the original under the same frozen compiler/runtime context. No original
function bodies are included. Only the existing entrypoint binding and runtime
support are added by the established rebuild route.

Evidence: `.cache/bc31-prototype-integration/generated-case/comparison.json`,
`receipt.json`, `assembled.c`, `GEN.C`, `GEN.EXE`, compiler logs, and the sibling
`original-runtime.json`. Generated EXE SHA256:
`01dcc772dfd2f1270b3c5bab9a34007bfb1ae117efd5c95949681b800bfb2ad6`.

The six helpers (0x1ce2,0x1d0c,0x1d47,0x1d82,0x1d99,0x1db6) retain statusOK.
MAIN0x1dc3 remains conditional under its explicit declared-entry premise;
its emitted/validated/GCC payload SHA256 is
`1efed5b218b515742e06f641ad746ffd365575404e6eb54814ae7ef3445c92a6`.
It finished413.76s with no timeout/source drift using diagnostic work cap200000
and CLI480s. Ordinary cap20000 is still unresolved. The complete generated
program now compiles/runs, but this is a diagnostic round trip, not another
formally accepted starter/matrix cell or an unconditional equivalence claim.

The coherent repair transports accepted scalar interfaces across existing
worker IPC and fresh-project cloning, authenticating source/native/ABI/payload/
producer bindings. Declaration lowering consumes them for proven VALUE slots,
including when no callee Function exists in the caller CFG. Pointer/unknown
storage retains its own authority. A portable integration test covers the full
worker→fresh project→storage→declaration chain; native observation confirmed all
six correct prototypes before the successful whole-source compilation. Source
preimages and the earlier conflicting-prototype failure remain in the same
integration directory. Targeted tests/lint and startup architecture checks pass;
broad integration gates remain outstanding.

The normal CLI now selects the native call closure of an explicitly declared
root and schedules its six helpers before MAIN. Environment-only declarations
retain ordinary discovery; unresolved targets remain explicit obligations. This
does not classify or discard the extra candidates in a whole-image sweep.

The normal sweep retained all seven final worker records: six OK with generated
C and source-bound scalar interfaces, MAIN timeout in recovery before its
decompiling marker. Runtime195.59s, peak744.5MiB, source identities unchanged;
ordinary60s function budget, no proof-budget override. Evidence:
`.cache/bc31-normal-sweep/summary.json` and `main-final-diagnostic.json`.
One bounded actual-worker observation then localized65.21s inside
`function_ssa_artifact_for_boundary_8616`, called by eager local Alias preparation
in the direct fast-probe phase. CFG recovery and caller-context setup finished
within1.4s. No decompilation-header event occurred. This establishes the slow
owner, not its internal root cause; do not bypass Alias or raise timeouts.
Evidence: `.cache/bc31-preheader-observer/events.jsonl` and `receipt.json`.

The narrower collector observation attributes64.49s to call-preservation
collection, including17 distinct caller-prefix derivations totaling57.49s.
Sharing a completed-proof traversal across independent collection requests was
tested and reverted: changing a descendant's native bytes between sibling
requests incorrectly reused success. Native regressions in
`tests/ir/test_entry_collection_sibling_freshness.py` preserve rejection at
both sibling and independent public-root boundaries. Budget sharing must not
extend completed-proof lifetime. The current CPU-profile capture uses fresh
six-helper receipts and the actual collector thread to distinguish derivation
cost from authentication cost; outer-stage timings alone cannot choose a fix.

The CLI now closes heavy fallback lanes after typed decompilation timeouts,
preserving their cause and partial output. This prevents a measured124s
redundant fallback path; focused regressions pass, but native savings and a
new accepted MAIN result remain unverified. Neither this fix nor the rejected
shared-traversal experiment increases accepted coverage.

Actual-thread cProfile now identifies a concrete copy cost:78 census requests
spend13.95s in their returned selected-block deepcopy calls. The census owner
now seeds those copies with the existing fully detached typed IR copier, also
used for native surfaces. It retains ordinary deepcopy fallback, graph aliases,
mutation isolation, freshness and unchanged work charges. Copier aliases join
the existing producer key; the caller already binds internal copier producers.
69 focused copy/freshness tests and scoped lint pass; independent review found
no binding gap. The separate equality optimization was abandoned without edits
because bounded DAG and schema memos already exist. A fresh ordinary sweep is
required before accepting a speed or coverage improvement. Profile and checks:
`.cache/bc31-collector-cprofile/`; sweep: `.cache/bc31-typed-copy-sweep/`.
Devin's independent isolated review also selects the same existing copier:
17 mutation/fallback/alias tests pass; a synthetic480-instruction graph copies
in31.95ms median versus94.48ms with plain deepcopy. These are microbenchmark
results, not MAIN latency or coverage evidence. Report:
`.cache/devin-native-copy-profile/findings.md` (process exit0).

The ordinary typed-copy sweep finished191.72s (baseline195.59s), peak748MiB,
with unchanged sources. Six leaves retain identical validated/GCC payloads;
MAIN reaches its decompilation header after roughly52s but still times out
at65.55s, with heavy fallback correctly disabled. No accepted-function gain:
the coherent MAIN repair remains open. Evidence:
`.cache/bc31-typed-copy-sweep/REPORT.md` and `summary.json`. Further work must
address remaining comparison/derivation cost or the later decompilation stage,
not claim the copying microbenchmark completed this repair.

Three full-source candidate prefilters now avoid native block comparison for
empty LOAD/interior-CALL maps. Nonempty maps retain full binding and original
post-binding iteration; exact IRInstr guards preserve malformed-row refusal.
Native controls show LOAD-map comparisons4→1 and empty-CALL comparisons4→0;
47 combined tests and11 final expanded tests pass, scoped lint passes. Devin's
independent review caught the missing malformed-row guards before the sweep.
The ordinary sweep is172.22s/670MiB, sources unchanged, still six identical OK
leaves and MAIN timeout65.22s. MAIN reaches its header after45s rather than52s.
Evidence: `.cache/bc31-feasibility-prefilter-sweep/` and
`.cache/native-equality-next/`. This is the second optimization without an
accepted-function gain: stop collector micro-optimization and measure the
remaining post-header stage. Reuse only this sweep's same-generation accepted
leaf receipts for that diagnostic; never rebind stale evidence or repeat the
six unchanged leaf runs merely to profile MAIN.

Observer correction: live `cProfile.dump_stats()` disables the profiler.
The collector capture's50s watchdog and post-header10s watchdog therefore
truncate their CPU coverage; their later dumps do not extend it. Their measured
prefix costs remain evidence, but cannot identify the entire request's hot path.
The corrected observer must use non-disabling snapshots and pass a smoke test
showing additional workload calls after the first snapshot before another
native diagnostic. Preserve the defective captures, label their limits, and
do not use identical late snapshots as evidence of stalled decompiler work.

The corrected live observer now proves coverage through shutdown (9.34M→
35.29M calls). MAIN progresses through Clinic simplification and variable/type
recovery, but has not reached recursive structuring or semantic tail validation.
There is no measured single remaining hot operation that justifies another
small collector optimization. Following the user's explicit authorization to
temporarily double the timeout and obtain a result, the next diagnostic is one
uninstrumented120s MAIN, unchanged proof-work cap and current-generation leaf
interfaces, supervisor150s/2GiB. Preserve the ordinary60s failures separately;
a120s result does not establish60s performance acceptance. Evidence directory:
`.cache/bc31-main-120/`. Prioritize generated C and its actual validation/rebuild
or the next concrete refusal over further infrastructure work.

The120s diagnostic reached structuring and reported `+reg:eax`, then timed out.
The bounded witness in `.cache/bc31-eax-native/` identifies a validation defect:
four existing EAX assignments are unchanged, but the baseline observation walker
skipped their reads inside `CITE` conditions. Simplification exposed those same
reads. The validation owner now visits the condition and both value arms.
Six new regressions reproduce the defect and preserve rejection of a genuine
extra write;25 focused tests and scoped lint pass. This is not MAIN acceptance.
A fresh seven-function sweep with the temporarily doubled120s timeout and a
pre-frozen whole-case request retained six validated helpers but MAIN timed out
(`.cache/bc31-cite-fix-run/`). A separate240s MAIN diagnostic completed in184.36s
of decompilation, with stable structuring and all20 required calls retained.
Final validation refuses12 uninitialized `SS:BP-4:size1` reads and four missing
branch-condition surfaces at `1f11`, `1f23`, `1f3a`, `1f4c`; partial C and exact
failure evidence are in `.cache/bc31-main-240/`. The native argument PUSH/POP
dataflow and the four AX/EAX condition projections are the next repair targets.
No whole-case rebuild was admitted. The ordinary60s performance target and
complete-case acceptance remain open; the larger diagnostic limit changes neither.

The next combined repair retains typed stack PUSH definitions still read by the
AST, projects a proven AX view from a stored EAX result without re-evaluating its
call, and preserves completed PUSH/POP pairing windows across an unmatched
epilogue POP. Existing word widening consumes those pairs; no rendered-C repair
or validation exemption was added.67 combined regressions and architecture-fast
pass. The fresh seven-function run in `.cache/bc31-main-semantic-fixes/` includes
the existing consumed-PUSH diagnostic. It finished with six helpers passed and
MAIN timed out at247.36s (402.73s total,764MiB peak, sources unchanged).
Composition refused the incomplete inventory; no rebuild ran. The diagnostic
did not capture the relevant PUSH LHS, so applicability remains unverified.
Intermediate validation lost all20 direct-call projections after a rejected
DCE rollback. A separate minimal reproducer confirms that snapshot/restore
alone loses call metadata: cloned AST identities no longer match the restored
summary keys. Repair that exact provenance defect before another native run;
neither the call projection loss nor focused tests establish a native semantic
mismatch or a function gain.

The rollback repair now transports exact source-to-clone call identities from
the copy memo, removes temporary provenance before publishing the live AST, and
rebinds only retained call occurrences. Repeated restores and duplicate calls
are covered without address/name matching.117 focused snapshot tests, scoped
lint, direct MyPy on the new owner, and architecture-fast pass. The independent
contextual-summary reproducer now retains its call description across rollback.
Fresh native evidence in `.cache/bc31-main-call-rollback-fix/` retains all six
validated helpers. MAIN completes in147.65s rather than timing out, with stable
structuring, all20 required calls retained, and zero control-flow guard failures.
The four missing condition surfaces are fixed. Final validation still refuses12
uninitialized `SS:BP-4:size1` reads; no accepted MAIN or rebuild exists. Total
wall312.0s, peak789MiB, sources unchanged. The opt-in PUSH monitor produced no
events, so it does not establish the removed stores' LHS or deletion path.
Next fix: establish which argument-consumption path deletes the still-read
stores, and preserve their definitions before existing word materialization.

The argument-consumption memory safety regression is fixed: consuming a call
argument no longer unconditionally deletes an unknown-identity memory store.
Late argument seeds also respect the existing replacement policy unless backed
by complete instruction-bound PUSH facts.251 focused tests, lint, and
architecture-fast pass. The fresh `.cache/bc31-main-memory-store-fix/` run keeps
six helpers passed and all20 MAIN calls, but MAIN still fails the same12 reads
(172.44s,303.96s total,780MiB peak, unchanged sources). No rebuild was admitted.
Read-only observation now proves the actual missing definitions are typed byte
stack stores: `1de1` writes `BP-4/BP-3`, and `1de5` writes `BP-6/BP-5`.
All four exist on entry to `_run_rewrite_root` and are absent on return. Neither
of the two previously investigated deletion predicates executes. Focus next on
the materializer's direct list-removal paths; further changes to those unused
predicates cannot fix this MAIN failure.

The actual third deletion funnel is now fixed: probe-frame cleanup no longer
deletes memory/typed stack stores on instruction/value matching without a
memory-liveness proof. Two native-backed bytepair regressions reproduce the
old loss, including an address-taken high byte;253 focused tests, lint, and
architecture-fast pass. In `.cache/bc31-main-typed-store-fix/`, all four watched
definitions survive the materializer. MAIN's12 uninitialized-read errors are
gone, and both structuring and postprocess are stable. Six helpers remain OK.
MAIN is still `validation_failed`: final emission rejects `ss << 4` in the
remaining byte-to-word stack expressions. Its partial C also retains CS-base
arithmetic in call/goto targets. Do not treat stable tail summaries as accepted
or compilable C. This run took145.61s for MAIN/291.27s total,788MiB peak, with
unchanged sources. No rebuild was admitted. Next work is typed stack-word and
control-coordinate materialization at their owning layers, not text replacement
or removal of the final-emission guard.

The shared-storage widening order defect is repaired: POP matching now runs
before changing its shared byte-sized variable to a word. The exact expression
regression is red-before/green-after;13 owning tests and scoped lint pass.
However, `.cache/bc31-main-word-rebind-fix/` still retains all17 SS expressions:
six helpers pass, MAIN143.60s remains validation_failed, both tail stages stable.
Total331.16s,790MiB peak, source hashes unchanged; no rebuild. This is not a
MAIN improvement. Existing worker debug logging did not reach retained output,
so it cannot establish whether pair admission or materialization was invoked.
Next diagnostic must observe that boundary directly rather than extend syntax.
An independent native Clinic regression also exposes missing CALL-target
admission under declared CS: plain CALL+RET has no raw refusal and incorrectly
skips collecting selector evidence. Backward JMP transport passes that fixture;
unrestricted CS cancellation remains unsound because IP16 wraps.

CALL admission now requests the existing bounded selector proof for typed raw
CALL instructions even when raw import has no refusals. Seven native controls
pass, including no-declaration and unknown-INT21-callee cases; scoped lint and
architecture pass. The affected cohort has55passes and one fixture failure
while monkeypatching the immutable compiled source-graph encoder, before its
assertions. No proof limits increased. Full tiny fixtures measured0.303s for
CALL,0.136s for JMP and0.254s for unknown callee; MAIN cost/benefit remains to
be measured. The new regression is enrolled in the routine test pipeline.

The actual focused worker diagnostic `.cache/bc31-main-call-target-fix/` is
terminal:178.19s,1057MiB peak, unchanged sources, exit4/final-emission refusal.
It still emits17SS shifts and72CS shifts. Thus the tiny CALL fix has not yet
improved MAIN. The external monitor confirms correct16-bit decoded operands
and12 completed immediate-only materializations with zero transfers; no
completed general stack rebinding or pair collector was observed. Investigate
actual dispatch/authority rather than adding expression recognizers. General
rebinding currently lives behind call-return-frame cleanup gates; ordinary
lowering only schedules the immediate-specific pass. Any dispatch repair must
retain alias/call/stack-effect evidence. A separate cheap native-entry probe
must expose why actual MAIN lacks the target authority that the tiny test has.

That preparation-only probe now pins the target blocker: selector induction
is PROVEN_CONDITIONAL with no obligations and20preserved call edges, at19104
shared work. Subsequent collection emits20budget-exhausted call records; fresh
head admission refuses at20078work against20000, with64domains remaining.
See `.cache/bc31-actual-target-admission/internal-result.json`; preparation
took8.75s. Preserve the cap and remove redundant authenticated collection work
where demonstrated; do not replace symbolic targets without admitted authority.

The actual stack-expression blocker is now fixed by canonical AST traversal:
SS lowering previously stopped at owned CSemanticCast nodes because it admitted
only angr module types. Existing alias projection already recognizes the saved
high-byte address;77owning tests now pass with exact high-variable identity and
foreign-node refusal controls. In the uninstrumented MAIN diagnostic
`.cache/bc31-main-stack-cast-fix/`, all17SS shifts disappear and whole-tail
validation remains clean. MAIN now reaches GCC, which refuses symbolic CALLs
and computed-goto adaptations.72CS shifts remain. Total233.77s/1032MiB, sources
unchanged, exit4; this is concrete emission progress, not function acceptance.

Measured budget authentication covers distinct surfaces; its6912unit final
charge cannot honestly be discarded as duplicate work. A bounded explicit
shared-work configuration is being added for diagnosis, keeping20000default
and existing proof checks. A30000unit/25s/2GiB preparation experiment must be
reported separately from default-budget acceptance. No budget increase has yet
been accepted as a normal-case result.

The explicit shared-work setting now exists with20000default and inherited
nested accounting. Its10new controls are in the routine pipeline. The affected
cohort is81pass/21fail; a reverse-delta module overlay reproduces identical21
node IDs and first errors, not a clean-HEAD claim. At30000work, actual MAIN still
exhausts the shared budget. One100000work calibration under the same25s/2GiB
caps reaches head admission at42121units in14.31s/279MiB. It then refuses all20
call records as callee_incomplete and the scoped view as application_empty.
Phase observation rules out the universal-closure factory: the existing
CS-only authority fails a later call-record seal. Investigate that precise
seal invariant; no further budget increase is warranted. Default-budget and
whole-program acceptance remain open.

The later seal refusal is now traced to a second, local resource cap:
the CS-preservation batch consumes21086units against20000. Index/callee seals
are valid; the rejected batch was mislabeled CALLEE_INCOMPLETE. Typed budget
obligations are now propagated separately, and an explicit local batch setting
keeps20000default with inherited nested accounting. A25000local/100000shared
preparation diagnostic retains the same25s/2GiB caps. Do not describe this
resource refusal as a demonstrated incomplete callee proof.

That diagnostic now admits all20 call records and the caller head, but the
scoped view still refuses: shared work reaches101793. Preparation takes16.45s
and282MiB. Observation identifies three complete selector batches, each21847
units: collection, CFG fixpoint, final revalidation. Native lifting and premise
callbacks occur between the last two, so retaining an earlier positive verdict
would be unsound. The next bounded change is a nonpublishing CFG proposal with
mandatory final authentication, not another cap increase or a new cache.
The budget/refusal controls pass28tests; this is not MAIN acceptance.

The nonpublishing selector proposal removes one21847unit batch; final graph
and application authentication remain mandatory.55existing tests and3native
mutation/performance controls pass. Full preparation calibration now succeeds
with20valid records, CALL_TARGETS and no view failure:101793work units,
17.24s preparation,282MiB, under the same25s deadline. Its explicit shared
allowance was250000; the actual charge, not that allowance, is the measured
requirement. Ordinary preparation-budget integration and real MAIN validation
remain pending; this is not an accepted function or generated-only rebuild.

The ordinary declared-preparation root now allows128000shared/25000local work
with its existing50s deadline. Nested requests keep their original limits,
consumed work and earlier deadline;40focused tests pass. Real MAIN then exits4
after68.23s/878MiB with unchanged sources: preparation succeeds, but Clinic's
fresh CFG projection refuses before AIL conversion. Tail evidence is uncollected;
no C is accepted. The next focused reproducer is preparation followed by
cfg_projection_for, whose replay currently opens another default-budget scope.
Evidence: `.cache/bc31-main-call-targets/REPORT.md`.

The build harness now allocates fresh attempt directories, freezes declared
selection before execution, decodes the exact final inventory, and routes
conditional-ready fragments through existing compilation/runtime machinery.
Aggregate process exits and conditional premises remain visible; compilation
does not promote conditional proof to unconditional acceptance. Request refusals
cannot fall back to ordinary acceptance. Portable wiring tests pass; the actual
normal sweep still cannot reach complete-case rebuilding until MAIN finishes.

The six previously validated MS C CMP16 leaves remain baseline successes.
The full sixteen-starter/118-cell/final-Watcom scope is unchanged.

## Scoped selector and target contract

Input is an authenticated declared entry/native caller, exact decoded near CALL
and native callee boundary under its near-return frame. Selector preservation
is conditional on that exact caller/callsite premise, never a universal summary.
Every consumer binds current source, callsite, frame, selector and callee surface;
scoped evidence participates in the final seal. STORE/fetch/control checks,
budgets and native mutation rejection remain mandatory.

One batch serves repeated CALL demands, with fresh authentication at each public
use. Foreign caller/frame/selector, changed bytes, lost premises, unknown effects,
late callbacks and exhausted budgets refuse. Target admission proves neither
calling convention, termination nor callee effects. Keep original raw CALLs and
CFG unchanged; apply proven targets through the private typed scoped projection.
A later target refusal must not silently erase an independently proved earlier
target or promote an incomplete whole region to proved. Preserve this partial
coverage obligation when extending beyond the current complete20target case.

## Next actions, in order

1. Pinpoint MAIN's pre-decompilation recovery bottleneck from the current normal
   sweep; remove redundant work without increasing proof budgets. Verify the
   normal complete-case consumer/rebuild route on the resulting seven records.
2. Resolve the ordinary resource budget and required integration gates, then
   accept the first complete case with its exact original/rebuilt observations.
   Preserve the working seven-body diagnostic as the regression baseline.
3. Complete the remaining starter cases, all118 matrix cells and final Watcom
   phase. Preserve original-only compiler obligations and corruption controls.

## Preserve established behavior

- One shared typed projection policy serves Clinic and semantic construction/
  reauthentication; unchanged native control can be consumed independently of
  target/effect proof. Declared-head preparation does not require a whole-body
  selector survey merely to retain an unchanged raw CFG.
- Fresh nested-call construction transports the already-derived caller state;
  public retained-evidence use still reauthenticates. Selected CALL cuts,
  native/source/capture identity, code-write guards and all five evidence-loop
  counters remain mandatory. Unknown effects remain explicit.
- Validation must give equivalent Boolean call wrappers the same exact
  callsite/orientation before and after Structuring, while keeping argument
  differences observable.
- Cyclic generation snapshots may share work under identical active ancestry
  **within one root traversal only**. Clear contextual memo at both public
  root entrypoints; graph mutations between roots must be observed. Cap4096
  retained references; evict a cold contextual batch at saturation, falling back
  to ordinary traversal for a single oversized context. The native
  work-count control is2046->20; it is not an end-to-end speedup claim.
- Do not revive unreviewed `.cache/cmp16-ssa-reuse/` snapshots, identity-only
  proof caching, speculative prefix replay or detached transcript publication.
  They have no accepted semantic/performance evidence. Existing negative
  tests, not old implementation notes, preserve the required boundaries.

## Shared invariants for bounded optimization work

- Work on one smallest failing real function before corpus expansion. Keep one
  owner on the semantic defect and another on its measured bottleneck, with
  explicit disjoint ownership. Each cycle needs exact diagnosis, focused
  red/green and a native result. Reuse unchanged successful checks; run broad
  gates at integration boundaries. A repeated diagnostic needs a new question
  and a verified actual-worker observer. Frozen sources, compiler context,
  budgets and owned subprocess cleanup are mandatory during
  provenance-sensitive runs.
- Reduce repeated work without changing budgets, typed verdicts or freshness:
  synchronous factory consumers may inspect the exact just-derived result under
  the same accounting/depth/work/deadline admission; operation-local
  native/CFG/capture projections require current
  project/function/source/entry/Alias/configuration/producer bindings and
  detached copies; proof/discharge/finalization rerun; bounds remain 4
  records/256 blocks; caller work is shared only through dependent facts under
  existing proof owners with separate callsite/register/memory states.
- Measure actual work in the uncached worker: derivations/lifts/preparations,
  changed-input refusals, wall/CPU/contention/memory. Report the five
  evidence-loop counts. Overlapping test counts are never summed; diagnostic
  counters are not closed proof accounting; phase values that overlap nested
  derivations are not a disjoint whole-request profile.
- Charged-work reductions are not wall-time speedups and neither is acceptance.
  Unit-test/control counts never establish case acceptance. Supervisor-measured
  times only; before/after claims need identical source/input/context hashes on
  frozen sources.
- Preserve typed cause/function/stage/budget before fallback; refuse before
  expensive inputs when work exceeds the existing limit; owned typed contracts
  for mocks; frozen actual-case evidence for any optimization claim; exact
  source/module/load/environment/compiler/payload bindings for cross-run
  artifacts; explicit pinned runner context for execution; shared
  active-domain/depth/work/deadline admission before any producer; each phase
  retains its own premise/status so conditional/refused never merges into
  stable acceptance.
- Never clear raw refusals, lower work charges, or weaken freshness to force
  admission. Unknown raw effects remain code, never universal proof. Remove
  only demonstrably redundant verification, with measured benefit required
  before claiming speed.

## Scope and open acceptance obligations

All 36 source entries are present/retained and hash-pinned; all 16 baseline
originals compile and meet runtime contracts. These are original-only facts.
MS C 5.1 signed bitfields and automatic array initializers remain compiler
obligations; do not change sources/flags to hide them. Fresh unchanged-source
MS C 5.10 probes reproduce five C2073 initializer errors (no object) and three
C4014 bitfield warnings followed by exit 2 instead of 255. Evidence:
`.cache/msc51-original-obligation/compile-receipt.json`. No compatible spelling
or exclusion is verified. Manifests/profiles/receipts are owned by
`compiler-coverage-matrix.md`, `examples/compiler_coverage/` and
`../PROGRESS.md`. Entry capture belongs to
`tools/compiler_toolchain/capture_real16_entry.py`. Service/allocator policies
are explicit measured declarations. DOSBox and kvikdos evidence are distinct:
resolve an explicitly pinned available runner, never substitute it silently.
The prior broad pipeline was red with incomplete attribution; focused checks do
not discharge it. Recheck at integration, keeping unrelated failures separate.
Full CRT recovery is not a corpus deliverable. The existing signature filter
already excludes matched library bodies and retains application bodies. Do not
build another filter or recover CRT merely to emit application C. Calls remain
external only with authenticated ABI/effects; names/extent alone prove neither
preservation, memory effects nor termination. Unresolved required effects
block.

## Source-free conditional application boundary

Function validation may be conditional on explicit typed entry premises; all
consumers must bind the same premise. Use the existing
`--real16-declared-input` loading path and frontend admissions, not a parallel
registry or MZ-entry rewrite. Bind original MZ/relocated module/load/function
entry+extent/native digest, environment digest, known register lanes/memory
spans and near/far return frame. Omitted lanes stay unknown. Loaded code
authenticates decoding, not unchanged writable globals: baseline data requires
explicit `use_environment_memory`. Otherwise only declared spans/observed
writes supply data knowledge. Services cannot reacquire undeclared initial
IVT/metadata assumptions.

Initialized contents and address authority are separate. With environment
contents disabled, freshly authenticated environment/image ranges may authorize
reading bytes proved written by the native census. They supply no initial byte
values: absent, unknown, tainted or out-of-range writes remain unknown. The
memory owner must retain this distinction in typed contracts and descendants.
Acceptance controls require known stack-write transport without a baseline,
unchanged refusal for unwritten module data, malformed/outside ranges and stale
source/environment rejection. The first CMP16 call must transport its return
value from those native writes before another whole-case run is justified.

Replay rechecks live native bytes, source/environment/declaration and exact
artifact/boundary identity; normal bounded census proves local effects. Retain
scope through raw IR, Semantics, Alias/SSA, scoped private Clinic partitions,
segment state, validation/cache keys and persisted snapshots. Original function
CFG remains unchanged; private control projections require current
authenticated partition/context and all-or-nothing edges. Refresh consumed
scopes explicitly; foreign/changed/detached evidence refuses rather than
falling back unscoped. Identity control views require complete source-bound native CFG coverage
without unresolved control candidates or refusals. Native CALLs remain intact;
control-only admission grants no target, stack, memory or callee-effect proof.

Near-callee entry and its eventual return theorem are separate: entry-only
binding authenticates exact caller prefix/native CALL/index/callee head while
chain seed proves CS/stack/memory. Keep unfinished return candidates visible
and unconsumed; ordinary links keep existing edge checks, explicit stale edges
refuse. Never relabel caller scope as callee scope or weaken raw/final native
equality. Known effects can refine feasible edges only through source-bound
consumers; unknown/refused effects retain edges. Early and post-simulation
authentication, whole fetched-code write guards, detached scratch ledgers and
budgets stay intact. Declared interrupts consume current IVT/frame/memory
effects, including vector query/update/query; unsupported handlers/selectors/
frame aliases refuse.

Conditional C still runs final quality/recompilation/payload-integrity checks.
Its companion receipt binds exact emitted SHA256 and premise. Exit 5 /
acceptedFalse and merge hold remain; it never enters unconditional accepted
caches. Missing/damaged/different premise or failed compilation/payload binding
remains failure. Complete-case consumer requires all selected functions exactly
once at final attempts, coherent source/load/environment bindings, fresh
payload/validation/compiler hashes, and original/rebuilt runs pinned to the
same compiler context and declared observations. Missing main or arbitrary
self-signed conditional JSON cannot pass. Freeze the original
observation/expectation contract bytes independently of current proof status;
changed expectations refuse. Per-function declaration entry and range start
must equal that selected function address; differing legitimate register
domains remain allowed. Concrete native behavior stays separate from symbolic
conditions.

## Objective And Limits

Build a systematic corpus of small C examples that exposes missing decompiler
support across language constructs and compiler-emitted structures. Large
programs such as SORTDEMO and unrelated random sources combine too many causes,
make repair slow and leave coverage accidental. Existing working tiny examples
are the foundation; new examples must fill a named gap or interaction.

Use **Microsoft C 5.1 and Borland C++ 3.1**, targeting **16-bit real-mode DOS,
C mode**. Start with small model; retain the original plan's targeted large-model
near/far ABI subset without duplicating the entire corpus. Decompile without
source-assisted semantic recovery, rebuild generated C with the same compiler/
configuration, and compare behavior. Fix the small failing witnesses at their
owning layers; whole-game repairs are not prerequisites.

After the MS/Borland corpus is accepted, run the required final Watcom 11.0b
16-bit phase below. It adds a third compiler lane, not another language corpus.

Both compiler directories exist under `/home/xor/inertia_player/dos_compilers/`.
Verify exact versions, flags, target bitness and compile/link/run availability
before freezing the batch. Do not silently substitute MS C 6, another Borland
version or a 32-bit target. Borland 3.1 is a representative choice, not a claim
of measured market-share leadership. The original Wolfenstein 3D release
[documents Borland 3.0/3.1 support](https://github.com/id-Software/wolf3d).

FPU, handwritten assembly, unpacking, protected mode and Ghidra/Reko parity remain
outside this plan. No exhaustive claim over all C programs or every optimizer
output is possible. Define finite required feature/output families and selected
compiler configurations, record missing coverage and preserve regressions.

## Coverage Matrix Is The Deliverable

Reuse the original variation inventory in `examples/compiler_coverage/pilot.json`.
Its historical `admitted`/`later` lists and old compiler profile are inventory,
not a completed coverage claim or permission to leave required families untested.
Map existing tiny fixtures before writing code; freeze exact obligations and
explicit exclusions for the finite pilot, then add gap-driven examples in batches.

| Family | C inputs and interactions to inventory | Binary/output evidence to check |
| --- | --- | --- |
| Values | Byte/word/long signedness, promotions, casts, arithmetic, shifts, Boolean conditions | Extension/truncation, multiword carry/compare/shift, flags and materialized conditions |
| Storage | Scalars, arrays including multidimensional, pointer aliases, globals/static state, structs/unions/bitfields | Field layout, strides, overlapping reads/writes, partial updates and preserved neighbors |
| Calls | Direct/indirect, nested arguments, scalar/pointer/aggregate arguments and returns, variadic and bounded recursive patterns | Stack/register transport, hidden result storage where emitted, cleanup, call-live state and target recovery |
| Flow | If/else, short circuit, switch, for/while/do, nested loops, break/continue/goto/early return | Branch chains, jump tables when emitted, joins, backedges and loop-carried values |
| DOS model/ABI | Small near code/data plus targeted large far calls/data/pointer transport | Segment:offset state, near/far returns, pointer width and segment preservation |
| Optimization | Representative verified configurations on selected witnesses | Folded versus runtime expressions, strength reduction, shared expressions, register/spill changes |
| Boundaries | Matched library calls and compiler-generated helpers used by these cases | Preserved call arguments/results/effects; no silent application-function exclusion |

Track language-feature coverage separately from emitted-pattern coverage and
compiler/configuration coverage. Each required matrix cell needs an identified
small source, defined input/output contract, compiler flags/model, actual binary
mechanism, round-trip verdict and evidence location. If a switch compiles to
comparisons it covers comparisons, not a jump table. If a construct disappears
under optimization, it is not an emitted witness. Select constants/runtime inputs
and verified configurations to obtain missing patterns; do not count source text.

Use the original 32–64-source pilot as a planning budget, counting reused sources,
not a quota or guarantee that every obligation fits. Freeze the actual source and
compiler/model selection before expansion; avoid a full Cartesian product.
If coverage cannot fit, report the exact missing cells and proposed budget/scope
change. Do not mark them covered, silently remove them or replace difficult cases.
Csmith supplies bounded interaction discovery; it cannot replace this matrix.

For a failure found in a large program, extract a small defined-behavior witness
for the missing construct/interaction. Confirm it reproduces the same semantic
failure before using it as the regression. Preserve the original failure as
evidence, but do not make whole-SORTDEMO repair the development loop.

## First Batch To Freeze (Not Full Coverage)

| Source ID | Required behavior | Configurations |
| --- | --- | --- |
| word_comparisons | Existing `compare16.c`: signed/unsigned comparisons, extreme values and unsigned wrap | MS C 5.1 small; Borland 3.1 small |
| array_pointer_writes | Existing `pointer_memory.c`: indexed writes, same-object alias, overlapping copies and pointer returns | Same two |
| branches_loops | Existing `simple_control.c`: conditions, loop-carried state and grouped switch cases/default | Same two |
| call_composition | Existing `function_pointers.c`: direct/indirect calls and nested arguments live across calls | Same two |
| struct_value_abi | Small mixed-width struct passed and returned by value, assigned to another object; check fields and unchanged caller input | Same two |
| bitfield_neighbors | Adjacent unsigned-int bitfields: assign/update one field while preserving neighbors and an ordinary member | Same two |
| multidim_alias | Small two-dimensional array passed as pointer-to-row; variable row/column indexing and same-array alias store/readback | Same two |
| csmith_seed2 | Pinned generated interactions with observable checksum/state | Same two |

Explicit scope revision following the user's existing-tiny-test correction:
four existing regression sources + three directed gap probes + one Csmith source
= eight sources, sixteen compiler/case pairs. The old five-source proposal was
not executed or frozen; no failed case is removed by this revision. Report the
subtotals separately: baseline N/8, directed additions N/6, Csmith N/2. Historical
tiny successes are useful regression evidence, not new-construction progress.

The three additions come from the original plan's structure ABI, bitfield and
multidimensional-array obligations. Direct inspection of `msc6_constructs/`
found ordinary struct-pointer access, scalar mixed-width arithmetic, globals,
loops and callbacks already represented; do not duplicate those as new coverage.
Before creating files, check existing fixture/runner mappings for an equivalent
probe and reuse it if present. Keep each addition to one interaction and 1–3
application functions, with a tiny deterministic input set.

For struct ABI, compare named fields, not padding; do not prescribe a hidden
return-pointer convention—the binary establishes it. For bitfields, use explicit
`unsigned int`, in-range values and a compiler probe for layout; never assume
matching packing across compilers. Each rebuilt binary is compared with its own
compiler's original. For multidimensional arrays, keep accesses within bounds,
use correct pointer-to-array types, and require both aliasing and disjoint cases.
Add matching negative controls: corrupt a returned struct field, clear a neighbor
bitfield, or change a row stride/store destination; each must be detected.
Other inventory items enter subsequent explicitly frozen coverage batches;
their admission and completion must be visible in the matrix.

These four sources already live in `examples/msc6_constructs/` and are selected
by `examples/compiler_coverage/pilot.json`; reuse their existing IDs, bodies and
checks. Do not create four equivalent new fixtures or a second runner. The old
pilot profile is MS C 6 small (`/Od /AS`), not evidence of MS C 5.1/Borland
acceptance. Add separate compiler profiles without overwriting historical ones.

The existing MS tiny-model lane and `examples/build_msc6_tiny/` remain useful
baseline evidence. Reuse source/runner infrastructure, but rebuild under each
new small-model compiler profile: tiny and small have different image/segment
contracts. Neither old tiny results nor existing build files establish new passes.
Preserve existing success exit255 instead of imposing the Csmith exit0 convention.

Freeze source hashes, inputs, observations and emitted-mechanism evidence before
repairs. Existing sources may contain more than three application functions;
keep all reachable application bodies and checks rather than splitting them
or dropping indirect calls to meet an artificial size limit. Use 1–3 functions
as a guideline only for genuinely missing new probes. Keep arrays/loops bounded.
An optimized-away construct is not a binary witness. Undefined
behavior, uninitialized/padding bytes and host-integer assumptions are not oracles.

Retain Csmith seed **2**, user fork branch `ms-c-dos`, revision
`35e702de01e158bc948a2024d0e187c1803d1ebb`, exact build/options and generated C.
Historical generated-source SHA-256:
`353845463705795ea0822c0ecaf5f956828405507d956d661e2fa124a4d66939`.
Verify retained artifacts; do not invent fresh equivalent evidence. Preserve
original failures when minimizing. Never replace a failing admitted seed or
source with an easier one, or drop a compiler to obtain a green denominator.

### Source-Informed Construct Selection

Bounded source review, 2026-10-06: the following two external reconstructed
compiler files informed the four directed cases. They are patched Hex-Rays
output with guessed types and host-x86-32 conventions, not original C source,
correctness oracles or proof of what the older DOS compilers will emit.

- Borland source: `/home/xor/inertia_player/dos_compilers/Borland C++ v5.02/BC5/BIN/rebuild/gen/BCC.c`.
  `fold_compare` (line 28521) branches on type/range/signedness;
  `make_bool` (line 28445) constructs explicit truth comparisons;
  `parse_decl_specifiers` (line 11949) combines repeated dispatch, grouped cases
  and short-circuit conditions. These inform the existing comparison/control cases.
- Microsoft source: `/home/xor/inertia_player/dos_compilers/Microsoft C v8/BIN/rebuild/gen/Q23.c`.
  `nibble_set` (line 3985) performs read/modify/write with masks and shifts;
  `page_cell_ref`/`page_cell_get` (lines 3911/3947) combine traversal
  and indexed fields; `rd_rec` (line 2139) copies words through an output pointer;
  `hash_walk_buckets` (line 3703) keeps traversal state live across a callback.
  These motivate masked updates, record/alias addressing and call-live state.

First map these patterns onto the existing fixtures. Additional nearby examples
already include `mixwidth.c`, `compare32.c`, `loops_jumps.c` and
`medium_structs.c`; consult them before adding code. Masks/nibble writes, mixed
widths and record fields are gap candidates, not automatic batch expansion.
Propose any missing-obligation extension before source freeze; preserve existing
checks and the first batch's eight-source/two-compiler denominator. Missing
required cells belong in the next declared batch, not silent changes to this one.
For a genuinely missing probe, write clean C89; do not copy raw casts,
numeric compiler opcodes, LOBYTE/LOWORD pseudo-assignments, guessed uninitialized
locals, calling-convention artifacts or suspicious pointer arithmetic. Use
unsigned operands for shifts, counts below width, and in-range signed arithmetic.
Exercise byte boundaries 127/128/255 and word boundaries 32767/32768/65535 via
appropriate typed inputs; check unsigned long carry across 65535 without signed
overflow. Do not assume
plain-char signedness or negative right-shift behavior is portable. Preserve
mask neighbors and alias readback as explicit observations, not only checksums.

Use runtime inputs to keep the target operation present, then inspect emitted
binary/IR evidence. Source presence alone is insufficient. The inspected BCC
folding/CSE machinery reinforces that rule; it is not a reason to add a compiler
exhaustive optimization matrix. Keep this batch's sixteen-case denominator and
existing bounds; later targeted configurations must fill a recorded output gap.
The existing `function_pointers.c` callback checks stay in call_composition;
do not defer or delete behavior already present in the selected source.
Additional C callback/recursion witnesses come from the coverage matrix, not a
port of these compilers. Their paged allocator, C++ types/exceptions and FPU do
not become mandatory implementations by appearing in these reference sources.

## Acceptance For Each Round Trip

`C → compile/link → original EXE → decompile → generated C → rebuilt EXE → compare`

1. Original compiles and executes under the frozen contract. Source expectations
   separately check compiler/harness correctness.
2. Every selected non-library application function is accounted for and emitted.
   Source/COD/listings cannot supply semantic answers or repair recovered bodies,
   arguments or types. Optional names/bounds remain diagnostic evidence only.
3. Semantic validation passes; required calls and value/pointer arguments survive.
   Generated C rebuilds without manual semantic repair or deletion of live code.
   Existing function-fix and tail-validation contracts remain in force.
4. Original/rebuilt termination, returns, output/checksum and declared memory
   observations match on frozen boundary/alias/branch inputs.
5. Reports separate symbolic validation from concrete execution. A checksum match
   is not all-input equivalence. Unknown/refusal/timeout never becomes success.
   Every frozen batch row remains accounted for, including blocked/failed rows;
   the first batch has sixteen.

Deliberately corrupt return, store and branch behavior on both compiler lanes;
the comparator/harness must detect each mutation. These negative controls
supplement the sixteen positive round trips and are mandatory acceptance evidence.

### Csmith Runtime Boundary

The historical seed-2 build emitted two application functions plus 67 runtime
helpers: `--max-funcs 1` did not bound linked runtime size. Establish this boundary
before another campaign. Use verified binary-signature matching, retain library
call ABI/effects and record matched addresses/provenance. No name-only exclusions
or source-membership shortcuts. Unmatched bodies remain accounted for and must
be analyzed or reported as blocking. Only dependencies of the frozen cases are
in scope; this is not a universal runtime-library recovery project.

## Execution And Completion

| Step | Required deliverable |
| --- | --- |
| 1. Probe and map | Both compiler probes; exact flags/libraries/backend/models; map existing tiny fixtures to required input/output obligations and freeze the finite coverage matrix |
| 2a. Freeze first batch | Sixteen-row manifest with sources, inputs, observations and budgets; record which matrix cells it does and does not cover |
| 2. Run the baseline | All sixteen attempted once; original/generated/rebuilt artifacts where available; typed per-stage failures/timings; corruption controls and timeout cleanup verified |
| 3. Repair one failure family | Retained reproducer, owning-layer fix, focused red/green, scoped lint/types and affected neighbors; rerun affected frozen cases without weakening acceptance |
| 4. Accept the batch | All sixteen complete round trips pass; negative controls detect corruption; reproducible rerun evidence and affected regressions pass; publish exclusions |
| 5. Fill named gaps | Subsequent small frozen batches from the matrix, reusing fixtures and adding only missing mechanisms/interactions; targeted large-model and configuration witnesses |
| 6. Accept MS/Borland corpus | Every required matrix cell has an accepted emitted witness under its selected MS/Borland configurations; all admitted cases and negative controls pass; missing/excluded cells and limits published |
| 7. Validate Watcom 16-bit | Reuse the corpus with installed Watcom 11.0b; prove its compiler/runtime profile, preserve independent ABI/layout evidence and pass the same applicable round-trip and corruption obligations |

Reuse `tools/compiler_toolchain/build_msc6_examples.py`, the compiler-coverage suite/manifest and
Csmith adapters. Extend their compiler boundary rather than build a second
pipeline. Existing `compiler-coverage-csmith` is a starting point, not evidence
of support for both requested compilers. Deliver documented commands for the
batch, compiler/case selection and failed-case reruns. Keep durable manifests,
fixtures and regressions in the repository; raw run artifacts in fresh directories.

Freeze stage/case/batch wall and memory limits before baseline. The existing Make
case default is 600 seconds; inspect actual limits and do not increase them to
turn failures green. Record source/toolchain/runtime/options/environment and
implementation identities. Reuse unchanged evidence only when relevant inputs
match; do not repeat the entire batch for documentation or unrelated edits.
Run Python/pytest at nice 10 with `PYTHON_JIT=1`, deterministic seeds and at most
six aggregate test workers. Begin external round trips serially; increase only
with measured resource evidence, at most two heavy jobs. Timeouts must stop owned
descendants and preserve partial artifacts. No endless seed campaigns.

Focused regression and changed-file lint are the development loop. Frozen-case
round trips and affected shared-owner tests are integration checks. Broad release/
PR gates are separate: record unrelated failures without making them milestone
blockers. Regressions caused by this work remain blockers. KVM-backed DOS execution
tests carry `requires_kvm`; static/Z3 tests do not. Missing execution is blocked
evidence, never an accepted case or permission to silently substitute backends.

**Runner operational** means batches execute with complete failure accounting
and passing corruption/timeout controls. **First batch accepted** means its
sixteen round trips pass. **Plan complete** means the required finite coverage
matrix and all admitted batch cases are accepted, including emitted-mechanism
witnesses and the final Watcom lane, not merely the initial sixteen results.
MS/Borland acceptance is a separate checkpoint and is not postponed by starting
Watcom early. Unit-test counts establish
none of these on their own. Report covered/required cells separately for language,
output and compiler/model configuration; also accepted cases per batch, exact
blocking families, next bounded action, time and peak memory.

Historical results are not automatically current acceptance. If a blocker
requires a substantial new subsystem, report the concrete dependency and leave
its case open; do not silently expand or weaken the plan. Large-program repair
queues and unrelated gates stay separate. Required missing constructs remain
visible obligations even when a simpler smoke batch passes.

## Staged Analysis: Raw Facts Before Deep Proof

Use existing source-bound raw intake, invocation census and scoped discharge.
Raw pending artifacts never enter the universal proven-function registry.

1. **Collect:** decode/lift exact source-bound instruction/effect facts once per
   analysis context; retain unresolved edges/typed reasons. Raw boot intake binds
   authenticated MZ state, project/artifact/boundary and current byte evidence.
2. **Propagate:** local SSA/Alias/control facts before recursive caller demands;
   deterministic dependency order, revisit only changed proof inputs, separate
   unknown/proven facts and retain the five evidence-loop counts.
3. **Close:** fixed point or existing request budget; deeper proofs only for
   required unresolved dependencies. Full source/evidence context, never address
   alone, governs any allowed reuse. Exhaustion stays unresolved.

Initial CS does not prove preservation. Census live calls/stores/interrupts/
selectors. Do not fabricate complete coverage, delete unknown edges, create a
parallel scheduler or renew budgets on identical retries. Native/decoded/image
bytes must agree. Both ordinary/raw imports stop lifts and finishing on expiry;
partial collected blocks remain diagnostics. Changes must reject foreign source/
artifact/boundary, unsupported selector/effects and code-writing stores. Retain
the selector-wrap leaf control: no calls does not authorize skipping entry proof.
Measure imports/dependency retries/time/memory on the frozen actual case.

## Final Phase: Watcom C/C++ 11.0b, 16-bit DOS

Selected installation:
`/home/xor/inertia_player/dos_compilers/Watcom C++ v11b/`.
This is the preferred installed candidate because it provides the 11.0 B-level
fixes and the 16-bit C compiler, linker and DOS runtimes together. This is a
selection rationale, not an assertion that it is fastest or universally best.
Local inspection found `binw/wcc.exe`, `binw/wcl.exe`, `binw/wlink.exe`, and
`lib286/dos/clibs.lib`/`clibl.lib`. The installation's `readme.txt` identifies
`wcc` as the 16-bit x86 C compiler and `wcc386` as the 32-bit compiler. No live
compile/link/run probe has yet established usability in the current environment.

1. Start only after the MS/Borland corpus checkpoint. Pin compiler/linker/library
   hashes, actual version, host runner, target, flags and environment. Use WCC
   (or WCL driving WCC), explicitly targeting 16-bit real-mode DOS. Do not use
   WCC386, DOS/4GW or a 32-bit extender. Compiler-host bitness is not target
   bitness: verify actual emitted objects and linked executable behavior.
2. Compile/link/run a small-model probe, then reuse the eight starter sources
   as eight additional Watcom round trips. Extend to the same admitted corpus
   and targeted large-model witnesses through frozen selections. Keep existing
   MS/Borland receipts and denominators unchanged; report Watcom separately.
3. Probe and record actual argument registers/stack use, preserved registers,
   multiword returns, struct return transport, near/far control and packing.
   Preserve the selected Watcom ABI instead of forcing every case to MS-style
   cdecl merely to avoid a decompiler limitation. Additional ABI options need a
   named coverage obligation, not an exhaustive configuration matrix. The
   [Open Watcom guide](https://open-watcom.github.io/open-watcom-1.9/cguide.html)
   is supplemental documentation; installed 11.0b binaries/probes determine
   this lane's exact behavior.
4. Compare each Watcom original with its own rebuilt output. Across compilers,
   compare only explicitly portable source observations; do not demand identical
   assembly, layout, padding, checksums over representations or calling conventions.
   Account for compiler-specific helpers with the same library boundary rules.
5. Acceptance requires every applicable admitted Watcom case, emitted-pattern
   witness and negative control to pass at the frozen budgets. Compiler errors,
   unsupported ABI recovery and runtime failures remain explicit open cases;
   they are not success or permission to silently drop a difficult construct.
   Fix only defects exposed by this lane and their affected regressions. Reuse
   unchanged primary-lane evidence; rerun relevant checks for shared-owner edits.

No further compiler release is added automatically. Watcom adds portability and
ABI/code-generation diversity to the same systematic small-example corpus;
it does not reopen whole-game repair or unrelated repository-wide gate work.
