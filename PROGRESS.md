- dosunit ABI-compose exponential fix (ongoing): `_merge_abi_states` used plain `==` on shared SSA term DAGs — O(root-to-leaf paths), the true cause of the multi-hour s0–s2 batch stalls (MemoryError was a symptom). New `_abi_terms_equal` memoizes on (id,id) pairs (O(DAG nodes)); compared roots pinned for cache validity; provisional entries rewind on mismatch/deadline. Deadline checks now inside `_compose_block_outputs`/`_merge_abi_states`/`_abi_terms_equal` loops (was per-block only → minutes of overshoot). Verified: stalled s0/s1/s2 batch-1 docs compose in 4s/28s/101s; `de_doit`/`check_user` refuse `compose_budget_exceeded` at 90s. Committed 204cdb1fb. 205 tests pass, 4 pre-existing fails. Full-corpus shards relaunched with `--resume` (run_shards.sh reboot-safe); s3 backfilled `oracle_ssa` tags so its 3 completed batches resume-skip; s0–s2 re-running timed-out batches.

- decompiler_postprocess_calls.py flatten+split (ongoing): mega `_materialize_callsite_stack_arguments_8616` dissolved into `_CallsiteStackArgsMaterializer8616` class via scope-aware AST transform; all nested `_impl` wrappers flattened to module fns (closure vars as kw-only params, binding-site dominance safety); manual phase splits for prune_consumed_segmented_stack_byte_arg_stores (94->0), ordered_callsite_pairs (79->0), attach_callsite_summaries (31->0), refresh_callsite_summary_node_ids (33->0), apply_callsite_summary_to_node (27->0), callsite seed/prototype paths; promoted findings 153->98; owning tests 178+2 pre-existing verified per batch.

# Progress

## 2026-09-29 — direct-call DS=SS proof completion guard

The nonpublishing IR proof now exposes `complete` only for closed five-stage
counters, exact SS-save/DS-restore roles, and ordered addresses within the
CALL block. Its producer refuses to return an internally incomplete PROVEN
record; diagnostics project the same completion result. A new regression was
red before implementation; the final three-worker direct-call cohort passes
42 tests, and the changed-file gate passes. This is a prerequisite for a safe
callee-entry relation, not publication of that relation. `/dev/kvm` is absent
in this session, so no new native pointer round trip is claimed. The first
`quality-dev` attempt stopped in mypyc's pyvex import because host `/tmp` was
unwritable. With `TMPDIR` under this workspace, static checks and 296 contract
tests passed; the fast pipeline ended red with 8,157 passed, 31 failed, one
skipped. Saved diagnostics include missing `/dev/kvm`, a source-drift runtime
guard, and still-unresolved semantic failures. This is not broad acceptance.

## 2026-09-29 — source-free COD empty-helper oracle

The routine gate's `_dos_setProcessId` signature assertion demanded an unused
`pid` solely from COD source annotation. Its machine body never reads BP+4 and
the fixture contains no caller, so that parameter is not binary-recoverable.
The oracle now requires the evidence-supported empty signature while retaining
the no-raw-stack-parameter and empty-body checks. Focused red: one failed, one
passed; green: two passed with three pytest workers. Scoped Ruff and diff-check
pass. This removes one stale gate failure, not a semantic `select_word` fix or
green whole pipeline.

## 2026-09-29 — compiler coverage gate and selected pointer replay

The previous quality-dev finished red (8,174 passed, nine failed). Parent fixes
its binary-lane inventory assertion and a sanitizer oracle that previously let
host loader failure satisfy nine negative controls. Focused three-worker checks
pass66; no full gate rerun is claimed. A fresh stable KVM pointer round trip now
shows exact remaining `select_word` blocker: tail-passed C returns `short*` but
adds bytes to a `void*` input, rejected by MS C C2147. Details and required
typed publication boundary are recorded at the top of the compiler coverage
ledger. Steps1–5 remain open.

## 2026-09-29 — bounded CLI traversal optimization

Class-layout caching and direct-child traversal pass54focused tests with3workers;
saved-baseline controls fail as intended. Four balanced source-free/KVM runs
produce identical C and tail-passed results; mean analysis CPU is14.2% lower on
one measured function (wall timings remain noisy, not a corpus speedup claim).
Details: `.cache/devin-reports/cli-ast-traversal-20260929/PARENT-REVIEW.md`.
InBox oracle/Make concurrency acceptance also closes with36focused tests passing.
Global compiler-coverage obligations and broad gates remain incomplete.

## 2026-09-29 — reviewed logical PUSH transport integrated

The parent integrated the staged transport after the owned gate coordinator
terminated. All six existing source/test files matched their saved dirty
baselines beforehand; all seven integrated files exactly match the reviewed
stage afterward. SSA PUSH roots survive the physical-byte definitions and bind
to the exact caller, callee, CALL, logical argument and byte piece. Invalid
present transport refuses; absent legacy transport is not whole-value proof.
DEFAULTED segment provenance is unchanged. No native pointer, pointee, body or
caller publication is inferred. Independent staged evidence remains five red
regressions followed by 30 focused and 69 neighboring passes. The new owner is
enrolled in normal lint/type, architecture promotion and test ownership gates.
Shared-tree changed-file checker59045 ends0:748passed/7warnings206.52s.
Scoped Ruff/MyPy/Pyright, changed-file type/dot/doc ratchets, startup architecture,
context and ownership checks pass. All seven reviewed source/test files retain
their exact staged bytes afterward. The preceding checker94804 fails only eight
GNU Make stdin-oracle tests because system temp is read-only; the same selected
checks pass with TMPDIR inside the repository. No test/assertion/source change
is used to obtain that pass. Both logs remain available.

Pre-integration quality-dev ends2 in2056.393s, with296 contract passes and
7936 unit passes/17 failures. Default test-pipeline ends2 in3445.845s:7937 unit
passes/16 failures,49 binary-relational passes/one failure, and four failed
pipeline lanes overall. Source, changed-test/config and runtime identities are
unchanged in both phases; failures remain unwaived. These are not post-integration
gate results. A separate staged real-binary observation times out at95s without
collected evidence; it is not a semantic regression or acceptance result.
Post-integration owned-Python identity is1240files/20902360bytes,
de9ac2b964b0ca946157262f58314740f5db4bbe77395376762400edeebd48cc.
Next: exact source-pointer/segment binding and coherent return/body/caller
projection, then native pointer replay. Broad post-change gates and all plan
acceptance remain open; this checkpoint is proof transport, not a function fix.
Artifacts: .cache/devin-reports/whole-push-retention-20260929/ and
.cache/devin-reports/rep-kernel-symbol-binding-20260929/.

## 2026-09-29 — ordinary REP wrapping passes; symbol-bound oracle strengthened

No deadline was changed. The unfiltered normal replay resolves the previous
timeout-only wrapping results: forward wrapping passes; backward wrapping exposes
a harness name assumption, not a memory failure. Optional binary labels name
the selected function differently. The harness now binds the sole public
procedure from compiled ELF symbol metadata; it never parses/changes generated
C or uses names as semantic proof. Multiple public procedures refuse. Saved-dirty
controls fail2 before; all9positive/label/corruption/refusal controls pass after.
Scoped Ruff/Pyright pass. The existing routine enrollment and strict GCC/memory/
return/high-EDI checks remain intact.

Final normal run23516 ends1:16passed/3failed/7warnings91.85s. All seven ordinary
kernel cases, including forward/backward effective-address wrap, pass. Three
original deliberate segment-straddle cases still fail memory behavior despite
passed tail validation. They remain visible and unaccepted; no global/function-
fixed or compiler-witness claim follows. The earlier timeout runs remain retained.
Cold versus shared PAT-spec diagnostic cache conditions are explicitly recorded;
no speedup/timeout cause is claimed from them. Reports/raw artifacts:
.cache/devin-reports/rep-kernel-symbol-binding-20260929/ and
.cache/devin-reports/rep-wrap-profile-20260929/.

The other session's broad gate is terminal, not an owned acceptance run. Owned
required gates are being started sequentially with verified KVM and stable-source
checks. Live production will remain frozen during those checks. The bounded
read-only Devin pointer-root map ends124 without REPORT.md; partial source-map
claims are not accepted until independent parent source review.

## 2026-09-29 — loop-header FLAGS liveness repaired; REP acceptance partial

Typed lift/SSA independently retains CLD/STD effects and the REP FLAGS read.
Two cleanup censuses omitted for-loop headers; the FLAGS census also confused
a shared variable's write occurrence with its read. Both now consume the
canonical structured syntax schema. DCE accounts for initializer/iterator RHS
and address reads as statements, without treating plain destinations as reads.
No semantic recovery, signature/body rewriting or refusal/validation weakening
is introduced. Parent saved-dirty red controls fail5 and2 respectively; all135
final neighboring cleanup/liveness tests and six memory-oracle controls pass.

Verified KVM transport run8881 ends1 with145passed/1failed/7warnings483.43s.
Forward F3/F2 count3 and forward/backward count0 pass CLI/tail/GCC and unchanged
full-memory/return/high-EDI checks. Ordinary F2 backward count3 hits the existing
decompiler deadline and leaves tail validation uncollected; it is not accepted.
The two added ordinary effective-address-wrap cases separately end as typed
timeouts (2failed/7warnings164.10s). The first cohort's selector excluded them;
no wrapping coverage is inferred from its145passes. All original segment-edge
cases, oracles and deadlines remain intact. Bounded ordinary-backward retry86043
ends0 with1passed/7warnings146.86s (call81.81s), including tail/GCC/full-memory
checks. The original timeout and both wrapping timeouts remain recorded; no
deterministic replay or fully green cohort is claimed. No owned job remains live.

Scoped Ruff and owner/test Pyright pass. DCE strict MyPy passes; FLAGS retains
exactly two imported-boundary findings independently reproduced on its saved
dirty baseline, not a globally clean typing claim. Another session's broad
quality-dev is live; it is not an owned result or permission to overlap gates.
Required final-source pipeline/quality checks, function acceptance and compiler
pilot/Csmith obligations remain open. Report and raw artifacts:
.cache/devin-reports/rep-flags-header-20260929/.

The independent read-only Devin timeout job ends124 without REPORT.md. Its four
source owners compare unchanged against saved dirty baselines. An unrequested
ignored control script and unverified partial claims are not integrated; the
actual InBoxLng lifecycle failure remains unresolved. Parent review:
.cache/devin-reports/inbox-timeout-lifecycle-20260929/REVIEW.md.

## 2026-09-29 — near-return operand preflight reviewed; global acceptance red

The bounded staged worker ended124 without a verified test/lint handoff. Parent
compares its source mirror to the live dirty tree: only the assigned new owner
is an additional production file. Independent staged controls pass15tests. Nine
new parent controls expose unsafe raw/unified variable binding, detached result
fields, modularly reduced C shift counts, and an incomplete codegen boundary.
After correction all25controls pass; the neighboring proof, Make, pipeline and
ownership family passes182tests/7warnings106.76s. Scoped Ruff, production-owner
strict MyPy and owner/test Pyright pass; an initial test Pyright annotation error
is fixed. Strict MyPy on pytest-decorated tests reports two untyped-decorator
errors; no strict-all-tests claim is made. Routine Make, pipeline, ownership and
the architectural map now enroll and document the new nonpublishing owner.

This proves exact numeric operand congruence to retained IR, not a publishable
pointer expression, DS=SS, source/result segment binding, or a function fix.
Accepted/refused counts remain1/1/1/1/0 and1/1/1/0/1 for a classified mismatch;
unknown operands keep the original code. Fresh source-free observations retain
two actual result uses: SS at call0x102c8 and DS at call0x102e6. The census's input
storage is still two DEFAULTED bytes per logical word, not new segment proof.
A fresh private metadata-only diagnostic attempts whole PUSH-root and C/IR
binding observation. It ends3/timeout after82.355s, unchanged implementation,
no exception, zero publication hooks. This is not evidence that roots/bindings
are absent; it supplies no new accepted observation or normal validation.

The preceding quality-dev62378 is terminal2, not still running: static/startup
checks and296local tests passed; the full fast unit lane has18failed/7859passed/
20warnings1542.20s. Six, not seven, failures are REP-store host behavior despite
reported tail validation. No causal/baseline waiver or green full gate is claimed.
Default/external lanes did not run in that fast gate. A separately sandboxed,
4GiB, read-only Devin job ends124 investigating the REP family, without a final
report. Its partial lift claims still require independent parent reproduction.
Required final gates and all compiler pilot/Csmith/function witnesses remain open.
Reports: .cache/devin-reports/near-return-congruence-20260929/ and the retained
near-return-address-binding-20260929/quality-dev-repaired.log.

## 2026-09-28 — reviewed bounds and generation comparison integrated

The saved dirty owners were rechecked before integration. CLI bounds now use
absolute inclusive max_addr once, and object-memory reads use relative spans.
Live controls pass58tests; two ranked-backend controls pass separately. Parent
strictly maps all55Pyright findings to the saved baseline with no changed-range
findings; this is debt parity, not globally clean typing. A redundant cast found
by live MyPy was removed without changing backend selection; scoped static,
startup, context and ownership checks then pass. New tests have routine Make,
pipeline and ownership enrollment.

The equality correction uses iterative request-local comparison only for exact
built-in values. A further parent control catches Python3.14's direct dataclass
field protocol: wrapping all fields in one tuple skipped shared scalar methods.
The final code preserves same-instance identity and field-by-field order. Both
new shared-scalar controls fail before; all15final controls pass, with scoped
Ruff/Pyright clean. The broader376-test family has one inherited switch-delta
failure, independently reproduced on both saved and staged sources. No return
delta is suppressed to make it green; the legacy shape-only predicate is not
expanded with a new textual prefix.

Normal source-free select_word replay10280 is terminal0: tail passed, emitted C,
36.493s, implementation unchanged, no profile/thread hooks. Function/recovery
caches begin empty; only matching signature metadata is retained. The entirely
cold metadata run reaches outer timeout124 and is not a comparable timing run.
The emitted signature still carries integer offsets rather than source pointer
types, so full source shape/call-class/round-trip acceptance remains open.
No function or feature witness is admitted and no isolated speedup is claimed.

The actual array_pointer_writes round trip57283 is running at its unchanged600s
case budget. Tracked Python stays frozen until it ends. Devin88647 stages only
four narrow loader-read exception boundaries and focused controls in ignored
copies; unexpected defects must propagate, genuine KeyError remains no evidence.
All required broad gates and remaining compiler obligations stay unwaived.

## 2026-09-28 — required checkpoint gates terminal; acceptance remains red

Coordinator34598 is terminal1, observed19:03–19:04UTC. Its sequential default
test-pipeline returns2 after4659.67s; the owned-Python fingerprint is unchanged
through that run. The unit phase is incomplete:4failed/2397passed/19warnings,
then xdist KeyError(gw8). External lanes also report decompiler/behavior failure.
The earlier quality-dev returns2 with29failed/7516passed and source churn.
Neither gate is green, and neither is waived. Read-only Devin is investigating
the initial worker exits separately from the subsequent scheduler error.

Independent saved-source image controls fail6/6 before the staged correction;
the candidate plus neighboring controls pass56tests/7warnings145.97s.
Pyright reports55findings in the two staged CLI owners; baseline parity is
being checked separately, so inheritance is not yet established. Both image
and generation corrections remain staged, not live decompiler acceptance.

## 2026-09-28 — changed-surface gate fails; shared source churn detected

Coordinator34598's quality-dev is terminal2, observed17:46:20UTC, elapsed
3598.755s. Static/startup/contracts stages pass; the unit subprocess reports
29failed/7516passed/20warnings3193.35s, then an xdist scheduler internal error
KeyError for WorkerController gw8. This is a partial failed run, not a complete
green suite; it supplies no final detailed failing-test inventory.
The owned-Python fingerprint changes during the run (same1237files, +2267bytes),
so patch attribution/stable acceptance is unavailable. The coordinator has
started the required default pipeline sequentially; its result is pending.

Parent independently compares all eleven image/generation proposal owners to
their saved dirty baselines: unchanged. Modification-time candidates are other
register/affine tests and the pipeline/ownership scripts. Without a complete
pre-run per-file baseline, this is not proof of the exact causal delta. Preserve
those concurrent edits and all failures; do not weaken the identity guard or
restart the still-live default run. Both Devin corrections remain staged only.

## 2026-09-28 — generation comparison cost independently reproduced

Read-only Devin11742 is terminal0. Parent compares the three dirty owners, reads
its probe and independently measures legal shared atom DAGs: equality36->44
unique atom nodes costs0.135285->1.147047CPU seconds; one-key mapping31->39
nodes costs0.056121->1.498831CPU seconds. Exact source confirms tuple comparison
and full repr sorting expand shared paths. Cache-key and optimization-witness
consumers use generation equality. This verifies component cost, not a real
POINT hotspot or end-to-end timeout cause. Parent17692 independently passes
equal/unequal atom/dataclass and cycle-marker controls; no semantic rule changes.

Parent rejects digest-only equality, cross-request interning and changed
canonical order. Devin75876 stages an exact request-local tuple-pair comparator
and zero/one-item sorting shortcut, preserving every generation field and hash/
dictionary-key behavior. Devin52383's separate image-boundary proposal remains
under focused validation. Both own ignored copies only; no live integration.
Broad34598 remains active and reports test-worker exits plus ordinary failures.
The two exited workers have status1, CPU limits are unlimited and the checked
cgroup reports no OOM kills or throttling; cause is not classified. Required
gates and all compiler/function/witness acceptance remain open.

## 2026-09-28 — live image-boundary defect confirmed; correction staged

Read-only Devin2519 is terminal0. Parent independently compares its four dirty
owners and reruns the live MZ probe: linked/mapped base0x10000, absolute inclusive
max_addr0x10c1a and relative backed span[0,0xc1b) imply exclusive end0x10c1b.
Nine discovery projections instead produce0x20c1b. The public loader property
is authoritative; internal Backend/Blob _max_addr conventions differ.
The bounded source review also finds four object-memory read counts using
absolute addresses and an isolated-target heuristic supporting contradictory
relative test doubles. This is a projection defect, not timeout causality.
The address-domain contract is now documented in the decompiler map.

Devin52383 stages corrections and focused tests only in ignored copies while
coordinator34598 keeps tracked Python frozen. Separate read-only Devin11742
measures shared-DAG normalization/equality costs without a full decompile or
production patch. Both workers' live address-space limits are independently
checked at4GiB; reports remain pending. No function, speedup or feature witness
is accepted. Required broad gates are still running.

## 2026-09-28 — actual pointer retry times out; required gates running

The post-TMP routine pointer case88403 is terminal2. Original compilation and
execution pass, but all five normal source-free functions return timeout3;
the outer case is timed_out, without a completed recompilation/behavior report.
Source and implementation identities remain unchanged. Compiler readiness is
not decompiler acceptance; no function or feature witness is admitted.

Normal fork-worker diagnostics confirm actual analysis executes: sampled stacks
include IR SSA construction, tail-generation fingerprints and Capstone-backed
stack-write inventory. This is not evidence of an IPC deadlock or a measured
cumulative CPU hotspot. The separate CPU-profile worker enters, then times out
without producing its snapshot; an empty profile does not establish absence.

Required quality-dev and default test-pipeline are running sequentially in
coordinator34598, observed started16:45:07UTC, with verified KVM, four external
workers and frozen Python sources. Results remain pending. Read-only Devin2519
checks loader/image-extent coordinate contracts; it owns no tracked-source
edits. Broad failures and all remaining compiler obligations stay unwaived.

## 2026-09-28 — MS C6 DOS temporary storage restored; routine retry pending

The unchanged routine pointer case failed before decompilation with compiler
C1043 and missing-object LINK L1093. A controlled identical-source compile
with only DOS TMP=C:\\ added exits0 in0.85s. Parent reviewed Devin17536's exact
dirty-source delta: only that override/comment in both source and runtime
compiler commands, plus a new focused test. Flags, mounts, linker and all
semantic/evidence gates remain unchanged. Four independent saved-source argv
controls fail before; the final eight delivered/independent controls pass.
New coverage has Make/contracts, fast-pipeline and ownership enrollment.
Final gate62270 is terminal0, observed16:32:45UTC: scoped static/ratchet/startup/
context/ownership checks pass;143tests pass/12warnings117.62s. The routine
pointer retry now uses a new artifact namespace, verified KVM and unchanged
budgets. This is toolchain readiness, not a decompiler function/witness fix.

Fresh normal select_word replay10747 is terminal3: implementation unchanged,
empty function/recovery caches, retained immutable signature metadata, no
profile hooks or forced thread mode. Discovery~79.78s leaves1s for the worker;
the60s budget is exhausted and tail validation is uncollected. The earlier
profile/thread success is not normal-lane or performance acceptance.

Read-only Devin39250 classified the retained eight REP cases: exit4 precedes
the test's compiled-memory oracle; DCE refusals are restored and the display
validation field is forced for non-OK fallback results. Parent rejects a
universal no-compiler/KVM inference because internal acceptance can compile.
The fresh bounded first-case replay46081 exits3 timeout instead, so the older
stdout blocker remains unresolved. No causal attribution, gate waiver or
semantic patch follows. Required broader gates and all compiler obligations
remain open.

## 2026-09-28 — scoped KVM/compiler checkpoint; far-control oracles strengthened

Parent reviewed Devin's repository-only launcher against saved dirty sources.
Its initial proposal failed six independent refusal controls; canonical exact
repository binding, early scope validation and empty-command refusal now pass.
The launcher retains hostRO/repoRW, private proc/dev and4GiB. Optional KVM uses
a Python-opened descriptor verified as character10:232/API12; the child reports
the same device/API. Default launches expose no host KVM. No host policy or
device-node change follows. Both live boundaries and32focused controls pass.

The actual MS C5.1 compiler then exposed C1043: host TMP did not designate a
writable DOS directory. Setting only DOS TMP=C:\\ makes the identical payload
compile; a file trace confines intermediates to the case's writable C mount.
The compile owner now supplies that environment. Inherited-TMP controls fail
before and pass after;56neighboring tests pass. The real fixed-width-alias
recompile regression passes under the scoped KVM launcher(91.42s).

Six far-control assertions had confused architectural offsets with loader
coordinates. Replacements retain and strengthen the original-byte oracle:
unhooked Unicorn checks guest CS/IP/ESP and returning helper scratch state in
both coordinate domains/nonzero callerCS, and corrupted projections fail.
No production semantics, flag/frame/whole-helper proof or acceptance gate is
changed.75focused tests pass. The final combined changed-file gate34965 is
terminal0, observed16:09UTC: scoped checks and92tests pass/7warnings67.73s.

One source-free select_word diagnostic now emits a body with tail passed,
but explicitly uses profile/thread settings and retained metadata. Actual
worker entry/return is1/1; this is not a normal-lane speedup or function fix.
An unprofiled replay with fresh function/recovery caches is running. Source
comparison, call classes, round trip and required broad gates remain open;
the prior33-failure checkpoint is not waived and no witness is admitted.

## 2026-09-28 — entry-word transport integrated; scoped gate green

The reviewed six-owner transport/effect/snapshot proposal now uses ordinary
production imports. Seven unchanged-behavior test suites are enrolled in
Make, the fast pipeline and test ownership; the strict MyPy cohort includes
the actual shared IR types rather than treating skipped imports as Any.
Transport is explicitly conditional on the known acyclic target cone, not
whole-frontier, caller-frame, return-IP or callee proof.

The existing entry-stack Word consumer now consumes the authoritative scalar
effect classification. Proven closed comparison/control effects preserve
unrelated register words; an IP write kills the IP family and unknown effects
clear current-register evidence. CALL targets still never become definitions.
Independent focused liveness regression: 2 failed / 5 passed before the change;
final neighboring transport/effect/Word tests: 227 passed / 7 warnings, 72.72s.
Final changed-file gate26855 is terminal0, observed15:20:51UTC: scoped static,
ratchet, startup/context and ownership checks pass; 227 tests pass / 7 warnings
in74.45s. This does not replace the required broader project gates.

Fresh ordinary-import linked POINT helper replay is terminal0: Word and
transport each have1/1/1/1/0 counts, with190observed/190closed/0refused traversal
effects. Scope remains known_acyclic_target_cone with whole_frontier_closed=false.
Frontend4/4/4/2/2 is incomplete;105c9/105cd remain unresolved and whole-callee/
generated-C acceptance remain false. No function fix or witness is admitted.

The preceding status turn confirmed the final scoped handle was terminal green;
this is new gate evidence, not global completion. Broader33-failure checkpoint,
select_word timeout and all outstanding compiler obligations remain unwaived.
Parent is now reproducing the six far-control assertions before deciding
whether their architectural-offset/loader-coordinate oracles are correct.

## 2026-09-28 — reviewed Devin result-width checkpoint

Parent reviewed and integrated two bounded Devin importer patches against
saved dirty sources: binary-result and generic temporary-result widths consume
the authoritative VEX type width, not operand/UNKNOWN-placeholder width.
Unsupported ITE value semantics remain UNKNOWN. Independent reds4failed/3passed
and3failed/3passed become48live focused passes/7warnings60.23s. Thirteen typed
normal-import regressions are enrolled in importer ownership/fast pipeline.
The current required quality-dev run is pending; prior broad failures are not
waived. No generated-C/function/tail-validation/witness acceptance follows.

Staged transport branch adaptation independently passes42tests. Parent
withdraws its stock-registry-only comparison oracle: actual custom-emitter
Binops prove the wider8/16/32/64 LT/LE/GT/GE domain. Independent24red/23pass
becomes119pass/7warnings82.97s, with malformed spellings/widths/views retained.
Snapshot Devin38618 caps124 without a final report; parent finds and fixes its
test enum-import error before reviewing architectural-view/version/duplicate
coherence controls. Corrected parent red4failed/9passed becomes174shared-stage
passes/7warnings82.62s after full-view/version/duplicate-projection fixes. Fresh
deterministic native transport now PROVEN1/1/1/1/0 with190observed/190closed/
0refusals, explicitly only known_acyclic_target_cone. The105cdexit and incomplete
frontend4/4/4/2/2 remain; whole frontier/callee/C acceptance are false. Proposal
is not integrated. Quality-dev12047 ends2 on unavailable sandbox temp storage;
retry36383 uses repository TMPDIR, passes39-module mypyc smoke, remains pending.

Fresh final-tree source-free select_word check91806 is terminal3, observed
14:31:53UTC:60s recovery timeout, tail validation uncollected/hold, no function
body (stdout contains only the generic preamble). The retained before diagnostic
also timed out. Shared changes preclude sole-width causality or performance
claims. Root ran it after the bounded Devin launch failed to resolve the scoped
nested KVM bind; host KVM API12 was verified. Static Devin83172 now checks only
normal-import/typing integration readiness under a verified hostRO/repoRW
boundary and4GiB cap. Transport remains staged; broad/witness acceptance is open.

Quality-dev retry36383 is terminal2, observed14:36:49UTC. Static/startup/context/
ownership checks and39-module mypyc smoke pass;296contract tests pass39.38s.
Fast unit lane:33failed/7248passed/1skipped/20warnings1545.07s. Five failed
sections explicitly report missing /dev/kvm; host stat still sees10:232/mode666.
No matching dirty pre-run baseline classifies other failures or attributes them
to the width fixes. Four far-return EIP assertions and two far-probe CX
assertions remain unclassified, alongside timeouts and other failures. No gate
is waived. Default/release lanes were not run by this fast-tier checkpoint.

Static-only Devin83172 caps124 without a completed report. Parent verifies all
six copied owners unchanged, corrects only the diagnostic PYTHONPATH dependency
boundary, and gets normal-import0/Ruff0. Six-owner MyPy reports two Any-return
findings; including the actual shared IR core/scalar-projection type owners in
the unchanged strict config gives eight-owner MyPy0, observed14:43:55UTC. No
code/type-ignore patch follows. Native cone and typing readiness are not live
integration, whole-callee, C or witness acceptance. FD3-based nested KVM binding
also fails(API ioctl errno25); that attempted workaround is not adopted.

## 2026-09-28 — CALL-input index coherence; transport proposal still staged

Parent corrected the shared raw/SSA scalar definition index and its complete
record contract: CALL.dst is an input, never a producer. Later explicit outputs
remain definitions; this does not establish callee preservation. The exact
dirty before-source baseline is retained. Independent reds10failed/6passed and
a separate1failed contract control become47focused passes/7warnings129.44s.
The final scoped53050 is terminal2, observed12:30:17UTC: static/startup/context/
ownership checks pass;101tests pass,1SORTD inventory subprocess times out180s,
7warnings447.53s. No matching baseline attributes that timeout; it is unwaived.

Devin's cross-block entry-word transport proposal is not integrated. Its30own
tests pass but20independent effect controls fail; parent then reproduces three
selected-site false proofs and inconsistent relation counts (4fail/1pass).
Parent's staged geometry/counter correction passes5controls66.65s before the
later scope/type refinement. The result is explicitly conditional on the known
acyclic target cone, not whole-frontier, return/frame/callee or emitted-C proof.
Native pre-correction transport refuses with an open frontend boundary; no
native success is claimed. Two disjoint bounded Devin tasks correct the effect
owner and split transport state/CFG ownership. Each has a saved dirty baseline,
repository-only write sandbox and4GiB cap; parent reviews all deltas.

The broader quality/default-pipeline failures, stale-provenance CLI refusal,
select_word60s recovery timeout and compiler-witness obligations remain open.
No function newly fixed, tail-validation pass or witness admission is claimed.

## 2026-09-28 — reviewed Devin provenance-invalidation test correction

Bounded Devin72723 staged the two real16 exception-to-skip removals under a
saved dirty baseline, repository-only write sandbox and4GiB cap. It ended124
without a completed report; parent reviewed every owned delta and narrowed its
new test catcher to RuntimeError and the explicitly asserted forbidden skip.
Parent independently reproduces baseline2failed/2passed30.72s and corrected
4passed25.18s. Existing proof/CLI assertions are unchanged; invalidated evidence
now propagates its original exception instead of becoming skip/pass.

Integrated focused binary/provenance checks98923 are terminal0:
16passed/5warnings87.77s. Ruff and test-ownership-check pass; the
forbidden fast-ownership skips are removed without weakening the checker.
Final changed-file gate54236 is terminal2, observed11:45:22UTC:12passed/1failed
7warnings160.45s; the CLI test receives exit1 instead of0. This is not a skipped
source-invalidation error and remains unclassified. Its MyPy stage selects no
promoted typed files, so no test-file MyPy claim follows.

Fresh source-free select_word baseline89379 is terminal3:
recovery exhausted60s, direct timeout and uncollected tail validation remain.
The interval from project-built to binary-signature metadata completion is
about286s of wall time, not a profile. Read-only Devin57441 began11:43:18UTC
to identify the exact setup call chain and a bounded next profiling hook. It
ended124, observed11:47:01UTC, without a report; findings require parent checks.
Latest required Word quality-dev49718 ended2 with type-ratchet command143
before units; no unit total is invented. Broad quality/default-pipeline and
compiler-witness acceptance remain open. No function or C improvement is claimed.

Subsequent artifact inspection binds the failed CLI case to its saved report:
UNKNOWN/stale_provenance, counters1/1/1/1/1. This identifies the refusal, not a
matching baseline attribution or waiver. Final Word scoped gate84096 is
terminal0, confirmed11:53:05UTC:46passed/7warnings93.22s with Ruff/MyPy cohort,
ratchet/startup/context/ownership checks. Parent's metadata profile33415 is
terminal0, confirmed11:56:14UTC:retained-cache metadata5.516740s wall/0.491211s
CPU,16labels/ranges. The earlier isolated cache directory also cold-started
signature matches; its286s gap is not a comparable warm benchmark. No production
optimization follows. Reports retain the exact baseline/probe conditions.

## 2026-09-28 — initial-entry word Value proof integrated; focused controls pass

Parent integrated the reviewed Widening contracts/bit calculus/selected-value
proof, not a C materialization pass. Devin supplied bounded test-only work;
parent rejected fabricated out-of-range bit provenance in one negative control
and replaced it with actual Alias-proven lanes. Parent independently reproduced
9false-positive refusal controls against the saved pre-fix engine (9failed,
5passed87.20s), then45staged controls pass/7warnings91.77s. A further repeated
producer-ID control was red1failed/7warnings63.85s; the canonical consumer now
refuses ambiguous IDs rather than guessing immutable lineage. CALL targets
remain uses and never replace captured values; unknown effects invalidate
register evidence. Displaced/indexed/contradictory views and width conflicts refuse.

Final canonical focused3495 is terminal0, observed10:56:12UTC:161passed/7warnings
119.16s, including new Word controls and retained Alias/projection/SSA regressions.
Word modules pass Ruff, MyPy with explicit owned dependency cohort, type/doc
ratchet and Pyright0errors. Initial MyPy/ratchet failures were resolved with native
type aliases and relative owned imports, not Any casts or waivers. SSA scoped
gate68984 is terminal0, observed10:30:05UTC:112passed/8warnings343.95s. IRInstr
now documents the input-target contract coherently with SSA and its consumers.
The routine pipeline, ownership and architecture promotion enrollments are updated.

Two newly lifted canonical native artifacts still prove only the selected word
Value1/1/1/1/0, with Alias2/2/2/2/0 and frontend4/4/4/2/2/incomplete retained.
No caller-frame, return-IP, callee/return, pointer, wider-memory-read or emitted-C
claim follows. No function newly fixed or compiler witness admitted.

The final full check-files retry15256 is terminal2, observed10:50:39UTC, before
pytest: binary-real16-state-and-callee-proofs has two forbidden fast-ownership
skip calls in test_real16_binary_compare.py. These remain unwaived. A read-only
Devin diagnostic67431 began10:56:12UTC under a freshly rechecked host-read-only/
repo-writable sandbox and4GiB cap; it may write only its ignored report, not alter
another owner's tests. Broad quality/default-pipeline acceptance stays open.

## 2026-09-28 — reviewed Devin CALL-target SSA correction

Devin's bounded SSA batch86024 was capped124, observed10:11:04UTC, without a
finished report. Parent compared every staged source delta with the saved dirty
baseline and independently ran the six controls: baseline4failed/2passed in
97.65s; proposed correction6passed/7warnings97.06s. The correction is integrated
in IR with durable routine/ownership/Ruff enrollment. CALL.dst is a pre-call
input target, never a fabricated definition; explicit later outputs still bind.
Callee preservation and outputs are not inferred. Final scoped gate68984 began
10:20:07UTC and remains pending; no generated-C/function/witness claim is made.

Hard31232 is terminal2, observed09:48:09UTC:173architecture findings/12categories,
before unit execution. Serial quality-dev60028 began09:48:53UTC and terminal2
was observed10:11:04UTC:39mypyc import-smoke modules and296contract tests pass,
but the fast unit command ended with143. This is an interrupted unit lane, not
a new passed/failed unit total. Remaining findings and default-pipeline failures
remain unwaived; no matching broad baseline attributes them to this slice.

Word-engine batch60781 was capped124 without an engine or tests; parent rejected
it as incomplete and owns the staged Widening engine. A newly lifted native replay
now proves only the selected word Value with1/1/1/1/0 counts, retaining Alias
2/2/2/2/0, frontend4/4/4/2/2 and the external call frontier. Two fresh artifacts
serialize identically. Word-test batch44290 began10:13:19UTC, capped124 observed
10:22:09UTC; it produced tests but no final report. Parent is reproducing those
controls and testing corrupt destination/register views independently. Initial
test collection missed the shared fixture path; the corrected isolated run is
pending. Test-only bit-calculus batch37534 began10:24:42UTC under the same
verified repository-only sandbox and4GiB limit. No word proof is integrated yet.

## 2026-09-28 — final entry-byte gates and scalar-projection review

The reviewed shared scalar projection owner is now integrated in IR. Devin's
correction75590 was capped124, observed08:27:34UTC, but its last-minute typed
operation/producer-label and header changes were captured and reviewed; it did
not finish tests or a report. Parent preserved that exact delta and independently
reproduced the earlier two failures. The first green run had14passes/7collection
errors because another ongoing lifter edit used absent cython.bytes; no pass was
claimed. Pure-IR replay passes both independent controls, and the normal retry
passes16tests/7warnings66.15s after the unrelated import was corrected.

Parent integrated only the reviewed adapter and flow consumer, added56durable
public metadata/producer controls, and enrolled Make, typing dependency cohort,
architecture promotion, routine pipeline and ownership. Final check-files9765
is terminal0, observed09:33:28UTC:330passed/7warnings141.10s, including legacy
constant-flow/stack-restoration consumers; Ruff, MyPy, ratchet, startup and
ownership checks pass. Scoped Pyright reports0errors. Conversion refusals now
avoid discarded private allocations; immutable identity relations and public
value/refusal behavior are retained, not exact counter equality. This is a
refactor checkpoint, not a new word proof, function fix or admitted witness.

The final entry-byte scoped gate passes53tests/7warnings36.50s. Required broad
quality-dev remains terminal2:296contract tests passed; unit6984passed/12failed
in1452.98s. No matching baseline attributes the failure-count change to this work.
After the reviewed documentation extraction, full architecture72957 is terminal2,
observed08:09:09UTC, with167findings/12categories. The map-size finding is resolved;
all remaining findings and the default pipeline stay required and unwaived.

Devin's staged shared scalar-projection extraction is not accepted. Parent read
every owned delta against the saved dirty baseline and found that register+register
Add lost its earned operand-name decoration. Independent baseline/staged controls
reproduce two failures: one valid reread refuses and one unearned reread proves.
Red20571 is terminal1 with2failed/7warnings92.62s. A six-minute staging-only
correction75590 began08:21:12UTC, resuming gratis-sidecar under the freshly checked
host-read-only/repository-writable sandbox and4GiB limit. Ownership is four staged
files and a report only; live flow remains at its saved pre-run hash. Parent
review, numeric/refusal parity, final scoped types/gates and routine enrollment
precede any integration. Private allocation-counter parity is not yet established.
No word-value, caller-frame, return/callee, generated-C or admitted-witness claim.

## 2026-09-28 — entry-stack-byte Alias primitive integrated; focused gate green

Reviewed Devin's corrected stage against nine independent controls and a
46-control native/owner replay. The canonical Alias consumer, typed contracts,
shared-snapshot extension and IR operation-membership adapter are integrated;
staging reflection is gone. The original snapshot owner remains byte-identical.
All three new test modules are enrolled in routine/ownership/quality registries.
The canonical focused run passed89tests/7warnings in35.39s, including the retained
36-test legacy baseline. The full MyPy dependency cohort passes; a narrower
first attempt skipped its base class and stopped before pytest. The complete
canonical `check-files` gate passed53tests/7warnings in29.94s; Ruff, MyPy,
docs/types, startup and ownership checks pass. Broad required gates remain
pending, not inferred from this focused result.

The subsequent hard gate is terminal2, observed07:22:20UTC, before unit tests.
It exposed four missing ownership headers in the new modules; parent added only
module docstrings, independently proving all four runtime ASTs unchanged.
Final scoped gate passes53tests/7warnings36.50s. The full architecture recheck
still has168findings in13categories, with no finding for these four modules;
those broader obligations remain open. No matching baseline waives them.

One bounded read-only Devin native byte-to-CX SSA probe failed to connect
(terminal1, retryable error, no report). Its single retry started07:22:55UTC,
session gratis-sidecar, using the verified repository-only write boundary,
4GiB limit and eight-minute process cap. Ownership is three ignored probe/report
artifacts only. Parent review and broader serial gates remain required.

Native probe retry99936 was capped124, observed07:31:18UTC, with an incomplete
TMP-name-only map. Parent rejected its missing-consumer inference and resumed
exact session gratis-sidecar for a bounded correction at07:33:43UTC. Correction
82297 is terminal0, observed07:41:33UTC. Parent read its delta and independently
replayed the raw operator window twice, verifying the byte-extension/shift/OR
word identity for all65,536byte pairs; Alias2/2/2/2/0 and frontend4/4/4/2/2 are
retained. The six reported 'proven' links are diagnostic references only: they
do not establish a reusable width/view/dominance proof or callee/return closure.

Independent doc-only batch49181 began07:39:21UTC and was capped124, observed
07:46:23UTC, before its final report. Parent reviewed both staged files and
reproduced the existing checker red1/green0. All147extracted lines are verbatim;
the staged map is100lines vs244. Live docs and checker hashes are unchanged;
integration remains deferred until the broad-source freeze ends. Its temporary
extraction scratch is not part of the accepted proposal.

quality-dev83950 began07:28:02UTC; contract296passed/7warnings44.87s, broad unit
lane remains running and non-green so far. No source edits are permitted during
this run. Staging-only word Value batch12140 began07:52:46UTC, with4GiB/ten-minute
cap, reusing gratis-sidecar. It must consume canonical Alias plus exact local
SSA, share IR conversion/provenance truth rather than duplicate it, and retain
typed refusals/counters. Parent review is required; no word API, generated C,
return/preservation or compiler witness has been integrated by this delegation.

quality-dev83950 is terminal2, observed07:57:11UTC: contract296passed and broad
unit6984passed/12failed/20warnings1452.98s. No matched baseline attributes the
failure-count change to this slice; full acceptance remains open. Source freeze
ended. Parent integrated only the independently verified map extraction using
apply_patch: all147moved lines remain verbatim, the100-line live map passes the
existing helper, and new routing targets exist. The extracted guide additionally
documents the accepted Alias primitive's scope and exclusions. No checker cap,
hard architecture finding exemption, runtime code or semantic gate was relaxed.

The final instrumented Devin replay also resolves the CLI delay's phase: startup
hash-seed reexec had discarded earlier hooks; with PYTHONHASHSEED=0, the sampled
post-terminal work is CPython shutdown GC after module/SystemExit/atexit. GDB
pauses inflate timing, and no specific project/cache owner is proven. No GC,
deadline or forced-exit policy was changed. The KVM weather replay's compiler
C1043 failure is distinct. Worker process caps ended two incomplete batches;
their live handles are terminal, not assumed stopped from missing output.

No caller-frame binding, complete helper/callee return proof, DS=SS entry fact,
pointee type, generated-C improvement, validation=passed or admitted compiler-
coverage witness is claimed. Next semantic action consumes the Alias bytes in
the existing SSA/Widening path; the seven failed tiny constructs stay required.

## 2026-09-28 — entry-byte proposal rejected and bounded correction delegated

Parent's final replay binds the staged source to SHA
4678b1d17f2c403d0b5b2b0aed645ed681f6c49c303a7c8f88565cbca6451cd4.
Four malformed producer/operation cases falsely materialize stack origins;
diagnostic serialization also differs for equivalent inputs. Valid capture and
redefined-temp refusal pass. These five failures reject the proposal despite
the worker's 27 passing controls. A duplicated frame-coordinate engine must
also be replaced by consumption of the shared Alias owner. No live source or
semantic consumer is changed by this rejection.

The exact owned batch84764 was cleanly interrupted; terminal exit1 observed
04:41:38UTC. Session rotating-patch resumed as batch42062 at04:48:01UTC, with
the 4 GiB cap and read-only-host/repo-writable boundary. Ownership is limited
to staged source/tests/reports, including a bounded shared-snapshot extension.
Parent review and red/green evidence remain required before integration.

Independent Devin81558 began04:51:40UTC with the same 4 GiB cap and sandbox,
owning only two saved-log triage reports for the 16 unit failures. It cannot
rerun tests or edit live files. Categories and proposed next checks require
parent verification; an older pipeline is not a matching baseline.

Batch81558 terminal0 observed05:01:44UTC. Parent independently verifies the
exact16-nodeid set and14timeout/1signature/1gcc categories, and all11 referenced
tail artifact files exist. The report's pending-pipeline caveat is stale;
post-output root liveness is unproved because inherited pipes may delay EOF.
Same session plum-nautilus resumed as75124 at05:05:16UTC for a bounded liveness/
pipe diagnostic, with no live patch authorization. Alias pre-integration
baseline36passed/7warnings in24.54s. No function fix or witness is admitted.

Alias correction42062 terminal0 observed05:38:19UTC. Its original seven parent
controls now pass; an independent registered-operation/memory-destination
control still falsely materializes one stack-byte origin. The unchanged width
disagreement control correctly refuses. The final staged consumer is bc0ba737,
snapshot extension ebbaa06f; neither is integrated. Session rotating-patch
resumed as96131 at05:41:14UTC for this bounded shape correction.

Liveness75124 terminal0 was observed05:33:14UTC. Parent accepts a sampled
4–6-second on-CPU root cleanup window after the timeout marker, not an exact
owner or proof that no descendant ever held a pipe. The weather replay was
environment-limited by hidden KVM. The scoped KVM binding returned API12;
session plum-nautilus resumed as9410 at05:41:14UTC for comparable serial replays.
Both new runs retain the 4GiB cap, repository-only write boundary and ten-minute
process cap. All old diagnostics remain immutable; no timeout policy is relaxed.

Default pipeline21617 is terminal exit2, observed04:58:09UTC (41m05s from its
recorded start). Its unit lane has 6,927 passed/16 failed in1,028.99s; contract
lane296passed. MS C external artifacts have one passing round trip of eight
constructs (simple_control); the other seven remain failed. Final summary
selected3/failed3 counts lanes, not constructs. No pipeline acceptance,
return/callee closure, pointer publication, function fix or compiler-coverage
witness is claimed. This run's source freeze has ended; no duplicate broad run
is required merely to recover its saved diagnostics.

## 2026-09-28 — final IR gate recorded; reviewed CLI promotion integrated

Final-IR `quality-dev` is terminal exit2, observed04:14:00UTC:296contract tests
passed; fast unit lane15failed/6928passed in997.78s. Its one-selected/one-failed
summary counts the unit lane. This is not a passing broad gate or an external
round trip. COD signature/call failures and typed recovery timeouts remain open;
no matching broad baseline classifies them as preexisting.

Devin's CLI quality batch is terminal0. Parent independently reproduced its
transport, runtime-AST and real-checker controls, then integrated the exact
module docstring and one promotion-registry entry after the source freeze
ended. No runtime body, Make registration, debt exemption or acceptance policy
changed. Final37focused policy tests pass68.53s; Ruff/MyPy/Pyright, docs/types
ratchet and targeted architecture checks pass. Hash reconstruction proves the
checker delta is exactly the reviewed entry, preserving its shared dirty edits.

Required default pipeline21617 started04:17:04UTC, serially, with live sources
frozen. Separate4GiB-capped Devin84764 is staging an Alias entry-prefix byte
origin primitive and tests. It may not publish return/callee/pointer proof or
modify live sources. This work and the CLI quality checkpoint do not admit a
compiler witness or mark a generated-C function fixed.

## 2026-09-28 — final-source hard gate rejected before unit execution

The final-source `quality-hard` run started03:46:43UTC and exited2, observed
03:50:02UTC (3m19s observation interval). Static/mypyc steps progressed, but the
full architecture check failed before unit execution. Retained findings include
owned dynamic attributes, missing typed-promotion registrations, CLI ownership
markers and two focused skip/xfail uses. These are not waived as preexisting:
there is no matching broad pre-change baseline. Full log is
`.cache/devin-reports/ir-known-lane-quality-hard-20260928.log`.

Serial `quality-dev` began03:54:17UTC with live sources frozen. A separate
4GiB-capped, sandboxed Devin batch began03:56:19UTC for a staging-only CLI
terminal-status quality proposal. Make already includes that module in its
typed/Ruff lists; the independent architecture registry and ownership docstring
need alignment. Worker may not touch live source, run broad gates or claim
decompiler acceptance. Parent retains review and integration ownership.

## 2026-09-28 — reviewed Devin known-bit owner integrated, scoped checks green

Parent reviewed completed Devin v3 against the saved live baseline, read both
test modules and independently reproduced all nine fixed controls. Formal
before-fix pytest recorded 23 failures/20 passes in the new modules; three
separate native-byte Alias consumer regressions also failed. The reviewed IR
owner now preserves proven sibling register bits, tracks exact producing
decorations instead of guessing conversion widths, invalidates malformed writes
and never treats CALL targets as output definitions. No recovery was added to
rewrite, and unknown values/operations remain unknown.

Integration's initial focused suite passed 157 tests. Parent corrected the
compound-condition lint issue and an explicit imported-family type boundary;
final scoped `make check-files` passes 436 tests in 65.32s, with Ruff, MyPy,
docs/types ratchet and startup/context/ownership guards. Module Pyright has
zero errors. Both new modules are enrolled in both routine Make lists, the
pipeline and ownership registry. Native Alias facts carry exact constants and
closed 1/1/1/1/0 counts. Broader final-source gates remain required.

Parent also verified Devin's saved-log triage: the prior default result's three
failures are three lanes. QuickC passed three fixtures and failed `args`; MS C
passed one of eight constructs. `scalar_types_io` recompiles but its run exits7.
The saved `cmp_i16` stderr names segmented-memory structuring at timeout, but
does not measure the whole budget's stage distribution. No baseline or timing
claim waives these failures. Triage is read-only and terminal exit0.

This is a local IR/Alias evidence milestone, not a fixed generated-C function
or admitted compiler-coverage witness. Helper return/frame/callee effects,
entry DS=SS propagation and pointer publication remain open. The observed
v3 staging/integration interval ended by 03:43:06 UTC; elapsed times above are
test observations, not a performance-speedup claim. No commit or push.

## 2026-09-28 — terminal gate and independently rejected Devin v2

The default pipeline is terminal exit 2 (observed 03:04:56 UTC), not pending:
296 contract tests passed; unit lane 6,882 passed/13 failed in 1,128.12s.
Its final three-selected/three-failed summary counts pipeline lanes, not
individual MS C constructs. A bounded read-only Devin task is classifying the
saved lane artifacts; no failure is waived or accepted as pre-existing.

The corrected known-lane proposal exited 0 (observed by 03:13:03 UTC). Parent
replayed all four original controls successfully, then reproduced four further
failures: unsupported-size writes retain sibling knowledge; target-width alone
is treated as conversion-production proof; CALL targets overwrite immutable
temporary definitions. The last two unsupported-write cases count separately.
The valid converted-temporary reread still passes. Proposal v2 remains rejected
and unintegrated; the exact Devin session owns a narrow staged correction.
Independent controls are `ir-known-lane-parent-extended-controls-20260928.py`
under `.cache/devin-reports/`. No function or coverage verdict changed.

New Devin batches now run behind an explicit Bubblewrap boundary: read-only
host, writable repository, private process/device setup, and verified 4 GiB
address-space limit. Startup was corrected after a saved syscall trace exposed
the missing private `/dev/null`; a fresh data-root authentication failure was
also kept separate from task failure. The implementation and log-triage batches
have disjoint ownership and neither may edit live sources or run broad gates.

## 2026-09-28 — reviewed Devin diagnostics and staged width refusals

The helper-error diagnostic exited successfully. Independent byte/IR replay
confirms AH=35h/25h/44h at the three retained INT21 sites, with altered-selector
and altered-vector controls. This does not close the helper: AH=44h has no
service-spec row, and callees/return feasibility remain unproved. Parent keeps
selector counters 3/3/3/3/0 separate from service metadata 3/3/2/2/1. The worker's
stronger all-returning wording is not accepted. Review and reproduction are in
`.cache/devin-reports/helper-error-terminal-parent-review-20260928.md`.

The separate known-lane IR proposal also exited successfully. Parent verified
its exact hashes and read the complete staged owner, then independently found
three refusal defects: a new malformed-write sibling-preservation false proof,
plus inherited implicit-widening and conversion-source-width false proofs.
The proposal is not integrated. Its exact Devin session was resumed, still
4 GiB-capped and staging-only, for these controls; parent controls remain owned
and immutable. Review: `.cache/devin-reports/ir-known-lane-parent-review-20260928.md`.

Required default pipeline remains live: 296 contract tests passed, then unit
lane 6,882 passed/13 failed in 1,128.12s. External lanes are still pending, not
assumed green. No live semantic source, entry relation, pointer publication,
tail result or admitted compiler-coverage witness changed at this checkpoint.

## 2026-09-28 — CALL-boundary broad recheck and bounded Devin follow-up

Final-source `quality-dev` completed non-green: static/startup/ownership and
296 contract tests passed; its fast lane reported 6,875 passed and 20 failed
in 1,014.90 seconds. Failures include decompilation timeouts, COD signature/
call checks and live-corpus acceptance; they remain open, not waived as unrelated.
Full output: `.cache/devin-reports/segment-call-guard-quality-dev-20260928.log`.
Completion was observed at 02:22:18 UTC. The required default pipeline started
next (observed by 02:22:56 UTC), with no overlapping broad gate or live source
edits; its final result is pending.

Two independent 4 GiB-capped Devin jobs are active: a byte-backed helper-error
termination diagnostic and a staged IR constant-lane proposal. Both are confined
to ignored diagnostic/staging paths; neither may publish a function result or
edit live source. Parent review and focused controls remain required before
integration. No segment-entry relation, positive helper preservation, pointer
publication or admitted-case result has changed.

## 2026-09-28 — reviewed Devin CALL-boundary checkpoint

Two 4 GiB-capped Devin batches investigated return provenance and prepared a
typed unknown-CALL guard. Parent retained only diagnostic return facts: both
helper exits and SP-memory refusals remain open. The IR solver no longer carries
segment/proxy identities across unmodeled calls. Parent caught an additional
CALL-target-as-output defect; nine red controls now pass after correction.

Checks: 39 focused tests; scoped `check-files` 364 passed plus static/startup/
ownership guards; two-module Pyright zero errors. Exact pre-run source replay
confirms the separate dword-call AST failure predates this patch. No positive
callee effect, pointer type, generated C, tail result or admitted case changed.
Required broad final-source gates remain due. Devin preference and bounded
baseline/review instructions are persistent in AGENTS.md.

## 2026-09-28 — reviewed Devin lineage checkpoint

Two bounded 4 GiB-capped Devin batches staged, without editing live sources
during broad validation, a non-creating raw-IR registry read and an IR/Alias
lineage acceptance gate. Parent reviewed exact deltas and reproduced the
byte-backed foreign-evidence counterexamples before retaining the patches.
The local DS=SS candidate now requires the exact registered IR object and the
Alias source built from that object; bare, foreign, copied and serialized-only
evidence refuses. Parent added red/green controls for registry-content
mutation detection and for distinguishing corrupt from missing registration.

Final checks: 64 focused tests; scoped `make check-files` 486 selected tests
plus guards/linters; module Pyright zero errors. Linked startup keeps its
local PROVEN candidate with 1/1/1/1/0 counts and zero IR refusals. No entry
state, pointer type, C expression or admitted-case verdict changed.

Earlier serialized broad gates remain non-green: fast unit lane 6,849 passed /
10 failed; default unit lane 6,850 passed / 9 failed. QuickC passed all four
selected fixtures; MS C passed five of eight constructs, failing `mixwidth`,
`pointer_memory` and `scalar_types_io`. Broad gates were not rerun after the
lineage safety patch. Next: generic helper return/call preservation, contextual
segment-entry propagation, independent pointee proof and atomic pointer
publication. Detailed evidence remains in `reference/compiler-coverage-plan.md`.

Current objective: implement `reference/compiler-coverage-plan.md` —
correctness-first compiler coverage with evidence-driven semantic recovery.
Tagged start: `far-pointer-candidates-93c6b401`.

## Completed milestones

- Fresh-result retained FPTR batch completes all six functions in 137.23s,
  each exit0/tail validation passed and standalone GCC-clean. Program-level GCC
  LTO rejects `select_and_apply`'s three-scalar `sub_10034` declaration against
  `apply_twice`'s function-pointer definition. Added typed optional
  `--check-cross-unit` batch gate and regression controls; the actual six-unit
  artifact is `compilation_failed`. Focused tests pass (17), scoped linters and
  ownership check pass. `check-files` still fails unrelated current
  shared-body-wide-condition architecture violation. No full coverage witness.

- Full-process profile identifies normal-budget cost in target CFG recovery
  (13.63s) and neighbor extension (41.85s: CFGFast 24.63s, ABI seed 17.20s).
  Direct far-call seed at 0x10006 -> 0x104b0 proves extension is relevant.
  After host load changed, fresh-JSON `inc_one` passes normal 60s functional
  budget/validation in 16.81s with byte-identical C. Full `function_pointers`
  round trip still build-fails: builder's kvikdos children see `/dev/kvm` ENOENT,
  proven by pre-call check and syscall trace, although direct KVM/CL calls work.
  Fresh-JSON six-address retained-EXE batch is active at
  `.cache/compiler-coverage/retained-far-fresh-batch-001/`.

- Fresh profiled `inc_one` diagnostic validates exit0, generated C byte-identical
  to the earlier accepted diagnostic artifact; 58.37s profiled worker time has
  14.77s Structuring baseline and 10.20s rewrite-loop cumulative costs. Fresh
  normal-budget retry still exits3 after 127.35s, starting decompilation with
  only 13s left. Full-process profile under normal functional deadline is active
  at `.cache/full-process-normal-001.{c,err}`. No full DOS round trip/witness.

- Startup stacks identify a missing current-generation PAT spec cache, not a
  stalled analysis worker. Existing cache owner builds 49,283 specs in 115.54s.
  Fresh normal-budget replay then reaches recovery but times out (118.80s,
  validation uncollected). Fresh diagnostic worker profile is active at
  `.cache/post-warm-profile-001.{c,err}`; no normal-budget acceptance claim.

- Warm-parent six-job replay ends at the 600.93s external bound: three exit3
  timeouts, `select_and_apply` and `combine_args` exit0/validation passed,
  `nested_arguments` interrupted without a completed record. No full round trip
  or new coverage witness. Tree-aware cleanup returns and batch root is gone.
  Fresh isolated `inc_one` profiling/parity diagnostic at
  `.cache/abi-block-size-parity-002.{c,err}` also reaches its 240s external
  bound (242.45s including cleanup), before entering the profiled worker.
  No profile/parity evidence; next diagnostic must sample startup, not just
  the analysis worker. Ordinary deadlines remain unchanged.

- DOSUnit comparator hardening round (Riptide v5 corpus): ptr16:16 lcall
  immediates are now masked in normalized binary signatures (capstone
  imm_size=0 gap) so shared prologue/thunk blocks match across layouts;
  near/far call-target enumeration tries the lifter-resolved raw target
  before low16 guessing; SSA-document linked_base is coverage-validated
  (oracle segment-base vs image-base confusion fixed); region-level call
  pairing gained a positional fallback and return-address-store
  normalization no longer requires callee equivalence (self-proving);
  claimed candidate parts refuse on reuse (`candidate_part_reused` /
  `ambiguous_candidate`) instead of emitting false semantic failures;
  failed pairs probe same-function candidate siblings and refuse
  ambiguously when a boundary-split sibling matches oracle operands;
  short string-table heads (e.g. `"?"`) prove via corpus-wide DGROUP
  paragraph witnesses and identical printable string-blob matching;
  batched compare children dedupe identical index/pairing doc loads.
  Targeted 13-function compare: 134 passed / 0 failed / 103 refused
  (refusals are honest artifact classes). Source fixes landed: strcmp
  argument order in gamemgr.cpp (remove_sound) and scores.cpp
  (cb_password), tab-vs-space in menu.cpp calibration-abort string.
  Known limitation: Borland FP-emulator sequences (`int 34h-3Dh` +
  inline operand bytes) terminate VEX blocks with no fallthrough, so
  code after them (e.g. cb_run_benchmark's show/inform tail) is a
  coverage gap that correctly refuses rather than failing. Full-corpus
  shard compare (709 fns / 10,046 parts, 4 shards vs recon.ssa.v5) in
  flight; 11 pre-existing test failures unchanged (verified vs parent).

- DOSUnit part-pairing + argument normalization hardening (Riptide batch
  triage): normalized block signatures no longer mask 8-bit literals
  (push 0xa vs push 3 collided -> wrong-part pairing in add_missile);
  int vectors stay literal; far-pointer push args now proven via MZ
  relocation-table segment paragraphs (load-bias corrected) plus their
  adjacent offset partner; seg-register string args got a two-pass
  content proof (>=4-byte strings establish paragraph witnesses,
  3-byte strings borrow witnessed pairs or require unique match);
  part-pairing exact-signature override fixed delta collisions
  (check_guages). Riptide source-level divergences found via comparator
  and fixed: game_cast::update var_2++ placement (63/63 parts proven),
  story_call_up local-init store order. Host reboot wiped /tmp corpus;
  SSA docs now generated under the repo (orig v2: 10,046 parts /
  0 refusals / 709 functions).

- DOSUnit Z3 comparator (straightline_ssa) hardened for Riptide verification:
  32-bit register model (EAX-family hi16/low16 split incl. partial writes),
  inc/dec32 eflags-arity fix, near-call target resolution via rendered absolute
  operands (caller-cs + by_linear, fixes low16 collisions), far-pointer push-arg
  normalization with EXE-content string proof (reloc-table DGROUP para), stored
  code-offset/dispatch-immediate pairs via entry-shift evidence, positional
  near/far call-return store normalization (no over-matching), residual
  same-delta constant sweep. Call-verdict gate: unresolved or unproven callees
  refuse honestly; only "different mapped functions" fails. Demangled Borland
  name aliases in discovery (signature + base, whitespace-normalized) lifted
  Riptide mapping 516->633. First real divergence found and fixed at source:
  game_cast::update `ed_list[var_2++]` placement — now 63/63 parts proven.
  Riptide corpus v2: oracle 5,998 parts / 0 refusals, recon 10,939 parts / 6
  refusals (47 reg32-refused orig functions re-lowered clean).

- Batch startup resolves the lazy CLI entrypoint in the parent before disposable
  jobs fork; analysis remains isolated. Parent-PID regression failed before;
  runtime/builder/binary-policy suite passes after (113 tests, 63.40s).
  Scoped Ruff/MyPy pass; quality-dev exits2 on broader lint/type findings
  (`.cache/batch-warm-import-quality-dev.log`). Retained six-job replay is active
  at `.cache/compiler-coverage/retained-far-warm-parent-001/`, with unchanged
  analysis deadlines and process-tree-aware cleanup. No new DOS witness.

- ABI instruction scans reuse positive CFG-proven block sizes instead of lifting
  merely to rediscover extents; unknown/invalid sizes keep the prior fallback.
  Two controls fail before; 28 ABI tests plus an installed-angr no-relift byte
  control pass after. Scoped Ruff/MyPy pass; quality-dev fails broader debt.
  Fresh normal-budget `inc_one` probe is active (`.cache/abi-block-size-normal.*`);
  output parity, runtime gain and DOS acceptance remain unproven.

- Isolated six-function replay ends at its 600s external bound: three timeout
  records retained, fourth incomplete, last two not reached. Hard-exit and outer
  process-timeout continuation are proven; no functions/witnesses accepted.
  Bare shell timeout left the active isolated job alive; it exited before cleanup
  signaling, and its group is confirmed gone. Future diagnostics use tree cleanup.
  Next measured hotspot: calling-convention seeding (42.493s observed wall).

- Batch jobs now use the existing disposable fork boundary; typed hard-exit
  records no longer kill subsequent jobs. Shared setup allowance preserves the
  existing deadlines. Real hard-exit control passes; final scoped suite 118 pass,
  scoped Ruff/MyPy pass, quality-dev fails broader debt. Retained isolated replay
  is active at `.cache/compiler-coverage/retained-far-isolated-batch-001/`;
  live continuation, performance and DOS acceptance remain unproven.

- Batch reports checkpoint completed jobs atomically and clear stale records at
  startup. Streaming revealed lazy loggers retaining closed job files; explicit
  per-job console-handler handoff fixes that regression. Final scoped suite:
  109 passed, Ruff/MyPy pass. Retained replay002 still runs pre-fix loaded code;
  its first two functions time out. No DOS witness is accepted.

- Streamed replay002 is now terminal exit3: `apply_twice` emits the hard recovery
  timeout comment and kills the in-process batch before its final report. Next
  repair is a per-job process boundary, not weakening the hard timeout or allowing
  timed-out analysis threads to continue contaminating later jobs.

- Batch artifacts now stream completed lines during execution and survive loud
  job failures. Three controls fail before repair; 42 runtime/policy tests pass
  after, scoped Ruff/MyPy pass, quality-dev still fails broader debt. The prior
  retained-EXE batch exits3 after its first timeout without a report; streamed
  replay001 stops at the concurrent-source-change import guard; replay002 is
  active at `.cache/compiler-coverage/retained-far-stream-batch-002/`.
  The stop cause and full DOS round trip remain unresolved.

- Two full large-model replays stop before compilation with `/dev/kvm` absent
  (24.43s / 23.28s, unchanged implementation). A direct original-EXE run passes
  between failures, so device availability is inconsistent. No acceptance claim.
  Retained-EXE six-function source-free batch is active at
  `.cache/compiler-coverage/retained-far-leaf-schema-batch-001/`; DOS build/runtime
  remains an independently open requirement.

- Exact AST leaf schemas skip display metadata while retaining reference fields
  and generic extension traversal. Final focused suite: 39 passed; scoped Ruff
  and MyPy pass. Diagnostic output is byte-identical, validated and GCC-clean;
  classifier calls fall 619247 -> 521583. Normal 60s fresh-cache replay passes
  with validated, byte-identical GCC-clean C (`.cache/leaf-schema-normal.*`).
  Quality-dev fails broader lint/type/mypyc debt;
  no new coverage witness or end-to-end speedup is claimed.

- Fresh-JSON normal-budget replay still times out. Larger-budget diagnostic
  profiling completes with validated byte-identical C: 12M calls, 56s worker,
  16.4s cumulative deep AST traversal and 619k boundary classifications.
  Profile: `.cache/direct-job-profile-1428223.prof`. Next measured target is AST
  traversal overhead; no new DOS witness or normal-budget acceptance.

- Zero-call snapshot diagnostic comparison passes validation with byte-identical,
  GCC-clean C: 120 -> 22 snapshots, 2.803 -> 0.338 CPU seconds in that component.
  No end-to-end speed claim. Normal-budget replay runs in
  `.cache/zero-call-snapshot-normal.*`. Small-model compare16 still times out
  at 601.35s with concurrent changes (two batch functions validate); no witness.

- Measured rollback cost: 120 snapshots, 19.384s wall / 2.803s CPU in the
  diagnostic far-model increment function. Per-pass call-loss snapshots now
  skip only zero-call/no-named-guard cases; all guards remain active. Two before
  failures; final 11 rollback tests and scoped Ruff pass. Same-budget profiling
  comparison is active in `.cache/coverage-repeated-work-no-empty-snapshot.*`.
  Runtime parity and normal-budget DOS acceptance remain unproven.

- Partial-batch far-model replay ends `timed_out` after 601.30s with concurrent
  implementation changes: two batch functions validate, four time out; no
  complete rebuild/run. Measured completed census/neighbor work is subsecond,
  not the dominant observed cost. Required small-model compare16 is rechecking
  in `.cache/compiler-coverage/sourcefree-compare16-batch-003/`; far obligations
  remain open and no new witness is admitted.

- Partial batch retry now preserves accepted bodies and original order, while
  retrying only missing/failed jobs. Source-free nonzero exits are refused;
  shared acceptance also requires an explicit clean/passed whole-tail verdict.
  Five before failures and one follow-up unknown-verdict failure; all 101
  adapter/policy tests pass after (57.64s). Full DOS replay is active in
  `.cache/compiler-coverage/sourcefree-far-batch-partial-001/`; no new witness.

- Source-free address targets now use the existing batch job-file path with
  local sidecars and alternate-source recovery disabled, normal isolation
  retained. Two before failures; 95 adapter/policy tests pass after (54.20s).
  Focused Ruff passes outside the builder's retained complexity debt;
  quality-dev exits2 on broader findings. Full DOS round trip is active at
  `.cache/compiler-coverage/sourcefree-far-batch-001/`. No witness or measured
  end-to-end speedup yet.

- The full batch adapter subsequently terminates `timed_out`: three batch
  functions validate, three time out, and serial fallback does not finish.
  Host load was about 28 on 8 CPUs. Recovery samples show CFG/lifting/emulator
  work, not a proven isolated hotspot. Normal nested-worker stack diagnostics
  are active in `.cache/direct-native-stacks.{c,err}`; no witness admitted.

- Catalog candidate filter implemented from a measured 66.287s Python-regex
  match over 49,283 patterns. Typed necessary literals reject impossible
  candidates without changing surviving backend checks. Two before failures;
  11 focused parity/cache tests pass afterward; full retained-catalog results
  match exactly. Warm-spec/fresh-result catalog stage falls from 69.799s to
  3.139s; first new-format spec construction costs 130.698s. Quality-dev still
  fails broader debt. Normal-worker replay `.cache/sourcefree-inc-filtered.*`
  is pending; no end-to-end performance or feature-witness acceptance yet.

- PAT spec caching now shares immutable catalog work across binary artifact
  directories and canonicalizes path/provenance together. Explicit cache
  overrides survive; literal-helper changes invalidate specs. Initial cache
  regressions fail before repair; final provenance-inclusive suite passes 11
  tests (48.89s). Cold replay `.cache/sourcefree-inc-shared-cache.*` timed out;
  warm normal-worker acceptance and the next full round trip are recorded below.

- Warm normal-worker `inc_one` exits0 with validation=passed and gcc-clean
  `arg_6 + 1` output; the cold replay still timed out. Full large-model adapter
  `sourcefree-far-shared-catalog-001` now terminates `timed_out`: original DOS
  execution passes, inc/dec validate, apply_twice times out twice (487.74s
  builder decompilation). No coverage witness admitted. Next: connect the
  existing address-job batch path without source/debug semantics or relaxed
  isolation/validation, then measure the retained case again.

- Compiler-coverage far-pointer storage repair: source-free typed evidence
  exposed a contained segment word incorrectly kept as a separate argument,
  shifting BP+10 to BP+12. Lowering now joins contained slots without moving
  later storage. Two before-fix failures; 21 focused tests including a crossing
  refusal pass after repair; scoped Ruff/MyPy pass. Source-free replay exits 0
  with validation=passed and both indirect calls in `.cache/sourcefree-parameter-joined.*`.
  Generated C compiles and passes a 65,536-input host composition/register check.
  Full large-model round trip `sourcefree-far-slot-join-001` times out on both
  `inc_one` attempts before generating a body (392.75s total); source identity
  also changed concurrently. Normal-worker startup timing is active in
  `.cache/sourcefree-inc-startup.*`. No witness; post-change gates remain due.

- Coverage now selects address-only recovery by default with same-build labels
  used only for harness binding. Original bodies and behavioral checks survive;
  injected prefixes and incomplete bindings refuse. 99 focused tests plus both
  artifact controls pass. Live `cmp_i16` exposes a DCE phase return-contract
  exception; raw artifacts retained. No new DOS witness admitted.

- Removed harness-side stack-argument/signature/global repair from acceptance;
  generated defects now remain visible to compilation. Four controls failed
  before removal; 70 focused tests pass, including real GCC corruption controls.
  Old round trips require revalidation under the stricter harness.

- MS C diagnostic bytes cannot crash UTF-8 decoding or erase the compiler verdict;
  two before-fix failures, then 24 recompile tests pass with scoped Ruff/MyPy clean.
  Live DOS execution still reports unavailable KVM; quality-dev remains red.

- Missing required fixture procedures now fail before rebuild rather than being
  skipped by diagnostic text; 65 focused runner/policy tests pass. Default
  pipeline terminated: 6,475 passed / 48 failed; fresh quality-dev exits 2.
  These broad failures remain open, with concurrent-edit effects to distinguish.

- Explicit source-free MS C runs can no longer enter sidecar-backed named
  fallback: before-fix regression reproduced the leak; 64 runner/policy tests
  now pass, with scoped MyPy clean. Coverage defaults retain their stronger
  behavioral harness; binary-only target binding remains required.

- Missing-body retry retains the selected small/large procedure model; large
  regression failed before repair, then 63 focused runner/policy tests passed.
  Scoped MyPy passes; 12 legacy builder Ruff findings remain. Source-free
  fallback policy propagation and broad acceptance remain open; see coverage plan.

- Large-model far-frame argument base proven from terminal `retf` evidence
  (`argument_frame_base.py`, `SimCC8616MSClarge`); far `inc_one`
  `validation=passed` with its argument at machine `BP+6` (commit d3dc07573).
- AGENTS.md hard rule 16 (loud exceptions) added; both silent far-proof
  catch-alls removed; incomplete test mocks completed instead (d3dc07573).
- Far function pointers proven by call-operand width
  (`FunctionPointerParameterFact8616.pointer_width`,
  `SimTypeFarPointer16_8616`); materialization widens the proven slot and
  re-sites later arguments; far-CC survives clinic via
  `PrototypeSource.CCA_DECOMPILER` (commit 2a446ba04).
- Near-model regressions hold: `apply_twice`, `inc_one` `validation=passed`.
- Far-pointer reflow now reports declaration refreshes and updates angr's
  separate rebuild argument storage; focused before/after regression added.
  Pointer/layout/codegen neighborhood: 16 passed; Ruff and focused MyPy clean.
- Traced the subsequent layout reset to COD labels being consumed as layout
  facts. Typed NAME_ONLY purpose now excludes optional labels from prototype
  geometry while preserving naming use; first focused neighborhood 87 passed.
- Positive-BP replay now consumes closed per-slot function-pointer evidence.
  The failing regression shrank `(4,4)/(8,2)` to `(4,2)` before the fix;
  the initial pointer neighborhood passes 12 tests after it. No signature
  authority promotion or complete-argument-census claim is introduced.

- Promoted-linter-debt cleanup (ruff C901/PLR0916/PERF102 only, no
  suppressions): stale Makefile mypy paths removed (`make mypy` green),
  PERF102 x2 fixed, and ~120 complexity findings refactored into typed
  helpers across ~150 X86_16 files. Owning pytest batches verified
  green per change (126/225/256/145/285+1 pre-existing/81/92/130/237/279/118
  /530/630/246/332/673/137+1 pre-existing/400/105+11/775/487/554+1 pre-existing/46/603+1 pre-existing/869/247/423/313/517/135/77/205/120/223/340/8/14/991+1 pre-existing/135 mid-batch/712+3 pre-existing/100/73/48/2685+2 pre-existing/178+2 pre-existing, lifter-union pass runs). X86_16 findings: 1507 → 962. Baseline suite remains 47
  pre-existing failures (far-pointer work), unchanged; the
  msc6_cmp32_regression sidecar-free CLI cases and the
  _MousePOS small-COD CLI case (byte-identical output verified via
  worktree/stash comparison) hang/fail identically at clean
  HEAD (cc2d1a195), confirmed pre-existing; the SORTD indexed-aggregate
  and sortd_runmenu_signed_wide_global sidecar-free CLI cases likewise sit
  in the recorded lastfailed baseline (240s timeout / exit-4 validation).
  Focused pytest
  needs `PYTHONHASHSEED=0` (make exports it); without it 8
  cache-surface tests fail on `allows_semantic_cache` refusal.

- lowering/segmented_global_loads.py driven to zero ruff findings (was ~70
  promoted sites at batch start): indexed/direct-global materializers,
  store-evidence collectors, stride/byte-address matchers, aggregate
  type/promotion/reconcile paths, and capstone-window classifiers split into
  typed module helpers and run-state dataclasses. Two splice regressions
  found and repaired during review: `_seg_global_debug_log_8616` restored to
  its env-gated `log.warning` body, and
  `_materialize_indexed_global_store_assignments_from_instruction_evidence_8616`
  rebuilt with its three extracted phases (facts-by-insn, assignment index,
  per-instruction materialization) preserving exact stats/decision counters.
  Owning suites: 181+187+15 passed; `test_synthesized_dword_return_call_
  keeps_exact_callsite_identity` confirmed failing identically on clean HEAD
  (pre-existing).

- tail_validation.py driven to zero ruff findings (was 61 complexity sites
  at batch start): the summary-build pipeline converted to a
  `_TailSummaryBuildRun8616` dataclass (context/support collection,
  normalization, node processing, finalize phases), boundary-fingerprint
  dispatch, contextual callsite maps, observable-location and
  prunable-write scans, and ~40 validation-delta suppressors split into
  typed helpers (delta-shape bundles, per-field gates, evidence matchers,
  shared touched-fields and other-fields-stable gates). Refactor surfaced
  and fixed ~14 new mypy errors back to the file's baseline (typed
  `summary_inventory`, `observed_locations` as `StackObservedLocations8616`,
  tuple/cache element annotations). Owning suite: 384 passed; the
  switch-decision-tree compare test fails identically on clean HEAD
  (pre-existing).

- decompiler_postprocess_stage.py driven to zero ruff findings (was 81
  complexity sites at batch start): materialization-loop matchers,
  instruction-window helpers, validation-delta classifiers, clone walkers,
  and stack-arg/prototype paths split into typed module helpers and
  run-state dataclasses. One real regression found and fixed during review:
  the `active_status_flag_lift_context_8616` wrapper around `_decompile_8616`
  had been dropped by an earlier splice and is restored. Owning postprocess
  suite: 639 passed, 2 confirmed pre-existing baseline failures.
  Focused mypy needs sibling promoted modules on the command line —
  `follow_imports=skip` makes off-run imports Any and reports false
  no-any-return errors otherwise.

- cli_c_text_postprocess.py driven to zero ruff findings (was 59
  complexity sites at batch start): signature/declaration normalizers,
  unused-declaration/staging pruners, fragment-carrier and stack-pointer
  rewrites, COD alias annotation, boolean-condition repairs, and helper-call
  formatting split into typed module helpers, run-state dataclasses, and
  shared arg-splitter/brace-scan utilities. Text-layer boundary preserved —
  cleanup/formatting only, no semantic recovery moved into this layer.
  Owning suites: 113 passed. Three COD CLI regressions
  (strlen stack-local copy, dos_getReturnCode, dos_loadProgram) fail
  identically on bare HEAD without this file's changes, at a
  frontend-lifter gate (`proven dead status-flag writes` in
  status_flag_lift_context.py) — pre-existing, upstream of this layer;
  clean cc2d1a195 baseline fails the same tests on an MSC51 recompile
  UnicodeDecodeError (env-level subprocess decode, also pre-existing).

- cli_c_ast_rewrites.py driven to zero ruff findings (was 59 sites at
  batch start, incl. a 365-complexity `_impl` closure): the whole nested
  simplifier became `_StructuredSimplifyRun8616` — a typed run dataclass
  holding all alias maps, caches, and protected-expression ids — with all
  38 nested helpers promoted to methods. The 104-complexity `transform`
  split into `_BinarySimplifyCtx8616` plus ordered `_arm_*_8616` rewrite
  arms preserving pass order (widened pairs, far-pointer MK_FP, word
  deltas, const-fold via `_CONST_FOLD_OPS_8616`, bitwise terms, And/Mul/Shr
  arms, dead-init pruning). Conservative refusal semantics preserved:
  unproven OR-base widening still refuses, protected dereference address
  expressions untouched, alias resolution stays conservative. Owning
  suites: 20 passed (ast rewrites + simplifier identity), plus 98 in the
  related postprocess/access-trait/stack-lowering set. mypy: 34 errors,
  all pre-existing unused-ignore debt — zero net delta vs HEAD.
  `.codebase-memory` index artifacts refreshed.

## Open work (far obligations, all still unadmitted)

- Native machine-frame correction is implemented: the tracker had popped two
  bytes for both near and far CALLs. Semantics now supplies exact encoded
  frame width; the adapter records typed counters and refuses unknown frames.
  Baseline 2 failed / 1 passed, initial neighborhood 69 passed. Final width
  and refusal rerun: `.cache/native-call-frame-final-widths.log`.
  Linked `.cache/coverage-apply-twice-machine-frame.{c,err}` exits 4 with
  matching SI/DI save/restore slots and final whole-tail clean. New active
  blocker: typed function-pointer calls retain `arg_6 & 0xffff`, rejected
  by gcc. Fix pointer target materialization at its owning lowering boundary;
  do not repair rendered C or assert unknown target preservation.
  Scoped Ruff/MyPy pass; quality-dev exits 2 on repository debt.
  Final focused result: 73 passed in 32.19 seconds (seven workers, JIT),
  including near/far 16/32-bit machine frames and refusal controls.
  Existing default pipeline is in its QuickC external lane (child PID
  3129058); do not restart it or count it as acceptance of this later fix.
- Fresh frame-boundary probe finished exit 4 at 10:30 local on September 24.
  `.cache/coverage-apply-twice-frame-boundary.err` proves the rebased native
  boundary accepts both indirect calls (0x1010, 0x101c), consuming all 12
  classified machine-frame effects with zero failures. Thus the observed
  four-byte save/restore coordinate drift is not explained by rejected
  indirect CALL-frame consumption. Next inspect surviving pre-SSA argument
  pushes/cleanup and native SP tracking. The direct-address fallback has an
  unmatched return edge and is a distinct path; no function acceptance claimed.
- Default gate pytest lane has now finished: 6,468 passed, 23 failed,
  10 warnings in 1,888.10 seconds. Pipeline PID 3110637 remains live at
  10:30 local; external-lane completion is not yet established. Preserve
  `.cache/pointer-slot-replay-pipeline.log`; do not launch a duplicate gate.
- `apply_twice` far now retains both pointer/value arguments in linked replay
  `.cache/coverage-apply-twice-pointer-slots.{c,err}`, but still exits 4 with
  `validation_failed` / `unassigned-stack-local`. It is not accepted.
- SI/DI save provenance is lost at calls with incomplete typed stack effects;
  final restore reads at `SS:BP-8..-5` remain uninitialized.
- Diagnostic replay `.cache/coverage-apply-twice-call-proof-seeded.err`
  finished, exit 4. First far call refuses `STACK_ALLOCATION_UNPROVEN`;
  both indirect calls refuse `TARGET_UNRESOLVED`. Set `PYTHONHASHSEED=0`
  before launching in-process probes:
  otherwise `decompile.py` exec-restarts and drops installed Python hooks.
  The first unseeded probe timed out and produced no hook evidence; do not
  interpret its empty observations as absence of call effects.
- Far allocation proof now requires the binary helper's exact return-frame
  kind and retains conflicting proofs for refusal. Baseline 3 failures / 12
  passes; initial neighborhood 42 passed; MyPy/Ruff clean. Final test run hit
  a transient concurrent IndentationError in `calling_convention_compat.py`;
  that file now compiles. Final rerun: 44 passed in 53.60 seconds, log
  `.cache/far-allocation-final-stable.log`.
  Linked replay `.cache/coverage-apply-twice-far-allocation.err` finished
  exit 4: allocation call now PROVEN/BP-preserved, leaving exactly the two
  indirect TARGET_UNRESOLVED refusals. SI/DI validation remains failed.
- Further diagnostic `.cache/coverage-apply-twice-spill-prune.err` finished
  exit 4: the spill-prune owner recognized SI/DI pairs but made no deletions.
  Do not change that owner on the assumption it removed these saves.
  Native codegen snapshots are now being captured in session `84619`, log
  `.cache/coverage-apply-twice-native-saves.err`, to locate their actual loss.
- Direct-caller census completeness only covers discovered direct callers;
  it does not close unknown incoming edges. Do not use it alone to assume
  the indirect targets or their preserved-register effects. The fixture has
  multiple pointer targets and branch-selected pointer arguments.
- Prior default pipeline process/session are gone; its log records only
  prerequisite 292 passed. Structured summary is stale (September 20), so
  no full-pipeline success is established. A fresh gate remains required.
- Expanded pointer neighborhood: 38 passed in 48.42 seconds after completing
  old mocks with the missing empty callee decoder surface. No production
  catch added. New default gate log: `.cache/pointer-slot-replay-pipeline.log`.
  Gate session `68055`, PID `3110637`, remains live; prerequisite 292 passed.
- Failed quality-dev (exit 2) log `.cache/pointer-slot-replay-quality-dev.log`
  reports repository Ruff debt and a mypyc type error in
  `validation_control_flow.py`; focused MyPy passes on both replay owners.
- `quality-dev` has typing failures outside this slice in
  `validation_condition_storage_views.py` and `semantics/call_stack_effects.py`;
  full log: `.cache/far-pointer-rebuild-quality-dev.log`.
- `fill_bytes`/`swap_ptrs`/`offset_copy` far-frame argument reads.
- Candidate manifest reruns for `large-far-pointer-001` and
  `large-far-function-001` once the above validate.

## Verification commands

- Focused regressions: `pytest angr_platforms/tests/...` (277 passing
  across the stack-prototype/GP-restore/CC/fn-pointer suites).
- Single function: `./.venv/bin/python decompile.py --no-alternate-source-c
  --timeout 60 --proc NAME --proc-kind {NEAR,FAR} <EXE>` in the retained
  `.cache/compiler-coverage/large-far-function-001/case-000` artifacts.

## Complexity cleanup — callsite materializer flatten (cont.)

- `_CallsiteStackArgsMaterializer8616` fully flattened: 184-def mega + nested
  def trees converted to methods with explicit ctx params (bindingsite-safe).
- `_normalize_materialized_call_args` split: per-arg verdict method
  `_normalize_rhs_register_arg_8616`, `_postprocess_normalized_arg_8616`,
  `_resolve_register_rhs_chain_8616`, `_normalize_call_helper_offset_8616`,
  `_group_single_far_pointer_arg_8616`, plus resolver/debug helpers.
- `_set_materialized_call_args` split: `_regroup_args_from_summary_widths_8616`,
  `_apply_zero_arity_ownership_8616`.
- `_direct_expr_from_push_source_8616` split: per-kind materializers
  (`bp_value`, `bp_addr`, `bp_index_addr`, `global_value`, `global_index`,
  `seg_indirect`, `expr_ops`).
- `_collect_backtracked_stack_args` nested defs hoisted:
  `_rhs_matches_call_return_addr_8616` (module), `_filter_call_return_frame_rhss_8616`,
  `_expand_typed_carrier_defs_8616`, `_trailing_stack_store_rhss_after_last_call_8616`.
- decompiler_postprocess_calls.py C901 findings ~300+ → 40; owning tests
  verified at every checkpoint (178 passed, 2 pre-existing failures).
- Additional splits: `_trailing_stack_store_rhss_after_last_call_8616`
  (typed/non-probe collect helpers), `_collect_backtracked_stack_args`
  non-store tail, `_stack_store_rhs_verdict_8616`,
  `_dirty_setup_candidate_reason_8616` + hoisted debug fns,
  `_post_call_relocate_gate_8616`, `_inline_arg_backtrack_step_8616`,
  `_consumed_setup_lhs_tail_verdict_8616`, `_remat_arg_verdict_8616` +
  `_remat_debug_8616`/`_remat_stack_variable_verdict_8616`,
  `_pre_call_alias_artifact_candidate_ok_8616`,
  `_ret_arg_without_nearby_call_8616`, `_push_op_scalar_step_8616`
  dispatch table (per-op verdicts), `_resolve_shr_word_8616` +
  `_resolve_dirty_rhs_fallback_8616`, `_probe_next_call_debug_8616`,
  `_pointer_arg_quality_8616`/`_value_arg_quality_8616`,
  `_setup_*_byte_variants_8616` per-op byte builders.

## Complexity grind continued (decompiler_postprocess_calls.py)
- Flattened nested defs file-wide via binding-site-aware flattener; `_impl` parents
  moved to module-level fns; DX/AX pair fold, scalar-global remnant scan, inventory
  publish, prototype evidence all split into typed helpers.
- Repaired stranded tails from scripted edits (`_pre_call_alias_artifact_candidate_ok`,
  `_inline_arg_backtrack_step`, `_debug_clobber_refuse` missing `call` param).
- Cleared all non-complexity ruff findings (collapsible-if, needless-bool, dict-keys,
  enumerate, dead vars, stale noqas).
- Remaining in file: 34 complex-structure + 19 PLR0916, dominated by
  `_rewrite_block_body` (~134). Baseline holds: 178 passed, 2 pre-existing fails.

## Complexity grind finished (decompiler_postprocess_calls.py → 0 findings)
- All PLR0916 boolean sites extracted into named module predicates; all remaining
  complex-structure sites split into typed `*_8616` helpers.
- `_rewrite_block_body` (134 branches) decomposed into phase helpers:
  `_rewrite_stmt_pre_gate_8616`, `_resolve_call_stmt_facts_8616` (returns frozen
  `_CallStmtFacts8616`), `_rewrite_probe_helper_stmt_8616`,
  `_rematerialize_call_stmt_8616` (drives `_resolve_call_arity_evidence_8616`
  → `_CallArityEvidence8616`, `_collect_call_evidence_flags_8616`
  → `_CallEvidenceFlags8616`, `_single_bp_direct_arg_stmt_8616`,
  `_strict_shape_remat_stmt_8616` → `_strict_remat_arm_{0..8}_8616`,
  `_remat_no_count_stmt_8616` → `_remat_fallback_args_8616` /
  `_remat_apply_fallback_args_8616` / `_remat_apply_backtracked_args_8616`),
  `_rewrite_child_blocks_8616` (child recursion via `_rewrite_child_merge_8616` /
  `_rewrite_switch_children_8616` / `_rewrite_deep_children_8616`),
  `_dedup_summaryless_call_stmt_8616`; module-level `_recover_call_evidence_gate_8616`
  + `_recover_debug_skip_8616`.
- Extracted helpers keep `continue`/`i += 1` semantics via `int | None`
  "consumed index" returns; loop-carried probe facts returned as tuples.
- Final: `ruff check` = 0 findings on the file; owning tests 178 passed,
  same 2 pre-existing failures (unchanged semantics).

## Complexity grind finished (decompiler_postprocess_globals.py → 0 findings)
- Hoisted nested defs (`visit`, `_impl`) to module fns; split word-global
  load/store traversal (`_visit_word_global_stores_8616`,
  `_word_global_store_pair_step_8616`), type application across
  `variables_in_use` / `cexterns` / `unified_local_vars`, and unused-global
  collect + drop helpers.
- Owning subset: 5 passed; ruff clean.

## Complexity grind finished (ir/ir_canonicalize_8616.py → 0 findings)
- `_impl` nested defs hoisted; per-op canonicalization consolidated into
  `_canonicalize_binop_dispatch_8616`; assoc `And`/`Or` flattening split into
  `_assoc_const_gate_8616` / `_assoc_walk_8616` / `_assoc_rebuild_8616` /
  `_assoc_combine_8616`; `Xor` walk hoisted to `_xor_walk_8616`; constant
  folding table-driven via `_CONST_FOLD_TABLE_8616` + `_fold_const_pair_8616`.
- Owning tests: 59 passed (canonicalize + full-width masks + layer boundaries).

## Complexity grind finished (widening/widening_rules.py → 0 findings)
- `collect_bp_stack_access_widths` split into summary-scan + capstone helpers.
- `_coalesce_direct_ss_local_word_statements` → `_DirectSSLocalCtx8616` ctx +
  `_ss_local_pair_lhs_8616` / `_byte_store_pair_lhs_8616` / `_direct_ss_pair_step_8616`.
- `_coalesce_segmented_word_store_statements` (94) → `_WordStoreCoalesceCtx8616` +
  typed helpers: node debug kinds, `_expr_width_bits_8616`,
  `_match_loaded_word_pair_expr_8616`, `_replace_loaded_word_pair_expr_8616`,
  `_word_lvalue_for_addr_8616`, `_runtime_word_store_lvalue_8616`, window steps
  (`_word_store_triple_step_8616` / `_word_store_quad_step_8616` /
  `_word_store_pair_step_8616` → runtime/ss-local/alias pair helpers),
  `_wstore_alias_pair_unjoinable_8616`, shared `_visit_structured_children_8616`.
- Owning tests: 63 passed (widening rules + stack arg widths + far load width +
  wrapped locals).

## Complexity grind finished (decompiler_postprocess_typed_conditions.py → 0 findings)
- Register-expr index split (`_register_exprs_from_assignment_8616`);
  `_build_c_expr_for_operand` → `_reg_operand_expr_8616` /
  `_ir_value_operand_expr_8616` / `_compat_operand_expr_8616`.
- Signed stack-arg retagging split across `_retag_body_stack_arg_cvars_8616`,
  `_retag_unified_local_vars_8616`, `_retag_arg_list_cvars_8616`,
  `_rebuild_args_from_arg_list_8616`, `_rebuild_args_from_old_prototype_8616`,
  `_publish_signed_arg_prototype_8616`.
- `_is_flag_based_condition_node` helpers hoisted; typed-condition apply
  decomposed into `_TypedConditionApplyCtx8616` + `_rewrite_*`/`_walk_*` helpers.
- Owning tests: 99 passed.

## Complexity grind finished (lowering/segmented_memory_lowering.py → 0 findings)
- `_match_segmented_memory_expr_8616` → `_access_prologue_8616` /
  `_decomposed_segmented_expr_8616` / `_linear_segmented_expr_8616`.
- `lower_runtime_segment_access_8616` → `_snapshot_adjusted_*` +
  `_lowered_matched_access_8616`.
- `materialize_runtime_helper_segment_carriers_8616` → `_collect_segment_carrier_proofs_8616`
  + `_SegmentCarrierCtx8616` + `_rewrite_segment_carrier_arg_8616`.
- `lower_runtime_ss_segment_helpers_to_stack_8616` → `_lower_ss_helper_lvalues_8616`
  + `_SSHelperLowerCtx8616` + `_ss_helper_transform_8616`.
- `apply_runtime_segment_lowering_8616` → early/late pass-chain helpers +
  `_runtime_lowering_transform_8616` (functools.partial) + `_publish_runtime_lowering_stats_8616`.
- `_materialize_binary_proven_near_pointer_argument_8616` → canonical-cvar,
  facts gate, missing-arg materialize, cardinality gate, commit helpers.
- `_near_pointer_arg_access_8616` → indexed/zero-plus access helpers +
  `_near_pointer_fact_cvar_8616` / `_near_pointer_width_facts_8616`.
- `_lower_typed_pointer_register_carrier_stores_8616` (44) → `_CarrierStoreCtx8616`
  + `_carrier_setup_gate_8616` / `_carrier_use_gate_8616` /
  `_extend_carrier_store_pair_8616` / `_carrier_consumption_ok_8616` /
  `_apply_mixed_projection_store_8616` / `_apply_wide_or_single_store_8616` /
  `_consume_one_carrier_store_8616` / `_consume_carrier_setup_8616`.
- Owning tests: 352 passed (one env-only kvikdos UnicodeDecodeError deselected:
  test_recompile_check_msc51_accepts_portable_signed_fixed_width_aliases).

### lowering/ir_segmented_load_carriers.py — promoted Ruff clean (12 → 0)

- `_constant_segment_offset_expr_8616` → `_matching_linear_base_indexes_8616`
  + `_residual_offset_expr_8616`.
- `_offset_expr_8616` → `_offset_base_terms_8616` (runtime/GP base projection).
- `_load_facts_8616` → `_track_mov_constants_8616` + `_stable_load_address_8616`
  + `_debug_load_fact_8616`.
- `_same_block_reload_for_read_8616` → `_same_block_window_clear_8616` +
  shared `_identity_register_names_8616` / `_use_block_for_addr_8616`.
- `_inherited_instruction_addresses_8616` → hoisted `_collect_inherited_addresses_8616`.
- `_nearest_linear_logical_fact_8616` (26) → `_nearest_dominating_fact_8616` +
  `_ssa_reachable_set_8616` + `_path_window_instructions_clear_8616` +
  `_debug_nearest_fact_8616`.
- `_insert_before_unique_following_statement_8616` (22) → hoisted
  `_collect_owner_paths_8616` + `_insertion_candidates_8616` +
  `_select_unique_insertion_8616` (tie-break preserved).
- `_materialize_missing_logical_assignments_8616` → `_collect_register_def_reads_8616`
  + `_materialize_identity_assignment_8616` + `_debug_logical_insertion_8616`.
- `_read_side_logical_replacements_8616` → `_read_replacement_for_node_8616`.
- `materialize_ir_segmented_load_carriers_8616`/`transform` (22/20) →
  `_CarrierTransform8616` dataclass dispatch (`_read_replacement`,
  `_assignment`, `_constant_segment_rhs`, `_logical_assignment`,
  `_register_assignment`, `_dirty`) + `_replace_constant_dereference_8616`
  (functools.partial). Mutation/classification order preserved.
- Owning tests: 73 passed (carriers + reload provenance + load origins).
- Layer boundaries: 15 passed.

### lowering/stack_prototype_materialization.py — promoted Ruff clean (8 → 0)

- `_existing_stack_cvars_by_offset_8616` → deduped scan loops.
- `_callsite_stack_arg_widths_8616` → object-width scan + source gate +
  per-summary body helpers.
- `_prune_stack_slots_covered_by_wide_args_8616` → deduped identical loops.
- `materialize_exact_trailing_stack_argument_8616` → gate + names recovery +
  publish tail helpers.
- `reconcile_exact_stack_argument_prototype_8616` (15) →
  `_ReconcileEvidence8616`/`_ReconcileArgResult8616`/`_ReconciledArgs8616`
  dataclasses + `_reconcile_width_evidence_8616`,
  `_conflicting_body_offsets_8616`, `_reconcile_one_arg_8616`,
  `_select_incoming_args_8616`, `_reconcile_width_facts_8616`,
  `_reconcile_args_8616`, `_publish_reconciled_prototype_8616`.
- `materialize_annotated_stack_prototype_8616` (13→0) →
  `_AnnotatedEntryCtx8616`/`_AnnotatedEntryResult8616`/`_AnnotatedMaterialization8616`
  + `_current_prototype_surface_8616`, `_current_arg_surfaces_8616`,
  `_annotated_entry_name_8616`, `_is_usable_annotated_name_8616`,
  `_materialize_annotated_entry_8616`, `_materialize_annotated_entries_8616`,
  `_commit_annotated_materialization_8616`, `_publish_annotated_prototype_8616`.
- Semantic fix preserved: annotated names validated by
  `_is_usable_annotated_name_8616`, distinct from prototype-name predicate.
- Owning tests: 238 passed (16 stack-prototype test files).
- Layer boundaries: 493 passed; architecture-contract failure is
  pre-existing (145 violations, none in this file).

### Single-finding sweep + scripts/tests cleanup batch

- `generated_external_function_contracts.py`: `_type_contract` →
  `_named_type_contract` tag-dispatch split.
- `generated_translation_unit_assembly.py`: `assemble_generated_translation_unit`
  → `_collect_declaration_sets` + `_canonicalize_declaration_sets`.
- `cli_mkfp_simplify.py` / `cli_cod_globals.py`: nested transform closures →
  `_MkFpFold8616` / `_CodGlobalLoadFold8616` dataclass folds +
  `_storage_object_artifact_for`.
- `function_ir_ssa_cache.py`: `_hydrated_hit_matches_8616` predicate.
- `function_ir_ssa_cache_key_8616`: node-hash + edge-collection splits.
- `function_graph_extent_repair.py`: `repair_undercovered_transition_sources_8616`
  → `_out_of_block_ins_addrs_8616` + `_extent_repair_plan_8616`; raw_fact_count
  derived from normalized sets.
- `rizin_evidence.py`: `collect_rizin_evidence` → typed fact collectors
  (`_function_facts`, `_xref_facts`, `_string_facts`, `_symbol_facts`,
  `_stack_var_facts`, `_cc_facts`, `_empty_evidence`, `_optional_int`).
- `indexed_alias_program_context.py`: `_transported_widening_bundle_8616` +
  `_reused_persisted_context_8616`.
- `indexed_alias_program_parallel.py`: worker hoisted + pool-lifecycle split.
- `direct_stack_move_pretest_body_evidence.py`: `Any` → `nx.DiGraph`.
- `direct_request_cache.py`, `serial_clean_worker_evidence.py`,
  `fork_timeout.py`, `batch_decompile_procs.py`,
  `generated_c_indexed_argument_contract.py`, `mypyc_build_cache.py`,
  `pytest_inventory_check.py`, `pytest_profile.py` (`_record_rss_sample` +
  `_record_outcome`), `pytest_dynamic_schedule.py` (`_WaveScheduler8616`),
  `agent_test_focus.py` (`_selection_payload`/`_print_plan`/`_run_selection`).
- Test files: `test_x86_16_structuring_lowering_order.py`
  (`_is_named_span_call`), `test_x86_16_cod_regressions.py`
  (`_DerefSubtreeCodegen` + `_build_deref_subtree_statements`),
  `test_x86_16_consumed_stack_address_setup.py` (`_SETUP_FAILURE_MUTATORS`
  dispatch table), `test_x86_16_indexed_stack_ranges.py`
  (`_TwoLoopOptions` + 9 fixture-construction helpers).
- Owning tests: 47 + 1 passed; `agent_test_focus --help` ok.
- Promoted inventory: 1212 findings across ~106 files (was 1238/~130).

### inertia_decompiler/runtime_support.py — promoted Ruff clean (15 → 0)

- `install_angr_peephole_expr_bitwidth_guard`/`_guarded_handle_expr` → module
  helpers `_normalize_replacement_bits_8616`, `_clinic_skip_complex_expr_gate_8616`,
  `_peephole_rewrite_loop_8616`, `_guarded_peephole_handle_expr_8616` + thin
  installed closure.
- `_seqnode_children_8616` → `_seqnode_attr_children_8616` +
  `_seqnode_cases_children_8616`.
- `_loop_exit_default_relation_8616` → `_collect_loop_exit_nodes_8616` +
  `_loop_exit_default_status_8616`.
- `_seqnode_map_region_id_8616` → `_seqnode_candidate_payload_8616`,
  `_preferred_exact_region_summary_8616`, `_region_missing_result_8616`,
  `_region_containing_summaries_8616`, `_exact_region_match_8616` +
  `_SEQNODE_PREFERRED_TYPES_8616`.
- `_seqnode_switch_artifact_mappings_8616` (37) → shared helpers
  `_common_int_path_8616`, `_switch_mapping_status_8616`,
  `_expanded_path_samples_8616`, `_expanded_region_mappings_8616`,
  `_expanded_root_geometry_8616`, `_expanded_root_verdict_8616`,
  `_expanded_root_switch_fields_8616` + per-artifact
  `_seqnode_switch_artifact_mapping_8616`. Nested
  `_expanded_root_normalized_body_8616`/`_path_tuple` deduped to existing
  module functions.
- `_graphregion_switch_artifact_mappings_8616` (33) → same shared helpers +
  hoisted `_common_prefix_len_8616`,
  `_default_case_region_ids_by_default_8616`,
  `_resolve_ambiguous_default_mapping_8616`,
  `_disambiguated_default_mappings_8616`, `_ambiguous_mapping_samples_8616` +
  per-artifact `_graphregion_switch_artifact_mapping_8616`.
- `_expanded_root_normalized_body_from_summary_8616` → `_append_int_values_8616`
  + `_accumulate_branch_subtree_ids_8616` + `_accumulate_branch_split_ids_8616`.
- `install_angr_pre_codegen_seqnode_probe_guard`/`_guarded_init` →
  `_record_pre_codegen_seqnode_probe_8616` with
  `_pre_codegen_condition_evidence_8616`,
  `_pre_codegen_grouped_switch_artifacts_8616`,
  `_pre_codegen_stage_mappings_8616`,
  `_pre_codegen_switch_replacement_probe_8616`; `_guarded_init` now a thin
  wrapper.
- `guard_angr_clinic_stage_markers` (46) + `_peephole_optimize` (21) →
  `_ClinicGuardState8616` dataclass (stage clock + counters + stats), wrapper
  factory `_clinic_stage_guard_8616`, module bodies
  `_guarded_simplify_block_8616`, `_guarded_peephole_optimize_8616`,
  `_debug_clinic_flags_8616`, `_clinic_peephole_capped_8616`,
  `_fast_block_peephole_8616`, `_debug_skip_complex_block_8616`,
  `_guarded_peephole_optimize_exprs_8616`, `_guarded_compute_propagation_8616`,
  `_NoPropagationResult8616`. Shared stage-marker wrappers now produced by the
  factory; peephole stmt/multistmt pair deduped.
- `run_with_timeout_in_daemon_thread` → `_enable_thread_stack_dump_8616` +
  `_daemon_thread_result_8616`.
- `guard_angr_structuring_codegen_internal_timing` (19) →
  `_timed_stage_guard_8616` factory + `_bounded_stage_guard_8616` +
  `_install_bounded_lowering_guards_8616`; ss-linear patch intentionally stays
  installed (documented).
- Owning tests: 7 + 30 passed (timing guards, msc6 runtime state, runtime
  support traces, clinic recovery contracts, clinic semantic stages).

### structuring_analysis.py — 7 promoted complexity findings → 0

- `_branch_split_partition_evidence_8616` (14) — earlier split into
  partition-stat helpers.
- `_collect_edge_guard_decision_tree_cases_8616` (43) →
  `_DecisionTreeScan8616` state dataclass with `record_case`,
  `record_empty_region`, `record_branch_split`, `_affine_step`,
  `continuation_step`, `_normalization_status`, `summary`; plus
  `_branch_split_child_summary_8616` and `_attach_expanded_root_summary_8616`.
  BFS order, affine-offset propagation, duplicate/mismatch counters, and all
  summary keys preserved.
- `_execute` (11) → flattened nested `_impl`; iteration body extracted to
  `_structure_iteration_8616`.
- `_try_edge_guard_switch_cascade` (22) → `_CascadeScan8616` dataclass +
  `_cascade_step_8616` + `_publish_edge_guard_cascade_8616`; module collector
  `_cascade_guarded_successors_8616`.
- `_find_next_edge_guard_switch_head_8616` (14) → `_next_head_walk_step_8616`
  returning (candidates, pushes).
- `_try_if_then_else` (11) → flattened nested `_impl`; merge tail extracted
  to `_merge_if_then_else_8616`.
- Owning tests: 99 passed (structuring switch/cyclic/grouped/codegen/
  integration).

### stack_c_ast_matching.py / validation_dataflow.py / corpus_scan.py / codeview_nb02_nb04.py — 30 findings → 0

- `stack_c_ast_matching.py` (7): hoisted AST walkers to module scope
  (`_iter_statement_nodes_8616`, `_push_statement_node_children_8616`), deduped
  scaled-segment matching into `_scaled_segment_name_8616`, converted
  `_stack_bp_displacement_8616`'s nested `collect` into the
  `_StackBpDisplacement8616` accumulator with per-term helpers.
- `validation_dataflow.py` (8): `_DefUseWalker8616` dataclass hoists the
  nested `_check_reads`/`_walk` closures; `walk` split into per-node-kind
  transfer methods. `_predicate_fact_8616` → `_predicate_node_token_8616`/
  leaf/op helpers; `_indexed_stack_storage_key_8616` → base/element/untrackable
  helpers; PLR0916 Shr gate → `_shr_rhs_byte_offset_8616`.
- `corpus_scan.py` (8): flattened all nested `_impl`s; `classify_failure` →
  `_stage_failure_class_8616`/`_failure_class_from_message_8616`;
  `scan_function` stages → `_scan_function_stages_8616` plus
  probe/prefix/cfg-preflight/cfg-shape/decompile helpers.
- `codeview_nb02_nb04.py` (7): `_NB0204Collections8616` sink + label/legacy
  subsection dispatch split; shared directory-entry walker; record/type
  helpers for symbol parsing and source-module line tables.
- Owning tests: 75 + 82 + 38 + 14 passed.

### structuring_codegen.py — 11 promoted complexity findings → 0

- Statement-ownership traversal split into `_c_statement_parent_paths_8616`,
  `_c_positioned_statement_ownership_8616`, `_statement_container_parent_span_8616`
  state helpers; `_populate_region_statements_from_cfunc_8616` simplified.
- `split_distinct_condition_call_occurrences_8616` → occurrence collector +
  per-call processing helpers.
- `coalesce_shared_call_side_effect_statements_8616` → context/state class.
- `evaluate_typed_edge_switch_replacement_safety_8616` (43) →
  `_SwitchSafetyScan8616` scan context: `_resolve_owned_statements_8616`,
  `_record_case_debug_8616`, `_collect_body_statements_8616`,
  `_single_container_span_8616`, `_dominant_container_span_8616`,
  `_owner_index_span_8616`, `_classify_covered_span_8616`. All refusal
  reasons, span sources, and debug projections preserved.
- Owning tests: 162 passed (segmented stack alias, structuring pass
  validation, induction summaries, runtime timing guards).

### structuring/condition_materialization.py — 7 promoted complexity findings → 0

- `materialize_same_block_condition_register_projections_8616` →
  `_matching_conditions_for_node_8616` + `_project_binary_condition_node_8616`
  with `_ProjectionNodeDelta8616` stat deltas.
- `_materialize_cfg_condition_chain_expr_8616` (30) → `_CfgChainBuilder8616`
  dataclass hoisting `prove_wide_pair`/`build_from_address`/`build_from_condition`
  closures plus `_proven_call_chain_expression_8616`.
- `_materialize_cfg_shared_body_condition_chain_expr_8616` →
  `_SharedBodyBuilder8616` + `_lower_shared_body_wide_8616`.
- `_materialize_cfg_single_branch_expr_8616` (33) → early-expr, region-expr,
  body-chain, fallback helpers plus `_proven_single_return_orientation_8616`
  returning `_SingleReturnProof8616`.
- `_materialize_existing_wide_call_return_conditions_8616` →
  `_lower_wide_call_return_pair_8616` with `_WideReturnPairDelta8616`.
- `materialize_structuring_condition_chains_8616` (80) →
  `_ConditionChainRun8616` pass context with `_semantic_call_arm_8616`,
  `_multi_arm_node_8616` (+ duplicate/exact/wide-return/shared-body arms),
  `_single_arm_node_8616` (+ root-fact selection, assignment diamond,
  arm replacement, apply helpers) and `_SingleArm8616`/`_ArmReplacement8616`
  per-node state. All debug projections and refusal paths preserved.
- Owning tests: 160 passed.

## decompiler_postprocess_jcc.py: promoted findings 31 -> 0

- `_rewrite_decoded_jcc_conditions_8616` (~421) -> `_JccRewriteRun8616`
  pass dataclass: 65 nested closures converted to `self.`-state methods via
  tokenize-based rename; `run` split into `_run_setup_8616`,
  `_run_collect_signatures_8616`, `_run_rebind_and_sibling_polarity_8616`,
  `_run_rewrite_node_conditions_8616` (+ `_rewrite_condition_pairs_8616`),
  `_run_prune_and_publish_8616`.
- Shared expression walkers hoisted: `_walk_c_expr_children_8616`,
  `_m_statements_from_root_8616`/`_flatten_c_statements_8616`,
  `_m_child_statement_roots_8616`, `_m_condition_exprs_from_stmt_8616`,
  `_m_assignment_rhs_has_real_call_8616`, `_m_expr_is_return_register_8616`,
  `_m_root_contains_ins_addr_8616` (+ `_root_children_8616`,
  `_root_tags_match_ins_addr_8616`), arg-offset collectors.
- `_CallReturnGuardScan8616` and `_CallReturnRebind8616` dataclasses replace
  nonlocal-closure collectors.
- `_decoded_condition_replacement` (38) split into pre-key gates, candidate
  resolution, signature/raw-state/materialized-keep gates, unknown-polarity
  inversion (`_DecodedGateResult8616`), and final replacement helpers.
- All refusal counters, debug events, consumed-low prune semantics, and
  call-return rebind behavior preserved.
- Owning tests: 159 passed (incl. idempotent typed-condition ordering).

## decompiler_postprocess_simplify.py: promoted findings 24 -> 0

- `_simplify_structured_expressions_8616` (345) -> `_SimplifyExpressionRun8616`
  pass dataclass: ~35 nested closures converted to methods (same tokenize
  rename as JCC); `run` split into `_collect_cfunc_roots_8616`,
  `_apply_root_transforms_8616`, `_refresh_root_children_8616`.
- `transform` (39) split into `_fold_stat_counted_8616`,
  `_fold_binary_transform_8616` (+ `_fold_concat_8616`,
  `_fold_zero_operand_binary_8616`, `_fold_or_word_or_zero_8616`),
  `_fold_not_transform_8616`, `_fold_tail_binary_8616` (+ `_fold_cmp_against_zero_8616`).
- `_fold_pure_constant_binary_8616` -> `_PURE_BINARY_FOLDS_8616` operator table.
- Counter bumps unified under `_bump_stat_8616` (dynamic codegen boundary).
- `_expr_contains_stack_or_flags_register_8616` -> offsets collector +
  recursive walker + shared `_seq_structured_children_8616` iterator
  (also used by `_contains_unresolved_virtual_expr_8616`).
- `_materialize_word_or_update_statements_8616` (107) -> methods on the same
  run class: `_gate_arithmetic_update_pair_8616`, `_match_arithmetic_delta_8616`,
  `_gate_duplicate_shift_update_8616`, `_match_duplicate_or_base_8616`,
  `_log_*_refuse_8616` debug helpers, `_probe_word_or_pair_8616`,
  `_try_duplicate_shift_8616`, `_try_arithmetic_pair_update_8616`,
  `_try_word_or_update_8616`, `_rewrite_statement_list_8616` driver.
  All INERTIA_DEBUG_WORD_OR_UPDATE refusal/match logs preserved verbatim.
- `_eliminate_single_use_temporaries_8616` (51) -> `_SingleUseTemporaryRun8616`
  accumulator + module-level `_is_virtual_register_temporary_8616`,
  `_crosses_nested_execution_scope_8616`, `_safe_inline_expr_8616`,
  `_count_var_uses_8616`/`_replace_var_use_8616` (+ seq/pairs/attrs helpers).
  Frozen `SingleUseTemporaryEliminationStats8616` still published per run.
- Owning tests: 90 passed.

## far_pointer_segmented_load_evidence.py (lowering) — clean

- Recovered file from truncated write (disk-full mid-edit); restored tail from
  HEAD verbatim, then refactored.
- `recover_far_pointer_segmented_loads_8616` (22) -> `_FarPointerScanState8616`
  scan-state dataclass + per-arm helpers `_apply_far_pointer_load_8616`,
  `_update_stack_slot_target_8616`, `_apply_mov_register_copy_8616`,
  `_apply_shift_index_8616`, `_invalidate_register_destination_8616`.
  Arm ordering and `continue` semantics preserved exactly.
- Owning tests: 7 passed.
- Disk: freed ~2.1G on /home (caches); /tmp overflow files removed.

## gp_stack_restore / positive_bp_arguments / structured_intrinsics / validation_storage — clean

- `gp_stack_restore.py`: `_snapshot_insertion_candidates_8616` + `_GpRestoreReplacer8616`
  (replacer closure -> dataclass) + debug/anchor/assignment helpers.
- `positive_bp_arguments.py`: `materialize_positive_bp_arguments_8616` (57) ->
  `_PositiveBpRun8616`/`_DesiredInterface8616` run dataclasses + phased helpers
  (prepare, collect, layout, body-plan, desired, source-types, publish, prune).
- `structured_intrinsics.py`: `_decoded_insert_operands_8616`,
  `_insert_identity_occurrence_counts_8616`, `_insert_statement_lists_8616`,
  `_prune_statement_list_8616`.
- `validation_storage.py`: `validate_storage_identities_8616` (42) ->
  `_StorageValidationRun8616` with per-phase methods (global/stack/field/copy).
- Owning tests: 422 + 77 + 54 passed. One tail_validation failure is
  pre-existing (baseline red, unrelated kvikdos/env path).
- cli_access_traits -> `_AccessTraitCollector` (traits buckets + stride evidence
  + indexed-key + address summarizer). cli.py lazy-proxy splits.
  cli_linear_aliases -> `_BytePairSeedVisitor`. telemetry -> env/summary splits.
  pytest_resource_history -> payload-decode splits. import_ultra_quickc_fixtures
  -> fixture-result/stage/decompile helpers. test files -> hoisted fakes +
  `_recorded_stub_8616`.
- One `test_x86_16_cli` failure: kvikdos non-UTF8 subprocess decode
  (pre-existing environmental, in recompile_check path).
- `turbo_debug_tdinfo.py`: full TDS 3.x table coverage — flat indexed type
  table (8B records, 1-based), member stream (fields/methods/var-decls/
  offset-exts/trailers), builtin descriptors + range extensions,
  MEMBER_FUNCTION(0x2D) + VL_STRUCT/VL_UNION extension slots, class table
  (11B: parent idx/count, member ordinal, name, vptr, info), parent table,
  module-class ranges, line/scope/correlation tables; per-module type
  copies reconciled by run anchoring + continuation; member offsets solved
  against aggregate trailer size (m_actor signal@82 matches TDUMP).
- `dump_debug_info.py`: serializes modules, sources, segments, classes,
  parents, module-class runs, line entries, scopes, correlations,
  descriptors (incl. builtin_type_id, member_ref), member lists
  (block_ordinal), and named raw_table_spans for every TDINFO region.
- `borland_mangling.py`: typed Borland C++ name demangler (`@scope@name$Q<types>`)
  — scopes, ctor/dtor/operator/conversion specials, builtins, near/far
  pointers & references, `<len>` class types, arrays, function-pointer
  signatures (`NQV$V`), member pointers, `T<n>` 1-based arg repeats,
  U/Z/X/W qualifiers. All 512 mangled names in RIPTIDE.EXE decode with
  zero errors; every function signature renders identical to TDUMP's own
  demangling (verified against TD.OUT). Exposed in the dump as
  `demangled_names` + per-list `method_signatures`.
- Member type resolution + `struct_declarations`: flat type indexes now
  render as C-style names via `TDINFO_BUILTIN_TYPE_NAMES` (evidence-mapped:
  id5=int, id8=uchar, id9=uint, id6=long, id0a=ulong, id4=char, id0=void,
  id0d/0f/10=float/double/ldouble; unconfirmed → builtin_NN).  Pointer
  targets recurse (m_actor far*, unsigned char far*, void(far*)() for fn
  pointers), array counts derive from size/elem_size when bounds absent
  (loop.cels → cel far*[16]), anonymous bitfield containers inline as
  `struct { unsigned deleting:1; ... }`.  Per-member `type_name` serialized;
  `struct_declarations` emits full reconstructed structs (m_actor 84B,
  FILE == stdio.h, GAME_CAST actors[200], PCXHEAD, TILEMAP 930B).
- MEMBER_FUNCTION extension decoded: the 8-byte slot after each 0x2D
  descriptor = `owner_type_idx u16, reserved u16, method_ordinal u16,
  flags u16` (owner verified: 0x6f3→m_actor, 0x7ce→text_pager; ordinal =
  the method's member-table record index, matching TDUMP [NNN]; flags
  0x1000=method / 0x3000=virtual — gui_item vtable methods — /0x9000).
  `TDInfoTypeDescriptor.extension` preserves all extension slots raw.
- `function_signatures`: symbol × descriptor join gives 492 signatures —
  seg:off address + demangled param list + descriptor return type
  (`m_actor::facing_actor` → `unsigned char`, `gm_read` → `long`,
  `check_new_pos` → `unsigned int`).  Return type is the piece mangling
  cannot express; this completes per-function signatures.
- BC31 empirical harness (dosbox + real BCC/TDUMP on TT/TT2/TT3.EXE) resolved
  the remaining unknowns: every Borland builtin id is now named from TDUMP's
  own Types Table — the exotics are Turbo-Pascal/DPMI shared builtins
  (0x07 signed quad→long long, 0x0C pascal_char, 0x0E pascal_real48,
  0x24 label, 0x28 pascal_bool, 0x2A pword, 0x2B tbyte); id4 corrected to
  `signed char` (TD32 folds plain char into id8=uchar, short/ushort into
  the int slots).  Pointer attr bits decoded: 0x01=huge, 0x04=_DS —
  serialized as `pointer_flags`.
- MEMBER_FUNCTION extension fully decoded against BC31: ext =
  `owner_type u16, vtab_offset u16, member_name_index u16, flags u16`.
  vtab_offset = byte offset into the owning class vtable (0 for
  non-virtual; gui_item/button virtuals at 4,8 — BC uses 2 slots for
  dtors).  Field [4:6] is the member's name-pool index (earlier
  `method_ordinal` was wrong — TDUMP's [NNN] is the name index; dump now
  emits `member_name_index`+`member_name`).  Flags high nibble
  (0x1000/0x3000/0x9000) varies per module for the same class —
  emission-state marker, not virtualness.
- New descriptor kind MEMBER_POINTER=0x38 (T K::*, size 4 data / 6 fn,
  ref=pointee descriptor, 8-byte ext slot).  SEGMENT=0x17 renders
  `T _seg *`, member ptrs render `member_ptr(T)`.
- VL_STRUCT/VL_UNION = named parameter-frame type tags (19 records named
  PARMS/WPPARMS/RPPARMS/SHOWPAGEPARMS, class STRUCT_UNION_OR_ENUM symbols);
  their member-payload encoding is the one unresolved format detail —
  redundant for reconstruction since signatures come from mangling.
- Coverage attribution verified: map entries are 1-based start indexes
  into the offsets table; regression test added
  (test_tdinfo_coverage_offsets_attribute_to_their_segment).

### Riptide reconstruction audit driven by recovered types (continued)

- Full struct dump cross-checked against decomp/riptide.h; every recovered
  struct annotated with original TDINFO names:
  m_actor (hit_x_step/my_map_width/my_map_height/hit_count/target_distance/
  aux_char_ptr; signal bitfield = deleting,in_window,dont_erase,hit,
  new_looping,sleep,aux1..aux9,active — door_open/s_aux2 kept as semantic
  names with orig-name comments), loop/g cel/pc_snd/voc/snd (all matched
  recon alias structs; loop_res was missing `name` far* at +0x02 — fixed,
  frames[] -> cels[16]), game_manager (player2_input/sprite_storage_total/
  game_flags[20]/sound_on/song/game_speed/player players[2]/loop_count/
  sound_count/all_loops[150]/all_sounds[40] — recon sounds[0x27]+tail was
  replaced with the real 40-entry array), tilemap (orig names incl.
  auxillery_ints[50], t_width/t_height/t_org/t_size/tiles/map_palette/speed/
  map — recon 'exploded'@0x39C is really 'speed'), ms_mouse, gui_item,
  vga_display+palette_cycle (speed/cur_shift/cycle_count/how_many/
  shifted_segments[48][16]/start/end/size/movsd_size), game_cast (size),
  level_def=game_level, score_entry=score_element (name[9]+pad),
  msl_def=projectile (sound/left_image/right_image/energy/max_speed/
  explosion/ego_hit_voc/bubbles), menu_entry=pull_down_item, map_entry=tattr.
- DERIVED-CLASS member offsets: TDUMP 'New Offset: 0013' marks the
  derived-part base (gui_item = 0x13; button.alignment@0x13 lives in
  gui_item's tail pad) — recon GUI layouts verified faithful.
- BUG FIXED in decomp/game.cpp kill_ego(): the `ego->status` guard was
  INVERTED (recon `== 2`, original `jnz` => `!= 2`) and the common tail
  (status=2, aux1=0x3C, kill_jason, control=0) was nested inside the else
  instead of covering both branches.  Effect: first death ran the gotcha
  grab path; repeated per-frame calls with status==2 re-ran
  load_loop("egodie2.l") until the element read failed — the reported
  `Error looking for loop : egodie2.l` crash.  Restructured to match
  seg03f9:1A65 flow exactly.
- check_new_pos return type corrected int -> uint (TDINFO signature).
- Rebuilt all touched translation units through BC31 -ml -3 -f -O -r- -vi-:
  actor/game/creature/gamemgr/gui/kbd/menu/scores/tilemap/util/vgadisp all
  compile with zero errors (only pre-existing warnings).

## decompiler_postprocess.py: promoted findings 55 -> 0

- Largest file cleared: 55 promoted sites incl. several 40-66 complexity
  `_impl` closures converted to typed run dataclasses
  (`_RetaddrPruneRun8616`, `_RepairExitGotosRun8616`, `_DedupeVarNamesRun8616`,
  `_SyncProtoLayoutRun8616`, `_ApplyAnnotationsRun8616`,
  `_SyncArgsFromAnnotationsRun8616`, `_ApplyRewritesRun8616`,
  `_PointerArgIndirectMaterializePass8616`, `_PruneFlagAssignRun8616`).
- Fat run bodies split into phase helpers: prototype resolution, candidate
  collection, arg promotion (annotated/fallback/legacy lanes), high-byte
  projection, return-carrier collapse, flag/return pruning, register
  read-before-write walkers (shared seq/pairs recursion helpers).
- Pointer-arg indirect-fact collection shares `_record_reg_indirect_fact_8616`
  for load/store arms; covered-slot prune shares
  `_prune_covered_stack_var_map_8616` over variables_in_use/unified maps.
- Semantic ownership preserved: all promoted closures are dynamic
  angr/codegen boundary accesses; no semantics moved into rewrite.
- Verification: ruff 0, mypy 0 (HEAD parity), arch-check 0 violations in
  file. Owning suite 631 passed; 13 failures all pre-existing —
  11 COD runs stop at the documented frontend-lifter blocker
  ("proven dead status-flag writes"), 1 wall-clock timeout flake,
  1 cli_decompilation CompilerHelperEvidenceKind attr failure on an
  untouched file.

## cli_function_discovery.py lint cleanup (ruff 53 -> 0)

- Same `_impl`-closure decomposition pattern: every promoted closure hoisted to
  module helpers or typed state dataclasses (`_SeededRecoveryState8616`,
  `_CandidateRecoveryCtx8616`, `_SeededExeCtx8616`, `_DisplayRankState8616`,
  `_SidecarShowcaseState8616`, `_GraphRepairDiscovery8616`).
- LST recovery split into lanes: exact-region derivation/validation,
  rebased-slice build/recover/evidence, lean windows, stitching + data-ref
  retry, truncated escalation, bounded fallback, tiny-candidate promotion.
- Seeded/cached/prologue recovery decomposed into context resolution,
  per-address processing, follow-on queueing, and merge/finalize phases.
- Label/seed ranking became ordered bucket helpers preserving the original
  elif priority; graph repair split into entry gates, BFS discovery, node
  seeding, and edge/return-site installation.
- Contract fixes preserved: stitch helper returns `(pair, score, stitched)` so
  `truncated` resets only on real stitch success; `nonlocal addr` rebase and
  raising semantics retained.
- Verification: ruff 0, mypy 0 (HEAD parity), arch-check 0 violations in file.
  Owning suite 78 passed; 5 failures all pre-existing on bare HEAD —
  cache-policy SimpleNamespace monkeypatch gaps in
  test_discovery_cache_contract / test_cli_function_discovery_regions.

## tail_validation_fingerprint.py — lint debt cleared (was 33 promoted findings)

- Same flatten + extraction recipe: nested `_impl` closures hoisted to typed
  module helpers (`_expr_fingerprint_impl_8616`, `_location_fingerprint_impl_8616`,
  `_cvariable_location_fingerprint_impl_8616`, `_iter_call_nodes_impl_8616`,
  `_contextual_call_fingerprints_run_8616`).
- Expression fingerprint split into cache ctx (`_FpCacheCtx8616` dataclass),
  probe lanes, semantic-cast arm, normalized arm dispatch, and typed per-node
  arms — preserving cache-identity-after-normalization semantics.
- Contextual call matching became contextual-call collection + two shared
  key-matching passes (callsite addr, canonical target) + singleton remainder.
- Location fingerprints split into early typed arms, stack/indexed/deref lanes,
  stable-SS dereference, and terminal cvar identities.
- Verification: ruff 0, mypy 0 (HEAD had 1 — improved), arch-check 0 violations
  in file. Owning suites 87 + 409 passed; 1 failure pre-existing on bare HEAD
  (test_tail_validation_compare_classifies_switch_decision_tree_without_helper_delta).

## cli_core.py — lint debt cleared (was 37 promoted findings)

- The two monster functions were converted to state dataclasses with phase
  methods: `_DirectAddrCliRun8616` (205-complexity `_run_direct_addr_cli_8616`)
  and `_MainCliRun8616` (136-complexity `_run_main_cli_8616`); thin wrappers
  preserve the original function signatures and entry points.
- Nested closures hoisted to methods; `self.`-field rewrites were
  position-targeted (AST columns) to protect kwargs, f-strings, handler names
  (`except ... as ex`), `nonlocal`, and loop variables.
- Phase methods return `int | None` exit codes propagated by the dispatcher;
  `break`/`continue` were kept inside their owning loops via sub-phase splits.
- Regressions found and fixed after extraction: inverted retry gate
  (`status == "ok"` must be rejected), main seed/rank dispatch reading
  pre-setup state (made lazy via dispatch phases), `.self.` injected mid
  attribute chain, duplicated expired-futures sweep block.
- Source-inspection tests updated to the class layout
  (`_DirectAddrCliRun8616`); serial-worker completion ordering invariant
  verified via dynamic call-chain discovery (b1 calls completion phase before
  the phase leading to robust retry).
- Verification: ruff 0, mypy 0, arch-check 0 violations in file, all HEAD
  top-level defs preserved. Delta test set vs HEAD baseline: all remaining
  failures (drawradaralt branch logic, 3 msc6 runtime-gate tests) reproduce
  identically on bare HEAD — environmental/pre-existing, including the
  kvikdos UTF-8 decode issue.

## straightline_ssa.py — lint debt cleared (was 48 promoted findings)

- Same recipe as prior files: dict-iterator fixes, op-dispatch tables
  (`_CONST_JSON_BINOPS`, `_Z3_*_BINOPS/_Z3_*_CMPS`), helper extraction, and
  state-dataclass conversions (`_ConnectivityGate` +
  `_ConnectivityPairTables`, `_LowerScanState/_LowerScanCtx`,
  `_TermInputScan`, `_RegionCompareCtx`).
- `_apply_ssa_connectivity_gate` (39) split into a gate dataclass with
  per-result/per-successor methods; `_z3_apply` (37) table-driven;
  `_const_json_term_value` (32) split into simple/structural/cmp op helpers;
  `_call_targets_equivalent` (30) into head/mapped/unmapped verdict helpers.
- `_BlockLiftTimeout.__exit__` narrowed to `Literal[False]` so mypy proves
  the alarm never suppresses the lowering return.
- Verification: ruff 0 (was 48), mypy 174 errors (HEAD baseline 175),
  arch-check 0 violations in file, all HEAD top-level defs preserved,
  `test_dosunit_tool.py` 198 passed.

## cli_decompilation.py — lint debt cleared (was 34 promoted findings)

- The 299-complexity `_decompile_function` became `_DecompileRun8616`: a
  plain state class whose `run_8616` dispatches phase methods via
  `_run_phases_8616` in the original order; nested defs hoisted to
  methods/module helpers and 166 shared fields declared `Any` in `__init__`.
- Remaining complexity ground down by lane extraction:
  `_decompiler_attempt_8616` (guarded with-chain + `_decompiler_codegen_empty_stop`
  + `_decompiler_timeout_lane`/`_partial_payload`/`_stage_detail` helpers),
  `_decompiler_codegen_none_lane` (isolated-retry + options lanes),
  `phase_emit_retry_8616` (x87 debug, `_call_semantics_retry_lane` +
  `_attempt`/`_score`), `phase_no_postprocess_lane_8616`
  (`_nonpost_arch_facts` + `_nonpost_call_arity_replay`),
  `_rewrite_round_8616` (prepare/apply/guarded-evidence split),
  `phase_late_lowering_8616` (three materialization chunks),
  `phase_cleanup_finalize_8616` (dead-local/stats + three finalize helpers),
  `phase_callsite_guard_8616` restored (its tail had been swallowed into a
  neighbor method during an earlier splice — repaired against HEAD text).
- Hoisted helpers re-typed (`CompilerHelperEvidence8616 | None`,
  `int | None`, `list[tuple[int, int]]`, `tuple[int, int] | None`, `Any` at
  dynamic angr/codegen boundaries) so mypy stays clean on this QA-typed file.
- Verification: ruff 0 (was 34), mypy 0 (HEAD 0), identical 62-failure set
  on `test_x86_16_cli.py -k "decompile or cli"` vs bare HEAD (all
  pre-existing env failures — kvikdos UTF-8 decode etc.), 10/10 targeted
  `_decompile_function`/retry/stub tests pass.

## Compiler coverage resume — 2026-09-26

- Refactored-checkout baseline: 45 focused stack-tracker/function-pointer
  tests passed in 48.38 seconds, seven workers, JIT enabled. Log:
  `.cache/coverage-resume-20260926-tests.log`.
- Live apply_twice replay now exits 4 with empty codegen / clinic=None and
  assembly fallback, earlier than the September 24 pointer-mask failure.
  `.cache/coverage-resume-20260926-apply-twice.{c,err}` retains the evidence.
  Do not attribute this to a particular refactor without a causal trace.
- Added a focused AST regression for the proven far-pointer target retaining
  an integer mask. After completing its mock codegen surface, it fails at
  the intended target assertion; `.cache/fptr-target-before-complete-mock.log`.
  This is an intentionally red regression awaiting its owner-layer fix, not
  a completed improvement. No production pointer-target changes yet.
- Diagnostic hook around Decompiler._decompile exposed no exception. The
  outer _decompile_with_cache probe also finished with empty codegen, exit 4;
  `.cache/coverage-resume-20260926-cache-error.{c,err}` retains the evidence.
- Entry-point repair started at 12:29 local. Commit `0388db438` removed the
  invocation of `_decompile_8616`'s nested implementation and placed its flag
  context around the validation-acceptance helper instead. Restored the context
  and call at the pipeline entry; acceptance again retains its explicitly
  supplied function. Four entry regressions failed before the repair; a fifth
  regression separately proved the acceptance helper replaced function identity.
  These tests live in the already-enrolled package-exports module.
- Scoped Ruff passes. The first after-fix neighborhood run had eight passes
  and two collection errors because a concurrent `stack_lowering_impl.py` edit
  was syntactically incomplete; not a completed after-fix regression run.
  `quality-dev` exits 2 with broader existing lint/type failures. Logs:
  `.cache/decompile-entry-{before,after,final-ruff,quality-dev}.log` and
  `.cache/decompile-acceptance-before-complete.log`.
- Linked replay finished with exit 4, enters the real pipeline, and reproduces the far-pointer
  target masks; the fallback also reports missing indirect-call arguments.
  `.cache/coverage-resume-entry-restored.{c,err}` retains the replay artifact.
  No far-pointer obligation or whole-plan completion is claimed.
- After the concurrent syntax repair, the entry/pointer neighborhood reported
  85 passes and the expected pointer-mask failure (56.18 seconds). Thus all
  five pipeline-entry regressions pass; earlier collection errors are not the
  current entry-repair result.
- Pointer-target Lowering now consumes a full-word IP mask only for an exact
  binary callsite fact and the same authoritative parameter storage. It preserves
  call arguments, unproven masks, other slots/regions, and non-call expressions.
  The typed evidence artifact retains a separate five-counter target census.
  A near-pointer coordinate control exposed the need to reuse exact argument
  object identity when no new coordinate publication is needed; that control
  failed before the adjustment. Final neighborhood: 94 passed, 65.31 seconds,
  seven workers/JIT, `.cache/function-pointer-target-verified.log`.
- Scoped Ruff and final MyPy pass; `.cache/function-pointer-target-final-mypy.log`
  is the clean final typing result (exit 0).
  Linked replay `.cache/coverage-pointer-target-materialized.{c,err}` emits both
  unmasked calls and reports a clean whole-tail check for the rebased attempt,
  but exits 4 on the integrated MS C check: `/dev/kvm` missing. The identical
  retained MSC payload compiles via direct kvikdos invocation (exit 0, identifier
  truncation warning). This discrepancy is under investigation, not round-trip
  acceptance. The direct-address fallback still lacks an indirect-call argument.
- `quality-dev` and `quality-hard` exit 2 on broader lint/type debt. Full logs:
  `.cache/function-pointer-target-quality-{dev,hard}.log`. The required default
  pipeline has started in `.cache/function-pointer-target-pipeline.log`; inspect
  its live handle/result before starting another broad gate.
- The default pipeline's prerequisite suite passes 292 tests in 66.16 seconds;
  the main curated pipeline is still live. The pointer result now has the same
  two sequential value-argument calls as the original `function_pointers.c`
  `apply_twice`; this source comparison is diagnostic, not source-assisted
  recovery or a substitute for DOS behavioral acceptance.
- Device diagnosis: `.cache/msc-kvm-import-diagnostic.log` reports `/dev/kvm`
  absent before and after project import, and kvikdos exits 252 in that process.
  Direct tool invocations see the device. Do not alter the compiler launcher
  to bypass this execution boundary; integrated acceptance remains pending.
- Recompile capability reporting repair (started 12:56 local): the MS C owner
  now uses kvikdos's documented execution probe before compilation. Failed,
  timed-out, missing, or denied probes return typed `TOOLCHAIN_UNAVAILABLE`;
  they never accept or reject the generated C. CLI diagnostics distinguish this
  from syntax failure and do not cache unavailable results. Three regressions
  failed before repair; the focused neighborhood passes 26 tests in 105.27
  seconds. Final five availability/cache boundary controls pass in 60.03 seconds;
  this repair checkpoint ended at 13:03 local (about seven minutes elapsed).
- Live evidence `.cache/recompile-capability-live.log` reports unavailable,
  exit 252, command `kvikdos --kvm-check`, with no compiler source artifact.
  Scoped Ruff passes. MyPy reports 13 pre-existing `cli_core.py` errors outside
  the edited collector; the recompile producer and contract have no findings.
  Logs: `.cache/recompile-capability-{before,after,mypy,final-boundaries}.log`.
  The existing broad pipeline predates this reporting change; do not use it as
  full-suite acceptance for this subsequent edit.

## check_decompiler_architecture.py — lint debt cleared (was 33 promoted findings)

- All 33 `complex-structure` findings ground down by behavior-preserving
  helper extraction: per-path/per-node check helpers, parameterized
  violation probes (`_node_references_any_name_8616`,
  `_textpp_helper_name_scan_violations_8616`, `_runtime_guard_main_violations_8616`),
  and table-grouped Makefile/manifest lane validators. Nested closures
  (`_find_getattr`, `_scan_statements`, `_function_returns_constant_zero`)
  hoisted to module helpers with explicit `class_fields`/`value` params;
  the terminating-guard scanner split into a per-statement
  `(found, guard)` dispatch plus the narrowing/invalidation loop.
- One defect caught and fixed during verification: the bulk
  name-reference predicate replacement had rewritten the predicate's own
  body into a self-call (infinite recursion); restored the leaf
  `Attribute`/`Constant`/`Name` conditions.
- Verification: ruff 0 (was 33), mypy 0 (new helper annotations typed
  concretely — `dict[str, tuple[frozenset[str], bool, str]]`,
  `frozenset[str]` skip sets, `tuple[tuple[str, str, tuple[str, ...], int], ...]`),
  checker output byte-identical to the pre-refactor baseline (same 189
  violations), `test_decompiler_architecture_check.py` 370 passed + the
  same single pre-existing contract failure as bare HEAD.

- 2026-09-26: MSC v8 flat32 comparison adapter staged at `artifacts/msc8-z3cmp32/` (external rebuild is read-only); 13 focused regressions pass, unnormalized six-target batch: 43 proved / 137 mismatches / 5805 refused, plus `sub_593B0` conditional relocation proof. PE candidate input and closed matched-CFG induction are available; future MSC-built binaries, calls, exception edges and differing CFGs remain pending. See `RESULTS.md` and the checked `rebuild.patch`; no shared dosunit modules edited by this task.

## stack_lowering_impl.py — lint debt cleared (was 18 promoted findings)

- `_canonicalize_stack_cvar_expr`'s 299-complexity nested `_impl` was
  converted into the stateful `_StackCvarCanonicalize8616` class
  (`__slots__`, `__init__` field declarations, `run_8616` phase dispatch,
  `run_8616_part{0..3}`), with the impl-level closure/nonlocal names
  becoming `self.` fields via a scope-aware, position-based rewrite
  (Store-context-only binding, comprehension/lambda/except/param scopes
  respected, `nonlocal` names forced to fields, sibling defs becoming
  methods).
- `run_8616_part3` split into five `(done, result)` lane methods
  (cvar/indexed/deref/stackaddr/tail); each lane further split
  (cvar-stackvar/rebind, indexed-materialize, deref-addr/chain/operand/
  resolve, deref-offset/apply) until all bodies are below the complexity
  gate. The trailing `active_expr_ids.discard(expr_id); return expr`
  tail is preserved verbatim.
- `_resolve_stack_pointer_alias_expr` split into reference/stack_base/
  cvar/binop arms plus a shared `_lookup_alias_keys_8616`.
- `_stack_pointer_aliases` fixpoint split into
  `_resolve_stack_pointer_alias_8616(aliases=...)` (with cvar/reference/
  binop arm methods), `_apply_assignment_alias_8616` per-statement step,
  `_stack_carrier_lhs_allowed_8616` guard, and
  `_fixpoint_stack_pointer_aliases_8616` loop.
- `_infer_stack_base_alias_from_bp_slots` deduplicated onto the existing
  `_stack_base_displacement_expr_8616` and split into
  `_known_bp_offsets_8616` / `_stack_base_displacements_8616` /
  `_best_stack_base_bias_8616`; `_iter_statement_nodes` attr walk became
  `_push_node_children_8616`; `_single_assignment_expr_for_cvar`'s
  `_same_lhs` hoisted with explicit node-* params;
  `_single_assignment_expr_for_virtual_name`'s index build became
  `_virtual_assignment_index_8616`; `run_8616_part0` refusal blocks
  became `_part0_{dirty_cycle,depth}_refusal_8616` -> bool.
- Module-level `_impl` pairs flattened: `_prefer_bound_stack_cvar_8616`
  (+ `_bound_cvar_for_stack_var_8616`),
  `_record_stack_canonicalization_bridge_8616`
  (+ `_local_unwrap_casts_8616`, `_indexed_bridge_operand_8616`),
  `_resolve_stack_cvar_at_offset` (+ `_best_stack_cvar_candidates_8616`),
  `_canonicalize_stack_cvars` (+ `_safe_child_update_eligible_8616`),
  `_bind_expr_types_to_project_arch_8616`
  (+ `_bind_expr_child_types_8616`).
- Verification: ruff 0 (was 18 incl. the 299-complexity `_impl`),
  mypy 0, 56 focused stack-lowering tests + 16 cli stack tests pass,
  no public API removed (only nested defs hoisted to `*_8616` methods).

- 2026-09-26: Hardened staged MSC v8 comparator verdicts (schema v2). Two pre-fix regressions reproduced false/unscoped PASS outcomes; now complete identified backend evidence is required, and relocation-dependent equality is `conditional`/exit 2. 25 tests pass; saved-report audit retains all 43 unconditional proofs. Fresh LINK selection: 5 passed; CL selection: 1 mismatch; normalized global leaf: 1 conditional. Standalone Makefile gate and checked nine-file rebuild patch are in `artifacts/msc8-z3cmp32/`; external rebuild remains read-only.

## cli_fallback_decompilation.py — lint debt cleared (was 12 promoted findings)

- Five wrapper+`_impl` pairs converted to typed state classes
  (`_SidecarSliceFallback8616`, `_NonOptimizedSliceFallback8616`,
  `_RuntimeHelperEmitter8616`, `_RuntimeHelperTail8616`,
  `_RuntimeHelperTail2_8616`) with thin compatibility wrappers; shared
  converter generalized (position-based `self.` insertion, Store-context
  binding, `nonlocal`/except-handler scopes).
- Three runtime-helper emitters (ordered `lowered`-dispatch chains of
  ~25-55 branches returning literal stub C) collapsed into ordered
  `(matcher, render)` tables consumed by `_runtime_helper_match_8616`;
  dynamic name-building branches became `(normalized, lowered)` render
  lambdas. Output verified byte-identical vs HEAD across ~100 names.
- `_recover_and_decompile`/`_attempt` nested closures hoisted to methods
  bound via `functools.partial` (decompile/inherit/run-attempt/failure/
  summarize callbacks keep their original signatures); fresh-project
  retry lane extracted to `_fresh_project_retry_lane_8616`.
- Converter regression found and fixed: `except ... as ex` names inside
  phase statements were wrongly field-qualified (`self.ex`) and then
  `ruff --fix` dropped the bindings; all five sites restored to real
  handler-scoped names.
- Module docstring gained the `Guard:` marker (clears the `cli-header`
  architecture rule; the remaining `cli-x86-16-import` violation is
  pre-existing on HEAD).
- Verification: ruff 0 (was 12), mypy 0 (HEAD 0), arch-check file
  findings equal-or-better than HEAD, all HEAD top-level defs preserved.
  5 focused slice-entry/non-optimized-policy tests pass; the
  ownership-manifest failure in the same run is pre-existing on bare
  HEAD.
## Compiler coverage: address-only replay checkpoint (2026-09-26 12:13 UTC)

- Verified the concurrent DCE repair with the saved fresh 77-test pass; this
  thread made no DCE implementation change.
- The original live `cmp_i16` replay is now terminal: CLI exit 3, analysis
  timeout, no emitted function body, tail validation uncollected. Full evidence
  is retained under `.cache/compiler-coverage/compare16-address-only-001/`.
- Identified an honest-reporting gap: the harness labels the inner timeout as
  validation failure. CLI exit 3 is also used for architecture-guard failure;
  a numeric-only timeout inference would be wrong.
- Started a bounded diagnostic profile in `.cache/cmp16-address-profile.*`;
  result pending. Routine deadline and acceptance requirements are unchanged.
  No DOS witness admitted; the full compiler-coverage plan remains incomplete.

### Follow-up completed 12:17 UTC

- Diagnostic replay finished with generated C and clean whole-tail validation,
  then failed the integrated compiler gate because `/dev/kvm` is unavailable.
  Actual spans show 51.94s direct decompilation; the changed isolation/deadline
  configuration is diagnostic, not routine acceptance or a performance win.
- Fixed coverage classification of an already-structured final function timeout.
  Regression before: 1 failed / 40 passed; after: 58 result/runner tests passed
  in 12.31s. Superseded attempts and malformed timeout fields remain distinct.
  Scoped Ruff/MyPy pass; quality-dev exits 2 on broader typing debt. Evidence:
  `.cache/coverage-timeout-classification-*.log`.
- Still open: structured CLI terminal-status transport, source-free routine
  round trips, unavailable DOS execution, and full witness/gate obligations.

### Structured timeout transport checkpoint (2026-09-26 12:23 UTC)

- Terminal direct, canonical-worker, and hard-exit timeout paths now publish a
  versioned typed record consumed by the shared MS C profile reader. No guessing
  from prose/exit code 3; malformed transport fails explicitly.
- Before: new profile control failed. After: 135 focused tests pass in 60.23s;
  scoped MyPy/new-code Ruff and ownership checks pass. Quality-dev exits 2 on
  broader lint/type debt. `.cache/cli-terminal-timeout-*.log` retains evidence.
- The live one-second probe exits 3 with the structured timeout record. This
  verifies transport, not a decompilation witness. Routine deadlines and the
  full coverage acceptance obligations remain unchanged; DOS execution remains
  unavailable in the last actual compiler probe.

### Owned source provenance checkpoint (2026-09-26 12:27 UTC)

- Coverage now records deterministic before/after identities for owned Python
  implementations, including uncommitted helpers, and rejects a would-be pass
  when those identities differ. Existing failed-stage outcomes remain visible.
- Before: both new controls failed. After: 68 focused tests pass, including a
  final rerun after report-reading cleanup. Scoped Ruff/MyPy pass; quality-dev
  exits 2 on broader typing/lint debt. Logs: `.cache/coverage-source-identity-*.log`.
- One fingerprint measured 1.19s across 1,192 files. This is limited source
  provenance, not an atomic snapshot or full dependency/native-environment pin.
  No new DOS witness is admitted; the full compiler-coverage plan stays open.

### DOS availability recheck (2026-09-26)

- Fresh source-free `compare16` adapter run ended `build_failed` after 23.88s:
  compiler execution could not see `/dev/kvm`; no decompilation was attempted.
  `.cache/compiler-coverage/sourcefree-compare16-002/` retains all evidence.
- The source-identity guard detected concurrent implementation changes; this
  thread made no code edits during the run. Earlier build failure stays visible.
- Standalone KVM self-check passed in one launch, while the subsequent import
  boundary probe saw `/dev/kvm` absent even before project imports and returned
  252. `.cache/coverage-kvm-boundary-current.log` records this distinction.
  Consistent permitted DOS execution remains necessary; no workaround changed
  permissions, sandboxing, deadlines, or the acceptance oracle.

### Csmith build pin enforcement (2026-09-26)

- The generator now verifies the existing pinned Release executable hash before
  launch and records its full revision. An unverified executable is refused;
  alternate builds require a deliberate rebuild/replay and pin update.
- Before: refusal control failed. After: 34 generator/runner tests pass in
  31.50s; scoped Ruff/MyPy pass. Quality-dev remains red on broader debt.
- Two actual seed-2 replays reproduce the earlier source hash exactly.
  `.cache/compiler-coverage/csmith-pinned-replay-{001,002}/` retains evidence;
  `.cache/csmith-build-pin-*.log` retains checks. Generation is not DOS behavioral
  acceptance; the generated round trip and bounded campaign remain open.

### Source-free far-call diagnostic (2026-09-26)

- Retained FPTR `apply_twice` at numeric address `0x10034` times out before
  meaningful decompilation: 24-function ABI seeding consumes 154.04s of the
  diagnostic 180-second budget. No tail validation or witness acceptance.
- `.cache/sourcefree-apply-twice-current.*` retains the terminal failure. A
  bounded stack-sampling replay is active in `sourcefree-apply-twice-stack.*`;
  initial invalid-frame samples are insufficient to select an optimization.
  Next action: poll that process, then profile the measured seeding boundary.
  No production changes or relaxed routine deadlines were made.

### Synthetic-code refusal checkpoint (2026-09-26 13:00 UTC)

- Profiling identified terminal-stack-cleanup scanning of CLE's synthetic
  external object. Frontend inventory now refuses those bytes as binary code,
  without excluding real loaded code or guessing a callee ABI.
- Before: 3 failed / 1 passed. Final focused checks: 22 passed in 58.63s;
  scoped Ruff/MyPy and ownership checks pass. Quality-dev fails on broader debt.
- Far-call replay now reaches decompilation (seeding 19.70s versus prior 154.04s
  diagnostic). It still exits 4: postprocess validation rejects an observable
  delta. Partial C keeps both indirect calls but has unresolved parameter
  storage/width; this is not function acceptance or a verified speedup claim.
- Required default pipeline is active in `.cache/synthetic-code-refusal-pipeline.log`.
  Raw replay: `.cache/sourcefree-seeding-refused.{c,err}`. Next: poll the gate;
  trace the parameter contract at its earlier owner, not Rewrite.
## Lint debt: dce.py cleanup (2026-09-26)

- `angr_platforms/X86_16/postprocess/optimization/dce.py`: Ruff complexity
  debt cleared to zero (was 14 findings incl. the 424-complexity state-class
  conversion landed earlier this thread; this session extracted purity arm
  helpers `_dirty/_cvariable/_call/_indexed/_typecast/_binary_value_purity_8616`,
  `_expr_value_purity_dispatch_8616`, debug-shape/pair formatters, statement
  walk/read/protected-key helpers, and the part5 debug/fixpoint lanes).
- Fixed converter fallout: `run_8616_part5` returned a bare `bool` where the
  phase runner unpacks `(done, value)` (now `return True, self.changed`);
  `__slots__`/`__init__` dropped method-name collisions; `for self._` loop
  var removed.
- Verified: ruff 0, mypy 0, 125 dce tests pass, zero architecture violations
  against this file.
## Lint debt: cli_interrupt_modeling.py cleanup (2026-09-26)

- `inertia_decompiler/cli_interrupt_modeling.py`: Ruff complexity debt
  cleared to zero (11 findings). Extracted arg-slot mapping, mirror-write
  table for x/h register views, int21/int10 service-call builders,
  helper-arg collection, shared `_interrupt_wrapper_callee_name` boundary
  resolver (replaced 3 copies), byte-extract builders, dos_version rebuild,
  hoisted `visit` into `_visit_wrapper_result_node` + per-statement lanes,
  and DOS pseudo-callee collection helpers.
- Verified: ruff 0, mypy 0, 58 interrupt/helper-modeling tests pass, zero
  architecture violations against the file.
## Lint debt: cli_local_rewrites.py cleanup (2026-09-26)

- `inertia_decompiler/cli_local_rewrites.py`: Ruff complexity debt cleared
  to zero (10 findings). Extracted live-name/unified sync helpers, shared
  placeholder-replacement bookkeeping, root canonicalization lane, stack
  identity/source sets, hoisted the six dedupe closures to module level,
  register-candidate materialization lanes, and void-return rewrite helpers.
- Verified: ruff 0, mypy 0, 163 local-rewrite/declaration tests pass, zero
  architecture violations against the file.
- `inertia_decompiler/cli_linear_recurrence_state.py`: Ruff complexity debt
  cleared to zero (10 findings). Hoisted the five nested `_impl` closures to
  class methods and extracted alias-chase, copy-alias resolution,
  linear-def inlining, variable-id collection, and stack-base-carrier
  traversal helpers. Preserved the carrier-rejection → linear-defs fallback
  ordering in `_copy_alias_for_variable`.
- Verified: ruff 0, mypy 0, 13 linear-recurrence/backedge tests pass plus
  the unarched-type refusal regression, def-integrity vs HEAD clean, zero
  architecture violations against the file.
- `inertia_decompiler/cli_stack_byte_offsets.py`: Ruff complexity debt
  cleared to zero (8 findings, including the 260-complexity
  `_rewrite_ss_stack_byte_offsets` wrapper). Converted the wrapper into
  `_SsStackByteOffsetRewrite8616` (35 nested closures -> state-class methods),
  extracted stack-pointer-alias resolution arms, SS-segment-scale checks,
  the alias-collection fixpoint step, and collapsed three identical
  resolve-or-materialize lanes in `transform` into shared helpers.
- Verified: ruff 0, mypy 0, 11 stack-byte-offset tests pass, def-integrity
  vs HEAD clean, zero architecture violations against the file.
- `inertia_decompiler/cli_linear_recurrence.py`: Ruff complexity debt cleared
  to zero (8 findings, including the 53-complexity `visit` closure inside
  `_coalesce_linear_recurrence_statements`). Hoisted `visit` to a module-level
  dispatcher, split its CStatements/IfElse/While/DoWhile/ForLoop arms into
  helpers, extracted pair-combine/shift-combine/linear-temp/self-update
  lanes, hoisted the five loop-rebind closures, and split delta/carrier
  matchers. Preserved protected-alias ordering and distinct loop debug kinds.
- Verified: ruff 0, mypy 0, 12 linear-recurrence unit tests + 7 cod
  regression tests pass, def-integrity vs HEAD clean (missing names are
  hoisted closures), zero architecture violations against the file.
- `inertia_decompiler/sidecar_metadata.py`: Ruff complexity debt cleared to
  zero (7 findings). Extracted the COD/mzre/FLAIR sidecar lanes, the COD
  label-reconcile entry merge, LST metadata/proc merge helpers, the
  ordered-label fallback region, and the all-empty metadata evidence check.
- Verified: ruff 0, mypy 0, 11 sidecar/signature-region tests pass,
  def-integrity vs HEAD clean, zero architecture violations.
- `inertia_decompiler/tail_validation.py`: Ruff complexity debt cleared to
  zero (6 findings). Extracted the record-identity build, snapshot/missing
  record lanes, count attachment, failed-stage collection, and per-stage
  diagnostic formatting.
- Verified: ruff 0, mypy 0, 283 tail-validation tests pass (1 pre-existing
  switch-classification failure identical on bare HEAD), def-integrity vs
  HEAD clean, zero architecture violations against the file.
- `inertia_decompiler/sidecar_parsers.py`: Ruff complexity debt cleared to
  zero (6 findings). Hoisted COD entry-pattern/memory-match helpers, base
  candidate accumulation, delta scanning, per-label CodeView reconciliation,
  and FLAIR startup/catalog merge lanes.
- Verified: ruff 0, mypy 0, 11 signature/sidecar tests pass, def-integrity
  vs HEAD clean (missing names are hoisted nested defs), zero architecture
  violations against the file.
- `angr_platforms/angr_platforms/X86_16/annotations.py`: Ruff complexity
  debt cleared to zero (6 findings). Extracted identity/prototype/CC
  assignment, declaration parsing, arg/stack/global annotation lanes, LST
  and synthetic-global label application, and arg-name tokenization.
- Verified: ruff 0, mypy 0, 10 annotation tests pass, def-integrity vs HEAD
  clean, zero architecture violations against the file.
- `angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py`: Ruff
  complexity debt cleared to zero (6 findings). Extracted env/codegen prune
  modes, prune gating, child-block recursion, per-candidate dead-carrier
  classification, probe-seen tracking, metadata-ID normalization, recorded
  store pruning, and nested-block recursion.
- Verified: ruff 0, mypy 0, 90 callsite/stack-probe tests pass,
  def-integrity vs HEAD clean, zero architecture violations against the file.
- `angr_platforms/angr_platforms/X86_16/cod_extract.py`: Ruff complexity
  debt cleared to zero (6 findings). Hoisted COD marker/source/asm metadata
  helpers to module level, extracted the proc-body collection lane,
  synthetic-global symbol ordering/addressing/patching lanes, and the tiny
  two-arg body collector.
- Verified: ruff 0, mypy 0, focused COD tests pass (three corpus-suite
  failures reproduce identically on bare HEAD — pre-existing),
  def-integrity vs HEAD clean (missing names are hoisted nested defs),
  zero architecture violations against the file.
- `angr_platforms/angr_platforms/X86_16/parse.py`: Ruff complexity debt
  cleared to zero (6 findings). Converted prefix/control-flow dispatch to
  lookup tables and extracted the immediate-decode lane.
- Verified: ruff 0, 32 decode/lifting tests pass, def-integrity vs HEAD
  clean, zero architecture violations against the file. One mypy error
  (`X86Instruction` typed Any in pyvex) is identical on bare HEAD.
- `angr_platforms/angr_platforms/X86_16/validation_calls.py`: Ruff complexity
  debt cleared to zero (6 findings). Extracted arg-list normalization,
  parameter BP-offset/entry-refusal helpers, required-call match resolution
  lanes, callee/helper-width/prototype fallbacks, classified and
  source-fact collection, class/interface issue builders, and the argument
  count mismatch lane.
- Verified: ruff 0, mypy 0, 74 validation-call tests pass, def-integrity vs
  HEAD clean, zero architecture violations against the file.
- `angr_platforms/angr_platforms/X86_16/verification_80286.py`: Ruff
  complexity debt cleared to zero (6 findings). Split the manual
  control-flow simulator into a per-opcode dispatch table with typed
  handlers (prefix scan, HLT, loop family, jumps, near/far calls,
  interrupts, IRET/RET variants, FF-group indirect forms), split
  `_compare_case` into register/RAM comparison lanes, and split
  `verify_case` into instruction-bytes/exception, relocated-IP retry,
  and repeated-string completion lanes.
- Verified: ruff 0, mypy 0, 75 80286-verifier tests pass, def-integrity
  vs HEAD clean, zero architecture violations against the file.
- `scripts/report_compiler_matches.py`: Ruff complexity debt cleared to
  zero (12 findings). Extracted JSONC comment/string skippers, the
  Microsoft C label chain, IDF/per-combo scoring lanes, capstone
  offset/shape feature lanes, the MZ RC-shift lane, and split `main`
  into typed `_ReportInputs`/`_ScanState` containers with parser,
  cache-restore, per-spec scan, flag-feature, runtime-bonus, and
  per-method reporting helpers.
- Verified: ruff 0, mypy 0, 5 flag-combo tests pass, def-integrity vs
  HEAD clean, zero architecture violations against the file.
- `angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py`:
  Ruff debt cleared to zero (6 findings). Extracted gated Boolean-form
  predicates, hoisted the stack-projection matcher, split wide-type
  propagation, wide-condition call candidate/rebind lanes, the
  consumed-carrier prune walk, callsite base collection, and the
  condition-slice grouping/object-fact materialization lanes.
- Verified: ruff 0, mypy 0, 54 call-output/wide-condition tests pass,
  def-integrity vs HEAD clean, zero architecture violations.
- `tools/dosunit/failure_report.py`: Ruff debt cleared to zero (9
  findings) and mypy debt reduced 23 -> 0 vs HEAD. Extracted the
  region-mismatch instruction lane, complexity per-function/refusal
  lanes, SSA-compare section appenders (result rows, region equality,
  connectivity gaps, external shared-tail proofs, candidate-only
  sections), grouped-entry/function and layout-normalization lanes,
  SSA region/ABI/result side and mismatch helpers, the
  connectivity-delta/missing-successor/region-incomplete detail lanes,
  and the batched-compare batch row. Added the typed `_dict_field`
  document coercer replacing the repeated `get ... if isinstance ...
  else {}` idiom.
- Verified: ruff 0, mypy 0 (HEAD baseline was 23), 194 dosunit tests
  pass; the 4 remaining failures reproduce identically on bare HEAD +
  uncommitted `straightline_ssa.py` WIP (pre-existing, that file was
  not touched). Def-integrity vs HEAD clean, zero architecture
  violations.
- `inertia_decompiler/cli_far_pointer_stack.py`: Ruff debt cleared to
  zero (5 findings). Extracted the copy-assignment classifier, the
  far-pointer group collection and per-group source selection lanes,
  and hoisted the coalesce pass's six nested predicates/resolvers plus
  the `Add`-node transform to typed module-level helpers bound via
  `functools.partial` (only the `nonlocal changed` transform wrapper
  stays nested).
- Verified: ruff 0, mypy 0, 13 far-pointer/stack tests + 4 CLI
  far-pointer/MK_FP tests pass, def-integrity vs HEAD clean, zero
  architecture violations.
- `inertia_decompiler/gdb_tui.py`: Ruff debt cleared to zero (6
  findings). Split the command-input dispatch into control, breakpoint,
  memory, and register/print dispatcher groups; extracted the
  restart/reset connection-lifecycle lane; and extracted the `FF /2|/3`
  ModR/M fallthrough-length lane.
- Verified: ruff 0, mypy 0, 3 TUI step-over tests pass, def-integrity
  vs HEAD clean, zero architecture violations.
- `inertia_decompiler/debugger_gdb.py`: Ruff debt cleared to zero (6
  findings). Split the RSP query chain into qSupported/qXfer, thread
  status, and Inertia-extension helpers; extracted packet normalization
  and an ordered handler tuple for command dispatch; and extracted the
  call-instruction length classifier for step-over.
- Verified: ruff 0, mypy 0, module imports clean, def-integrity vs HEAD
  clean, zero architecture violations (no dedicated debugger_gdb test
  file exists; TUI step-over tests pass on the sibling gdb_tui file).
- `scripts/decompile_cod_dir.py`: Ruff debt cleared to zero (5
  findings). Split the 35-complexity `main` into a typed
  `_RunAccumulator` state (result/failure/scheduler-timeout handlers)
  plus `_build_arg_parser`, `_collect_work_items`,
  `_print_parallelism_banner`, `_run_single_worker_lane`,
  `_run_task_batches`/`_drain_batch_futures`, `_finish_writers`, and
  `_emit_tail_validation_report` lanes; extracted the scan-safe field
  tail and the COD selector-match lane.
- Verified: ruff 0, mypy 0, `--help` smoke clean, def-integrity vs HEAD
  clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/jcc_condition.py`: Ruff debt
  cleared to zero (5 findings). Split the IR-value conversion into
  per-space register/temp lanes, hoisted the masked-zero and binary
  compare result builders to module level with a typed ordered
  compare-dispatch table, and extracted the unary zero/nonzero lane.
- Verified: ruff 0, mypy 0, 100 postprocess-jcc tests pass,
  def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/addressing_helpers.py`: Ruff
  debt cleared to zero (5 findings). Extracted `typed_address` segment
  field and raw-offset lanes into private methods, merged the identical
  SS/DS int-offset returns, extracted the BP two-arg fallback, and
  split `_collect_add_sub_terms` into leaf and combined add/sub lanes.
- Verified: ruff 0, mypy 0, 54 addressing/instruction-core tests pass,
  def-integrity vs HEAD clean. The 4 promoted-typed-file dynamic-attr
  findings are unchanged from HEAD (inherited debt on moved getattr
  lines, not new).
- `angr_platforms/angr_platforms/X86_16/validation/canonicalize.py`:
  Ruff debt cleared to zero (5 findings). Extracted the binary
  canonicalization arm, replaced the seven repeated optional-attr
  comparisons with an ordered accessor table, extracted binary/unary
  shape equality lanes, and split the Z3 conversion into leaf and
  binary helpers.
- Verified: ruff 0, mypy 0, 3 canonicalize tests pass, def-integrity
  vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/structuring_grouped_graph_builder.py`:
  Ruff debt cleared to zero (5 findings). Split condition-hint rendering
  into logical vs comparison lanes, extracted the per-region support-entry
  factory plus condition-IR/edge-evidence collection lanes from the
  support builder, and hoisted the cross-entry role map out of
  `build_grouped_region_graph`.
- Verified: ruff 0, mypy 0, 21 grouped-graph/grouped-pass tests pass,
  def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py`:
  Ruff debt cleared to zero (5 findings). Extracted the capstone
  instruction/block frame-evidence lanes, a shared IRSB register-offset
  resolver, the function IRSB gather, and the per-IRSB frame-delta scan.
- Verified: ruff 0, mypy 0, 3 stack-frame-recovery tests pass,
  def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/recovery_confidence.py`:
  Ruff debt cleared to zero (3 findings). Split the evidence appender
  into output-stage/summary groups, the assumptions appender into
  helper/failure/summary groups, and the two summary OR-chains into
  signal predicates. Evidence/assumption ordering preserved.
- Verified: ruff 0, mypy 0, 38 recovery-confidence tests pass,
  def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py`:
  Ruff debt cleared to zero (5 findings). Extracted the interior-scaled
  candidate lane, the instruction access classifier and BP-access bucket
  lane, the full-frame/bottom-indexed recovery lanes, and split
  `_materialize_fact` into candidate collection, missing-aggregate
  creation, frame/boundary type persistence, and unified-entry rewrite
  helpers. Hoisted the decay debug/call-arg lanes and the carrier-prune
  visitor to module level.
- Verified: ruff 0, mypy 0, 48 stack-aggregate tests pass, def-integrity
  vs HEAD clean, zero architecture violations. The SORTD sidecar-free CLI
  regression remains the known pre-existing 240s timeout (documented
  earlier; reproduces on clean HEAD worktree).
- `angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py`:
  Ruff debt cleared to zero (5 findings). Split the pointer-swap splice
  into leaf-scan, materialized-early, and splice-region lanes; extracted
  the byte-fill fact, delta-token, swap-stats, and swap-triple guards
  into named predicates (delta tokens via a validating accessor).
- Verified: ruff 0, mypy 0, 15 pointer-memory tests pass, def-integrity
  vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py`:
  Ruff debt cleared to zero (5 findings). Hoisted the duplicated
  segment-scale predicate into a shared helper, extracted the single
  register-base-term lane, and split `_stable_hint_kind` into
  structured/simple kind lanes.
- Verified: ruff 0, mypy 0, 30 object-lowering/segmented-memory tests
  pass, def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py`:
  Ruff debt cleared to zero (4 findings + 1 moved bool-expr). Split
  condition-ownership decode into per-block/condition-only/graph lanes,
  extracted pending-source conversion, and decomposed artifact
  collection into seeding, relift resolution, cached-block, and
  bind/filter lanes.
- Verified: ruff 0, mypy 0, 84 condition-transfer/evidence/carrier
  tests pass, def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py`:
  Ruff debt cleared to zero (4 findings + moved bool-exprs). Extracted
  summary matching, call-identity canonicalization, return-contract
  joins, declaration selection/recording, ambiguous resolution, and
  per-call processing lanes; preserved matched-count semantics on
  macro/refused exits.
- Verified: ruff 0, mypy 0, 93 callsite-prototype/identity tests pass
  (1 pre-existing cache-surface failure reproduced on bare HEAD),
  def-integrity vs HEAD clean, zero architecture violations.
- `angr_platforms/angr_platforms/X86_16/lowering/balanced_memory_stack_restore.py`:
  Ruff debt cleared to zero (5 findings). Split immediate-transfer pairing
  into push-entry/pop-transfer lanes, container matching into match/insert/
  read-replacement lanes, structured pairing into window-scan and ordered-
  candidate lanes, and pair rebinding into exemplar selection, pop rewrite,
  and word-push lanes; deltas returned as typed tuples.
- Verified: ruff 0, mypy 0, 7 balanced-restore tests pass, def-integrity
  vs HEAD clean, zero architecture violations.
- `pyvex_compat.py` + `sitecustomize.py`: Ruff debt cleared to zero
  (2 + 1 findings). Split runtime patch install into per-target
  installers with a hoisted bounded-lift preamble/instruction lane,
  and extracted the msgspec JSON shim to module level.
- Verified: ruff 0 (not in mypy files scope), monkeypatch smoke test
  shows all four adapters installed with correct `__name__` guards and
  idempotent double-apply; msgspec shim decode/loads verified
  byte-identical; def-integrity vs HEAD clean.
- `scripts/build_msc51_flag_profiles.py`: Ruff debt cleared to zero
  (3 findings). Extracted instruction shape markers, argparse block,
  COD profile collection, dataset-row lanes, and IDF payload build.
- Verified: ruff 0, mypy 0, `--help` and end-to-end fixture run produce
  identical payload shape; def-integrity vs HEAD clean (nested `_impl`
  bodies preserved inline).
- `scripts/compare_msc6_ssa_examples.py`, `benchmark_optimization_quality_guard.py`,
  `compare_discovery_backends.py`, `build_pat_from_exe.py`: Ruff debt cleared
  to zero (2+1+1+1 findings). Extracted SSA part/backedge lanes, manifest
  function gates, table-driven aggregate quality gates, backend selection and
  print lanes, and PAT wildcard operand lanes.
- Verified: ruff 0, mypy 0, 4 msc6-compat tests pass, `--help` parses on both
  CLIs, def-integrity vs HEAD clean.
- `tools/dosunit/complexity.py`: Ruff debt cleared to zero (3 findings).
  Extracted scan-window resolution, lifter block lift, per-block
  instruction scan, branch/opcode/effect metric lanes, and control/data
  risk-kind lanes. Also fixed pre-existing mypy debt in the module
  (counters annotation, sample-instructions narrowing, bool return).
- Verified: ruff 0, mypy 0 (10 pre-existing errors also cleared), 4
  dosunit complexity tests pass, def-integrity vs HEAD clean.
- `tools/dosunit/{mapping,discovery,model,region_effects,solver_slice,
  libdosbox_import,dosunit,generate,kvikdos_backend}.py`: Ruff
  complex-structure debt cleared to zero (2+2+1+1+1+1+1+1+1 findings).
  Extracted mapping candidate/entry lanes, discover module/segment/parse
  lanes plus hoisted `_entry_sort_key`, normalize pre-regs/memory/observe
  lanes, region window/lift/scan lanes, manual-solution condition lanes,
  libdosbox code/access/snapshot collection lanes, batched-compare command
  build/run/failure-row lanes, edge-generation refusal/per-target solve
  lanes, and harness entry/pre-state/image-embed/capture-layout lanes.
- Verified: ruff 0 on all nine files, dosunit suite 194 pass with 4
  failures reproducing identically on bare HEAD d68c8d56c (pre-existing
  compare_ssa_documents semantic-status changes from the parallel
  straightline_ssa.py work, not this refactor), def-integrity vs HEAD
  clean (only extracted helpers added).
- `tests/{_x86_16_borrow_80286,test_x86_16bit,
  test_x86_16_cli_stack_byte_offsets,test_dosunit_tool}.py`: Ruff
  complex-structure debt cleared to zero (1 finding each). Hoisted the
  ABI-doc builders to `_abi_*` module level, split `compare_states` into
  register/flag pair lanes plus per-register diff, extracted the MOO
  per-opcode case collector, and table-driven the deep C-node type walk.
- Verified: ruff 0 on all four files, 258 borrow-corpus + 11 stack-offset
  + 4 stack-arg tests pass, instruction smoke test exercises normal/cf/
  flag/ret paths with zero diffs.
- NON-WIP complex-structure debt: 0. Remaining 31 findings are all in
  user-WIP files (omf_pat.py, build_msc6_examples.py, signature_catalog.py,
  straightline_ssa.py).
- `tools/dosunit/straightline_ssa.py` + `scripts/build_msc6_examples.py`
  (+ omf_pat.py, signature_catalog.py): remaining complex-structure debt
  cleared to zero repo-wide. straightline_ssa splits: pair-boundary
  detail, unproven-call-target mismatch, normalized z3-solve tail,
  relocation-site imm16 collection, segment-adjacent differing pushes,
  strong/weak witnessed string pairs, far-pointer run emit/proven-push
  helpers, entry-ip resolver and shifted-immediate pair lane;
  build_msc6 splits: decompile candidate probing/fallback/timeout lanes,
  `_DecompileValidateOptions` config + fallback-first/decompile-failure/
  rebuild-run/post-rebuild-merge lanes, per-example build/decompile
  dataclasses and report writer in main.
- Verified: ruff 0 repo-wide for complex-structure/too-many-boolean
  (remaining findings only in vendor/ + artifacts/), mypy 0 on
  build_msc6_examples.py, 107 msc6 tests pass, dosunit SSA-compare
  surface 145 pass with the 4 known compare_ssa_documents failures
  reproducing identically on bare HEAD (pre-existing, owned by the
  parallel session's semantic work). straightline_ssa.py committed;
  omf_pat.py, signature_catalog.py, build_msc6_examples.py left
  uncommitted because they carry interleaved user WIP.


## Riptide corpus session (continued)

- `straightline_ssa.py` candidate pairing hardened against delta/shape
  collisions: masked-signature multi-maps now retain collisions, a coarse
  tier masks all call/jmp operands to form the ambiguity set, and
  `_arbitrate_signature_collision` picks the candidate whose *fallthrough*
  successor signature matches the oracle's (control-flow order — part
  index follows lifter discovery order, not addresses). A delta hit whose
  shape differs from the oracle and has no stronger evidence now yields
  no candidate (honest `candidate_ssa_missing`/`part_boundary_mismatch`
  refusal) instead of a guaranteed-bad pairing; all three resolvers share
  `_resolve_candidate_via_tables`. Committed 0e32fa30a.
- Riptide: `show_prelude` `var_4` was `long` not `int` in the original
  (dword mov/sub/cmp); fixed in decomp/game.cpp, committed 9487a9e.
  Rebuilt EXE + re-lowered SSA: all dword parts `block_binary_equal`.
- Shard batch results with the fix: batch002 46->63 clean passes and the
  call-target mispairing cleared; batch004 mv_pace boundary artifacts now
  refuse/region-prove (2 covered_by_region_equal) with zero failures.

## BC5 z3cmp32 region/auto mode (session checkpoint)

- Ported the msc8 flat32 region composer to `artifacts/bc5-z3cmp32/`
  (`flat32_region.py`): bounded acyclic CFG composition over full-width
  linear successor keys via `_compose_block_outputs`/`_merge_abi_states`;
  calls, loops, indirect/unmodeled branches, and partial scans refuse.
  `--mode region` composes; `--mode auto` retries loop refusals through
  `flat32_cfg.compare_cfg` (8 blocks, 250 ms cap). Relocation-only output
  diffs map to `conditional` via the `--normalize-globals` map.
- flat32_adapter region seams now mirror the msc8 contract: native
  multi-block scan lowering, `_finish_irsb_lowering` native (full-width
  `ip`), `_can_add_dynamic_successor_range=declared_bounds_only` (strict
  `.lst` extents — out-of-extent successors refuse instead of scanning
  into neighbours).
- Engine fixes in `tools/dosunit/straightline_ssa.py`:
  - `_lower_binop`: Iop_DivMod{U,S}64to32 lowered as
    concat(trunc(rem,32), trunc(quot,32)) (x86 DIV/IDIV packing, verified
    on concrete z3 values); Iop_NwHLtoMw concat family lowered.
  - `_prepare_region_call_normalized_groups` boundary-shift fix: the
    normalized candidate call part is stored under its own delta, not the
    paired oracle part's delta — the old keying clobbered an unrelated
    candidate block and dropped the normalization (phantom
    `candidate_ssa_missing`/`missing_successor` rows).
  - `_record_lowered_part`: flat32 `entry_delta`/`block_ip` mask to
    32-bit two's complement so below-entry blocks keep parseable deltas.
- Refusal anatomy measured: most leaf-mode "CFG" refusals are actually
  call-bearing bodies (`call_or_exception_boundary` dominates); loops
  are the next-largest honest refusal class; jump tables refuse
  `indirect_or_unmodeled_branch`. Callee summaries remain the blocker
  for the 635 call-boundary functions — the honest frontier.

## BC5 z3cmp32: full-corpus region/auto measurement + normalization fix

- Full `--all-mapped` run (2228 functions, `--mode auto --normalize-globals`,
  6 shards): **83 conditional / 132 failed / 2013 refused**.
- Transition vs leaf baseline: zero conditional lost; 20 previously-refused
  functions now prove `region_equal` modulo relocation; 91 previously-refused
  now surface honest `observable_mismatch`/`matched_cfg_induction` failures —
  the per-function triage queue (real term diffs, not comparator artifacts).
- Fix: relocation normalization now happens *inside* solving, matching leaf
  semantics — `flat32_region.compare_region` attaches
  `_constant_normalization`/`_reasons` to the composed candidate summary so
  `_normalized_constant_value` rewrites candidate consts during `_z3_term`.
  Before this, region verdicts post-mapped only witness-value pairs, so any
  relocation const embedded in a store/load chain (e.g. a global store feeding
  the `eip` ret-target load) failed `observable_mismatch` — 43 formerly
  conditional leaf functions regressed; all recovered plus 20 more.
- `flat32_cfg.compare_cfg` gained the same `normalization` param (cssa docs +
  `checked_results(relocation=...)`); threaded from `--mode matched-cfg` and
  the auto-mode loop retry.
- Lint hygiene: extracted `_term_children` out of `_abi_terms_equal` (complexity
  16→under limit), `ANN401` noques, `zip(strict=)` — ruff clean.
- Refusal frontier is now explicit and honest:
  `call_or_exception_boundary` 1639 (needs proven flat32 callee summaries),
  `region_lowering_incomplete` 130, `loop_requires_inductive_proof` 124,
  `region_expression_limit` 37, `successor_outside_complete_region` 36,
  `indirect_or_unmodeled_branch` 35, `uninterpreted_x86_flags` 7.
- Gates: ruff clean on touched files; `test_dosunit_tool.py` 205/209 pass —
  the 4 failures are the documented pre-existing `compare_ssa_documents`
  expectations (reproduce on bare HEAD). Repo-wide mypy debt in unrelated
  modules still fails `quality-fast` globally (pre-existing, none in touched
  files).

## BC5 z3cmp32: reviewed Devin 256-block scanner experiment

- Devin tested the first 12 sorted functions from the 53 unique functions
  represented by 104 saved 128-block-limit events (53 oracle, 51 candidate).
  At 256 blocks, 8/12 became `call_or_exception_boundary`, 4/12 reached the
  256-block limit, and **0/12 gained a proof or conditional verdict**.
- The bounded warm-cache sample took 3:18 wall time, 41.2 s user CPU, and
  peaked at 634 MiB RSS. Because that cost bought no proofs in the sample,
  the reviewed driver keeps 128 as the default and offers
  `--region-max-blocks 256` for targeted experiments. Scanner and composition
  caps share the selected value; composition, expression, and store limits
  remain unchanged. Partial scans still refuse.
- Focused BC5 tests: 8 passed; scoped Ruff and Pyright: clean. Full corpus
  rerun and the call-boundary proof work remain outstanding. The changed-file
  gate passed. `quality-dev` reached the unrelated existing mypy error in
  `interprocedural_storage_simtypes.py:174` (`no-any-return`); its mypyc smoke
  passed after setting a writable project-local `TMPDIR`.
  `test_dosunit_tool.py` reported 200 passed, 5 skipped, and the same four
  compare-SSA assertion failures recorded above; no shared dosunit code was
  changed in this experiment.

## BC5 z3cmp32: reviewed Devin direct-call abstraction

- `--assume-paired-calls` is an opt-in region/auto policy. It resolves only
  uniquely addressed `sub_*` pairs from the full oracle boundary and candidate
  symbol catalogs, so six-way sharding does not hide mapped callees. Indirect,
  unmapped, mismatched, and unsupported transfers still refuse.
- A paired direct call havocs all modeled post-call registers, memory, and IO,
  keeps the composed caller ESP plus a shared unknown stack effect, and resumes
  at the full-width fallthrough. Equality is **conditional** on an explicit
  paired post-call-state relation; matching names do not prove that relation.
  A counterexample under havoc refuses rather than reporting a real binary
  mismatch. Relocation and call assumptions are both retained in the verdict.
- On 15 formerly call-boundary-refused BCC functions with 5 s solver timeouts,
  the opt-in policy produced 2 conditional, 13 refused, 0 passes. The focused
  three-function recheck after refusal classification yielded 2 conditional
  and 1 `paired_call_model_counterexample` refusal. No unconditional proof gain
  is claimed. Focused BC5 tests: 14 passed; scoped Ruff, Pyright, and the
  changed-file gate: clean. A later `quality-dev` retry exceeded its 120 s
  bound during the repository-wide linter stage; a prior run reached unrelated
  mypy debt at `interprocedural_storage_simtypes.py:174`.

## Riptide corpus: v6 rerun + string-content bug sweep (session checkpoint)

- v5 shard compare (fixed comparator) surfaced ~23 `observable_mismatch`
  rows; triage split them into real source bugs vs comparator artifacts.
- Real source bugs fixed in `decomp/` (all verified byte-equal vs oracle
  strings in RIPTIDE.EXE):
  - `menu.cpp`/`game.cpp`: 12 string literals used `\t` where the original
    uses literal spaces (about-screen credits, "Goodies           : ",
    "Bonus X 50/100", "New setting?", "  Enter new shot size:  ",
    "In Search of Dr. Riptide", "Riptide (Registered) 1.0 (C)", etc.).
  - `end_game`: "you are a big cheater, so no cigar." -> oracle text
    "you used the cheat code...  Sorry!".
  - `init_game`: truncated message restored ("... Increase memory or run
    with the -pcsound option.").
  - `dump_pcx` inform: "Riptide.pcx has been written" ->
    "'riptide.pcx' has been dumped.".
  - menu labels: "Run Benchmark"->"Run benchmark", "Your Score"->
    "Your score: ", joystick prompt "fire button." -> "fire button...",
    "show_stats" divide message trailing '.'.
  - `seg2608.asm`: 6 extracted-data strings had `?` corrupted to `q`
    ("Continueq"/"leaveq"/"settingq"/"scoresq"/"beginingq"/"gameq") —
    restored to `?`.
- Known remaining comparator-artifact fails (not source bugs):
  `check_new_pos` 0x20/0x80 arm cross-pairing (semantics verified identical
  — oracle `jnl`->0x20 / cand `jl`->0x80), `___fpreset`/`terminate`
  relocated far-pointer stores via locals, `check_user` function-extent
  mismatch (oracle part pushes reset-scores string), frame-slot
  permutation fails (pull_down/show_pcx/explode_pcx/dump_pcx/text_pager),
  `do_probe` para-witness gap ('prober.l' identical under 0x2708/0x22bc).
- Rebuilt `decomp/link/RIPTIDE.EXE` (194001 B) and re-lowered recon corpus
  to `recon.ssa.v6.json`; shard rerun launched via `run_shards_v6.sh`
  (batches_v6_s*, --resume + progress.json checkpoints for reboot safety).

## Riptide corpus: v6 compare complete + proof artifacts regenerated

- v6 corpus: `recon.ssa.v6.json` = 12147 parts / 890 functions, 3 honest
  refusals (`unsupported_ir` in Abs FIDRQQ/FIWRQQ helpers). The main pass
  truncated `x_explode_map` at a 30 s lifter-block cap (524/644 parts);
  re-lowered that single function with a 240 s block budget and merged —
  no coverage loss vs v5.
- v6 shard compare (all 12 batches, run_shards_v6.sh, --resume):
  **6825 passed / 14 failed / 2872 refused** (v5: 6709/23/2751). All nine
  cleared fails were the fixed string-content bugs (`cb_about_de`x4,
  `init_game`, `show_stats`, `end_game` cheat text, `check_user`,
  `cb_debug_shot_size`).
- Remaining 14 fails are all classified artifacts, no source bugs:
  - `check_new_pos`x2 — branch-polarity arm cross-pairing (oracle
    `jnl`->0x20 vs cand `jl`->0x80; semantics verified identical)
  - `pull_down`/`text_pager`/`show_pcx`x2/`explode_pcx`/`dump_pcx`x3 —
    frame-slot allocation divergence (bp-4 vs bp-2 class; conflicting
    slot deltas show genuinely different local layouts)
  - `do_probe` — unwitnessed DS para pair; 'prober.l' byte-identical in
    both binaries under 0x2708/0x22bc but no strong witness establishes
    the pair
  - `end_game` — residual `ds:0xf29` empty-string push / extent edge
  - `terminate` — relocated far-call return shape; `___fpreset` —
    relocated seg:off store via lds+int21 (IVT install)
- Regenerated proof artifacts from `batches_v6_s*`:
  `tools/z3cmp/proven_equal.json` + `PROVEN.md` — **365 functions fully
  proven** (all mapped SSA parts pass; 2973 parts), 344 functions
  partial/refused (mostly `successor_state_unobserved`/`mapping_missing`
  coverage refusals, not mismatches).

## Riptide corpus: v7 cycle — codegen fixes + comparator lane + region axis

- Post-v6 source codegen fixes (decomp commit `af81822`, verified via
  `.gen.asm` against RIPTIDE.lst):
  - `do_probe` ternary -> `if (a->facing == 0) probel else prober`:
    oracle has two `push ds;push off` sites, arm order `jnz`->prober /
    fallthrough probel (ternary emitted a DX:AX pointer select).
  - `check_new_pos`: `a->x < act->x` (0x80 then-arm) reproduces oracle
    `jnl`->0x20 / fallthrough 0x80.
  - `pull_down::activate`: `uchar save_bg, save_fg` declared before ints
    reproduces oracle frame (bytes bp-1/-2, ints bp-4..-10).
- Comparator: `_local_far_pointer_offset_pairs` lane — `mov [bp-N],segr`
  + `mov [bp-M],imm` far-pointer construction gets the same
  string-content proof as `push segr`+`push off`, plus lone-NUL (`""`)
  acceptance under witnessed paragraph pairs.
- Region-equality axis audited (was untriaged): v6 batches carry
  `region_failed` = 37 functions. Classes: sp residuals across
  jmp-linked shared epilogues (12), dead high-byte/dead-reg returns (9),
  relocated pointer/cell values in composed memory (10), RTL-extract
  `ftol@`, `abs` branchless-vs-branch codegen variant (pre-3.1 vs 3.1).
- REBUILD PITFALL: the function catalog (`recon_funcs.*.json`) embeds
  module-relative entry addresses — **it must be regenerated via
  `dosunit discover` after every link**, else a shifted exe lowers at
  stale mid-instruction offsets (v7a lost `kill_ego` 54->2 parts etc.).
- v7: exe 193985 B, `recon_funcs.v7.json` regenerated, lowered to
  `recon.ssa.v7.json` = 12144 parts / 890 functions / 3 unsupported_ir
  refusals; shards launched via `run_shards_v7.sh` (batches_v7_s*,
  --resume + progress.json).
- v7 shard compare COMPLETE (all 12 batches): **6840 pass / 7 fail /
  2864 refused** main + region_equality 37 failed (same classified
  artifact set as the v6 audit: sp-composition, dead-ah, relocated
  cells, ftol, abs codegen).
- v7 cleared vs v6: `check_new_pos`x2 (arm order), `pull_down`
  (frame), `do_probe` (two push sites), `end_game` (local far-ptr
  lane), `text_pager`, `explode_pcx`, `terminate`.
- v7 remaining main fails: `___fpreset` (IVT far-ptr store artifact),
  `@game_manager@$bctr` (vtable push: all consts layout-paired,
  residual store-shape), `show_pcx`x2 + `dump_pcx`x3 (frame order).
- Frame-order rule confirmed: BCC allocates locals in declaration
  order, shallowest first, with a 1-byte pad when a word follows an
  odd-depth byte run. `show_pcx`/`dump_pcx` declarations reordered
  (decomp `84aa8c2`) to byte-first + split far-ptrs; VGADISP.ASM
  output now reproduces oracle frames exactly (`var_1` -1, `src` -6,
  ints -8..-0x12, `dest` -0x16, `var_1A` -0x1a / `var_1` -1,
  `handle` -4, uints -6..-0x10, `block` -0x14). Rebuilt exe (same
  193985 B, addresses unchanged), re-lowered the two functions into
  `recon.ssa.v8frag.json` + spliced `recon.ssa.v8.json`; fragment
  compare `batches_v8/compare.batch001.json` verifies the fix.

## BC5 z3cmp32: full-corpus paired-calls measurement + wider callee map

- Full `--all-mapped` rerun (2228 fns, `--mode auto --normalize-globals
  --assume-paired-calls`, 6 shards, ~22 min): **325 conditional / 131 failed /
  1772 refused** — up from 83 conditional without the call policy.
  242 verdicts carry `paired_call_assumptions`; 74 carry
  `relocation_assumptions`; 9 `matched_cfg_induction`.
- Call-boundary decomposition (was one 1639-class refusal): 242 conditional
  pairings, 274 `call_target_unmapped` (x87 helpers / unimplemented RTL /
  VAs not at mapped entries), 195 `paired_call_model_counterexample`
  (inconclusive under havoc — refuses, never false-fails), 149
  `call_indirect_or_unmodeled_target`, 10 `unmatched_call_order`,
  9 `call_target_mismatch` (guarded calls: jcc inside the call block — a
  correct refusal, unimplemented).
- Havocing calls lets callers compose deeper, surfacing the real blockers:
  `loop_requires_inductive_proof` is now the largest class (451), then
  `region_expression_limit` (249), `slice_too_large` (94, the 4096-assignment
  cap), `successor_outside_complete_region` (83).
- `mapped_call_entries` no longer requires the `sub_` prefix: the oracle/cand
  name intersection also covers `nullsub_1`, `__matherr`, Win32 import thunks
  etc. (2279 mapped names vs 2228). A targeted rerun of the 315
  `call_target_unmapped` functions moved 17 to `paired_call_assumptions`
  conditional; the rest still have genuinely unmapped callees.
- `test_z3cmp32.py`: 14/14 pass. ruff clean on touched files.

## BC5 z3cmp32: successor_outside_complete_region root-caused and fixed (3 defects)

The 83-function `successor_outside_complete_region` class was a coverage
defect, not honest frontier. Root causes found and fixed:

- `.lst` proc extents understate real reachability: functions jump into
  shared tails (`sub_45E3DA` → `loc_45E408`) owned by no proc. Region scan
  policy changed from `declared_bounds_only` to `executable_section_bounds`
  (any successor inside executable image bytes is admissible; budgets still
  bound the walk). 70/83 converted past the wall on rerun.
- Rep-string asymmetry: `_repeat_string_transfer` rewrote successors to
  fallthrough-only unconditionally, while `_lower_repeat_string_summary`
  was gated on the 16-bit reg set (`_has_16_bit_repeat_state`) — under
  flat32 the transfer promised successors the lowering could not deliver,
  and the raw back-edge `ite` stayed in `ip` (e.g. `rep movsd` at
  sub_4023A8). `_lower_repeat_string_summary` + `_repeat_string_family_versions`
  are now width-parametric via `_repeat_string_state()` (16-bit ax/cx/si/di/
  flags or flat32 eax/ecx/esi/edi/eip + cc_op/cc_dep1/cc_dep2/cc_ndep), and
  the transfer is gated on the same check. rep movs/stos/scas/cmps now lower
  to congruence-comparable `summary_rep_*` ops under flat32.
- Mid-block `div`/`idiv` fault exits (`Ist_Exit` with `Ijk_SigFPE*`) folded
  into `ip` as ite arms pointing at the faulting instruction — a VEX trap
  edge, not a CFG successor. `state.exits` now records the exit jumpkind;
  `_finish_irsb_lowering` emits `trap_exits` (const Sig* targets) on the
  part; the region walk canonicalizes trap arms to a shared `TRAP_EIP`
  terminal (fault reachability still compared through the guard — div-by-0
  candidate vs div-by-12 oracle correctly FAILs). `Ijk_Ret` blocks accept
  `ite` chains whose only leaves are TRAP markers + one shared ret spine
  (`conditional_exit_in_return_block` still refuses real multi-ret cases).
- Refusals now carry `refusal_detail` (e.g. the missing successor address);
  `reason` stays canonical for aggregation.

Rerun of the 83 affected functions: 0 remain in
`successor_outside_complete_region`. Conversions: 3 conditional
(paired_call_assumptions), 1 failed (observable_mismatch, real diff), and
the rest refuse deeper and honestly — `call_target_unmapped` (13),
`loop_requires_inductive_proof` (17), `region_expression_limit` (6),
`region_lowering_incomplete` (9), `unmatched_call_order` (10),
`slice_too_large` (1), `region_composition_limit` (1),
`call_target_mismatch` (1).

`test_z3cmp32.py`: 19/19 pass (3 new: flat32 rep summary, div trap
terminal, executable-section bounds). `test_dosunit_tool.py`: 206 pass /
4 failed — the same pre-existing failures as bare HEAD. Ruff clean.

## Compiler coverage: staged generation review (2026-09-28)

- Reviewed Devin's exact dirty-baseline delta; rejected its recursive comparator
  after reproducing a depth regression, scalar-subclass mismatch and three
  Pyright errors. Parent's separate ignored candidate preserves native custom
  equality and uses iterative memoization only for proven built-in values.
- A meaningful saved-source regression fails through the existing equality
  path. Final staged run94337 passes12tests/8warnings74.84s, observed18:42:10UTC;
  scoped Ruff/MyPy/Pyright pass. No live Python integration yet. Routine
  enrollment, final shared-tree checks and required project gates remain open.
- Default pipeline's unit phase reports4failed/2397passed/19warnings2535.23s
  plus xdist KeyError(gw8); this is a partial failed run, not acceptance.
  Coordinator34598 continues; image fix52383 remains under staged review.
  No function fix, compiler witness, macro speedup or global completion claimed.

## Compiler coverage: linked pointer checkpoint (2026-09-28)

- The reviewed image-bound correction and native-compatible generation
  comparison are integrated and routine-enrolled. Focused live checks pass;
  required broad gates remain failed/incomplete. These are component results,
  not whole-plan acceptance or an isolated end-to-end speedup claim.
- The latest `array_pointer_writes` small-model case completes all five
  source-free function jobs with return code0 and clean tail-validation reports.
  It then fails MS C recompilation: the integer-valued `select_word` declaration
  cannot be dereferenced (`C2100`, followed by `C2106`). The case remains
  `recompile_failed`; roundtrip and feature coverage are both false.
- Next semantic obligation is binary-derived near-pointer input/result typing
  and a coherent guest-address return projection, not a cast in the original
  caller harness or a rewrite-stage signature/body replacement. A bounded
  read-only Devin diagnostic owns only ignored report artifacts; parent review
  and acceptance remain mandatory. The separate loader-exception candidate is
  still staged pending independent parent red/green checks.

- Parent completes the loader-exception review and integrates only four named
  missing-memory catches plus the real-MZ regression/routine enrollment.
  Independent saved-source red8fail/4pass, staged green12pass and final shared
  tree53pass. Scoped Ruff/MyPy and startup/context/ownership/type-ratchet pass;
  Pyright's five findings strictly match inherited rule/message/full ranges.
- A bounded in-worker diagnostic locates the pointer case's first production
  refusal: both caller inputs reject logical index1 with `SIGNEDNESS_UNKNOWN`,
  before pointer-return classification. The static sandbox lacks KVM, so its
  exit4 is environment-limited evidence, not comparable tail validation.
  Parent independently obtains PROVEN, closed binary SSA and modular-use facts
  for both BP-word inputs, each with counts1/1/1/1/0. A separate bounded Devin
  task stages a typed sign-insensitive input join; no pointer/return publication
  or semantic acceptance follows from those bit-pattern facts alone.
- Independent fresh-project frontend replay also records both caller-return
  uses for the selected target with a complete2/2/2/2/0 census. Source review
  finds the direct CLI copies its clean-worker census before recovery records
  the selected target and fast preparation records neighbors. A second
  disjoint Devin task stages that metadata lifecycle correction; no semantic
  classifier or caller-use verdict is invented. Parent rejects the earlier
  diagnostic's predicted next refusal because its census snapshot was
  overwritten rather than retained per publication.

## Compiler coverage: bounded batch dispatch staged (2026-09-28)

- The retained five-function pointer report totals155.7349s of individual job
  wall time against157.564s for the outer decompile batch. Current batch main
  dispatches serially; the pipeline's construct-level worker setting does not
  parallelize these functions. This is measured orchestration evidence, not an
  end-to-end speedup result or a reason to weaken function deadlines.
- A third disjoint Devin task stages at-most-four function dispatch with
  deterministic reports and unchanged process-isolation/timeout/failure gates.
  Dirty source baselines and a task-specific prompt are retained; the verified
  host-read-only/repository-writable sandbox inherits the4GiB address limit.
  Parent review and source-frozen KVM measurement precede any default acceptance.
- The caller-return snapshot candidate is undergoing independent saved-source
  red/green replay. Its canonicalized clean-worker lanes require optional
  sidecar hints; this separate transport repair does not by itself address the
  current hint-free pointer-case refusal. The modular input join remains the
  active semantic slice. No new witness or required gate is accepted.

- The caller-return snapshot correction is now integrated and routine-enrolled
  after Devin exits and independent parent review. Saved-source red4fail,
  staged green4pass and final shared-tree22pass verify late-fact preservation,
  UNKNOWN retention, same/rebased transport and snapshot isolation. Parent
  Pyright maps all50findings exactly to the saved source; MyPy retains one
  identical old no-any-return. Ruff/startup/context/ownership/type-ratchet pass.
  Review: `.cache/devin-reports/direct-caller-return-snapshot-parent-20260928/REVIEW.md`.
  No hint-free pointer repair, full roundtrip or required broad gate is claimed.

- The modular input handoff is not integrated yet. Parent refuses its six new
  fixture typing errors as new debt, fixes the third-party fixture projection
  in an isolated candidate, and demonstrates an additional missing callee-scope
  guard (worker candidate falsely classifies another callee's modular proof).
  Independent old-source red3fail/4pass, foreign-proof red1fail, corrected
  candidate15pass. Parent Ruff/Pyright/strict MyPy pass; final integration,
  enrollment and normal KVM replay remain pending. The worker's fixture claim was
  corrected: controlled0x1010 blob evidence is not a real POINT collection run.

## Compiler coverage: modular input join integrated (2026-09-28)

- The parent-corrected callee-bound modular word proof is integrated at Types/
  Lowering and routine-enrolled. It supplies SIGN_INSENSITIVE scalar evidence
  only when the existing IR proof is complete and condition interpretation is
  absent; pointer and condition-conflict proofs retain precedence. It does not
  relabel census segment storage or infer pointer/return/source signedness.
- Final shared focused checks:115passed/7warnings54.77s. Ruff, strict MyPy,
  Pyright and startup/context/ownership/type-doc ratchets pass. Three initial
  ownership expectation failures reproduce with the saved pre-integration
  manifest; expectations now include all newly enrolled regressions, with no
  removed coverage. Parent review remains under the modular-input report path.
- The normal KVM pointer replay completes five jobs with return0/clean tails,
  but MS C caller dereferences still fail C2100/C2106. Its source fingerprint
  changes during execution, so the309.68s run is diagnostic-only, not acceptance
  or comparable performance. A bounded single-function diagnostic now retains
  census/target aliases per publication and checks the complete source identity.
- The staged parallel dispatcher is not accepted. Parent review finds masked
  IPC read errors and cleanup that can signal already-reaped PIDs; its claimed
  process-group tests cover direct children only. A bounded follow-up Devin
  task owns only the staged scheduler/tests, with saved pre-review sources and
  required red/green/actual-descendant controls. No witness or broad gate closes.

## Compiler coverage: real modular inputs close; return census unavailable

- The current source-free POINT diagnostic executes the original publication
  hooks in the analysis worker and retains every attempt separately. All four
  observed selected-target publications close input collection at
  raw/normalized/classified/materialized/failures = 2/2/2/2/0. All eight observed
  callee-bound modular proofs are PROVEN. Source fingerprints are unchanged.
- All four publications return the typed RETURN_EVIDENCE_UNAVAILABLE verdict.
  Their exact accepted target is 0x100f1; before/after registries contain only
  the unrelated 0x105bc census. No pointer classifier runs. This proves the
  real input refusal is removed, not a pointer-return or function fix.
- The diagnostic uses an initially signature-metadata-only private cache and
  explicit in-process/thread hooks. Its internal decompilation deadline still
  expires while building caller semantic SSA; the CLI exits3 with failed/
  uncollected tail validation. It is not normal performance or acceptance.
  Evidence: `.cache/devin-reports/near-return-modular-join-current-metadata-20260929/`.
- Next boundary: distinguish a typed non-result from the source-free frontend
  recorder versus evidence loss across CLI project transport. A setup-only
  observer calls the originals and stops before Types/decompilation. Do not
  inject the separately successful fresh-project census or relax return gates.

## Compiler coverage: binary caller census restored (2026-09-29 local)

- The setup-only observer identifies the producer defect: optional signature
  0x101b5 clips the caller before calls0x102c8/0x102e6. The source/direct project
  is the same; no selected census exists to transfer. Independent loaded-byte
  Frontend reachability closes72/72/72/72/0 across the full caller and contains
  that conditional return arm and both calls.
- Caller-census limits now consume the existing closed Frontend body, with
  project/entry/extent guards. Only proven interior signature delimiters are
  removed; genuine unreachable library neighbors and unavailable/open proofs
  retain their limits. Candidate recovery/library exclusion is unchanged.
- Parent red2fail/2pass; an additional review control rejects dropping a later
  genuine delimiter (red1fail/2pass). Final focused/routine checks172pass in
  74.89s. Ruff/MyPy and startup/context/ownership/type-doc checks pass. All five
  CLI Pyright findings exactly match the saved dirty source, shifted by imports.
- The corrected real-binary setup records selected USED evidence2/2/2/2/0,
  with both exact calls and unchanged sources. This closes the census producer
  gap, not pointer typing, tail equivalence, feature admission or the roundtrip.
  Review: `.cache/devin-reports/return-census-lifecycle-20260929/REVIEW.md`.
- Devin's dispatcher follow-up times out after its reported43green tests.
  Independent parent review catches a false-death test oracle, adds a genuine
  wait-interruption control, reproduces red5fail/3pass and green45pass. Project
  scoped static checks pass; no live integration/default or real speedup is
  accepted. Review: `.cache/devin-reports/bounded-function-batch-parent-20260929/REVIEW.md`.
- Another full required pipeline is running in the shared workspace; the next
  linked KVM pointer replay remains serialized. No broad gate is waived or
  claimed green from focused results. Steps1–5 remain incomplete.

## Compiler coverage: staged worker budget reviewed (2026-09-29 local)

- The bounded Devin test task exits124 before its final report. Parent review
  confirms only one staged test was added; all five saved candidate files are
  unchanged. Its retained green result alone is not accepted.
- Parent independently proves the budget delta red: nine selected command cases
  fail on the saved serial build source because --workers is absent. The final
  candidate passes all12budget/flag/default controls, seven warnings,44.36s,
  after mechanical Ruff import/noqa cleanup. Scoped Ruff passes. Binary targets,
  not a different fallback inventory, own the at-most-four count; numeric target
  selection and source-free flags survive, and generic default remains1.
- The dispatcher stays isolated: no live/default integration, real KVM speedup,
  memory threshold or semantic acceptance is claimed. Review and logs:
  `.cache/devin-reports/msc6-batch-worker-budget-parent-20260929/`.
- The previous external pipeline's tracked handles are now absent, but its
  outcome is not owned/verified here. The corrected pointer_memory adapter
  (manifest ID array_pointer_writes) is running at the existing600s case budget
  in a private cache and verified KVM sandbox. Original DOS build/run passes
  with exit255; five jobs keep numeric targets/no source-debug recovery. The
  linked roundtrip result and source/environment stability checks remain pending.
- A separate120s nonpublishing return-collector probe expires before reaching
  its boundary, without a typed result. Its clinic/setup trace is diagnostic,
  not a new refusal verdict or acceptance. Do not inflate its/normal deadlines.

## Compiler coverage: stable pointer replay identifies C bridge failure

- The corrected KVM/private-cache pointer_memory roundtrip exits1 after320.78s
  with typed outcome validation_failed. Implementation/environment fingerprints
  are unchanged; original DOS build/run passes255. Four batch functions exit0;
  select_word exits4 and a focused retry retains the same compilation failure.
- The selected function now emits a pointer return and a sign-insensitive
  unsigned-word index, but the return expression adds the scaled byte offset
  to a void-pointer input. MS C syntax validation correctly rejects C2147
  (unknown size). Tail checks are clean, but final validation/recompilation fail;
  no rebuilt DOS execution or function/witness acceptance is claimed.
- Next owner is Types/Lowering's address-expression/native-C bridge: consume
  exact modular16 arithmetic and storage/segment bindings into one coherent C
  projection. Do not infer the input pointee from the returned load width, apply
  a rendered-C/harness cast, or replace modular guest arithmetic with unproven
  native pointer arithmetic. Existing scaled-return IR evidence remains a
  nonpublishing math proof, not permission to guess a pointer representation.
- Artifacts: `.cache/compiler-coverage/caller-census-pointer-20260929/`.
  The dispatcher remains staged; required final-source gates and Steps1–5 stay
  open. The previous external pipeline outcome is not verified here.

## Compiler coverage: near-return address bridge prerequisites (2026-09-29)

- The exact modular affine Value now survives the scaled-return IR result.
  The candidate exposes that same object only with a complete proof and exact
  coefficient-to-storage binding. Parent review adds wrong-register, reversed-
  input and refused-candidate controls; independent saved-dirty baseline
  red9fail/26pass, final focused35pass/7warnings39.82s. Devin1837 exits124 at
  its480s limit without a report; its four-file delta is reviewed independently.
- Return trials now retain full caller pointer-use evidence, not only pointee
  width. Exact caller/call/witness bindings are checked without inferring the
  input pointee or segment. Focused red2fail, final34pass/7warnings57.11s.
  One synthetic caller-clone mock required a coherent copied proof; no production
  catch, refusal or validation gate was weakened to accommodate it.
- Explicit near-offset/byte-add runtime representations pass host O0/O2 and
  native MS C6/KVM checks (30pass/7warnings38.07s). Wrong segment flattening,
  element scaling and nonwrapping helpers are deliberately rejected. Portable
  operands require the supplied guest-memory view; unrelated native objects
  abort. Null and modular16 are preserved. Native results still require proven
  native near-data binding. Scoped Ruff and strict MyPy pass.
- These are prerequisites, not the pointer_memory repair. No prototype/body
  consumer is connected yet. Source-pointer space, segment preservation and
  structured-return congruence must be proven before atomic publication, followed
  by the same normal DOS round trip and mandatory final-source gates.
- Changed-file gate passes318tests/8warnings161.10s; scoped Pyright reports0
  errors. Broad quality-dev initially stops before tests on a duplicated MyPy
  input. The recipe now checks each unique path once; saved before/after sets
  are identical (334files), no exclusions or diagnostics are removed, and actual
  mypy-dev passes. Red duplicate-input controls cover default and override scopes.
- The native near-pointer control is now an explicit default/expanded execution
  target, with routine Ruff enrollment; the existing GP runtime file is exactly
  unchanged from its saved dirty baseline. Full runtime/pipeline/Make controls
  pass92tests/7warnings58.25s after the exact inventory expectation is extended
  (not weakened). No final-source broad-gate or function acceptance follows from
  these scoped results.


## Binary comparator loader checkpoint — 2026-09-29

- Corrected PE inclusive-end initialization in one shared loader consumed by
  both flat32 adapters. Exact byte reads and native RET decode now agree; the
  seed is contiguous before relocation, with explicit mapped-size refusal.
- Seven routine controls cover both drivers, virtual zero tails, final-word
  relocation, resource bounds and BC5 cache source identity. Actual dirty driver
  baseline:2 failures. Final combined cohort:190 passes in49.46seconds; scoped
  Ruff, strict MyPy and correctly scoped Pyright pass.
- MZ/ELF/PE byte binding and full-state initialization relation remain staged.
  Caller/code aliases retain countermodels; no whole-binary recursive pass.
  New final-source quality-dev is running; KVM absent at launch. Earlier broad
  failures remain unresolved, and full binary-equivalence plan acceptance is open.

## Binary comparator entry-domain checkpoint — 2026-09-29

- Added staged loader/bootstrap-derived selector and stack-alignment evidence,
  universal physical stack geometry, and complete per-effect preservation.
  Native comparison consumes the exact required ledger and retains every output.
  No recursive or whole-binary acceptance is granted by this scalar theorem.
- Initial seven failures came from an incomplete bootstrap fixture range;
  correcting the actual range preserves admission gates and yields seven passes.
  Final native/initialization/default-refusal/both-flat32 cohort:108 passes in
  83.46seconds. Contract/native/bootstrap cohort:71 passes in79.36seconds.
- Nine source-owner mutation controls invalidate domain reuse. Retained old
  seal misses six owners. Sandbox Devin oracle delta reviewed and independently
  reproduced; mismatched selectors and missing-selector mutations are checked.
  Scoped Ruff and strict MyPy pass. Final bootstrap control passes in42.76seconds:
  unconstrained alias countermodel retained; changed saved return word rejected
  even though scalar initiation and preservation still prove.
- Terminal quality-dev:296 preliminary passes; main curated gate7924 passed,
  25 failed,1 skipped in1818.60seconds; exit2. Three files changed during the
  gate; no fixed-tree acceptance or failure-cause classification. Full failure
  list and source audit retained under the staged binding-gate terminal summary.
- Full plan remains open: independently bind supplied native effects to decoded
  immutable images, close recursive caller/control/progress/fault/environment
  evidence, both flat32 reachable domains, M4/M5 general cases and M6/M7 gates.

## Binary comparator actual caller-frame checkpoint — 2026-09-29

- Actual relocated MZ bootstrap effects now prove the independently decoded
  saved return word and all entry-frame clauses over arbitrary background state.
  Real CALL-to-JMP and missing/corrupt word controls refuse. Scalar receipt
  consumers bind predicate fields to the authoritative loader-derived factory;
  saved dirty baseline reproduces falsely accepted alignment changes.
- Final source/domain/frame/native cohort:27 passes in96.93seconds. Complete
  joint composition:2 passes in94.27seconds, retaining all native transitions,
  both sides' frames and atomic dispatch/progress. Only complete composition
  closes caller-entry evidence; physical code/address/fault/environment scope
  stays CONDITIONAL, with no binary proof or production recursive promotion.
- Joint source-owner mutation reproduces a missing dispatch-evaluator seal
  (expected red); seal correction and final checks are running. Scoped proof
  owners pass Ruff, strict MyPy and configured Pyright.
- Parent-reviewed no-access Devin delta:2 expected saved-baseline ELF/PE failures,
  then14 green controls. Observation/mapping Devin remains active; its candidate
  requires independent review of complete evidence and repeated-claim bounds.
  Full M4-M7, production integration and fixed-tree project gates remain open.

## Flat32 memory-observation production checkpoint — 2026-09-29

- Parent reproduced observation-created mappings on the saved dirty baseline,
  reviewed/froze the sandboxed Devin delta and independently found three further
  completeness/work-budget defects. Parent red:3 failures in26.58seconds;
  aggregate byte-budget red:1 failure in32.79seconds. Corrected staged22 controls
  pass in26.43seconds; public CLI baseline control fails as expected.
- Production has separate typed replay-model, permission and memory owners.
  Observations are read-only; patches seed already mapped bytes; data-only
  caller scratch is explicit and cannot widen FILE permissions. FILE NONE,
  unsupported provenance, required-observation denominators and finite repeated
  claim/aggregate byte work remain visible through API and public CLI.
- Final production replay/enrollment cohort:169 passes in54.11seconds. Six
  owners pass scoped Ruff, strict MyPy and configured Pyright. New helpers/tests
  are enrolled in Make, ownership and routine pipeline. No binary proof follows.
- Fresh quality-dev baseline:2,548 files, saved dirty sources. First attempt
  terminal2 at sandbox temporary-directory setup with no source drift. Retry
  using repository TMPDIR is active; KVM absent. Actual fetched-code preservation
  Devin is active in ignored staging. Full real16/flat32 M4-M7 and release gates
  remain open.

## Ordered binary memory-prefix evidence — 2026-09-29

- Raw unoptimized native access intake retains dead reads and intermediate stores;
  actual save/write/restore controls expose temporary code changes hidden by final
  memory equality. Nonvacuity, finite intake and original deadlines remain explicit.
  Final raw-access/byte-oracle cohort:8 passes in65.86seconds.
- Code-fetch Devin timed out124 with one untested partial owner; parent rejects
  final-memory-only preservation and retains the exact terminal proposal. Parent
  now binds every store prefix to fresh immutable MZ decoding and consumed source/
  entry-domain evidence. Joint composition requires this child and seals its
  dependencies. Saved old joint seal:3 expected mutation failures; missing-request
  denominator control:1 expected red. Final code-prefix/joint cohort:11 passes
  in76.25seconds; scoped Ruff, strict MyPy and configured Pyright pass. Child
  receipt deadline reasons/causes remain explicit, without a renewed budget.
- Quality-dev retry terminal2:296 preliminary passes;7955 curated passes,29 failures,
  1 skip,2007.38seconds. All2548 saved production hashes match terminal. KVM was
  absent in that sandbox. Exact device/API12 subsequently verified; a bounded
  sandboxed Devin rerun is terminal0:14 tests pass,15 fail,493.80seconds pytest,
  all2548 saved sources unchanged. Parent reviews the six assertion/validation
  failures, eight timeouts and one ASan-limit refusal; source-regression provenance
  remains unresolved. Parent ASan control independently passes in6.27seconds
  with normal address-space limits and no source edits. A disjoint bounded Devin
  stages every raw access's first-MiB address bounds. Full address/fault/environment
  closure, recursive binary proof and full M4-M7 acceptance remain open.

## Native operand scope and source connection — 2026-09-29 (staged)

- Original decoded operand widths and logical segmented coordinates survive raw
  byte splitting. Independent native-address binding and unsplit segment-scope
  checks refuse wordFFFF and insufficient dword stack alignment. Source/domain
  initiation, physical permissions and faults remain independent obligations.
- Saved ledger/model-seal controls:2 expected failures in29.73seconds. Corrected
  raw/operand/scope/prefix/joint cohort:36 passes in69.09seconds. Exact counters,
  unique required occurrences and valid access facts are mandatory for completeness.
- The new MZ connection independently decodes every consumed immutable request,
  uses loader bootstrap or established cutpoint domains, retains missing graph
  nodes and reconsumes prerequisites. Child deadline control:1 expected failure
  in34.57seconds; connected cohort:24 passes in57.40seconds. Four staged owners
  pass scoped Ruff, strict MyPy and configured Pyright. Final shared cohort:
  41 passes in88.96seconds.
- Both earlier Devins timed out124; their partial proposals are unaccepted.
  Parent recompiled all three frozen REP probes and independently reproduces
  the memory oracle differences at0x10000/0x20000 with matching return and EDI
  controls. Earliest-layer fix and gate acceptance remain unresolved. The bounded
  sandboxed review Devin timed out124 without a patch, test or report; parent
  verifies its owned source unchanged. Full M4-M7,
  production integration and physical/fault/environment acceptance stay open.

- Parent physical-owner regression:2 expected failures in31.01seconds for raw
  incompleteness and duplicate/missing-witness block evidence. Corrections retain
  native solver outcomes/deadline flags, distinguish UNKNOWN from vacuity and
  require exact manifests. Six local controls pass in39.03seconds; scoped Ruff,
  strict MyPy and configured Pyright pass. Final physical cohort:7 passes
  in39.84seconds, including actual-MZ source/domain and stale/missing/expired
  controls. Final accounting and duplicated source ownership still require
  review; no binary proof follows.

## Mandatory joint data-address prerequisites — 2026-09-29 (staged)

- Joint induction now requires source-bound original operand and physical-byte
  proofs, retains both children/counters/deadline reasons and seals their models.
  Saved baseline:5 expected failures/4 passes in59.30seconds; ignored-child
  controls:2 expected failures in73.88seconds; child-reason red:1 in37.21seconds.
  Isolated9 controls pass in95.39seconds. Full physical/fault/environment scope
  remains conditional, and no binary proof is granted.
- Devin timed out124 with a partial physical-source patch and test; exact delta
  frozen, shared prefix/raw inputs unchanged. Parent fixes its zero-access
  injection control and independently proves the old early-failure denominator
  drops31 required rows to21. Complete source intake now freezes later accesses
  before bounds queries and reuses the authoritative source owner. Unproved
  source results and stale transitive source models refuse (two parent red cases).
- Final shared joint/source cohort:14 passes in111.20seconds. Three owners pass
  Ruff, strict MyPy and configured Pyright. A combined isolated run reports
  16 passes/1 final-receipt deadline; unchanged-budget positive control passes
  separately with19.95second test body. Final physical/source cohort:14 passes
  in89.62seconds, including the corrected31-row countermodel ledger, with
  unchanged positive budgets.
  Production integration, fault/environment closure and full M4-M7 remain open.

## Fetched-span source prerequisites — 2026-09-29 (staged)

- Independent geometry now proves a nonempty native domain, the entire decoded
  CS window and the first-MiB physical extent. Legacy VEX IP is not an architectural
  witness. Source-prefix blocks require this child with matching address/size;
  model seals include the fetch and coordinate owners. Control correspondence,
  permissions, traps and asynchronous effects remain independent obligations.
- Saved source control:1 expected failure in76.49seconds; the old preservation
  connector lacks an independent refusal for a bootstrap fetch below CS. The
  first correction cohort has13 passes/1 test-selection failure: the bootstrap
  follows graph rows, so the parent corrects selection using actual binding.entry.
- A bounded saved-source profile proves the old15-second producer in14.51seconds
  and refuses the new producer in15.26seconds, with4.37seconds in eight fetch checks.
  Parent retains those failures and replaces fresh per-fact solvers and mixed
  integer arithmetic with one incremental context and exact64-bit extents.
  Optimized fetch/source cohort:17 passes in130.35seconds, with budgets unchanged.
- Saved joint-controller replay:1 expected deadline-reason failure in137.21seconds.
  Prefix and prerequisite receipt deadlines now retain typed DEADLINE at the
  parent, and failed prefix counters cannot enter induction. Final fetch/joint
  cohort:20 passes/1 recursive positive deadline in247.26seconds. That120-second
  exhaustion occurs in the native child; its legacy parent branch still reports
  UNKNOWN. Entry/native/frame reason propagation and positive acceptance remain
  open. Four owners pass Ruff, strict MyPy and configured Pyright.
- Sandboxed read-only Devin82370 times out124 after420seconds with a partial
  store-owner note. Parent verifies its five saved inputs unchanged and confirms
  the runtime word-store join lacks segment-wrap evidence; its exhaustive
  only-producer claim is unaccepted. No production patch was accepted.
  Full M4-M7, production integration and project gate acceptance remain open.

## Compiler-coverage bounded dispatcher — 2026-09-29

- Integrated the independently reviewed function dispatcher: one-to-four
  disposable workers, original per-job budgets, ordered streamed checkpoints,
  loud IPC/result refusals and owned child/process-group cleanup. Generic CLI
  default remains one; MS C selects at most four from the actual job inventory.
- Parent complete-frame stall regressions fail2 before correction; missing or
  invalid result regressions fail2 before collection guards. Staged35 checks
  pass46.13s; shared runtime/command/fork cohort129 passes109.21s. Scoped Ruff,
  six-owner MyPy and configured Pyright pass. Final check-files passes366tests
  in227.07s after removing staging-only skips from the enrolled tests; startup,
  ownership and ratchets pass. Existing dirty-source edits are preserved.
- Source-stable raw caller IR confirms both AX PUSH definitions and isolates
  the refused BP live-in across earlier CFG blocks/real calls. It publishes no
  Alias identity, pointer type or body/signature fix. Bounded read-only Devin
  times out240s without a completed report; parent verifies its five saved
  sources unchanged, all12raw call effects unproved, and the exact bp_preserved
  producer restrictions. Raw/entry-wide frame facts are not per-use preservation.
- Normal four-worker KVM replay retains all5ordered results in153.89s with
  2CLI successes/3timeouts and unchanged owned sources. Sampled aggregate
  process-tree PSS is1.35GiB/RSS1.70GiB, not a universal bound. Serial replay
  records5results/one CLI success/4timeouts548.30s but Widening/ownership sources
  change during it. No controlled speedup or linked-roundtrip claim follows.
  Quality-dev89472 is terminal2:296 preliminary passes; fast unit8010passed/
  22failed/67warnings. It ran09:25:36-10:28:32UTC for3775.4038s with KVM API12,
  unlimited address space and unchanged owned-Python sources. Default/external
  lanes were not reached. Whole-gate, pointer, pilot and global-plan failures
  remain open.

## Compiler coverage: reviewed caller BP transport candidate — 2026-09-29

- A new isolated IR owner transports bare word BP only to one exact reaching
  definition across every supplied predecessor path. Explicit complete CALL
  preservation is required even when SSA has no BP destination. Conflicting
  definitions, unknown edges, overlapping EBP/ESP writes and width mismatches
  refuse atomically. Entry-register traces retain consumed CALL sites.
- Parent reproduces saved-source8fail/7pass and two failing width controls;
  four further review controls fail before correction. The Analysis adapter now
  retains the actual full predecessor census rather than treating a missing
  map as an empty CFG. Final isolated cohort62passes in119.01s; controller and
  seven workers record identical eight-owner provenance. Scoped Ruff, strict
  MyPy with the actual scalar contract and configured Pyright pass.
- Fresh source-stable binary caller replay retains12/12/12/12/0 CALL effects,
  zero proven BP-preserving calls and both real whole-PUSH refusals. Artificially
  replacing BP flags yields entry-SP-minus22 only as a counterfactual diagnostic,
  never as proof or pointer/function admission. Three of five leaf callees have
  non-SS writes; Alias restore candidates do not close whole-callee preservation.
- Integration follows the terminal neighboring gate8008pass/23fail/1skip,
  not a green gate. Devin29769 owns only three isolated registration snapshots, under a
  verified rootRO/repoRW/no-host-KVM/4GiB sandbox. It is terminal0; parent reviews
  all15added registration lines and independently reproduces Ruff, AST/body
  identity, literal counts and a real-target Make dry-run. Registration hunks
  are staged/accepted for integration, not semantic acceptance. Concurrent live
  registry additions must be retained; never copy a snapshot over live files.
  Review: `.cache/devin-reports/frame-register-livein-20260929/PARENT-REVIEW.md`.
  Parent integrates the reviewed seven-file patch via apply_patch after checking
  the old process tree has ended. Every semantic/test owner matches its reviewed
  stage hash; all concurrent registrations survive. Normal shared-tree checks
  pass62tests/7warnings59.83s, Ruff, strict MyPy with the actual scalar contract,
  configured Pyright and startup/context/ownership. Parent adds the scalar
  consumer to the ownership rule, final registry delta16lines.
  Final-source gates, linked roundtrip, Steps1-5, frozen pilot and Csmith remain
  required and unaccepted. Ordinary quality-dev15418 starts11:14:27UTC with
  KVM API12/unlimited parent VAS and retained before/after source identities.
  Static/startup and296 preliminary tests pass. At the user's three-pytest-worker
  instruction, parent orderly interrupts only the owned controller52110;
  the seven workers and gate exit, with partial156passes/7warnings and required
  gate terminal2 at11:47:29UTC (1983.44s wall). Logs/results remain intact.
  Source identity also changed during the run, so this is explicitly interrupted
  and unaccepted evidence, not a green gate. Restart must use three workers and
  new artifact names; test defaults and execution guidance are being updated.
- The bounded Alias worker88123 ends124/600s without any authorized file. Five
  snapshot owners still match the dirty baseline; its partial IR inspection is
  not accepted proof. Parent retains further Alias implementation and explicit
  ESP/SS-mutation refusal controls; the completed registration work is unaffected.
  Review: `.cache/devin-reports/real-callee-bp-20260929/LEAF-ALIAS-PARENT-REVIEW.md`.

- User selects three pytest workers. Make's ordinary, focused, profile,
  contract and whole-suite test defaults are separated from CPU/linter/compiler
  pools; both pipeline lanes and direct partition defaults use three. Existing
  heavy/exclusive limits are retained, without nested xdist pools. Runner
  regression cohort89passes9.59s; final combined cohort below reruns it after
  lint cleanup. Execution guidance records the new default.
- Parent reviews the later test-only Devin87701 timeout124/600s rather than
  accepting its partial report. Alias now invalidates saved SS bytes on an
  explicit SS-selector write, including when its instruction address is unknown.
  Captured LOAD values and fresh post-change saves retain their own proof.
  Real PUSH/POP, binary/supplied edges and word/parent-SP refusals are covered;
  final normal three-worker red4fail/5pass41.03s, green combined175pass/3warnings
  28.79s. Scoped Ruff, strict MyPy with actual IR contracts, configured Pyright
  and startup/context/ownership pass. Routine QA, pipeline and restoration
  ownership enroll the new control. This is not whole-callee BP preservation
  or function/pointer admission. Review:
  `.cache/devin-reports/real-callee-bp-20260929/SS-PARENT-REVIEW.md`.
- Fresh ordinary quality-dev15273 starts11:59:25UTC with explicit three-worker
  pytest defaults, char10:232/API12 and unlimited parent VAS. Logs/start/result
  use `shared-quality-dev-three` names; the interrupted artifacts are untouched.
  Owned-Python start SHAabe93ba81f69af41c6e73bd8cdb9f309528d73ef1071d979bea0e6a96fac317a.
  Static/startup checks and296 preliminary contracts pass with three workers
  (40.72s/3warnings). The main lane is waiting on the shared pipeline lock;
  the gate remains pending. A fresh native exit7 COM succeeds both directly and
  through the verified KVM sandbox, but the scoped storage_classes retry again
  reports build_failed with child `/dev/kvm` absent (implementation/environment
  unchanged). A bounded FD-verified-launcher retry then fails loudly at its own
  device stat before creating a fixture report. KVM is still boundary-dependent;
  successful probes do not close DOS roundtrip or semantic acceptance.


Compiler-coverage native/provenance checkpoint (2026-09-29): direct commands
retain verified KVM while shell log redirection loses it in paired probes.
Internally opened logs permit the same rootRO/repoRW/private-device4GiB boundary:
storage_classes original build/run succeeds (exit255), then PREFIX_UNSUPPORTED
correctly refuses source-derived declarations (26.97s). simple_control original
build/run succeeds, but the fixture times out601.58s with all three batch jobs
timed out/uncollected; no case is admitted or replaced. A single classify
force-thread diagnostic executes actual analysis at its original60s deadline,
exits0 with tail validation passed, and takes44.84s decompilation/97.89s overall.
Source identity is unchanged. This diagnostic is not default-lane or roundtrip
acceptance. Artifacts: .cache/compiler-coverage/*three-kvm-direct-20260929-* and
classify-timeout-profile-20260929.

The nonpublishing leaf-BP prototype now independently rejects a forged retained
restore fact by recomputing Alias from retained IR; its valid control survives.
Scoped static checks pass; all19 snapshot controls now pass/3warnings10.40s
with three workers and unchanged source/test bytes. The initial harness import
failure is retained; a clean child avoids the outer live-package shim while
keeping all seven snapshot-origin assertions. Reviewed Devin60502's SS-local
proposal retains unresolved16-bit wrapping,
write-width and must-coordinate obligations, not whole-callee proof. Nothing is
promoted, and all five real callees remain refused. quality-dev15273 is terminal2
at13:13:17UTC, with unchanged owned-Python SHAabe93ba81f69af41c6e73bd8cdb9f309528d73ef1071d979bea0e6a96fac317a.
Main lane:9failed/8109passed/63warnings2071.36s;296preliminary tests passed
40.72s. Whole4433.35s includes lock wait. Default/external lanes were not reached.
Remaining failures concern DOS signatures/arguments, three SORTD obligations,
a stale SS-copy control, InBox incidental argument names and two CLI timeouts.

Parent corrects the stale SS-copy expectation without relaxing Alias: an SS
selector change invalidates the old PUSH storage. Three real binary controls
retain typed source-missing/changed-SS refusals, including captured pre-change
values. Focused red1fail precedes3passes; the final live SS/provenance family
passes50tests/3warnings17.38s with three workers, unchanged source/test bytes.
This is focused evidence, not a new green broad gate or whole-callee admission.

Default-fork classify diagnostic exits0/tail-passed19.49s decompilation/50.18s
whole, with generated C identical to the earlier force-thread diagnostic.
Parent-reviewed measurement observes121scalar-index builds(1.506s inclusive),
74logical traces(0.671s),9stack transfers(0.597s) and9pointer-stack contexts
(0.687s) in25.52s decompilation; do not sum nested timings. Even removing all
transfer-builder cost saves at most2.34%, so no local-index optimization is
accepted. Sequential runs do not prove causality or a controlled speedup.
The full simple_control native roundtrip remains timed_out and unadmitted.
Artifacts: .cache/compiler-coverage/{pytest-checkpoints,
classify-default-lane-20260929,classify-index-parent-20260929}/;
.cache/devin-reports/classify-index-measurement-20260929/PARENT-REVIEW.md.
One bounded, workspace-sandboxed Devin test-only InBox oracle handoff starts
14:57:46UTC; the parent retains exact dirty baselines and acceptance ownership.

Native simple_control checkpoint: original and recompiled executables both
exit255; all three numeric source-free function jobs/tail reports pass and the
full adapter is passed27.43s. Source/environment fingerprints stay unchanged;
the binary is identical to the retained failed case. classify/sum_to are validated
cache hits; switch_fold analyzes live. Record warm behavior, not cold speedup
or automatic feature admission. Artifact:
.cache/compiler-coverage/simple-control-native-final-20260929-1501/.

One missed compiler-coverage-contracts-n7 recipe is corrected to the shared
three-worker setting. The new Make concurrency parameter fails before the
change and all six direct dry-run controls pass afterward, without starting
another pytest pool. Actual pytest is serialized behind unrelated run22547.
InBox Devin1281 expires124/360.54s, with red evidence but no completed green
report. Parent reviews its exact test-only C-AST delta, keeps the unchanged
compiled/tail oracles and adds4positive/11negative durable mutation controls;
the exploratory worker script did not make unexpected outcomes fail its exit.
Scoped Ruff/format and15direct durable structural assertion controls pass;
no extra pytest pool starts. Parent live pytest and semantic acceptance remain
pending. Later owned-Python audit changes to5ff3cbc309725ace2361d90cdd85e9ecd86e281c738a388ec4eab2ba7f5345b0
with1243files; recent unrelated check_unused_python_files.py is preserved.
Historical source-stable results are not current final-tree gates.

User-supplied MS C8 and Borland5.02 rebuild/gen directories are read-only
compiler-implementation references. They contain patched executable decompiler
exports (including C23216 and BCC/Hex-Rays), not required binary-recovery hints.
Paths and evidence boundary are recorded in the compiler-coverage plan; no
external files or frozen acceptance scope change.

## Comparator model-seal and runtime store checkpoint — 2026-09-29

- Fresh traversal-local native fingerprints remove repeated source scans while
  preserving independent before/after freshness and package/owner identity.
  Actual recursive positive plus snapshot controls pass6 in204.26s at the
  original proof budget; this remains a conditional caller-entry theorem.
- Parent reproduces Devin's saved-source6red/2green store controls, then requires
  alias-proven nonwrapping byte identities before runtime word widening.
  Store/snapshot cohort13 passes; store controls enter the routine test lists.
- Two unchanged partial-C kernels now agree with the compiled memory/return
  oracle. Tail validation and the third binary remain unaccepted: KVM access
  differs between a successful launcher probe and failed subsequent launches.
  No full binary proof, green broad gate or full M4-M7 completion is claimed.
- Bounded sandboxed Devin54715 owns only new staged child-deadline tests/report;
  parent owns the controller patch and acceptance. Current source/evidence is
  frozen under the recursive stage's snapshot-store-checkpoint.

- Deadline-test Devin54715 exits124 without a patch or report; all four saved
  owners remain unchanged. Parent adds controller-only typed regression controls;
  mocked successes are accounting instrumentation, not semantic evidence.
- First quality-dev attempt stops in linters with compiled-import smoke unable
  to find writable temporary storage. Corrected gate uses repository TMPDIR;
  tests were not reached by the first attempt.


## Comparator nested causes and package preparation — 2026-09-29

- Three saved-source cohorts each reproduce3 lost-deadline failures/3 valid
  nondeadline refusals. Parent propagates typed causes through joint, native
  before/transition/after and entry before/clause/after boundaries. Combined18
  routing controls pass132.61s; scoped strict MyPy and configured Pyright pass.
- Actual joint positive recheck still expires at the original120s budget during
  entry consumption; its typed producer loss is corrected after that run.
  Final positive and whole-binary acceptance remain open.
- Devin54715 and48989 time out124 without patches/reports; parent records those
  limits and supplies direct tests/inventory. The34module production package
  candidate preserves executable ASTs and documented typed contracts, passes
  Ruff/import checks, and remains unpromoted pending semantic integration checks.
- Repository TMPDIR resolves the quality-dev smoke environment failure:39module
  compiled smoke and296 preliminary tests pass. Main fast pipeline93212 remains
  active; no green full gate or full-plan completion is claimed.

- Candidate initial Pyright overlay could not resolve its staged tools namespace
  (177 diagnostics). A complete isolated package layout uses unchanged durable
  dependencies and no suppression; configured Pyright now reports0errors0warnings
  across all34 candidate modules. The candidate remains unpromoted; semantic
  checks/enrollment and the live broad gate are still required.


Binary comparator production checkpoint (2026-09-29): recursive local proof
contracts now have a36module tools/dosunit/recursive_proofs package with durable
fast controller tests and actual-MZ slow controls. Candidate25controls pass;
initial production25cohort has24passes/1typed deadline refusal, so semantic
acceptance remains pending. Fresh source-key optimization preserves all1103keys
and exact fresh digests while reducing measured hashing cost; final proof and
freshness checks remain active.37production modules pass MyPy/Pyright; scoped
Ruff/doc/type/dot-access/startup architecture and ownership checks pass.
No binary_equivalence_proved/validation=passed promotion, whole-gate acceptance,
full-plan completion or flat32 completion is claimed. Detailed evidence and
remaining obligations:reference/binary-behavior-equivalence-plan.md.

Final production proof/freshness cohort:34passes/1typed physical-access deadline
refusal in261.90s. Hash parity/freshness is verified; the actual recursive
positive remains unaccepted. A current production checker profile is active.
KVM recheck fails before launch with absent /dev/kvm. Full goal remains active.


Comparator receipt-consumer checkpoint (2026-09-29): parent-reviewed Devin static
audit supports one fresh local native-model leaf per invocation, retaining the
independent final complete-model refresh and all per-side binary/effect checks.
Parent applies that delta and preserves3typed child deadline causes. Baseline
has4new red controls; final30routing/accounting controls pass114.89s, with both
new roots enrolled in routine gates. Scoped Ruff/Pyright/doc/type/dot-access,
ownership/startup architecture pass; strict37owner MyPy passes. Actual-MZ5case
proof recheck76845 and broad quality-dev93212 remain live. No proof/binary
acceptance, green broad gate or full-plan completion claimed.


Receipt checkpoint final evidence: actual-MZ5controls pass143.60s at unchanged
120s proof budget (positive86.17s), preserving CONDITIONAL/local scope and all
four remaining machine/environment requirements. Fresh-source7controls pass.
Broad quality-dev93212 exits2 with8008passes/23failures/1skip2395.46s; source
changed during the run, so it is not a stable final-tree gate. Reproduced and
corrected the stale slow-lane inventory; all56pipeline-controller tests pass.
Remaining KVM/timeouts/semantic/signature/process failures need baseline
classification. Full plan, both flat32 acceptance and final gates remain open.


Explicit seed checkpoint (2026-09-29): initialized-memory owner constructs and
validates actual loaded-byte arrays over arbitrary background for real16/flat32.
Five before-patch failures become78passing seed/receipt/freshness/pipeline
controls147.97s;37owner MyPy/scoped Pyright/Ruff/contracts/ownership/architecture
pass. Loader-entry-only API is documented; fetched-code dynamic certificate and
recursive assumption removal remain open. Devin73749 times out124 without its
report; parent direct-source findings are independent. Saved dirty baseline
reproduces _dos_envSize validation failure; current timeout leaves delta
unresolved. Actual-MZ final5case recheck76640 remains live at original budget.

Explicit seed final-tree actual-MZ5controls pass180.48s at unchanged120000ms
proof budget (positive114.69s call). Source identity stayed unchanged during
validation. No remaining recursive machine requirement removed; full goal active.

## Comparator coverage/resource priorities — 2026-09-29

- Added five planned experiments to `reference/binary-behavior-equivalence-plan.md`:
  direct relational proofs, shared memory expressions, adaptive region boundaries,
  bounded invariant refinement, then expanded proof/summary reuse. Each has its
  M2-M7 dependency, binary acceptance controls, success metric and fallback.
- Made unrolling-by-two/remainder/progress checks explicit M4 controls and fixed
  the shared-budget, full-state, alias, freshness and evidence requirements.
  Existing soundness/model closure and unresolved acceptance retain priority.
  Documentation change only; no implementation or new proof acceptance claimed.

## Comparator incremental deliveries — 2026-09-29

- Added D0-D5 deliveries to the comparator plan, from a stable baseline and
  usable real16 function pilot through broader loops, both flat32 adapters and
  environment/recursive acceptance. Estimates are conditional engineering ranges,
  not deadlines or evidence of completed work; reestimate after the baseline.
- Defined reproducible commands/reports, experimental versus accepted checkpoints,
  stable-source gates and measured ways to shorten the development cycle. The
  full two-track scope and all existing proof/refusal requirements remain intact.
  Documentation update only; no implementation or test execution in this turn.

- User requested a distinct notification when the original M0-M7 plan is fully
  accepted. Added an instruction at the top of the plan: report that milestone
  directly to the user without waiting for the later five experiments or D0-D5
  additions, while retaining every original two-track acceptance requirement.

## Compiler coverage KVM recheck — 2026-09-29

- This session can open `/dev/kvm`, read API version 12 and create a VM.
- Fresh `pointer_memory` round trip at
  `.cache/compiler-coverage/pointer-kvm-restored-20260929` builds and runs the
  original DOS binary, but fails decompiler acceptance after 74.05 seconds.
  `select_word` still fails MS C 5.1 syntax validation with C2147 (unknown size)
  for unsized pointer arithmetic. Whole-tail clean is not function acceptance.
- No recovery source was changed during this run. KVM availability removes the
  environment blocker; the pointer-lowering obligation and full plan remain open.
- Focused `test_x86_16_rep_store_codegen.py` recheck passes all 19 tests in
  175.25 seconds with `PYTHON_JIT=1` and three pytest workers. This includes ten
  sidecar-free generated-C execution cases and corruption controls. The earlier
  ten failures do not reproduce with restored KVM; no semantic patch was needed.
  Full log: `.cache/rep-store-kvm-restored-20260929.log`.

## Segment exit evidence checkpoint — 2026-09-29

- IR segment contracts now check every edge escaping the function artifact,
  including blocks that also have an internal successor. A restoring internal
  path cannot hide the escaping path's segment clobber.
- New focused regression fails before the fix (1 failed, 3 passed), then the
  contract/summary suites pass all 11 tests. Scoped Ruff and Pyright pass.
- This closes one local effect-proof defect; it does not establish complete
  callee effects, publish pointer arithmetic, or accept `select_word`.

## Shared IR boundary coverage checkpoint — 2026-09-29

- Extracted the direct-call proof's CFG census checker into
  `ir/ir_boundary_cfg.py`. Direct-call entry proof now consumes the shared owner.
  Added nonpublishing instruction-coverage evidence bound to the identical
  registered raw IR artifact and frontend boundary, with typed refusals and
  closed counts. Coverage alone never authorizes segment preservation.
- Integrated tests cover omitted/extra/disconnected CFG evidence, missing and
  unlocated instructions, foreign project/artifact, registry replacement,
  multi-operation IR expansion and corrupted accounting. The final focused
  boundary/direct-call/segment/pipeline-controller check passes 118 tests in
  19.12 seconds; scoped Ruff and Pyright pass. Both new coverage tests and the
  segment-contract exit regression are admitted to the routine pipeline.
- Scoped `make check-files` also passes: strict promoted-owner typing, type/doc
  ratchet, startup architecture, context and ownership checks, then 62 focused
  tests in 22.85 seconds. The new owner is enrolled in Make's Ruff/MyPy/test
  targets; no cast or typing suppression substitutes for its typed interface.
- The preceding required pipeline run completed its initial 296 checks and
  main unit lane (8210 passed, 6 failed, 1222.85 seconds). Failures are SORTD
  runmenu/insertionsort/initmenu, DOSFUNC loadprogram/loadprog, and SetGear.
  Parent intentionally stopped its verified owned process group during the
  next lane to resume implementation. Exit 143 means canceled, not a completed
  full gate; remaining lanes are unverified. Retained log:
  `.cache/pipeline-segment-exits-20260929.log`.
- Complete callee-effect classification, preservation consumption, pointer
  publication, final quality-dev/pipeline gates and the full plan remain open.

## Local segment-effect closure owner — 2026-09-29

- Segment state now retains its identical source IR artifact; serialized source
  address is diagnostic only. Added `ir/segment_effect_closure.py` to consume
  shared coverage, require bound complete block/register state, classify terminal
  RET exits and retain local CALL census with typed refusals and closed counts.
  Local closure does not prove targets or transitive callee preservation.
- Closure/state/contract checks pass 20 tests. Final scoped `make check-files`
  passes strict typing, architecture/context/ownership and 42 focused tests in
  33.89 seconds; scoped Pyright and Ruff pass. New owner and tests are enrolled
  in Make and the routine pipeline.
- This proof is not yet consumed by segment summaries. Next: attach it to local
  contracts, require a matching transfer census and propagate incomplete locals
  as UNKNOWN_REFUSE before adding preservation consumers. No pointer acceptance
  or full-plan completion claimed.

## Segment-summary closure integration — 2026-09-29

- Focused empty-callee regression demonstrated the defect: a zero-fact contract
  was classified PROVEN solely because its target existed. Local contracts now
  retain closure evidence, require the exact clobber projection, and expose
  `effects_complete`. The production attachment resolves an exact frontend
  boundary without source/debug semantic evidence.
- Summaries require complete local effects, the exact nonduplicated CALL census,
  classified targets and same-project caller/callee evidence. Incomplete locals
  propagate UNKNOWN_REFUSE transitively while known clobber floors remain visible.
  Local completeness has a typed field and its own counted proof/refusal fact;
  empty evidence is no longer reported with zero failures. Foreign project
  authorization is discarded on attachment, without discarding diagnostics.
- Final closure/summary/contract suite passes 21 tests in 20.58 seconds; final
  scoped Make checks pass 19 tests in 35.48 seconds plus strict typing,
  architecture/context/ownership. Ruff and Pyright pass. Positive controls use
  real registered raw IR and solved state, not fabricated proof flags.
- Fresh `pointer_memory` round trip is running at
  `.cache/compiler-coverage/pointer-closed-segment-summary-20260929`.
  Preservation consumption, pointer publication and full gates remain open.
- That round trip finished with original build/run passing and the same four
  accepted functions; `select_word` still fails MS C C2147. Decompile wall time
  was 144.20 seconds versus the earlier 74.05-second run, so this is not a speed
  improvement. Scoped checks overlapped part of this run; timing attribution
  needs profiling/controlled remeasurement. A fresh single-function worker
  profile is active before adding preservation consumers.
- Profiling completed via the explicit clean-worker entrypoint (the ordinary
  CLI did not write a worker profile). The instrumented diagnostic timed out,
  but captured the actual closure functions: one segment-contract attachment
  0.0563 seconds, boundary capture 0.0035 seconds, and summary attachment
  0.0015 seconds. Existing lifting dominates captured project CPU time. This
  does not attribute the round-trip wall-time difference to closure and is not
  semantic acceptance or a speedup claim. Profile:
  `.cache/segment-closure-worker-239793.prof`.

## Bound leaf-call segment preservation consumer — 2026-09-29

- Added a typed proof factory binding complete raw caller coverage, closed
  leaf-callee effects and an exact decoded near-call index entry. It derives
  preservation only from matching proven entry/return identities; indirect,
  far, nonleaf, incomplete and foreign evidence cannot authorize it.
- Segment solver/transfer now accept this evidence and retain only the proven
  segment identities across CALL. GP proxies are still always dropped. State
  retains supplied proof lineage and counted CALL classification; later closure
  refuses stale evidence rather than reusing previously preserved state.
  Codegen attachment accepts an explicit typed evidence tuple, defaulting to
  the original drop-all behavior when absent.
- Focused regression first failed on the missing consumer API, then passed with
  DS preserved, callee-clobbered ES refused and saved AX proxy dropped. Controls
  cover absent/duplicate/foreign/stale/far evidence and post-solve invalidation.
  Final scoped Make checks pass 326 tests in 48.85 seconds, strict typing,
  architecture/context/ownership; Ruff and Pyright pass. Tests are enrolled in
  routine Make/pipeline roots.
- At that checkpoint, automatic proof collection from closed callees was not wired;
  transitive/nonleaf preservation, entry-context propagation, pointer publication
  and full semantic gates remain open. No function acceptance claimed.

- Follow-up: summary attachment now collects exact proven near-call requests
  before joining contracts, decodes through the existing frontend request owner,
  and refreshes IR state when closed registered leaf evidence is accepted or
  previously accepted evidence is withdrawn. Missing, duplicate and undecoded
  requests retain typed refusals. Integration regression demonstrated red before
  wiring; final focused cohort19 passed with3 workers. Ruff and Pyright pass;
  scoped Make gate passed51 tests in46.40s plus typing and architecture checks.
  Real Capstone bytes now exercise request decoding, proof collection and state
  refresh; removing the registered callee withdraws preservation and restores
  UNKNOWN DS. Final focused8 tests passed in11.25s. No binary/function acceptance
  claimed. Production still needs closed callee contracts available in isolated
  analysis workers; this collector does not analyze missing callees or prove
  transitive/nonleaf effects.

- Registered-callee follow-up: a requested callee with no summary contract can
  now derive one from the existing immutable raw-IR registry, using the normal
  segment-state and contract owners and exact frontend boundary. No recursive
  lifting or SSA rebuild was added. The regression failed with zero materialized
  proofs before this change, then the focused cohort19 passed in11.31s; Ruff and
  Pyright pass. Scoped gate passed51 tests in29.91s. Missing raw IR, incomplete boundaries
  and nonleaf effects remain refusals; full binary acceptance remains open.

- Fresh KVM witness `.cache/compiler-coverage/pointer-call-preservation-20260929`
  completed validation_failed in107.13s with implementation/environment unchanged.
  Original build/run pass; select_word remains rejected by MS C5.1 C2147 on
  `(arg_6 << 1) + arg_4` with void-pointer input. Whole-tail diagnostic is clean,
  but syntax/round-trip acceptance fails. No witness gain or speedup attributed
  to preservation work. Next action is the evidence-bound near-pointer lowering
  bridge, not further summary-only acceptance claims.

- Near-return bridge review found a stale-AST proof defect: a retained Add
  expression changed to Sub still reported complete. Focused regression was
  red1/green26; the proof now retains the canonical coordinate registry and
  re-evaluates current arithmetic and exact operand projections before use.
  Ruff/Pyright pass; scoped gate is running. This is a publication prerequisite,
  not a pointer_memory fix or new feature-witness acceptance.

- Follow-up scoped gate for the near-AST proof passed38 tests in9.78s after the
  startup source-race retry. Isolated callee-demand collection now reuses the
  existing exact-boundary SSA/raw-IR registry owner when raw IR is missing,
  without recursive segment-summary expansion. Red missing request became
  green19/18.21s; scoped gate51/18.98s, Ruff/Pyright pass. No witness acceptance.
- Near-source binding review: retain exact input near-offset representation,
  not guessed input pointee or global DS==SS. Existing NEAR_BYTE_ADD can rebase
  proven source offset into the independently proven return-use segment. The
  real main-caller probe confirms both PUSH roots retained, but affine tracing
  refuses both as SOURCE_UNPROVEN. Call effects currently do not prove BP
  preservation. Artifact: .cache/near-input-real-caller-probe.log. This is a
  diagnostic, not validation or permission to substitute a frame address.
- Devin task input-offset-value-20260929 is live under the verified rootRO/repoRW
  sandbox and4GiB limit; owns only two new collector/test files. It stages exact
  numeric PUSH-root evidence, not source-segment or native pointer proof. Parent
  review/integration pending; baseline and batch output retained under
  .cache/devin-reports/input-offset-value-20260929/.
- Callee-demand refusal control: conflicting retained raw IR now refuses before
  invoking SSA rebuilding. Red1/8 became green20/17.82s; Ruff/Pyright pass.
  No broad acceptance attributed; the exact real caller input-offset probe still
  refuses SOURCE_UNPROVEN and source/native-pointer binding remains open.
- Devin input-offset-value task finished with two new owned files only; parent
  reproduced14 passing tests. Review found a replaced retained affine constant
  could still report complete. Parent corruption regression was red1/13, then
  green14/10.81s after completeness re-traces the exact original SSA root.
  Ruff and final Pyright pass. Parent reviewed the two owned files and enrolled
  the collector's regressions in routine Make/pipeline roots. Scoped typing passes
  when the affine/frame contracts are included; startup/context checks pass and
  the scoped gate passed390 tests in97.85s. Production wiring and pointer/segment proof remain
  open; no binary/function acceptance is claimed.
- Numeric input-value integration: production input trials now retain the exact
  caller-SSA proof or typed refusal separately from interface type evidence.
  Binding checks exact logical root, definition and CALL use; DEFAULTED segment
  origins are unchanged. Red missing-field regression became green. Refused
  numeric traces count classified0/materialized0/failure1, rather than counting
  structural input binding as classification of an unproved affine value.
  Final scoped gate391 passed/84.33s, strict typing/startup/context/ownership
  pass; Pyright passes. This does not authorize native pointer publication or
  fix pointer_memory; source/native-pointer representation binding remains open.

- Comparator optimization (2026-09-29): real16 identical-input self comparisons
  reuse one freshly sealed lowering through independent copies, preserving
  per-side admission and full proof gates. Seven new controls are enrolled;
  final wrapper/nested-loop cohort22 passed with3 workers. Scoped gates pass.
  Frozen timing27.05/30.27s versus31.56/31.93s baseline is noisy; one eliminated
  lowering and about0.24s copy are verified, with unchanged three UNKNOWN
  obligations. Latest completed quality-dev:8253 passed/29 failed/1 skipped;
  final-source rerun remains active. Plan checkpoint records exact limitations.

- Exact carry-helper checkpoint (2026-09-29): production SSA shares arithmetic
  admission/CF semantics with the branch owner. Red48 failures; combined96 green;
  final neighboring cohort163 green, all-n3. Fresh MSC8 self2 proves; rebuilt1
  modeled counterexample replaces abstract-flags refusal,1 stays incomplete.
  Latest full gate before carry:8266 passed/31 failed/1 skipped. Two additional
  failure fingerprints pass isolated baseline; root causes remain open. Parent
  reproduces import-order duplicate typed-contract classes and stages a bounded
  Devin compatibility fix for review. Full-plan acceptance remains open.

- Cold import identity checkpoint (2026-09-29): parent rejects staged finder
  cache divergence and integrates deferred canonical loading at the package
  boundary. Four cold import order/layout regressions red;21 neighboring tests
  and108 expanded focused checks green, all-n3. Reload/metadata and source
  mutation controls pass. Both comparator and persistent IR/SSA cache identities
  bind new package sources. Final static/cache-scope checks running; broad gate
  causal confirmation and original M0-M7 acceptance remain open.

- Combined carry/import broad gate:8358 passed/8 failed in928.32s, plus296
  repository contracts passed. All8 failures were in the preceding31-failure
  run;23 prior fingerprints disappear. Gate remains red and later Make stages
  do not run. Final flat32 outer-shim receipt closure passes254 scoped tests;
  refreshed MSC8 self2 passes, rebuilt1 modeled mismatch/1 refusal, with all3
  package files bound. Fresh isolated nested-loop diagnostic proves7 transitions;
  broad-run discrepancy remains open. Devin final review times out without a
  report or source edits. No original milestone is fully accepted.

- Nested-loop order diagnosis (2026-09-30): strict failure-only SSA/proof capture
  added. Seed0/-n3 targeted prefix287 passes79.45s; full collection plus the same
  prefix287 passes293.15s. Correctly seeded broad diagnostic remains active.
  Prior unseeded8345/25 result is explicitly non-comparable to Make. Fresh-cache
  substitution inspection finds no established identity-reuse path; no guessed
  semantic fix. Address audit Devin times out without a report; bounded static
  collection review is staged. Original-plan acceptance remains open.

- Pending-CMP execution correction (2026-09-30): seeded broad diagnostic
  terminates8353 passes/17 failures in714.64s. Exact nested-loop failure reduces
  to stale address-only CMP evidence replacing TEST/FLAGS in native Jcc IR.
  Repeated-image regression4 semantic failures/2 adjacent-CMP passes before;
  final92 loop/condition/capture/transfer controls pass43.64s, all-n3. Lifter
  now retains architectural FLAGS without an actual adjacent producer; metadata
  transfer remains separate. Scoped Ruff/Pyright pass. Broader gate and original
  acceptance remain open; static Devin audit times out without a report.

- CMP/Jcc live FLAGS follow-up: independent guest exposes a full-state SSA false
  proof (FLAGS0x46 versus0x97). Ten binary/polarity regressions fail before the
  correction. All simple CMP paths now publish defined FLAGS even with a direct
  following predicate. Earlier overwritten flags remain eliminable with proof.
  Branch-only quality-dev is stopped after296 contract passes; combined focused
  checks and final gates are pending. No original milestone is promoted.

- Combined branch/FLAGS checkpoint: corrected saved-dirty-lifter regression
  gives10 semantic failures in10.74s; final119 controls pass26.25s, all-n3.
  Earlier enum-name test errors grant no red evidence. Ruff/Pyright pass;
  native mutations, adjacent CMPs, nested loops and safe earlier flag DCE are
  covered. Combined-source quality-dev is starting; original acceptance open.

- BP-preservation prerequisite (2026-09-30): KVM opens with API12 and creates
  a VM in the current restricted session. Binary-derived Alias evidence proves
  entry BP save/restore across both pointer-witness callees, including the loop.
  Restore artifacts now retain exact source IR identity for safe downstream
  consumption; equal same-address replacement artifacts remain unbound.
  Two lineage controls fail before the change;61 neighboring stack-restore
  tests pass13.82s with3 workers. Ruff/Pyright pass; scoped gate285 passes
  in28.58s, including startup/context/ownership and changed-surface checks.
  Return-path closure and production CALL-effect integration remain open;
  this prerequisite is not whole-callee preservation or function acceptance.

- Closed-leaf BP proof (2026-09-30): typed Alias owner closes incoming BP over
  every return path, including loops, and rechecks exact raw-IR/frontend
  coverage. Same-instruction second-write corruption reproduced a false proof;
  unique-write admission now rejects it. Initial scoped gate303 passes33.13s.
  Real pointer callees exposed four omitted unconditional JMP instructions;
  the existing VEX control-flow owner now retains otherwise effectless terminal
  Boring transfers and their exact destinations. Two binary jump controls fail
  before;75 combined controls pass14.52s with3 workers; Ruff/Pyright pass.
  Fresh witness probe now has identical instruction censuses and complete BP
  preservation for both callees. Combined changed-surface gate583 passes/1
  failure78.29s: MousePOS CLI expects source parameter names but receives
  arg/arg_6 despite validation=passed. One bounded isolated baseline disables
  only new Boring transfer retention; its diagnostic observer sees zero new
  transfer requests, so causal classification remains unresolved rather than
  claiming preexisting debt. Both baseline/current MousePOS diagnostics retain
  the unexpected signature and pass tail validation; timings are noncomparable.
  Final32 BP/terminal controls pass18.85s, including a real frontend-bounded
  framed loop and rejected missing-JMP projection. Production caller-effect
  integration, broad final gates and end-to-end acceptance remain open.

- Production BP-call binding (2026-09-30): exact mapped E8/return/target proof
  consumes closed Alias body preservation, retains typed per-call outcomes,
  and checks the IR CALL target before projecting BP preservation. Positive
  production control fails before integration; mismatched IR-target control
  reproduces a false proof before the binding guard. Missing optional function
  ranges fail before mapped-entry Frontend closure. Final40 focused controls
  pass16.49s with3 workers. The initial witness proves all three calls and both
  roots, but that result is superseded by the cross-selector correction below.
  Initial changed-surface gate342 passes/
  4 failures20.77s, all in return-frame VEX-index/projection fixtures; causal
  classification remains open. A bounded sandboxed4GiB Devin test-only review
  is active with saved dirty baseline; parent review is required. Native input
  representation binding and original compiler-plan acceptance remain open.

- BP cross-selector correction (2026-09-30): rereading the plan's unresolved
  non-SS-write obligation exposes an unsound body-only restore admission.
  A real PUSH BP / DS:[SP-derived BX] write / POP BP control falsely proves
  preservation before the fix. Restore-dependent bodies now explicitly refuse
  non-SS stores without a cross-selector disjointness proof; logical segment
  names cannot establish distinct runtime selectors. Final41 focused controls
  pass9.65s with3 workers; Ruff/Pyright pass. Safe witness now proves both
  arithmetic-callee calls but refuses offset_copy; both offset roots therefore
  remain SOURCE_UNPROVEN across that earlier call. Caller-context disjointness
  is the next obligation, not guessed ABI preservation. Devin's bounded fixture
  review remains active and unaccepted. No function or plan milestone accepted.

- Comparator address-scope intake (2026-09-30): parent/agent review identifies
  architectural PC/CS and near-wrap correspondence as the missing cross-child
  theorem. Existing fetch/operand/raw-access certificates remain required;
  ADDRESS_MODEL is not promoted. Parent startup probes verify repository-root
  PYTHONPATH makes Python-c workers import the6GiB sitecustomize cap, whereas
  current Make workers have unlimited AS. Earlier ASan launch attribution is
  pending exact environment confirmation. Bounded Devin diagnostic and current
  three-worker quality-dev remain active; no original milestone accepted.

- Production segment collection checkpoint (2026-09-30): the existing stage
  now resolves uncatalogued callees through closed mapped-entry/raw-IR owners;
  normal contracts use that Frontend fallback only when no optional function
  boundary exists. Existing raw registry conflicts stay refused. A real
  repeated-call control is red before repair (0 proofs/2 refusals), then green
  with one retained callee object across calls and later refreshes. Explicit DS
  clobber, nested-call and nonreturning controls remain conservative. Final
  scoped checks pass21 tests in6.71s with3 workers; Ruff/MyPy/startup/ownership
  and production Pyright pass. Cold real POINT.EXE production collection closes
  12/12/12/12/0; contextual DS=SS reaches all12 CALL entries. No pointer or
  function acceptance. Next obligation is caller-bound write-range disjointness;
  existing indexed-range owners currently require constant unsigned global
  ranges and explicitly refuse pointer-relative Alias projections.

- Segment-entry saved-byte correction (2026-09-30): a byte-backed
  PUSH SS / DS:[SP-derived BX] overwrite / POP DS / CALL control falsely
  proves equality before the correction. BP and direct-call entry proofs now
  consume one Alias-owned save-to-restore cross-selector guard. Typed entry
  refusal is STACK_SAVE_ALIAS_UNPROVEN; contextual DS provenance has its own
  CALL_ENTRY_RELATION kind. Final scoped gate passes393 tests in34.33s with
  3 workers, including Ruff/MyPy/startup/ownership checks; Pyright is clean.
  Scoped MyPy required its already-typed ir_boundary_cfg dependency explicitly
  selected, not a production Any cast. Real startup/main context still binds;
  no pointer or whole-function acceptance. A terminal nonpublishing diagnostic
  then binds all12 main CALLs to five closed leaf segment effects; preserving
  one raw artifact per callee retains DS=SS at all12 call entries. Rebuilding
  repeated targets invalidates earlier identity-bound proofs and was corrected
  in the diagnostic, not waived. Durable production collection/routine controls
  and caller-bound write-range disjointness are next; this is not C acceptance.

- Contextual callee segment entry (2026-09-30): added a typed, rechecked
  caller/callee/index/Alias-bound DS=SS entry context and optional request-local
  solver propagation. Default analysis/project registries remain unchanged;
  unknown calls drop equality and generic closure refuses contextual states
  instead of publishing a universal preservation claim. Final scoped checks
  pass392 tests in33.59s with3 workers; four production modules pass Pyright.
  Real POINT.EXE startup and main both have complete raw-IR census; startup
  context binds with1/1/1/1/0 and gives main DS/SS the same entry source.
  The first raw-IR CALL at0x10123 drops it. Initial test intake exposed an
  unrelated effectless-NOP instruction-census refusal; retained as a future
  coverage obligation, not hidden as complete. No pointer or function accepted;
  transitive call preservation and caller-bound write ranges remain open.

- BP saved-byte lifetime checkpoint (2026-09-30): two binary controls with
  cross-selector writes before the save or after the final restore fail before
  the fix. Alias now checks instruction-order CFG save-to-restore reachability,
  including backedges and full machine-instruction groups, instead of rejecting
  every non-SS store indiscriminately. Corrupting in-lifetime stores remain
  refused. Scoped checks pass309 tests in20.98s with3 workers; real caller probe
  still refuses offset_copy and accepts both select_word BP effects. Raw IR
  census identifies the remaining writes as two DS:[BX+SI] byte stores inside
  the saved-BP lifetime. Caller-bound offset/extent and segment relation proofs
  remain required; no full-gate, function or original milestone acceptance.

- BP-call checkpoint (2026-09-30): parent reviewed Devin's exact test-only
  delta against the saved dirty baseline and independently reproduced its
  four baseline failures (23 passes). Final shared-tree scoped checks pass
  with651 tests in46.80s, three workers, and exit0. Independent VEX-store
  census and closed projection/failure-count assertions strengthen the oracle.
  This accepts the bounded fixture repair, not function or compiler-plan
  acceptance. offset_copy cross-selector store disjointness remains unproved.

- Comparator checkpoint (2026-09-30): quality-dev ends2 after296 contract
  passes and8370pass/32fail/1skip1181.76s. Nested-call-loop failure is absent;
  source drift prevents fixed-tree acceptance. Public register controls5green
  do not reproduce broad UNKNOWNs. Corrected the CFG-liveness oracle to keep
  the final CMP write while removing only its overwritten predecessor;77
  neighboring tests pass44.52s with3 workers. UNKNOWN public reports are now
  preserved. Native control intake reproduces9 wrap/high-address mismatches;
  helper/frontend integration remains staged and must preserve proved calls.

- Comparator native-control checkpoint (2026-09-30): source-bound near16
  coordinate proofs are mandatory in recursive induction. Bootstrap uses real
  constant CS without guessed stack alignment; RET checks the actual stack word.
  Final focused43green44.89s, scoped98green32.83s, exactly3 workers; configured
  lint/type/startup/ownership and final Pyright pass. Native9 wrap/high-address
  countermodels remain refused; frontend helper is unintegrated. Conditional
  model gaps and original-plan acceptance remain open. A90s sandboxed Devin
  audit times out without evidence; one concurrent-source UNKNOWN is unclassified.

- Comparator gate reconciliation (2026-09-30): the subsequent quality-dev
  terminates2 with296 contract passes and8406pass/35fail/1skip808.08s, three
  workers. Three public register failures explicitly report source changes
  during lowering; eight tracked source owners changed during the run. One
  owned failure was the binary-lane expected inventory missing three newly
  enrolled controls; repaired and61 focused tests pass13.78s. Other31 broad
  failures remain unclassified. This is not fixed-tree broad acceptance.

- Symbolic call-target prerequisite (2026-09-30): parent reproduces
  the actual staged simple-lift native oracle: baseline3/12 targets, candidate
  12/12, saved CALL words4/4, executed candidate helper12 times. Frontend patch
  remains staged. Production direct-call composition now accepts symbolic
  full32 targets only with a universal proof over the existing entry CS interval
  and unchanged session deadline. Wrong metadata, alias-dependent wrap, missing
  budgets, narrow control, unknown and late solver completion remain refusals.
  Initial new regression6red/1green0.87s. Final scoped check-files327green47.22s
  with three workers, configured lint/type/startup/ownership checks and new
  boundary controls; changed production owners pass Pyright with zero errors. No
  original milestone or whole-binary equivalence accepted.
  A final unsigned-target metadata boundary check is added; its selected-owner
  check-files cohort passes273 tests54.23s, three workers, and Pyright remains
  zero errors. Parent reproduces the staged conditional/operand32 candidate's
  36/36 full loaded controls and4/4 saved words; metadata and full EIP checks
  remain under review before any frontend integration.
  Expanded staged oracle independently reproduces38/38 loaded controls and
  full architectural EIP projections,5/5 CALL32 saved words, all corrupted
  controls refused. Integration awaits typed symbolic Jcc/CFG target evidence;
  replacing concrete target metadata with None is not accepted as parity.

- Symbolic acyclic-successor checkpoint (2026-09-30): parent reproduces a
  distant successor falsely admitted by the legacy word-wrapped delta helper.
  Acyclic composition now shares exact physical-successor intake with matched
  induction and proves symbolic branch arms under every entry CS alias, using
  the original session deadline. It retains the entire state and both guarded
  effects; opaque arms, wrap-dependent targets, word control and expired time
  refuse. Initial controls5red/2green1.11s; a separate word-control oracle
  reproduces1red/7green2.05s. Scoped336green46.47s precedes the final width
  guard; final shared-tree scoped gate passes337 tests54.99s, exactly three
  workers, and changed owners pass Pyright with zero errors. Controls are enrolled
  in ownership and binary lanes. Frontend default integration remains open.

- Decoded relative-edge checkpoint (2026-09-30): reviewed a terminal0 Devin
  staging delta under the verified repository-only4GiB sandbox, independently
  promoted exact-byte edge contracts, and centralized relative offset/control
  arithmetic. Native control intake now consumes this shared decoder. ConditionIR
  builders retain optional raw edges and deduplication retains their byte/source
  identities without inventing concrete CFG targets. Initial constructor/storage
  controls3red/34green9.40s; isolated37green10.53s. Scoped gate1958green284.12s
  with three workers and changed-owner Pyright zero errors. One earlier combined
  worker exit inside Unicorn is unclassified, not hidden by subsequent greens.
  A separate Alias oracle reproduces ambiguous raw edges silently selected as
  one condition (1red16.55s); its identity guard is patched. Final scoped
  checks pass38 tests9.37s with three workers; Pyright reports0 errors. Global frontend target binding and native default repair
  remain open; this accepts neither original milestones nor binary equivalence.

- Memory-offset numeric prerequisite (2026-09-30): new IR owner retains the
  exact SSA memory use and two scalar-affine roots, with atomic refusal and
  closed counts. Initial composite regression3red/2green; final scoped
  check-files27green6.63s with three workers, lint/type/startup/ownership checks
  and Pyright zero errors. Real POINT.EXE fill_bytes and both offset_copy
  STORE byte lanes produce complete modular word sums with1/1/1/1/0 counts.
  This proves only the numeric low-word offset, not address width, caller-bound
  ranges or saved-BP disjointness. No function or original milestone accepted;
  broad gates remain pending/non-green.

- Range-proof intake and numeric corruption controls (2026-09-30): current
  POINT.EXE SSA proves both relevant natural loops use signed16 slt against
  a stack-loaded count at SS:BP+8. Existing unsigned constant-bound range
  contracts cannot establish their write ranges. Signed dynamic count binding
  and load stability must precede range publication. Four numeric equality
  corruption controls reproduce red; the memory-offset owner now refuses bool
  and float constants/coefficients. Final scoped check-files31green10.29s,
  three workers, and Pyright zero errors. Saved-BP/function acceptance remains
  unproved; no original milestone accepted.

- Signed range prerequisite (2026-09-30, in progress): retained signed guards
  and positive constant-bound/no-overflow proof in the existing IR range owner.
  Three new binary controls reproduce red. Intermediate scoped84green68.98s;
  final integrity checks additionally bind compare width/storage/constant and
  reject signed-to-unsigned relabeling. Final focused rerun pending; full
  test-pipeline remains live with log .cache/signed-loop-range-pipeline.log.
  Its296green contract pre-gate is not pipeline acceptance. Dynamic caller
  counts and pointer-relative range publication remain unproved.

- Range-review counterexample (2026-09-30): parent reproduces an indexed
  loop whose body overwrites i with7 after testing i<4; signed and existing
  unsigned range owners both wrongly publish [0,4). Complete mutation census
  and all-entry initializer proof are required before accepting this work.
  Both real offset_copy call-count transports independently close at3; this
  is diagnostic input evidence, not caller-bound range publication. Broad
  pipeline and sandboxed4GiB read-only Devin audit remain live.

- Parent range review (2026-09-30): read-only Devin completes0 with unchanged
  owned sources. Parent reproduces all three write classes plus guard/update
  ordering holes; eight durable regressions are red9.46s. Fresh signed-bound
  controls6green12.03s. Broad unit8454green/14red896.55s includes three
  relabeling failures absent from the fresh source run; other11 remain
  unclassified. Relational121green139.07s; external pipeline lanes remain live.
  Shared range mutation/order/all-entry proof must be repaired before acceptance.

- Mutation-census follow-up (2026-09-30): initial repair is scoped92green32.55s
  with three pytest workers and zero Pyright errors. Raw byte/unclassified
  writes, initializer dominance and guard/increment ordering are now checked.
  Typed census retention reproduces7red9.58s then14green7.50s; final scoped
  omission/relabeling check-files92green40.87s with three workers and configured
  lint/type/startup/ownership checks; changed-production Pyright0 errors.
  Candidates retain the complete
  raw-site denominator and explicit failed effects, without caller-bound range
  publication. The separate explicit candidate/fact boundary still needs an
  authoritative census certificate; pointer extents and saved-frame coordinates
  remain open. Live caller diagnostics again prove count3 with1/1/1/1/0 at
  both0x10254 and0x10290, not a universal callee constant. Broad pipeline ended
  non-green (contract296pass, unit8454pass/14fail, relational121pass; final
  lanes1pass/3fail). No semantic function acceptance claimed.

- Explicit range-boundary closure (2026-09-30): reproduced binary-backed
  missing-census acceptance red7.12s. Collector and fact completeness now bind
  mandatory mutation evidence to function/induction/write/loop coordinates and
  initializer dominance; downstream facts retain it. Missing or corrupted
  evidence refuses rather than bypassing SSA generation checks. Focused54pass
  in8.53s; final check-files92pass40.99s with three pytest workers and configured
  lint/type/startup/ownership checks, Pyright0 errors. Caller-bound pointer write
  extents and saved-frame disjointness remain unproved; broad pipeline non-green.

- Development gate follow-up: quality-dev exposed a missing owned condition-
  provider MyPy closure, then two implicit SSABlock imports in far-return
  consumers. The Make development scope now includes the existing range
  provider cohort; those consumers import SSABlock from its actual SSA owner.
  No cast or check exclusion was introduced. Far-return focused22pass10.74s.
  Third quality-dev run is live (session40412), log
  `.cache/range-boundary-quality-dev-owned-imports.log`; do not restart while
  its handle remains live. First two runs failed during linting, before the
  pipeline. The latest run passed lint/startup checks and296 contract tests
  in8.09s. Third run terminated2: fast unit-focused lane8452passed/31failed/
  1skipped664.09s. Several failures explicitly report missing /dev/kvm, also
  freshly confirmed by stat. Remaining failures are not yet causally classified.
  The gate is no longer live; do not present it as green.

- Final-gate environment triage: all10 REP STOSW failures retain stdout
  artifacts explicitly reporting missing /dev/kvm under pytest-878. Those
  controls did not reach their compiled-behavior oracle; do not classify them
  as proved REP semantic regressions or passing tests. Static development
  remains possible. A bounded4GiB sandboxed Devin review is live at session60399,
  owns only `.cache/interinstruction-word-review/`, and must not edit shared
  sources or run pytest. RootRO/repoRW/4GiB boundary was freshly verified;
  target source/test hashes still match its recorded dirty baseline. Parent
  review and reproduction are required before using its staging results.

- Wide-frame mutation correction (2026-09-30): real MOV EBP,1000h is retained
  as a4-byte EBP write, not a BP-named write. Two signed/unsigned binary
  controls reproduce false range publication (2red/6green7.35s). The census
  now consumes the architectural overlapping-register family for BP and SS,
  so wide EBP writes invalidate the frame proof. Focused16pass22.74s; final
  check-files94pass42.44s with exactly three workers, configured lint/type/
  startup/context/ownership checks and changed-owner Pyright0 errors. This
  corrects a false premise, not caller-bound range or function acceptance.
  Devin60399 remains a separate read-only/staging review; production word-value
  owner and its test hashes still match the saved dirty baseline.

- Caller-bound count coordinate intake (2026-09-30): fresh byte-backed scratch
  probe shows both count PUSH words occupy callee-entry SS offsets6/7 at the
  actual CALL. The machine CALL envelope lowers SP by2. Existing frame owner
  independently proves callee BP=entrySP-2 with1/1/1/1/0, so SS:BP+8 maps to
  those same bytes; no source argument numbering is needed for this relation.
  However, the IR logical-word value owner refuses both PUSH values as
  MIXED_INSTRUCTION because AX's constant producer precedes the PUSH. The
  successful Lowering input-value diagnostic must not bypass that IR boundary.
  Next: retain bounded interinstruction constant provenance with explicit CALL/
  clobber refusals, then prove pushed-byte stability and callee bound-load
  stability jointly with write-range disjointness. Do not simply remove the
  same-instruction guard: scalar definition indexing alone proves no CALL
  preservation. Probe `.cache/caller-count-coordinate-probe.py` is diagnostic
  only. No production source changed during the live quality-dev unit lane.


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

### Current corpus checkpoint (2026-09-30)

Executed the frozen real16/MSC8/BC5 public CLI corpus and verified all 1,144
source and 10 input hashes afterward. MSC8 self: 2 passed; changed: 1 lowering
refusal and 1 modeled observable mismatch (independent replay pending).
Real16 self: all 3 requested proofs unresolved at admission, underlying call
targets unmapped. BC5 cold/changed/warm: all 15 refused in each run; exit 2
represents refusal, not a crash. Call retries already run, with exact indirect,
boundary, return, limit and loop refusals retained in the reports. BC5's cold
7.045 s and warm 8.960 s single observations establish no speedup. Next bounded
diagnosis: BC5 `sub_4023F4` return-target mismatch. Commands, hashes, reports,
timings and current result ledger are in
`.cache/comparator-implementation/corpus-current-20260930/`.
Original M0-M7 acceptance remains open; no milestone newly accepted.

Bounded follow-up: exact CALL bytes confirm `0x2222` is the real target of all
three real16 selections, rather than an established truncation artifact. The
uncatalogued binary entry contains stack allocation and an indirect return
through CX, plus a failure branch. Callee coverage and that control contract
must be proved; it cannot be admitted as an ordinary RET leaf by adding a name.
The BC5 `sub_4023F4` diagnostic found CALL `0x402492` → `0x4011ac`, return
`0x402497`, pointer stores and RET 4. One bounded check timed out at 1,024 ms;
the earlier mismatch has not been independently reproduced. Keep refusal until
return-slot preservation or corruption is established from actual evidence.

### SCC status and flat32 return evidence (2026-09-30)

Fixed a reproduced false-proof promotion: conditional/unsupported/unmapped/
unrecognized SCC members cannot roll up as passed or disappear from counts.
Reviewed and integrated a bounded Devin patch retaining typed flat32 call
return-proof failures and solver countermodels. Parent separated exact CALL
addresses from block starts and verified RET 4 alias/corruption controls.
Final focused cohort: 44 passed, 3 warnings, 22.54 s, pytest -n3. Ruff and
changed typed owners' Pyright pass; whole legacy SSA typing remains 197 errors
versus saved dirty baseline 203. Startup/context/ownership checks pass.
The frozen broader run is non-green: 227 passed, 19 failed, 5 skipped in
25.28 s. All failures were reproduced diagnostically: 16 missing call proofs,
one slice budget refusal, one modeled caller mismatch and one obsolete COPY
flag test (corrected and verified in the final focused run). Full acceptance
remains open. Evidence and exact deltas are under
`.cache/comparator-implementation/{scc-status-admission,flat32-return-evidence,return-and-scc-frozen}/`.

Final counter-publication gate: 336 passed, 3 warnings in 68.72 s, pytest -n3,
with configured scoped lint/type/startup/context/ownership checks. SCC reports
retain closed raw/normalized/classified/materialized/failure counts. Changed
typed owners' direct Pyright: 0 errors. The failed broader snapshot remains
unchanged and is not superseded by this narrower gate.

Native return-slot alias control: 5 concrete-replay tests pass in 1.39 s with
three workers. Valid mapped-stack execution returns on clean code and faults
at `0x2a` after the pointer store corrupts the callee's saved continuation;
repeated corruption is deterministic and remains incomplete replay evidence.
The control is enrolled with flat32 call ownership. It does not establish
replay acceptance for the unreproduced BC5 corpus countermodel.

### Caller-count word replay prerequisite (2026-09-30)

Parent reviewed the bounded Devin interinstruction diagnostic, rejecting its
suggested manual register-liveness implementation and incorrect AL byte example.
The IR word-value owner instead consumes the existing constant-flow owner through
a retained exact-prefix receipt. Register overlaps and unknown CALL effects stay
with that owner; access identity, STORE slices, current source and five-counter
accounting are checked before accepting a constant. Existing increment and
invalid-root refusals remain intact. Range and reaching-read consumers use the
typed constant predicate rather than a single enum variant.

Scoped check-files: 268 passed in 43.21 s. New receipt tests are enrolled in both
Make test/Ruff lists; enrollment gate: 9 passed in 7.03 s. Additional source-drift
control: final receipt cohort 10 passed in 6.50 s, pytest -n3; Ruff passed.
The fresh binary POINT coordinate diagnostic now proves count 3 at both caller
PUSH sites, 0x1024b and 0x10287, with no word-value refusals. Both byte pairs map
to callee entry-SP+6/+7; the callee frame separately proves BP=entry-SP-2.
This establishes written value and coordinates only, not later byte stability,
callee bound stability, pointer extent or saved-BP disjointness. No function is
newly accepted. `/dev/kvm` remains absent in this session; runtime validation and
the previously non-green broader quality-dev lane remain unresolved.

Fresh caller-window diagnosis inventories eight raw STORE byte slices per POINT
call block: the count's two lanes, four disjoint later-argument lanes and two
disjoint CALL-envelope lanes. No block IR refusals; the selected terminal CALL
is the only observed CALL/INT/DIRTY barrier. Coordinates use arbitrary block
incoming SP, not an assumed function-entry coordinate. The next production
obligation is an Alias-owned retained local lifetime census with source/coverage,
selector-write and opaque-effect checks. This diagnostic does not publish a
preserved value or callee bound. Script:
`.cache/caller-count-store-window-probe.py`.

Implemented the local Alias lifetime owner and routine Make/pipeline/ownership
enrollment. It retains exact raw/SSA sources and the checked STORE census;
unknown effects/addresses, SS selector writes, overlap and unproved boundaries
refuse. A forged temporary-provenance regression is red1/green7 in6.23s before
switching from dataclass equality to full structured projection comparison.
Final check-files8passed17.66s; owner/constant/snapshot cohort45passed8.81s,
pytest -n3; changed owner Pyright0 errors. Fresh real POINT checks prove count3
at both IR CALL boundaries, offsets6/7, with six later STORE slices checked and
closed1/1/1/1/0 candidate counts. These proofs remain conditional on supplied IR
coverage and are not yet consumed by contextual callee binding. Next: bind
registered raw binary coverage and the exact CALL boundary, then prove callee
bound-load stability. No function or compiler milestone acceptance is claimed.

Added the binary-associated count binding owner. It retains exact registered
raw coverage, same-source lifetime evidence, real near-CALL target agreement and
the two-byte raw envelope/SP delta. Current registry replacement invalidates it;
coverage/source/target/return/frame conflicts have typed refusals. UNKNOWN-status
SS STORE corruption reproduces false disjointness (1fail/8pass7.70s); shared
coordinate checks now require stable selector/address evidence and byte-width
agreement. Final scoped check-files15pass6.20s, combined owned prerequisites
68pass10.04s with three workers, Pyright0 errors. Fresh POINT calls each bind
count3 to callee-entry offsets6/7 with closed1/1/1/1/0 counts. Call return-value
constant proof remains unknown and separate. No exhaustive caller census,
global bound, callee-load stability or function acceptance is claimed. Next:
prove the callee memory invariant without assuming the unchanged bound needed
to establish the pointer writes' disjointness. Production consumption remains
open. Diagnostic: `.cache/caller-count-binary-coverage-probe.py`.

Induction census now refuses opaque non-STORE effects instead of assuming their
absence of explicit STORE means preservation. Three binary-backed corruption
controls are red9.40s before repair; retained verdict relabeling cannot bypass
the classifier. Added validated direct-JMP IP effects and backend one-bit
Boolean effect shapes, with positive and malformed-width controls. An initial
scoped gate330pass/1fail31.80s exposes the real shifted loop's missing Xor1
classification, now resolved without relaxing opaque refusal. Final scoped
check-files334pass34.07s with three workers; changed-owner Pyright0 errors.
Fresh callee evidence changes the next action: two normalized BX+SI word
accesses refuse MULTIPLE_DYNAMIC_TERMS, so zero range candidates reach bound
stability. Next is typed loaded-base/induction separation, not injecting the
proved caller constant into an unproved callee range. Full pipeline and original
milestones remain open. Diagnostics:
`.cache/{induction-effect-closure-probe,callee-bound-lifetime-probe}.py`.

Multi-component affine-address prerequisite now retains binary-derived loaded
terms and scales without pointer-role guessing. A NOT BX regression demonstrated
a false copy proof (1red/4green); scalar tracing now checks the shared typed
projection owner, refusing unsupported decoration/conversions. Focused cohort:
19passed10.97s with three workers; Pyright0 errors. Real POINT accesses0x100db
and0x100e6 both decompose with closed2/1/1/1/0 counts and one coalesced byte pair.
Range selection, load stability and callee pointer-write invariants remain open;
no function acceptance is claimed. /dev/kvm now opens successfully/API12.
Final scoped check-files142passed34.33s, including lint/type/startup/ownership
checks. The new owner and regressions are enrolled in routine gates.

Affine induction-role bridge now selects a term through exact loop initializer,
latch increment and strict typed guard, not register spelling or term order.
Both real POINT accesses select BP-2*2, retaining BP+6/BP+4 loaded residuals
without pointer/stability claims. Final scoped check-files14passed12.21s;
Pyright0 errors. Signed/unsigned and corruption/refusal controls are enrolled.
Production range acceptance remains open until contextual memory lifetime and
pointer-write disjointness are proved; the existing one-register lane remains
unchanged. Full compiler-coverage goal is not complete.

Fresh admitted array_pointer_writes run through the verified --with-kvm launcher
finishes validation_failed51.85s, with source/environment guards unchanged.
Original compilation/DOS exit255 pass; four functions validate, select_word
fails MS C C2147 on integer addition to void* despite its pointer return type.
Artifacts: `.cache/compiler-coverage/array-role-kvm-direct-20260930/`.
Next integration must keep typed address expressions and pointer prototypes
coherent in Lowering; no rendered-C repair or guessed pointee family. Ordinary
child execution still misses KVM, while verified descriptor transport succeeds.

Worker-side type diagnostic narrows select_word's current C2147 cause: its
void* base / unsigned-short* return signature already exists before priming and
survives every observed later phase unchanged. Owned pointer-argument Lowering
reports zero facts. Parent-only counters were not observed in the worker and
are not evidence of absence. Actual worker hook/log are retained under
`.cache/near-return-probe-site/`. Next: upstream type/codegen integration with
proved near-address semantics, not late return-shape or rendered-C repair.

Exact live assignment trace identifies the owned mismatch publisher:
interprocedural_storage_prototype_application applies an accepted contract,
promoting scalar arguments/return to void*/ushort* without a corresponding
callee return-address expression preflight. The initial CFunction is scalar;
positive BP materialization is also scalar. Next integrate body/address
preflight atomically at this Lowering transaction, with independent segment
and representation proof rather than guessed base pointee width. Assignment
stacks retained in `.cache/near-return-probe-site/assignment-results.log`.

Pointer-retyping preflight now refuses unlowered numeric arithmetic before
any prototype/cvar/metadata mutation, with typed POINTER_ARITHMETIC_UNPROVEN.
Isolated guard-bypass controls4fail; application cohort12pass5.71s includes
unrelated-arithmetic positives. Scoped static/startup/ownership checks and
Pyright pass. Broader scoped tests244pass/8fail20.83s; the same8failures recur
with the guard bypassed in the bounded split/trial baseline20pass8.44s.
Live select_word returns0/validation=passed while retaining scalar offset types;
this is refusal of unsupported pointer publication, not pointer/function or
linked-case acceptance. Next remains independent near-address/body publication.

Contextual DS==SS transfer now replays a retained parent invocation through
raw caller effects and exact near-CALL binding, consuming only complete bound
call-preservation receipts. It rejects segment loss, stale/foreign identities,
far calls and hidden same-instruction segment assignments; third-depth contexts
remain callsite-local and cannot certify universal segment preservation.
Real POINT replay proves all12main-to-helper contexts (including both
select_word sites), each with1/1/1/1/0 accounting. Initial focused cohort23pass;
initial scoped check-files393pass26.46s; final expanded scoped checks398pass
35.97s, with Ruff/MyPy/type-ratchet/startup/ownership and Pyright0errors.
Quality-dev's fast pipeline finished8528pass/31fail/1skip778.62s (not green).
One stale binary-lane expected-set assertion was reproduced red1fail2.43s,
then reconciled with the already-enrolled relative-condition-producer regression:
test_test_pipeline56pass1.31s and Ruff pass. Lane membership was not changed.
Other failures remain
unclassified against a full pre-run baseline. This supplies an independent
segment prerequisite only, not native-pointer representation or acceptance.

Fresh admitted array_pointer_writes after the pointer-retyping guard now
finishes recompile_failed91.12s rather than a function validation failure.
All5functions decompile with clean tail validation; original build/DOSexit255
pass, and implementation/environment guards remain unchanged. MS C rejects
the scalar select_word interface with C2100/C2106 in the pointer harness.
No rebuilt behavioral acceptance. Artifacts:
`.cache/compiler-coverage/array-context-kvm-direct-20260930/`.
Production census probing on a cold catalog-free project also returns empty
main/helper caller censuses despite registered raw IR, so contextual source
receipt collection must not assume optional catalogs populate that authority.
Devin is preparing only a pure near-return AST candidate in ignored staging;
parent review and all segment/representation/publication integration remain.

Compiler-coverage result-selector checkpoint (2026-09-30): production decoded
boundary call indexing now uses the retained reachable instruction census,
not optional catalogs. The new nonpublishing near_return_segment_use owner
joins caller return-use receipts, exact call preservation and raw segment
must-state. DS/SS/ES selectors require actual equality to callee-entry DS;
contextual DS==SS must be retained and replayed for the exact caller artifact.
The focused binary cohort passes10/12.09s with3workers, including local SS/ES
copies, contextual stack use, stale context/counts and segment-loss refusals.
The previous DS-only admission fails both new local-selector controls
(2fail/7pass17.79s); deliberately unchecked lifetime/preservation fails3
semantic controls (3fail/6pass19.25s). Initial scoped gate9pass25.65s,
Ruff and Pyright0errors; final expanded scoped gate10pass5.96s with startup,
context, ownership, MyPy and type-ratchet checks passing.
Real POINT catalog-free diagnostic collects12 complete preservation proofs;
both select_word caller uses (SS and DS) now bind1/1/1/1/0 with retained main
entry context. This establishes only the result-selector theorem, not native
input-pointer representation, body publication or DOS round-trip acceptance.
Devin remains restricted to ignored AST staging. Parent review has identified
closed-count, mutable-selector replay and C undefined-behavior obligations;
its candidate is not accepted or integrated.
Parent reproduced all5 additional staged corruption/refusal controls failing
semantically (5fail8.72s), including unsigned-scale-type replacement. Original
Devin batch exited0 and the three live evidence-source hashes are unchanged.
Its three staged files were saved as the review baseline before starting a
new sandboxed4GiB correction batch. Parent owns the separate review controls;
worker still owns only its three staging files. Correction review is pending.

Compiler-coverage stack-input selector checkpoint (2026-09-30):
near_pointer_stack_input_segment joins registered Semantics SSA address-of
push evidence to complete result-selector/call-preservation receipts. Exact
SS:BP word sources may arrive as two contiguous byte slices; missing/duplicate
slices, forged source offsets/targets, foreign SSA and boolean coordinates
refuse. DS at callee entry must actually equal SS at the push, replayed with
retained caller context. Initial cohort7pass29.43s; expanded scoped gate8pass
8.07s plus Ruff/MyPy/type-ratchet/startup/context/ownership and Pyright0errors.
Deliberately unchecked DS==SS fails the unequal-selector binary control
(1fail/6pass15.43s). Real POINT both calls prove SS:BP-20 transport, alongside
their SS/DS result-use proofs. Routine tests/ownership/typing are enrolled.
Still no native-pointer/body/publication or rebuilt-DOS acceptance claim.
The Devin correction fixes the first5 parent controls, but3 further C-promotion
controls fail (3fail/5pass14.39s): host signed-int overflow from unsigned-short
multiply, DOS signed-word negation and DOS promoted-uchar left shift. Candidate
remains staged/unaccepted until those are fixed and parent reviewed.
Combined result-use/input-selector/pipeline-enrollment cohort74pass9.81s
with3workers. The initially supplied nonexistent tests/test_test_pipeline.py
path returned exit5/no tests; it is not a passing gate. The correct enrolled
angr_platforms/tests/test_test_pipeline.py is included in the74-pass cohort.

Compiler-coverage detached near-return AST checkpoint (2026-09-30): Devin's
correction batch exited0. Parent reviewed the exact source/test delta against
the saved dirty staging baseline and independently reran controls. Original5
and further3 failures are fixed; an additional literal-format promotion control
failed1/9pass10.32s and was fixed by a parent-owned signed-int16-safe left-shift
bound. Explicit u16 casts remain admissible. Reviewed code is now owned by
near_return_expression and near_return_selector, with enrolled construction and
replay regressions. No body/prototype mutation or pointer authority is granted.
Focused57pass9.07s; final scoped gate57pass6.58s with Ruff/MyPy/type-ratchet/
startup/context/ownership and Pyright0errors. Combined candidate/result-use/
stack-input/pipeline-enrollment cohort131pass28.59s with3workers. GCC helper
validation is mandatory, not skip-permitted. This supersedes staged/unaccepted
status for detached construction only: native-input representation, complete
body-use preflight, atomic publication and linked rebuilt-DOS acceptance remain.

Binary-equivalence current call checkpoint (2026-09-30): real16 near/far,
operand-size and loop-call focused matrix passes84/41.73s with3workers.
Public shifted branch-inverted callee now has a complete-call positive and
changed-value counterexample, retaining two proved return targets/dependency
sides. Its configured scoped gate passes5/32.64s plus lint/startup/context/
ownership. Legacy stopped-at-CALL address comparison remains separately open;
its mismatch is not whole-caller behavior failure. Full-index missing nested
callee proof regression now checks resolution and explicit refusal. Original
M0-M7 acceptance remains open. See binary-behavior-equivalence-plan.md and
.cache/comparator-implementation/flat32-return-evidence/ for exact evidence.

Binary-equivalence follow-up: reviewed bounded Devin signature-control patch;
parent red4fail/9.94s -> combined9pass/20.35s with3workers. Resolution/signature
coverage retained; incomplete proofs refuse. Real corpus helper exact-byte
catalog intake retains both guard arms and refuses out-of-body tail closure.
Production replay has5 deterministic initialized helper vectors:3 positive
self agreements/3 stack-update mutation mismatches;2 fallback paths explicitly
incomplete. This is isolated helper evidence, not whole-program acceptance.
See binary-behavior-equivalence-plan.md and call-signature-review/helper-intake
artifacts. Original M0-M7 and final project gates remain open.

Binary-equivalence memory-control recovery: fresh dosunit baseline197pass/13fail
(33.16s,-n3). Three invalid scalar-memory/unequal-offset fixtures replaced with
actual MZ full-state CALL/RET callers. Same effective BP-4 disp8/disp16 encodings
prove; changed stored values produce array-memory countermodels. Focused3pass
(20.60s,-n3) before name-coverage extension. Production replay of all three
complete callers repeats deterministically, with equivalent addressing agreement,
store corruption mismatch, restored BP and SP, and explicit stack observations.
New binary renamed/decorated-callee positives await final tests. Bounded Devin
alias-stub corrections are live and parent review remains required. No broad
suite or milestone acceptance is claimed. Artifacts: call-memory-controls/.

Binary-equivalence call normalization + staged selector review (2026-09-30):
parent review fixed the near-return builder's three C-promotion defects —
selector ``Mul`` refused (host int32 signed-int overflow), ``Neg`` gated on
unsigned-word operand (DOS int16 -32768), ``Shl`` gated on exact uint16
declared type (u8 promotes to signed int16). Staged focused 55 pass, 0 Ruff,
0 Pyright. Builder remains unpublished pending representation/prototype/
census/replay obligations. In the comparator, target-valued ``ip``/
``control_ip`` outputs are now normalized to the proven-callee token via
``_with_call_bound_control_outputs``; shifted/mapped call positives prove.
Full test_dosunit_tool.py 210 passed, 0 failed. Refusal semantics unchanged;
no proof gate weakened. M0-M7 acceptance and broad gates remain open.

Compiler-coverage runtime near-input checkpoint (2026-09-30): runtime zero
offsets (including65536 narrowed to a word) no longer become DS:0. Compiled
baseline4fail/2pass7.85s; the Lowering-owned single-evaluation NEAR_ARG_PTR
conversion preserves target representation and near null. Enum-tagged owned
conversion replay is idempotent, without name-based machine-call proof.
Portable/header45pass11.56s, scoped51pass20.67s, final focused caller/value
cohort21pass11.27s, Pyright0errors; MS C6/KVM native control1pass7.18s.
Required default pipeline main lane8694pass/20fail754.54s; remaining lanes
still running. The TIDShowRange ASan family fails to reserve shadow memory under
the launcher's4GiB virtual-address limit, not a changed TID function. Rerun under
normal Codex confinement with no artificial virtual-address cap; retain ASan
and the Devin sandbox boundary. This focused rerun is now11pass13.34s (10 ASan
controls and the exact Unicorn worker-crash case), unlimited RLIMIT_AS,3workers.
Live py-spy stacks proved an xdist scheduling deadlock after the capped worker
crash: controller waiting for events, all3 survivors waiting for queue input.
Verified pidfd SIGINT terminated that owned lane with166pass/1crash and explicit
incomplete status; compiler lanes continue. Do not count the interrupted lane
as acceptance or weaken the Devin-specific resource boundary. A bounded
read-only sandboxed Devin review of the two return-trial failures is active.
Other failures remain unclassified against a
saved baseline. Global gates and atomic pointer publication
remain unaccepted. No original-source function is claimed fixed.
Focused return-trial rerun remains2fail19.13s under normal confinement:
signed AX is WITNESS_CONFLICT; split DX:AX is RETURN_TYPE_REFUSED with
SPLIT_CFG_INCOMPLETE. These are typed refusals, not ASan/virtual-address failures.
Return-trial source/test hashes remain unchanged during Devin's read-only review.

Compiler-coverage accepted-slot/word bridge (2026-09-30): exact split input
pieces now bind to the existing modular-input owner's callee-proven word,
without relabeling the census or granting pointer authority.10 binary-backed
controls pass; combined body/word changed-file gate25pass18.33s, Pyright0errors.
The isolated unchecked-envelope oracle yields7 expected failures/1pass11.39s
with3workers, demonstrating that these controls reject the unsafe shortcut.
Owned register assignments and semantic casts retain their canonical fields in
the exact body census; two new controls reproduced red before the change,
while the plugin-subclass refusal remained green. Fresh-cache KVM observations
proved both POINT word inputs and return congruence, with clean scalar tail
validation. The later diagnostic uses dummy selectors solely to test AST
closure, never as input/result segment proof. Native representation and the
atomic caller/body/prototype join remain open; no function-fixed claim.

Compiler-coverage body-preflight checkpoint (2026-09-30): the mutation-free
near_return_body_preflight receipt closes an exact structured-node census,
binds the sole retained return, and refuses base uses outside that return,
unknown/plugin nodes, cycles, volatile operands and hidden constant reference
substitutions. Selector purity also refuses reference substitutions. The
changed-file gate passed70 tests (11.42s), with startup/context/ownership checks.
The saved unchecked-body control previously failed4 of11 tests; publication
remains unauthorized pending native representation and coherent integration.

KVM recheck opened character10:232/API12 successfully. The repository-only
sandboxed POINT direct-address run exited0 with validation=passed and a clean
one-function tail. It still emits the scalar interface; this is baseline
validation, not pointer recovery or rebuilt-program acceptance. The diagnostic
candidate refused because the probe supplied a defaulted one-byte slot piece,
not the required proven word identity. Do not relabel that piece or relax the
pointer-arithmetic guard. Graph access was permission-blocked; targeted source
fallback was used. Original compiler-coverage acceptance remains open.

Binary-equivalence control-domain checkpoint (2026-09-30): call-bound DWORD
control normalization now requires exact physical destinations; WORD logical
IP remains a separate architectural projection. Parent saved-baseline review
reproduced three false bindings. Corrected an intermediate undefined logical_ip
in the live shared tree. Final control module21pass/1.99s; combined dosunit,
public complete-call and control cohort235pass/5skip/21.24s, exactly3workers.
Five KVM-dependent skips remain unverified. Shared-config direct Ruff passes.
Plan updated with the domain invariant and intermediate/final evidence; original
M0-M7 and final release acceptance remain open. Next production gap: source-bound
uncatalogued leaf intake with exact CALL destination, terminal-RET body receipt,
full-state lowering and existing saved-return proof, rather than signature proof.
Configured comparator owner gate is red:327pass/2fail/92.31s,3workers.
Equivalent public near32 CALL and call-loop induction now return UNKNOWN.
Startup/context/ownership pass; legacy MyPy exclusions reported. Next action
is exact-refusal diagnosis against saved dirty source, preserving the physical
vs logical control-domain safety controls. No checkpoint acceptance claimed.
Public-refusal diagnosis: both cases prove in fresh production runs; two focused
modules46pass/20.09s and identical configured owner cohort329pass/58.05s,3workers.
No production edit during this investigation. Earlier327pass/2fail remains an
unclassified intermittent condition, not a fixed regression. Saved fresh reports
and optional failure-capture plugin: public-refusal-review/. No M0-M7 acceptance.
Binary-equivalence omitted-leaf intake started: bounded sandboxed Devin job
session51730 owns two new files; parent owns public integration. Three actual
CALL/RET public controls reproduce3fail/10.29s with3workers, while independent
initialized replay validates equivalent relocation and AX/flags mutations.
Current public proofs all UNKNOWN. Saved baseline/red log: binary-leaf-intake/.
This is pending implementation/acceptance, not completed M2/M5 work.
Omitted-leaf parent controls extended with branch, nested CALL, INT, far RET
and potentially return-slot-aliasing store refusals; focused execution pending
worker completion to preserve one pytest pool. Saved freshly lowered exact
CALL bytes/full physical target/continuation in binary-leaf-intake/lowered-caller.json.
Devin session absorbed-conga (exec51730) verified live via process handle and
current session tool activity; no production intake patch available yet.
Omitted-leaf refusal baseline5pass/23.84s plus physical-low-word-collision
control1pass/17.18s, exactly3workers. Parent collision keeps actual target
looping and places matching RET body64KiB away. Intake review must validate
physical target, actual near RET bytes and typed IO effects; jumpkind alone
is insufficient. Devin exec51730 remains live; no owned patch yet.

MSC8 sub_319B0 countermodel replayed concretely (2026-09-30): independent
Unicorn execution of the solver counterexample (eax=0x7ffbbfba ebx=0x100,
mapped stack) on exact catalogued bytes reproduces every modeled difference
— oracle returns eax=0/ebx=0x100/esp+4 with no writes; candidate returns
eax unchanged/ebx=0/esp+12 and writes 0x01 at eax+1. Verdict mismatched.
The observable_mismatch is real, not a model artifact; the candidate .lst
boundary itself remains a separate open question. Artifacts under
.cache/comparator-implementation/msc8-sub319b0-replay/. Comparator dead
signature-reason threading removed; 210 dosunit tests still pass. Real16
helper tail 0x2062 remains reachable on concrete inputs — closure requires
environment/termination modeling (M6-scale), unchanged blocker.
Omitted-leaf fault refusal baseline: DIV-BX/RET control1pass/10.13s with3workers;
a terminal RET must not hide possible divide faults under the fault-free model.
Parent public regression now includes this control. Intake exec51730 remains
verified live; integration waits for its owned patch and terminal review.
Binary-equivalence environment-admission checkpoint: actual unregistered
immediate-port reads falsely PROVED; public red3fail/3pass19.19s. Decoded
instruction-ID scan now preserves IN/OUT events despite lifter constant folding,
checks exact complete bytes/mode and refuses missing decoding evidence.
Final configured owner gate95pass/39.52s,-n3, includes flat32 lane/replay/boundaries;
Ruff/MyPy/type/startup/context/ownership and separate Pyright0errors pass.
Existing routine enrollment retained. Logs/baseline: decoded-port-admission/.
Demonstrated M5 soundness hole closed; broader environment/corpus/release and
omitted-leaf implementation acceptance remain open.
Omitted-leaf Devin draft now exists (worker still live exec51730). Parent read
its full initial source and saved pending corrections in binary-leaf-intake/
parent-review.md: shared decoded-port owner, actual VEX exit evidence, loaded-
image/model/selector identity, shared evidence counters and typed frame/status.
No worker-owned file edited by parent; draft is not integrated or accepted.
Separate public outcome probes retain DIV/INT refusals. Await terminal worker
validation, exact-delta review and before-seal public integration.

Omitted-leaf checkpoint (2026-09-30): Devin terminal, parent delta reviewed and
public real16 discovery integrated before sealing. Byte/image/model/selector
receipts and counters rechecked; ISA16 decoder and mapped-caller work selection
corrected. Public12pass/21.64s; final test log538pass/122.44s,-n3; Pyright0errors.
That Make run supplied empty FILES, so explicit-five-owner validation is now
running (explicit-owner-gate.log). Budget/deadline and unsafe-body refusals remain
visible; this checkpoint does not accept whole-program or original M0-M7 scope.
Compiler-coverage default pipeline checkpoint (2026-09-30): terminal exit2;
all four selected lanes failed. Unit-focused:8694pass/20fail; binary-relational:
166pass/one worker crash then owned-controller interruption (incomplete).
QuickC and MSC6 round-trip lanes also failed; no semantic acceptance claimed.
The outer4GiB address-space limit was inappropriate for the broad ASan/Unicorn
gate: ten ASan controls and the exact crashed Unicorn case independently pass
without that limit (11pass/13.34s). Keep the Devin sandbox4GiB contract; do not
apply its resource ceiling to broad parent validation. Remaining unit and
compiler failures still require bounded attribution, not a full-gate rerun.
Two return-trial controls reproduce2fail/19.13s in normal confinement. Read-only
Devin diagnosis is pending parent review; correct CMP flag effects must remain.
Live /dev/kvm opens successfully and reports API12 in the current session.
Return-proof parent repair: reviewed terminal read-only Devin diagnosis and
verified its two baseline hashes unchanged. Types/Lowering now canonicalizes
repeated direct reads only at one physical comparison site with one known SSA
value; derived expressions do not stand in for direct storage reads. Split
condition paths admit a single effect-free constant JMP only when its target
agrees with the unique retained CFG successor. Original regressions and signed,
unsigned/equality cohort37pass/18.80s,-n3; Ruff and three-owner Pyright0errors.
Additional scalar refusal projections added afterward; final focused rerun and
quality-dev still pending. No compiler round-trip/function-fixed claim.
Final test-file Pyright also passes after replacing its existing broad object
return annotation with the actual typed classifier result. Quality-dev terminal
exit2:296-test contract lane passes (17.31s,-n3); fast unit lane8682pass/31fail/
1skip1195.11s. Log .cache/return-proof-quality-dev.log. Some native recompilation
failures explicitly report nested /dev/kvm absence; do not classify all failures
as environmental. Other failed assertions remain unaccepted/unattributed.
The directly relevant duplicate synthetic-witness refusal exposed a missing
source-origin obligation. New shared Types/Lowering owner return_witness_source
requires distinct exact VEX statement identities before grouping repeated reads.
Existing duplicate-address oracle unchanged. Final focused46pass/20.55s,-n3;
explicit four-owner check-files264pass/86.35s with lint/type/startup/context/
ownership gates; three-owner Pyright0errors. Split controls now enter the routine
pipeline. This is a local proof-boundary checkpoint, not function/linked-case
acceptance or a green global gate. No broad rerun solely to recover output.
Near-return integration review terminal exit0, parent read report and verified
caller source/materialization and existing segment-state selector ownership;
log .cache/devin-reports/near-return-integration-readonly-20260930.log.
Outer rootRO/repoRW and4GiB inheritance reverified. No edits/tests/compiler jobs
delegated. Review must distinguish msc-dos native near offsets from portable-flat
SEG_PTR guest-memory representation; the existing rebuilt native harness passes
ordinary C arrays, not proof that host locals denote guest memory. Parent owns
the atomic body/prototype/caller integration and linked-case acceptance.
Do not adopt the review's proposed input-pointee-width inference from returned
dereference width; source pointee type needs independent evidence. Do not splice
the body before all prototype and caller preflights have succeeded. Saved dirty
publication baseline: .cache/near-return-integration-baseline-20260930/.
Bounded selector implementation staged by sandboxed Devin session27303 under
.cache/devin-staging/near-return-selector-20260930/; production edits and pytest
forbidden during the live parent gate. Parent review/red-green/integration pending.

Corrected explicit-five-owner gate terminal exit0:538pass/240.40s,-n3;
selected-owner Ruff/MyPy/type and startup/context/ownership checks pass.
Whole quality-dev stopped before tests on4near-pointer AST narrowing MyPy errors.
Exact-class receipt retained with guarded cast; before17focused passes, after52
owner passes/11.58s,-n3 plus scoped checks. quality-dev retry running. Devin has
report-only DOS initialized-program/termination seam audit; no source edits.
Real16 frozen-corpus self refresh terminal exit1/UNKNOWN: per side15omitted-body
attempts refused (6branch exits,9nested calls), no admitted bodies. New bounded
leaf capability does not yet improve representative callers; original budgets
retained, exact report binary-leaf-intake/corpus-real16-self.json.
Devin DOS audit terminal exit0; parent verified loader/frame/interrupt seams and
Microsoft DOS reference. Distinct initialized-program contract needed; no fake
function return or guessed complete RET outcome. quality-dev retry296preliminary
passes/19.04s; main fast pipeline active, no final project acceptance.
quality-dev retry terminal2:296preliminary passes,8682main passes/31fails/1skip
in1139.82s. Fixed exact pipeline inventory missing3leaf-intake files; remaining
failures not collectively classified. Initialized-MZ termination lane implemented
with reviewed Devin boot owner, exact caller-declared arena, header entry/stack,
no fake frame, typed DOS4C/fault/refusal outcomes, complete named outputs and
snapshot-bound public replay-program16. Draft red4fail/57pass at POP-DS admission;
after shared typed segment-transfer correction90pass, final public92pass/8.65s.
Final explicit9-owner gate292pass/38.46s,-n3 plus scoped checks; Pyright0errors.
Shell equivalent returns0/agreed; changed exit1/mismatched. Docs and routine
enrollment coherent. Artifacts real16-program-start/. Bounded termination step
done; full M6/flat32 program parity/environment/corpus/release remain open.
Fresh quality-dev checkpoint terminated with 8716 passed, 31 failed, 1 skipped
in 1368.46s (-n3). Stage source hash receipt is saved under
real16-program-start/quality-dev-source-manifest.json. Sources changed during
the run; this is not a stable-tree acceptance result.
Isolated same-budget public affine case now exit0/PROVED,3materialized facts,
0failures/no assumptions (affine-public-diagnosis/report.json). Earlier broad
UNKNOWN remains unexplained; no raised budget or proof gate. Failure assertion
now exposes exact verdict row to classify the next broad result.

### 2026-09-30 — Reviewed Devin real16 output service

Parent integrated opt-in bounded INT21/AH40 successful independent stdout/stderr
streams into initialized MZ replay, manifest, identity and public report. Reviewed
Devin two-file delta; found/fixed bool/float handle and oversized-AX contracts via
red regression. Final175focused controls pass/14.89s,-n3; six-owner Ruff/MyPy/type
ratchet, Pyright0errors and startup/context/ownership checks pass. Review and
remaining original-plan acceptance: reference/comparator-devin-review.md.
Concrete replay remains not_established_by_execution; arbitrary files/devices,
flat32 program parity, representative corpus and full release gates remain open.

### 2026-09-30 — Revalidated broad-gate failures on current sources

Public loop/call suite: 34 passed/35.14s, -n3, including the previously failing
9043c3 positive and changed-leaf refusal. Return-witness address suite: 6 passed/
22.98s, -n3. Current materialization consumes distinct_return_witness_sources_8616
to refuse duplicate operations without distinct retained statement provenance;
the source owner was read directly because graph coverage is not_tracked.
No new semantic patch was needed for either reproduction. Their earlier broad
failures remain historical failures, not proof of a current defect or a resolved
root cause. The broad gate is still red; other failures and original M0-M7
acceptance remain open. No proof budget or refusal gate was weakened.

### 2026-09-30 — Flat32 concrete machine-input admission

Reproduced four false admissions: RDTSC, CPUID, RDRAND and RDSEED all returned
from function replay despite missing clock/CPU-feature/entropy contracts
(4 failed/14.15s, -n3). Shared binary-decoded admission now produces typed
undeclared_machine_input for these operations plus RDTSCP and XGETBV, before
execution. Both function replay and the staged initialized PE32 executor consume
the same rule. New regressions extend the already enrolled full-state test owner.
Combined function/full-state/PE32 controls: 38 passed/37.27s, -n3. Scoped
linters-files passes Ruff, MyPy and type ratchet; the existing test owner is
excluded from MyPy's QA typed-file list, reported by the gate.
The first combined run also exposed staged PE32 null-SS bootstrap faults;
a concurrent edit replaced selector writes with explicit fresh-state checks,
which the final run verifies. This agent did not author that bootstrap patch.
Sources saved under flat32-environment-intake/. No declared environmental state
was substituted with backend defaults. Full M6 and original-plan acceptance
remain open; quality-dev is a separate pending checkpoint.

### 2026-09-30 — Both-track replay machine-input closure and gate preflight

Devin's bounded read-only real16 audit was reviewed against current source.
Actual real16 regressions reproduced15fail/1pass in2.93s,-n3: CPUID/clock/entropy/
XGETBV admitted without environmental state; RDTSCP already refused through a
privilege tag but lacked the declared-machine-input reason. Shared owner
replay_machine_inputs.py now owns decoded IDs and typed ReplayInstructionReason;
flat32's existing model reexports that enum and real16 consumes its refusal.
Both function and initialized-program consumers inherit admission, including
16/32-bit RDRAND/RDSEED forms. Final four-owner replay cohort89pass/19.86s,-n3;
scoped Ruff/MyPy/type ratchet pass and five production owners pass Pyright0errors.
The existing test modules remain excluded from the MyPy typed-file list.

quality-dev preflight exited2 at five near_return_entry_selector MyPy errors,
before pytest. Preserved exact CVariable class admission and added explicit
foreign-boundary cast; documented the optional angr surface at its owning
function. Selector controls21pass before/18.82s and after/11.96s,-n3, scoped
checks green. No return/selector semantics changed. Development-gate retry
pending; broader gates, staged PE32 review failures, ELF32 program parity,
environment/services/corpus and original M0-M7 acceptance remain open.

### 2026-09-30 — Retained-corpus source checkpoint

Revalidated all10 frozen inputs against the existing three-track manifest;
kept its20-function selection unchanged (real16:3, MSC8:2, BC5:15). Captured2758
Python/schema files plus3 explicit deleted Python paths under
.cache/comparator-implementation/corpus-current-20260930-_ka3a2jo/sources.
Inventory and byte hashes were checked again after copying; receipt.json binds
selection, input/source identities, interpreter and package versions. The first
copy attempt stopped loudly at a tracked deletion and is not an accepted
snapshot. Isolated z3func.py --help exits0 from the complete snapshot; this
checks CLI startup only. Compiled extensions were not copied, so future timings
must disclose source-only conditions and cannot claim normal-build speedups.
Devin is preparing a serial, identity-checked cold/warm runner in this ignored
checkpoint, with no production edits or comparator execution authorized in its
job. Parent review and actual corpus runs remain pending. Historical reports
remain historical. quality-dev retry is live:296preliminary tests pass/14.65s,
-n3; the subsequent fast pipeline is not yet terminal. No milestone promoted.

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

## Comparator Devin review checkpoint (2026-09-30)

Parent reviewed bounded PE32 boot/real16 file-input deliveries and rejected the
unsupported categorical REP/KVM diagnosis. REP19, process-helper2, COD CLI1 and
marked MSC-target1 pass current focused checks. Remaining14 current audit is
terminal:14failed/278.00s, with5explicit KVM blockers,7code/validation failures,
1timeout and1unclassified corpus failure. Full quality-dev remains failed.
Acceptance-reporting Boolean gate/headline correction is staged with Devin,
not accepted into production. Detailed disposition and artifacts are recorded
in reference/comparator-devin-review.md. Original M0-M7 remains incomplete.

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

## Final acceptance reporting corrected (2026-09-30)

Reviewed staged Devin delta and reproduced baseline reds independently. Integrated
BooleanFalse merge gate and separate acceptance failure headline, preserving all
semantic evidence/counts; repaired scorecard text/structured projections. Durable
controls enrolled. Combined57tests pass9.85s; selected Ruff/MyPy/type ratchet and
ownership pass; two reporting-owner Pyright0errors. Evidence: acceptance-reporting/.
Full broad gate remains failed; original M0-M7 completion remains unproved.

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

## Backend-dependent gates classified (2026-09-30)

Five missing requires_kvm markers added with assertion bodies intact; worker
context reports5explicit skips, parent context independently can accessKVM.
Pure BIOS/InBox cohort23passes13.20s;4test owners Ruffclean and ownershipcheck
passes. These skips do not discharge native DOS acceptance. InitMenu saved C
still reproduces2gcc errors; bounded isolated diagnostic Devin live, not accepted.
Artifacts: kvm-gate-markers/ and initmenu-gate-review/. Original plan active.

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

## Clone coordinate ambiguity refused (2026-09-30)

Integrated general competing-domain guard with durable red1test and green50
coordinate controls; selectedlint/type and ownerPyright0errors. Ownership-driven
check-files102pass/1fail:Sleep unassigned-stack-local. Saved pre-edit owner in
isolated process reproduces sameexit4/refusal; Sleep remainsunresolved. No broad
gate/function-fixed/M0-M7 claim. Artifacts coordinate-clone-review/. Devin still
owns read-only InitMenu diagnosis; its initial fresh probe predates this guard.

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

M4 read-only audit55214 terminal0; parent verified singular flat32 ordered
proposal vs shared bounded branch-pairing enumeration. Staged-only Devin74977
started after rootRO/repoRW/4GiB check for both-lane real-byte red/green/mutation
controls, cap64 and shared deadline. Production integration/acceptance pending.
Audit baseline14paths, plan-only parent drift; no new test/pass claim. Graph
transport closed; exact source fallback. Original M0-M7 remains open.

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

Original M4 unequal-step design62531 terminal0, parent reviewed with explicit
endpoint/coverage/progress/type/freshness corrections (see comparator-devin-review
and m4-unequal-step-intake/parent-contract-review.json). Staged implementation
Devin3617 started under verified hostRO/repoRW/4GiB, ignored ownership only and
eight source baseline snapshots. Both-width solver/negative/resource acceptance
required; production integration and original M0-M7 closure remain pending.

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

Branch-search Devin74977 exited0, parent declined promotion: no demonstrated
new proof and no measured gain; sampled canonicalization is not universal
impossibility proof. Production consumer unchanged. Actual unequal-step3617
continues; original M4/M0-M7 acceptance remains open.

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

### M4 macro-step checkpoint (2026-09-30)

Reviewed Devin3617 delivery and parent corrections are now production dosunit primitives. Exact real16 MZ and both flat32 driver/PE controls plus adversarial admission/deadline/full-state controls: 52 passed in 20.70s. Shared flat32 retry now invokes complete macro-step proofs under one total deadline, preserving prior counterexamples and every attempt; retry/register cohort 20 passed in 7.02s, scoped Ruff and Pyright clean. Public real16 wiring, environment/provenance review, representative corpus and broader gates remain pending; original M0-M7 scope is unchanged and incomplete. Detailed evidence: reference/comparator-devin-review.md and .cache/comparator-implementation/m4-macro-step-stage/parent-review/.


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

Latest redundant test-inclusive Pyright recheck ended134 (RTK SIGABRT, no diagnostics) while /home filled again; it is not a passing gate. Earlier test-inclusive Pyright0 and final scoped Make lint/type0 receipts remain separate. Final focused136-test run completed before disk exhaustion. Current filesystem free space is insufficient for broad gates.


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

## 2026-10-02 — Riptide v8 corpus compare; dosunit region-proof recovery

Comparator work on the region-composition path
(tools/dosunit/straightline_ssa.py plus new dosunit proof/control modules):
pooled evidence-backed layout_normalization pairs across per-part results
(`_region_adopted_layout_pairs` feeding `_region_step_quick` and the
transition-system compare as `global_map`), added the `cutpoint_state`
gate, and taught `_target_key` exact literal conversion via
`ssa_constant_terms.constant_bitvector` (const/trunc/zext/sext/add/sub) —
oracle `ip = trunc16(const32 linear)` terms now follow their jump
(@abs$qi composes 2 blocks, was 1). New `callee_state_relation_required`
refusal pins call hardening: a region containing an Ijk_Call part refuses
pending a complete callee state relation.

Full 4-shard corpus re-run (orig.ssa.v2.shard0-3 vs recon.ssa.v8,
mapping.v4; run_shards_v8.sh → batches_v8_s*): 4920 passed / 1 failed /
4790 refused per-part rows (v7: 6840/7/2864). Region axis: 0 failed
(v7: 37 — all cleared), 2 passed, rest refused honestly
(callee_state_relation_required 512, cutpoint_state_incomplete 24,
control_flow_unproved 1, function_missing 62, region_incomplete 1,
slice_too_large 1). The ~1920-row pass drop is honest de-proving: v7
passed call-containing parts on mapped/name-equivalent callees with no
proof_fact; hardened rows now refuse callee_not_proven pending a real
callee equality fact (e.g. @mv_std → check_new_pos). Sole remaining fail:
___fpreset memory_expr_changed (already failing in v7; needs per-case
evidence, no blanket normalization). realloc/farrealloc and the other
regionfail functions left the failed axis; @gui_item@poll gained proof
full-corpus. proven_equal.json/PROVEN.md regenerated from batches_v8_s*:
82 functions fully proven (1081 parts), down from 365 recorded under the
unsound balanced-callee-omission rule. dosunit suite: 216 tests pass,
including the new truncated-const-ip region regression
(`blocks_composed==2` on both sides) and the `_target_key`
trunc(non-const) negative guard.
