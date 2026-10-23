# Evidence Contract Improvements

## Objective and acceptance

Improve Inertia's semantic recovery using explicit, durable evidence contracts.
Implementation proceeds in bounded slices; the supervising agent owns
architecture, review and acceptance. Existing compatible contracts should be extended rather
than duplicated. External product names do not belong in implementation code,
comments, docstrings or tests for this work.

This is a multi-slice effort, not complete when one focused suite passes. Each
implemented behavior needs a saved pre-change regression, a reviewed delta,
positive and refusal controls, closed evidence counters and the applicable
integration checks. Whole-function fixes additionally require tail validation,
preserved calls/argument classes, comparison with original source when present,
and applicable executable roundtrips. Skipped or interrupted gates are not passes.

A later CLI publication repair preserves the selected function's originating
manager when installing lookup aliases. Four focused checks pass, including
native execution, tail validation and compiled generated C; scoped MyPy,
iteration lint and startup architecture checks also pass. This removes the
CFG-lookup exception on the real scalar-addition example.

A subsequent typed read-order proof distinguishes pure assignment operands from
their destination store. It fixes the refused entry-SP read without relaxing
the final def-use guard. Forty focused checks and the twelve native call-input
cases pass on the same frozen source; compiled word updates preserve wrapping
and upper ESP bits. The evidence loop is 1/1/1/1/0 for the new assignment case.
Exact-region recovery now compares recovered instruction heads with the closed
native census, without a minimum function size or a byte-coverage ratio. This
recovers the three-block scalar-addition body and does not mistake unreachable
padding after a complete return for missing code. Unresolved native terminals
still refuse reconstruction.

Readiness observes each registered IR body and producer output once within one
admission, sharing fingerprints across that admission's dependency checks.
Every later admission starts a fresh observation: edited source bytes, changed
producer evidence, cycles and stale AST versions still revoke readiness. The
preceding readiness checkpoint passes 90 focused checks, two native-stage
checks and all twelve machine/C call-return cases on one frozen source.
These are scoped results, not a current full integration pass.

The actual scalar-addition CLI now emits both signed-byte arguments, their sum
and the return within the same 30-second limit. It still exits with a typed
validation refusal: the call's callee SP effect is unproven, so Alias cannot
publish its stack position and the call-input validator rejects the missing
binding. The legacy rendered-text deletion of helper calls by name has been
removed, including its three formatting entry points and obsolete deletion
test. Its replacement executes the actual CLI output with gcc: all 65,536
signed-byte sums pass and exactly one helper call survives each invocation.
Before the removal, the same executable returned the correct sums but executed
zero helper calls. All 99 checks in that CLI regression run pass. This proves
emission behavior, not the helper's native SP contract. Tail validation and
native equivalence remain required before calling the function fixed. The
current quality gate stops in linters before decompiler checks; no whole-goal
or integration success is claimed.

The call-input checkpoint binds architectural numeric SP at generated call
execution using source-proved caller/callee positions and one immutable
entry-SP capture. Independent validation checks the actual binding, argument
and result transport, and both word/upper-ESP equations before existing call
validators consume a pure logical view. Missing bindings remain tail failures.
The saved pre-binding native control returns AX=32769 instead of the machine's
32767 despite stable local snapshots. The stronger test compiles both real
functions and retains nonzero upper ESP. The current native cohort passes all
12 controls: ten framed call variants and two programs compiling both generated
functions. Final AST call-input reports and tail snapshots pass, including a
recovered `PUSH 0x1234` argument and the numeric-SP pair's four extra machine
boundaries and complete 65536-word compiled-C sweep. Ordinary and far calls,
stack arguments and live upper ESP are covered at this checkpoint. The source
fingerprint is unchanged across that run. A focused Lowering suite passes 321
tests. General argument-class recovery, performance and broad acceptance remain
open; no current full pipeline pass is claimed. See
[runtime call inputs](p0-call-return-stack-effects.md) for contracts and receipts.

`alias/call_stack_positions.py` now derives caller-before, callee-entry and
caller-after SP offsets from the canonical must-state solver. It authenticates
the existing frame/body effect, observes the physical frame push exactly once,
and freshly reproduces saved proofs before consumption. These positions are
distinct from the seven existing frame/effect/argument slots. C runtime input
binding and its validation remain required; the Alias proof alone supplies no
generated-C ABI repair. See [the stack acceptance contract](p0-call-return-stack-effects.md).

The shared Types entry-capture owner now retains both exact return uses and
Alias call-position uses in one canonical census. Adding either consumer
reuses the same dominating word local. All retained uses and the codegen source
publication must still match before reuse; foreign marker entries return a
typed refusal. Two new controls initially failed, then passed after those
guards. The configured Cython cohort passes 292 tests; 63 snapshot/materializer
controls pass after the native tag-interface typing correction. Scoped lint,
MyPy and Pyright pass. That capture-only checkpoint prepared the call-input
consumer; its evidence alone did not fix the two-generated-function failure.

The earlier capture-only native pair finished with one scalar pass and the
expected cross-call failure in 143.53 seconds. All 2,183 production Python and
compiled artifact hashes remained unchanged across that run. Actual AX was
32769 instead of 32767, with upper ESP preserved. Both canonical local tail
predicates returned true despite the wrong cross-function input, preserving a
negative baseline for the newer binding. That checkpoint's full MyPy reproduced
the prior 776 diagnostics. Historical review:
`.cache/devin-prompts/function-readiness-20261016/parent-entry-capture-review.json`.

Earlier parent integration review remains partial. Subsequent readiness fixes
bind rendering to the active producer and preserve final-output mutation checks.
Conservative scalar declaration cleanup now runs before Rewrite publication;
the CLI consumes that same cleanup owner. Earlier focused evidence included 161
passing contract tests and 12 passing CLI regressions, with no added scoped
typing diagnostics. Both process-ID examples pass tail validation; the setter
timed out at 20 seconds and passed with a 60-second budget. These results do not
establish a 20-second performance guarantee or replace broad pipeline acceptance.
The original COD bodies of both process-ID examples contain only a frame push,
frame pop and return. Their validation establishes the empty-body regression
case; it does not establish substantive DOS recovery or recovery of the original
non-void C signatures.
The review and source hashes are recorded in
`.cache/devin-prompts/function-readiness-20261016/parent-scalar-declarations-review.json`.

Latest native integration repairs reuse source-bound missing-service
prerequisites from registered boot IR through the existing request owner, and
preserve authenticated physical STORE captures for CS/DS/SS without inventing
segment aliases. The current ten-module integration run passes 205 tests on a
frozen source snapshot; the three-owner MyPy comparison decreases from 26 to
25 diagnostics with no additions. These are bounded results. The unchanged
InitMenu regression still returns a typed 150-second recovery timeout (latest
test call 259.86 seconds), so it is not an accepted whole-function fix. Details
are in `.cache/devin-prompts/function-readiness-20261016/parent-registered-blocker-review.json`.

The completed full pipeline on the preceding frozen source passed five lanes
and failed four. The unit lane reported 256 failures and 71 errors; the
relational lane reported 60 failures and nine errors. These are retained as
integration failures, not converted into accepted results.

A subsequent Pipeline-owned call-input outcome contract lets cleanup preserve
an unproven Alias position refusal and skip eight retries that cannot supply
that missing proof. Status DTOs and their read-only publication accessor have
one owner; semantic binding helpers remain in Lowering. Architecture, scoped
MyPy and Pyright pass. The focused run passes 175 tests, and the concurrent
native/load cohort passes 15, including the real CLI emission regression under
its unchanged timeout. The CLI retains native validation exit 4 and compiled-C
execution exit 0. The native callee SP proof and a new full integration pass
remain open; this is not whole-function or whole-goal acceptance.

## Work inventory

| Area | Required behavior | Current evidence and next obligation |
| --- | --- | --- |
| Pipeline readiness and refusal | Typed readiness/preconditions, explicit refusals and invalidation after changed evidence; diagnostics consume the same owner. | Integrated generation-bound IR lifecycle, shared IR/SSA projections, source/body/producer attestations, actual AST handoff and schema-5 cache restoration. Root focused run: 208 passed and one pre-existing source-inventory failure; 14 native/Cython/cache scenarios, four independent live-evidence controls and five IR/cache mutants pass. All five new test modules are enrolled in the routine component catalog. Strict typing returns to its exact 68-diagnostic baseline after two integration corrections. Broad pipeline acceptance remains open; see `function-evidence-readiness.md` and `.cache/devin-prompts/function-readiness-20261016/parent-root-integration-review.json`. |
| Call register effects | Distinguish input/pass-through, clobbered, dead and result registers, including overlapping subregisters, from proven call effects. | Integrated independent input, may-clobber, caller-dead and result artifacts, canonical output provenance/width validation, pre-insertion CALL indexes, and Alias view preservation. Parent eight independent probes pass on integrated sources, including missing-branch deadness, partial-bit completeness, and malformed output refusal. Final configured-backend static run:171 passed in13.26s; lint, contextual MyPy with IR core, and startup architecture pass. Standalone startup fixtures preserve all original assertions. Broader gates remain open; this is not whole-function or full call-effect completion. |
| Call stack accounting | Publish first-class callsite SP delta, argument-stack top and callee-purged byte count, independent of return-frame width; preserve returning-edge ownership and low-SP arithmetic. | Seven-slot frame/effect coordinates authenticate source and callee-body SP evidence, with independent argument-top refusal, Alias/SP consumers, native copy and serializers. Word far calls are supported; unsupported wide forms and unknown/synthetic targets refuse. Alias positions distinguish caller-before, callee-entry and caller-after relative to function entry, including RET-N. Types now binds generated-call SP inputs; independent validation proves actual bindings before logical normalization. The generated caller/callee pair passes five real machine inputs and an exhaustive 65,536-word AX16 C sweep, with upper ESP preserved. Broader call variants, argument classes, performance, gates and whole-function acceptance beyond this pair remain open. Scoped returning-SP now has independently reviewed Alias, dual-context Semantics and IR/SSA transport; 137 transport/source-binding controls pass after parent repairs. Caller Alias integration is in progress; Lowering and Validation still require explicit scoped-authority transport (see `scoped-call-stack-effects.md`). |
| Split wide values | Preserve proven low/high identities, widths, signedness and provenance through Types with a durable named pair contract; carry typed split/unpaired transform-legality evidence and reject partial, overwritten or mismatched pairs. | Integrated a named logical pair type and per-operation pairing/split legality retained from Widening through Lowering. One half-legality owner governs construction and later authorization. Lowering authenticates the operation, source versions, segmented source/destination ranges and legacy ownership before retiring carriers. Parent configured-backend static checks:132 passed, four independent corruption probes passed, lint/architecture/contextual typing passed. General split-transform recovery and whole-function acceptance remain open. |
| Allocation convergence | Restart the native local/stack-variable allocation owner when evidence changes; require deterministic convergence, explicit refusal and coherent publication. | Integrated the bounded native transaction: restart from detached raw input, seal consumed evidence and publication content, restore state on refusal, and retain typed cycle/exhaustion causes. Parent verified 42 configured-root tests and nine independent native Cython controls, including ignored legacy skip hints, two real Clinics, revised-versus-fresh state, nested rollback, producer types and in-place publication damage. Focused typing/lint and architecture/context checks pass. Whole-function semantic and broad integration acceptance remain open. |
| Canonicalization rules | Named, auditable canonicalization rules with typed preconditions/evidence, per-rule enablement, deterministic application and recursion protection. | Integrated semantic IR pattern registry for the existing known-guard SELECT normalization, retaining scalar/known-bit authority. Per-rule configuration, checked action evidence, deterministic census and recursion protection are enforced. Native cache configuration derives from the same typed policy owner. Parent configured run:168 passed; independent unknown-guard forgery and enabled/disabled cache controls pass. Existing cleanup runtime remains separately bounded. No semantics added in Rewrite; whole-function/broad acceptance remains open. |

## Remaining acceptance obligations

The reviewed cleanup and wide-carrier guards are partial improvements, not
completion of their areas. The alias-cache repair and native allocation transaction now have separate
bounded evidence; whole-function and broad integration acceptance remain open.
Existing contracts count only when their real producers and consumers enforce
the required behavior. Do not duplicate an owner merely to match terminology.

- Readiness: apply [the function-state contract](function-evidence-readiness.md),
  including the owned IR stage/refusal, and verify pass preconditions across all
  owning stages, including invalidation when earlier evidence changes.
- Calls: combine independently proven input/pass, possible-clobber, caller-dead
  and result roles with canonical subregister overlap; preserve unknown effects.
- Stack: verify shared SP-delta/argument-top/purge fields and all projections,
  not only the return-immediate decoder. Callee-body SP transfer must also be
  proven on returning edges: plain RET does not prove a zero net call delta.
  Parent binary/Unicorn control shows a normal returning callee which removes
  an argument with pop/add-SP/push and plain RET; its real call delta is +2,
  while a cleanup-only draft reports zero. The integrated result must account
  for that evidenced body effect, not merely refuse this supported case or
  infer net SP from RET-N plus frame width alone.
- Pairs: verify the named Types projection and operation-legality contract
  survive split/wide transformations; register-claim rejection is a guard only.
- Allocation: extend the accepted native restart/rollback/publication controls
  to whole-function semantic acceptance and broader pipeline integration;
  retain the separate cache and native-allocation evidence.
- Rules: verify named pattern preconditions, individual enablement, recursion
  protection and consistent diagnostics, beyond existence of a pass list.

Each area needs current integration evidence at its owning layer and the
mandatory function acceptance where output semantics change. The full goal
remains open until these obligations are met.

## Recorded checks and limitations

The later 2026-10-18 checkpoint passes 588 focused tests with the configured
native source-graph backend. A canonical call-effect serialization now observes
the callee body at most twice, rather than nine times; eight saved coordinate
encodings remain identical. Retained transfer values serve the census, while
fresh source and body checks still authorize current SP effects. Immediate
word far calls now consume actual callee SP dataflow. Six independent controls
check `RETF`/`RETF 2`, a nonzero selector, Unicorn execution and refusal after caller
or callee byte changes. The earlier near-only RET register-preservation proof
keeps its original scope.

Lint and scoped MyPy pass for the five changed production owners. The current
`quality-fast` run exits 2 with unchanged 776 MyPy diagnostics and three Vulture
findings, on stable sources. Logs and current hashes are recorded in
`.cache/devin-prompts/function-readiness-20261016/parent-coordinate-far-review.json`.
The real far-call control now publishes a zero SP delta in current SSA, but its
generated C still fails the numeric-SP oracle; its diagnostic run takes 167.29
seconds. Whole-function correctness and performance remain unaccepted. The
native input-provenance gap is recorded in `p0-call-return-stack-effects.md`.

The earlier 2026-10-18 corrective checkpoint passes 224 focused tests with the configured
native source-graph backend. The CALL observer fixture now delegates universal
intake before observing conditional scopes. Structured output snapshots retain
all native AIL virtual-variable fields and refuse unknown tags. A callee-SP
projection now delegates once to the current Alias body proof, while subsequent
reads still detect changed callee bytes. These changes have saved failing
controls and passing mutation/refusal controls under
`.cache/devin-prompts/function-readiness-20261016/parent-{declared-fixture,ast-vvar,call-proof-once}-review.json`.
The combined result is `parent-corrections-focused-root.log`. The current
`quality-fast` run exits 2 with the same 776 MyPy diagnostics and three Vulture
findings as its preceding baseline; its source snapshot remains stable.

Whole-function acceptance is still open: the native far-call numeric-SP control
now reaches compiled-C execution, but returns 4294967294 instead of the machine
result 32766. The source-bound SSA proves ESP as a live-in; its dirty entry
version remains unprojected after CALL. Supporting its AST representation does
not establish correct lowering or tail validation. The separate native-call
latency diagnostic also remains open; reducing duplicate body proofs alone is
not an end-to-end speedup claim.

Numeric-SP source proof follow-up (2026-10-18): the canonical Alias CFG transfer
establishes `entry_SP - 2` at the real word assignment to AX after the accepted
near call. `alias/numeric_stack_pointer_values.py` now exposes an exact MOV-value
proof query that replays current call evidence, keeps captured values distinct
from live SP, and refuses unknown calls, changed operand views, duplicate blocks,
and incomplete CFG scope. It reuses the existing stack transfer rather than
introducing another SP simulator. The Semantics return inventory now consumes
that query in the authenticated IR/Alias prefix and publishes one typed outcome
for each RET before Alias completion. Exact same-block definition-to-return
ownership is required; a preserved path into a shared epilogue is insufficient.
The inventory and its source binding are the ninth retained prefix output, with
an independent mutation control. Publication of these source proofs does not
establish C materialization or a fixed function.

The native return probe also shows why value-origin metadata alone cannot bind
this proof: the propagated return expression retains the ADD instruction's
origin, while the return statement identifies the later RET. The existing
`ReturnValueOrigin8616` contract now transports both locations independently;
absent or malformed statement coordinates remain unknown. The final scoped run
passes 193 tests across Alias, call proofs, return provenance, existing return
lowering, and structured AST transport. Iteration lint and explicit three-owner
MyPy pass. Receipts are `parent-numeric-value-*` under the readiness artifact
directory. Source-to-return ownership, entry-value C capture, compiled-C behavior,
tail validation, and the full acceptance gates remain open.

An independent malformed-producer control initially exposed acceptance of
displaced, versioned, or memory-decorated TMP definitions with an unchanged ID.
The producer must now be an exact word scalar as well as having an exact read
view; those controls fail before and pass after the correction. The broader
`quality-fast` run before that final conservative guard exits 2 with the same
776 normalized MyPy errors and three Vulture findings as its preceding baseline.
Final scoped lint, MyPy, and the 193-test cohort pass after the guard.

The next return-ownership cohort passes 126 tests across the source inventory,
return transport, prefix sequencing, branch returns, and native prefix scope;
a separate shared-epilogue control proves that a valid selected return path
cannot authorize another predecessor's value. Unknown returns remain typed
refusals in the closed publication ledger. Both the new owner and its structuring
integration pass scoped MyPy. Standalone return-transport tests now install their
own native adapter; previously they depended on another module's bootstrap order.
At this earlier checkpoint the real near-call numeric baseline still failed its compiled-C oracle in 144.32
seconds with one preserved call and the same wrong value. Its test now also
records the actual native publication, so source-proof acceptance and generated-C
acceptance remain separate assertions. A C materializer was not installed at
that checkpoint; the latest materializer and open cross-call failure are recorded above.

The closed combined cohort passes 286 tests. On the actual native numeric-SP
function the publication assertion also passes: its word AX definition at
`0x100a` is `entry_SP - 2` and reaches RET `0x100f`, with all five proof counters
equal to one except failure count zero. The subsequent executable-C assertion
still fails with the old wrong value. The diagnostic proof is retained as
`parent-numeric-return-native-producer.json`; the overall native test exits 1,
not a pass. Its 248.91-second run overlapped the combined cohort and is not a
controlled performance comparison. Final iteration lint and two-owner MyPy pass;
`parent-numeric-return-review.json` remains explicitly unaccepted.

The first cleanup slice has reviewed source/test changes in
`inertia/semantics/terminal_stack_cleanup.py` and
`tests/semantics/test_x86_16_callee_cleanup_compat.py`. Its behavior is documented
in [callee cleanup](p0-callee-argument-cleanup.md). The saved evidence lives in
`.cache/devin-prompts/hex-call-boundary-20261015/parent-review.json`.

That checkpoint's scoped Ruff/MyPy checks passed. `quality-fast` failed on
other files. The default pipeline passed 309 contract tests but later reported
scope and comparator failures and was interrupted; it is incomplete. A GNU
Make fixture failure caused by read-only temporary storage was resolved in a
focused 43-test rerun with workspace-local `TMPDIR`. InitMenu was skipped
because KVM was unavailable inside the execution sandbox. These facts are
checkpoint observations, not a current whole-tree acceptance claim.

The next split-value task keeps private source baselines and its bounded prompt
under `.cache/devin-prompts/pair-evidence-20261016/`. Every subsequent slice must
update this inventory with verified evidence and remaining obligations.

The independent convergence task keeps its private baselines and prompt under
`.cache/devin-prompts/alias-convergence-20261016/`. Its ownership excludes the
split-value task's files. The current task now has a four-hour allowance; no patch is
accepted until the supervising agent reviews a concrete reproducer and delta.

The split-value review is recorded in
`.cache/devin-prompts/pair-evidence-20261016/parent-review.json`. Its new cases
deliberately corrupt Alias facts derived from binary fixtures; they prove that
the Widening boundary refuses inconsistent carrier claims. They do not prove
source-resolution correctness for arbitrary forged Alias facts, nor establish
a corpus improvement: valid producer facts already satisfy the new checks.
The parent independently repeated the eight-module extended suite: 81 passed
in 10.32 seconds (one third-party deprecation warning), with the reviewed
source hashes unchanged. Scoped Ruff and MyPy also passed independently.
This is bounded static integration evidence, not whole-function acceptance.

The independent named-rule controls task keeps private baselines, its prompt
and a process-local baseline failure under
`.cache/devin-prompts/canonicalization-controls-20261016/`. It owns the
optimization driver and only the guarded optimization runner/imports in the
postprocess stage; it does not own the alias-cache invalidation hooks.

Additional bounded source audit: `WideCarryBorrowValue8616` is already an
immutable named 32-bit value with exact low/high slices, UNKNOWN signedness
and carry provenance. `WideCarryBorrowStorage8616` retains its destination
and source versions, and Types/Lowering has typed placement/refusal records.
These existing contracts should be reused; they do not by themselves prove
general pair type propagation or every split operation. Actual local-variable
recovery also crosses the angr boundary in `cli/cli_decompilation.py`; the
current stack-alias cache task is not that allocator.

The call-register implementation is integrated with four independent roles,
bit-view preservation, source/origin binding and canonical output validation.
Eight parent probe scripts passed with stable source hashes, and 171 focused
static tests passed on the configured Cython backend. A malformed unnamed
pair-output crash exposed by the broader typing context was independently
reproduced and corrected. Contextual typing with the IR owner passes; the
broader development typing batch retains exactly its prior 68 diagnostics.
This slice has no whole-function acceptance claim. Its receipt is
`.cache/devin-prompts/call-register-roles-20261016/parent-review.json`.

An integration prerequisite was repaired in the recursive control-view source
fingerprint: three moved source paths now resolve to their canonical owners,
while all thirteen dependencies remain sealed. Parent verification passed 97
focused tests on the configured Cython VEX backend, including corruption and
missing-source controls; this is static binary-proof coverage, not KVM runtime
acceptance. Receipt: `.cache/devin-prompts/control-view-source-paths-20261016/parent-review.json`.
The obsolete routine-unit selector was also replaced by the current six-case
unknown-memory retention regression; full unit collection succeeded before
the new sixteen fingerprint controls were admitted. Broad acceptance remains
open: the saved default pipeline has six failed lanes, and the later hard gate
stopped in its MyPy development batch with 68 diagnostics across 19 files.
See `.cache/devin-prompts/parent-integration-20261016/parent-review.json` for
the exact scopes and unresolved failures.

The refreshed required pipeline terminated with three passed and six failed
lanes. Its unit lane reported 15,592 passed, 362 failed, 71 errors, 28 skips
and one expected failure; the checked new role surfaces were absent from its
failure list. Native acceptance also lacks writable KVM. The post-correction
broad typing batch matches the 68 pre-existing diagnostics exactly; later
hard-gate batches remain unverified. Broad ownership checks report 43 other
test modules missing from the catalog, while both new role-test modules are
enrolled. Full reports are retained in the role task directory.

The named-pair contract is now integrated. Its type identity covers width, half
layout and signedness; operation kind and segmented source space remain on the
evidence. ADD/SUB positives and deliberate operation, version, address-space,
destination and half-invariant corruptions exercise materialization and legacy
ownership. Four parent probes passed on the production tree with stable source
hashes, and 132 configured-backend static tests passed in 13.55 seconds. Scoped
lint, startup architecture and contextual MyPy (ten explicit source files) pass.
The new contract and regression module are admitted to the authoritative
component catalog and routine pipeline. Receipt:
`.cache/devin-prompts/pair-types-20261016/parent-review.json`. These checks do not
establish whole-function equivalence or general split-transform recovery, and
the prior broad pipeline and hard-gate failures remain unresolved.

The readiness task now has a concrete early-consumer failure rather than only
an architectural inventory. In the parent's control, the original machine bytes
`89d8c3` produce BX/SP live-ins. Replacing them with `89d0c3` leaves those old
live-ins visible through `runtime_gp_state_names_8616`, while a fresh project
correctly reports DX/SP. The registry continues to return a proven IR-stage
artifact. The saved reproducer and failing log are in
`.cache/devin-prompts/readiness-audit-20261016/parent-stale-ssa-probe.py` and
`parent-stale-ssa-red.log`. The private `function-readiness-20261016` task owns
the source-bound contract, actual consumer enforcement and later-stage
invalidation; its implementation is not accepted yet.

Two additional parent controls constrain the private stack-coordinate work.
A plain RET does not prove zero callee-body SP effect, and absence of an
immediately adjacent PUSH does not prove zero stack arguments. A real
`PUSH 1; NOP; CALL` followed by a framed argument read and RET2 returns AX=1
and restores caller SP in Unicorn, but the draft describes its argument region
as empty. Unknown argument setup must retain a typed refusal while preserving
an independently proven call SP delta. The reproducer and execution evidence
are retained as `parent-nonadjacent-argument-probe.py` and
`parent-nonadjacent-argument-unicorn-red.log` in the stack task directory.

The semantic-pattern table is integrated and accepted as a bounded semantic IR
slice. Parent review reproduced and rejected unknown-guard proofs and stale
rule-policy cache reuse before the corrections. The checked action now requires
the proven guard bit, and native cache configuration derives from the canonical
typed rule policy. Final production controls prove same-policy cache hits,
enabled/disabled/enabled behavior, unknown-name refusal and unknown-bit forgery
refusal. The configured static cohort passed 168 tests. Scoped lint, contextual
typing, startup architecture and component catalog checks passed; ownership
checking retains three independently baseline-confirmed policy violations.
Receipt: `.cache/devin-prompts/semantic-patterns-20261016/parent-review.json`.

The stack-coordinate slice is integrated with independently retained callee-body
SP evidence and all seven coordinate slots. A plain RET callee which removes an
argument now reports the Unicorn-confirmed +2 call delta, and Alias restores the
correct caller SP. A nonadjacent PUSH is retained as unknown argument extent,
rather than falsely described as empty. Present invalid coordinates cannot
silently fall back to a stale legacy delta. Native copying retains the live
immutable source authority, detaches mutable payloads and preserves later
invalidation; source-graph serialization and native equality cover the coordinate
projection. Preimage controls demonstrate that the old copier drops the field
and the old serializer ignores its corruption. Parent production checks passed
239 tests and seven independent controls using the configured Cython lifter and
rebuilt serializer. No whole-function equivalence is claimed. Receipt:
`.cache/devin-prompts/stack-coordinates-20261016/parent-review.json`.

An additional stack-consumer cohort passed 222 tests across invocation transfer,
scalar-affine SP reasoning, native census/equality and JSON graph transport.
One existing counting mock omitted a current production keyword; the mock now
forwards both explicit flags and retains every original assertion. The catalog
now contains 1,726 test modules; three previously reproduced ownership-policy
violations remain outside the changed slice.

Native allocation integration check (2026-10-16): 42 focused tests and nine
independent native controls passed. `quality-hard` exits 2 with the same 68
MyPy diagnostics as its saved baseline (path, message and multiplicity).
`quality-fast` also exits 2 in its broader typing scope; the earlier fast
run stopped at duplicate-module collection and is not a comparable full
typing baseline. Full pipeline acceptance remains open. Detailed receipts
and logs: `.cache/devin-prompts/allocation-restart-20261016/parent-review.json`.

The subsequent full pipeline run completed with 2/9 lanes passed and 7/9
failed. Its completed unit lane reported 15,856 passed, 329 failed and 71
errors; compared with the saved unit baseline, 47 failure nodes disappeared
and 14 appeared. Eight new GNU make failures were caused by readonly `/tmp`;
the entire official GNU lane passes all 43 tests with a writable repository
`TMPDIR`. The ordinary zero-argument call test now supplies real caller and
callee bytes and retains a separate missing-caller refusal control (20 tests
pass). Five new toolchain failures do not reproduce alone or within their
full modules; the full-suite interaction remains unresolved. These checks
do not establish broad semantic acceptance. Receipts are stored beside the
native allocation review in `parent-root-pipeline-comparison.json` and
`parent-new-failure-classification.json`.


### Optional-cache integration repair (2026-10-19)

Both production PAT/bundle readers now decode historical serialized parser
identities through `tools/signatures/pickle_cache.py`, without root import
aliases. Missing files remain cache misses; known IO/format/class failures are
diagnosed. Unexpected object-construction errors propagate. Decoder source
changes invalidate the PAT and match-cache fingerprints. Signature data remains
optional naming evidence and grants no semantic authority.

Before repair, 17 focused reader checks failed. The complete signatures and
compiler-id test directories now report 129 passed and 3 skipped (pinned
fixtures unavailable). Iteration lint, four-owner MyPy, startup architecture and
scoped Vulture pass; the decoder alone passes Pyright. Four-owner Pyright still
reports two diagnostics in the parser (optional extension import and optional
tuple entries). Basta reports 26 findings and exits zero.

Evidence: `.cache/devin-prompts/function-readiness-20261016/parent-signature-readers-review.json`
and the matching red/complete test logs and JUnit receipt. This repairs an
integration failure only; all six original areas and broad pipeline/native SP
acceptance remain open under their existing obligations.


### General-register stack-coordinate propagation (2026-10-19)

The shared Alias snapshot owner now retains exact live word-register copies of
entry-SP coordinates. The canonical stack must-state carries them between
blocks; joins require agreement on every predecessor. Partial/wide/decorated
writes and unknown external effects invalidate the relevant live information.
Immutable temporary captures remain distinct. No second stack solver, call
name recognition, segment flattening or rewrite repair was introduced.

Before the change, eight focused binary/execution checks failed. Current
focused acceptance reports 211 passed with no skips; four additional new
generated-C cases pass with mandatory whole-tail validation, exact call counts,
and both zero and nonzero upper ESP. Independent Unicorn checks include word-SP
underflow. The new numeric-return census closes at 1/1/1/1/0
(raw/normalized/classified/materialized/failure). C sources, harnesses, binaries
and typed source/tail evidence are archived. Production fingerprints stayed
identical during the runs.

Iteration lint, isolated MyPy and Pyright on the three owning modules pass.
Contextual MyPy still reports the scalar-instruction-effects return annotation
error. `quality-fast` stops in linters with 775 repository MyPy diagnostics;
comparison against the prior 778-diagnostic gate finds zero new diagnostics and
three removed. The changed Alias modules have no diagnostics in that gate.

Evidence: `.cache/devin-prompts/function-readiness-20261016/parent-affine-gp-stack-review.json`.
This is scoped acceptance, not completion of call-stack accounting or the other
five areas. The actual TYPES/add_sc CLI still exits 4. Its callee's conditional
control scope, publication refusals and input-dependent SP transfer remain
unproven. The subsequent full pipeline exited 2: five lanes passed and four
failed. Its sealed receipt is
`.cache/devin-prompts/function-readiness-20261016/parent-affine-gp-stack-pipeline.summary.json`;
that run predates the comparison changes below.

### Complete output comparison within the existing deadline (2026-10-19)

The final SSA comparison now discharges only output inequalities that exact Z3
simplification reduces to false. It retains all unresolved observations, the
complete caller domain, independent output queries and the original absolute
deadline. Unchanged outputs no longer spend solver queries or copy the same
assertions repeatedly. Solver Boolean results and array sorts have explicit
boundary checks; no type suppressions or proof assumptions were added.

The new unchanged-output regression fails before the change. Both independent
controls for a changed final output and the original caller domain pass before
and after it. Final acceptance is 197 passed, no failures or skips, with two
workers and the configured Cython source-graph backend. This includes all six
new failing nodes from the preceding full-pipeline comparison, plus the complete
loop/register/narrowing suites and output-lemma/scalar controls. Ruff, the
type/doc/access ratchet, scoped MyPy, Pyright and diff checks pass. All 2192
source/compiled files in the acceptance fingerprint remained unchanged.

An additional eight-case artifact replay passes and preserves two successful
constant-invariant proofs and six deliberate refusals. Both positive censuses
close at 4/4/4/4/0. The original 5000 ms comparison budgets remain unchanged.
The positive pair changes from two failures in 20.17 seconds to two passes in
3.20 seconds; the four-module run changes from 139 passes/two failures in
467.40 seconds to 141 passes in 271.35 seconds. These are individual observed
runs, not a general throughput guarantee.

Evidence, the authenticated owner delta, complete final logs/JUnit, source
fingerprints and eight unmodified result artifacts are indexed in
`.cache/devin-prompts/function-readiness-20261016/parent-output-tautology-review.json`.
This removes a measured acceptance bottleneck. All six areas retain their
existing whole-function/native and broad integration obligations; the real
dynamic-SP function remains unresolved and no function-fixed claim is made.

### Rewrite publication at actual producer completion (2026-10-19)

Inner cleanup completion no longer publishes a snapshot while its outer
producer still owns naming, regeneration and validation. It explicitly requests
completion instead. Successful producer exit checks the identical consumed
Structuring record and its current prerequisites, then snapshots the actual
final AST. Exceptions discard the request; duplicate, foreign or inherited
producer authority refuses. A standalone completion still records its actual
output immediately. Later output mutation remains stale.

Three regressions fail before the change. Final configured-backend acceptance
reports 156 passed with no failures or skips across lifecycle, native CALL,
actual AST, observation-scope, cache and Structuring controls. Nine completion
controls cover late naming, later mutation, outer failure, changed/replaced
inputs, duplicate requests, inherited processes and foreign identities. Iteration
lint, scoped MyPy, readiness-owner Pyright and diff checks pass. The 2192-file
source/compiled fingerprint is unchanged across acceptance.

The actual TYPES/add_sc CLI still exits 4 and emits unchanged C. Instrumented
canonical AST observations retain unchanged producer identities and run inside
the analysis worker. Delayed publication removes the naming drift, but later
CLI replay still changes argument storage widths from two bytes to one and
assigns types after Rewrite. The live-output refusal remains correct. Moving
that semantic materialization to its owning stage and independently proving
physical SP/register call inputs remain open; this is not a function fix.

Authenticated owner deltas, before/after test receipts, binary/source hashes,
ordinary CLI output and diagnostic snapshots are indexed in
`.cache/devin-prompts/function-readiness-20261016/parent-rewrite-completion-review.json`.
The six-area scope and all remaining broad integration/native obligations are
unchanged.

### Typed argument value views inside ABI slots (2026-10-19)

Positive-BP plans now distinguish the physical slot stride from the size of an
already typed body value. Replaying a word-slot plan preserves a byte-valued
`SimTypeChar` variable instead of overwriting its size with ABI padding. This
preserves stack coordinates and subsequent argument offsets. Explicit wide-body
evidence supersedes the narrow view; a view outside its slot produces typed
refusal. Mutating reused argument fields also records the change before mutation.

The corrected regression fixture fails before this change for signed and
unsigned bytes (`size=2`, expected `1`), with both word controls passing.
Afterward, 110 focused tests pass. Two missing-factory fixture failures reproduce
on the unchanged owners and are explicitly deselected in the final run.
Iteration lint, scoped MyPy and diff checks pass. Evidence and the owner delta
are indexed in
`.cache/devin-prompts/function-readiness-20261016/parent-argument-view-review.json`.

The ordinary TYPES/add_sc CLI still exits 4 with stale Rewrite evidence and an
unproved stack call input. This change does not establish whole-function
equivalence or a passing broad pipeline. The earlier width-reset observation
is not considered fully resolved by these focused tests. On the user's explicit
instruction to finish the current task and stop, work pauses here; the six-area
objective and remaining native/integration obligations stay open.

### Resumed native observation (2026-10-20)

The user resumed the full objective. Fresh observations of the unchanged
production code confirm that both argument storage sizes remain one byte
through Types/Lowering, Structuring, Rewrite and CLI replay on TYPES/add_sc.
The earlier byte-to-word reset is no longer observed. Producer identities are
unchanged, and the 2192-file source/compiled fingerprint is identical before
and after this investigation.

The remaining stale Rewrite refusal has a different cause: CLI
`_run_evidence_dce_pass` invokes the owned DCE walker after Rewrite publication.
It converts an assignment of a call result into a standalone expression and
removes its unused local. The canonical AST comparison records 46 differences;
these are not evidence of argument-width drift. Whole-tail validation had
already rejected the preceding postprocess output for a missing physical stack
input. Re-publishing the later AST would not establish semantic equivalence.

A serial native run observes the typed failure chain for callsite `0x10016`:
`CalleeStackCallFailure8616.BOUNDARY_MISSING` →
`CallStackPositionRefusal8616.UNPROVEN_EFFECT` →
`CallStackInputFailure8616.POSITION_UNPROVEN`. The lowerer records one raw fact,
zero classified/materialized facts and one refusal. The ordinary execution
still exits 4. A concurrently instrumented run timed out; it is retained as a
timeout, not counted as semantic acceptance, and was retried serially without
raising the timeout.

Fresh invocation-bound intake exposes 42 callee blocks but refuses raw
publication with six conditional control obligations. The next integration
point is the existing scoped-control machinery, including
`prove_scoped_control_obligations_8616`. Its independent invocation-domain
requirement must be preserved: neither the call-frame premise nor the proof
itself grants an invocation scope, and projected artifacts must not enter the
context-free registry. Stack effects still require Alias proof over the
authenticated consuming scope. No conditional fact is promoted to universal
callee behavior by this investigation.

Receipts and next-action evidence are indexed in
`.cache/devin-prompts/function-readiness-20261016/parent-resumed-native-review.json`.
No production module changed in this resumed investigation. The six-area goal
remains active and incomplete.

### Invocation-source check and complete focused acceptance (2026-10-20)

The actual MZ project installs a header-authenticated invocation source with
eleven indexed calls into the selected callee. Availability of that source
does not establish a usable scope for every call. The selected caller's raw
artifact publishes successfully, but its invocation-premise resolver returns
no domain. An identity-preserving trace follows the dependency to
`declared_service_unproven` in the startup path; earlier raw attempts also
record `coverage_unbound`. No service effect, GP register value or consuming
scope has been invented to bypass those refusals. The scoped-control route
therefore cannot yet supply the required stack proof for this call.

Two width-contract tests previously excluded from focused acceptance now
provide the decoder interface that their test objects omitted. Their decoder
returns no instructions, so it supplies no callee-body evidence. Before this
fixture correction the module has two failures and two passes; afterward the
complete ten-module argument/prototype suite reports **112 passed with no
deselections**. Iteration lint passes. Production exception handling and proof
requirements are unchanged. Receipts and the reviewed test snapshot are indexed
in `parent-width-fixture-review.json` in the existing evidence directory.

The required `make test-pipeline` was launched with two pytest workers and two
compiler workers to refresh integration evidence after the accepted changes.
Its live output is `.cache/agent-tool-output/latest-resumed-pipeline.log`;
terminal output is retained as `parent-resumed-pipeline.log` with an exit receipt.
The previous pipeline summary was preserved separately. A running or partially
passing pipeline is not acceptance of the full goal; inspect its terminal
summary and every failing lane before making that claim.


### Exact invocation-context blocker (2026-10-20)

A fresh identity-preserving native/Cython observation of the actual TYPES.EXE
caller at 0x10010 reproduces an unavailable invocation scope. The first service
refusal occurs at instruction 0x103aa in the startup artifact at 0x103a8:
INT 21h, AH=30h, AL unknown. The path has proven CS=0x1000, SS=0x10cc and
SP=0x800, but its environment is None, its declared-service relation count is
zero, and both environment digest and declared arena are absent.

The refusal is emitted by `_cross_authenticated_declared_service_8616` before
service binding because AL is unknown. Even proving AL would not supply the
missing environment or service relation. The canonical version-response
contract admits AL=00 only. Do not synthesize AL=0, invent a DOS environment,
relax service authentication, or republish stale Rewrite readiness to bypass
this refusal. The next investigation must distinguish local callee/callsite
proofs from proofs that genuinely require an independently supplied execution
environment; a scoped projection cannot become an unconditional boundary.

Evidence: `.cache/devin-prompts/function-readiness-20261016/parent-current-service-refusal-summary.json`,
`parent-current-service-refusal-trace.jsonl`, and
`parent-current-service-refusal-run.log`/`.exit` in that directory. Probe exit 0,
50 observed returns, six propagated service refusals, function identities
unchanged. This is diagnostic evidence, not native function acceptance;
add_sc and broad integration acceptance remain open.


### Layer inventory repair and remaining structural failure (2026-10-20)

Parent repaired tests/cli/test_x86_16_layer_boundaries.py inventory: scan all inertia and tools production paths (retain historical roots if present), exclude tests. Fresh targeted baseline2failed/1passed ->3passed. IMPORTANT correction to earlier handoff: acceptance_scorecard IS production-used from tools/compiler_toolchain/build_msc6_examples.py and tools/dev/benchmark_optimization_quality_guard.py; earlier searches omitted tools. Production LayerModuleRecord now correctly marks it PRODUCTION_WIRED with an accurate note; no gratuitous imports or runtime effects added.

Remaining migration checks now assert that eleven removed forwarding files stay absent, retain the original no-owned-implementation check for the still-existing alias/stack_lowering.py bridge, use canonical scorecard name, and construct module paths from the repository root. Full module baseline6failed/9passed ->1failed/22passed. lint-iteration and scoped MyPy pass. Remaining failure is real/pre-existing:10 CLI-helper imports from lower layers. Do NOT weaken that test. Details .cache/agent-tool-output/latest-layer-import-violations.log and latest-layer-import-symbols.log. Helpers cli_access_profiles.py381lines and cli_storage_objects.py137lines currently own definitions in CLI; cli_c_ast_rewrites.py also consumed by postprocess. Moving these owners needs a separate bounded migration and consumer/evidence review, not alias reintroduction.



### Canonical access-profile and storage-object owners (2026-10-20)

Moved the two pure contract/helper modules out of CLI into Types/lowering;
updated production imports, test imports, source inventories, cache provenance,
and CLI facade resolution. No historical forwarding files were introduced.
The structured bucket decoder now returns its validated count as part of its
typed result, preserving the old accepted/rejected inputs (45 differential
cases against the retained preimage).

Pre-move focused baseline:17 passed. Final eleven-module regression:143 passed.
Iteration lint passes for all changed Python files and the count followup;
scoped MyPy passes for both canonical owners. Canonical facade class/function
identity passes with lazy imports enabled and disabled. Both new source paths
are present in decompilation cache provenance. An unchanged Any-return issue
in the CLI widening-proof compatibility helper remains; whole-CLI typing is
not claimed green. Retained evidence and final file hashes are in
`.cache/devin-prompts/profile-owner-migration-20261020/parent-review.json`.

The guarded-layer audit improves from10 forbidden imports to5, all remaining
in postprocess consumers of CLI AST adapters. Full architecture and pipeline
acceptance remain open. This relocation is not a new whole-function semantic
acceptance claim.

The independent local-call investigation is now reproduced by the parent:
15 probe steps agree, scoped obligations close with counts2/2/2/2/0, conditional
coverage is accepted and context-free coverage remains refused. The current
SP consumer still rejects that scoped coverage. The fixture has an explicit
declared environment, SS/SP and return bytes; it supplies no missing evidence
for actual TYPES.EXE. See
`.cache/devin-prompts/local-call-stack-proof-20261020/parent-review.json`.


Scoped returning-stack acceptance and integration obligations are specified in
[scoped-call-stack-effects.md](scoped-call-stack-effects.md). In particular,
universal coverage does not authenticate an arbitrary offered scope; conditional
entry-state effects require a separate binding check and cannot be installed in
old context-free scalar carriers.

### Scoped stack transport and flag-preservation checkpoint (2026-10-20)

Scoped Alias and Semantics proofs are retained through IR/SSA without filling
universal SP fields. Parent review reproduced and fixed coordinate/frame/source
forgery at accessor time and the omitted native effect-schema field. The final
focused native transport/source-binding set passed137 tests; catalog tests
passed71. All four scoped implementation sources participate in the live cache
fingerprint. Evidence and source hashes:
`.cache/devin-prompts/scoped-stack-transport-20261020/parent-review.json`.

A separate P0 flag-preservation repair retains decoded REP metadata, so repeated
comparisons with possible zero count do not count as definite overwrites.
Native decoded lookahead now respects max_inst. The failure was reproduced on
preimages; the resolved REP/SCAS xfail was removed. All140 selected flag, CFG,
lifter and binary-comparison controls pass on both Python and rebuilt Cython.
Evidence: `.cache/devin-prompts/repeat-flag-preservation-20261020/parent-review.json`.

Caller Alias consumption is delegated under bounded ownership. Source review
also identifies a downstream gap: call-input plans/markers currently store
plain positions and validation replays only the universal producer. Scoped
integration must preserve authority through those owners, not merely copy an
offset. Neither this checkpoint nor focused success establishes full pipeline,
whole-function acceptance or a valid entry environment for the real scalar
example. The original six-area acceptance scope is unchanged.
