# Bounded Parity Evidence Audit

September 20, 2026. This is a requirement-by-requirement working audit, not
closure of Steps 10-12. Scope and DoD remain in
[remaining-plan-acceptance.md](remaining-plan-acceptance.md).
Graph indexing and coverage calls failed with `Transport closed`; the evidence
below comes from direct source/test reads and saved generated artifacts.

## Current Positive Cases

Inspected `.cache/gp-word-complete-functions` from the accepted 20-function run.
That run passed semantic validation, compilation and all 19 behavior harnesses.
Those gates establish output behavior, not completeness of every mechanism.

| Requirement | Current generated evidence | Remaining proof obligation |
| --- | --- | --- |
| 7.1 Sleep | `10f38`: wide clock-plus-duration deadline and signed wide poll comparison | Trace changed-input scheduling and exact carrier provenance through producers and consumers |
| 7.1 ReInitBars | `10678`: one clock result assigned to `g_0BA6` | Verify the live wide-store proof and closed counters, not only the rendered assignment |
| 7.1 Beep | `10e70`: division, low/high quotient bytes, minimum duration, Sleep, speaker restoration | Preserve binary divisor overwrite; verify boundary-driven recovery and negative provenance/CFG cases |
| 7.2 recursive contracts | Existing SCC tests retain opposite argument orders, deterministic SCC results and incomplete-census refusal | Capture live accepted contract/caller coverage for the selected inventory and verify clean-worker transport |
| 7.3 InitBars | `10560`: `unsigned short local_5a[43]`, initialization and random replacement accesses | Link the bounded random index to the accepted local-array contract; the inspected allocation/stride test alone does not prove this |
| 7.3 independent globals | Separate `g_08F0[]` and `g_0B4C[]`, each with two byte fields | Verify live alias/range evidence and all required refusal cases |
| 7.3 Swaps | `107b8`: typed two-byte temporary and three object assignments | Trace the accepted copy/storage contract through definition and callers |
| 7.3 ReInitBars | `10678`: `g_0B4C[local_2] = g_08F0[local_2]` | Verify distinct bases survive the copy proof and transport |

Do not reimplement these visible features merely because the old plan says
pending. Conversely, do not mark the mechanism complete from this table.

## Reviewed Owners And Controls

- `widening/carry_borrow_pipeline.py` closes Semantics, Alias, value-Widening
  and destination/storage-Widening evidence. It reuses an artifact when the SSA
  and stack-Alias objects are identical. This is not yet evidence of the required
  affected-candidate scheduling after value/call-summary changes.
- `test_x86_16_indexed_global_object_ranges.py` contains dynamic-bound,
  segment, stride, overlap, uncovered-access and copy-endpoint refusals.
  Its segment control preserves the independently valid DS candidate.
- `test_x86_16_stack_aggregate_objects.py` proves the 86-byte/43-word local
  extent from allocation, index scale and scalar boundary, and rejects missing
  scale. A separate live bounded-index proof still needs tracing.
- `interprocedural_storage_pipeline.py` collects function inputs/returns;
  `interprocedural_storage_solver.py` resolves retained SCC trials;
  `interprocedural_storage_transaction.py` publishes one atomic payload.
- Storage trial/consumer tests cover recursive argument order, incomplete
  census, pointer/value conflicts, missing callsite bindings and shared layouts.
  These synthetic controls do not establish full live inventory coverage.

Transport trace for the next 7.2 investigation:
`inertia_decompiler/serial_clean_worker_evidence.py` schema 7 carries caller-return
evidence, callsite censuses, program summaries, pointer evidence and global
layout/range/source evidence. Its explicit write/read/hydrate fields do not
carry `ProgramStorageResolution8616`. The inspected in-process transfer owner,
`project_evidence_transport.py`, likewise copies the evidence inputs rather
than that accepted payload. This does not itself prove a runtime defect:
workers may reconstruct equivalent contracts from those inputs. Next compare
their actual accepted contracts and census against the parent/other workers,
including recursive edges, before deciding whether a new codec or an earlier
publication boundary is necessary. Do not blindly copy project-specific
addresses across rebased slices or create a duplicate solver.

## Step 11 Whole-Inventory Comparison

Compared the bodies of all 20 individual C exports in
`.cache/step9-final-sortd-functions` against `.cache/storage-refresh-functions`.
Inspected every body diff: all changes are the accepted coherent SI/DI word
assignments and three signed-conversion projections (one in InsertionSort,
two in QuickSort). No call, argument, branch, loop or memory operation was
otherwise added or removed. This comparison excludes declarations/runtime
headers; their changed ABI is covered by the dedicated cross-translation-unit,
mixed-width, compiled-C and MS C tests, not by text equality.

Residual readability debt remains visible: split saved-register byte locals,
masked word reads from coherent full lanes, segmented global accesses mixed
with named objects, and QuickSort's duplicated pivot-byte stores. Swaps already
has word saved-register locals; the other byte forms must not be joined without
the exact stack/storage/use proof. The failed saved-register projection and its
uninitialized-DI regression remain documented in the execution ledger; do not
retry shape-only joining. This comparison closes the all-body comparison item,
not Task 5's remaining proof/projection obligations.

## Demonstrated Lifecycle Defect

An accepted contract survived a later incomplete collection. The lifecycle
returned a refusal but left the old accepted project contract available to
prototype consumers. Reproduced for incomplete inputs, unavailable return
evidence and refused return collection: all three new tests failed before the
fix (`.cache/storage-refresh-before.log`).

The Types/Lowering publication boundary now raises `PipelineHardError` before
consumer execution when a refused refresh would reuse an accepted contract.
It reports function address, layer and the complete typed refusal result. It
does not manufacture replacement arguments, erase the atomic payload or turn
first-time unknown evidence into success. Complete refreshed trials still use
the existing solver, including its typed conflict results.

Regression controls exercise direct publication and the production consumer
path. Existing first-time refusal and unchanged-success replay tests remain.
The already enrolled pipeline/ownership test module contains these controls;
no extra slow binary test was introduced. Final gate results are recorded in
[remaining-plan-execution.md](remaining-plan-execution.md).

## Next Order

1. Contract refresh, caller ownership and NOP-entry identity are accepted slices.
   Discarded-return and caller-boundary transport now also resolve accepted
   Swaps/QuickSort contracts in normal workers. The fallback caller-range
   summed-size defect also passes its final regression gates.
2. Finish the remaining live inventory/consumer audit for 7.2, including exact
   reaching arguments and closed-census refusal coverage. Do not repeat the
   completed worker-transport experiment or add an accepted-payload codec.
3. Trace 7.1 changed-input recovery and 7.3 bounded-index/copy evidence against
   the positive cases above; implement demonstrated missing mechanisms.
4. Finish Step 11's remaining proof/projection obligations and evidence-backed
   disposition of saved-register byte locals, then perform bounded Step 10
   measurements. The all-body comparison above is complete for this source state.

No numerical completion percentage follows from this partial audit.

### Next Widening Probe

Update: [the live wide-store provenance checkpoint](step12-wide-store-provenance.md)
confirms Sleep materialization and ReInitBars' separate wide-store path, and
records a call-placement repair with near/linear target coherence. Complete
typed store provenance before affected-candidate scheduling; neither Task 7.1
nor Steps 10-12 are closed.

Bounded source follow-up after the worker repair: the inspected
`widening/carry_borrow_pipeline.py` rebuilds Semantics, Alias, value Widening,
destination Alias and storage Widening together. Its apply function reuses the
artifact only when both source SSA and stack-Alias object identities match.
`decompiler_structuring_stage.py` invokes this owner after call-stack effects
and stack Alias, before memory/object Lowering. This is evidence of ordered
projection and reuse, not yet the requested affected-candidate scheduling.

Next action: observe input identities, candidate dependencies and closed counters
for Sleep, ReInitBars and Beep at their actual evidence-producing boundaries.
Exercise a real changed value/call-summary input, identify which candidates
change, and verify consumers receive refreshed facts. Do not infer stale-cache
failure from object-identity caching alone, or implement another solver without
showing the existing owners cannot provide the required scheduling. This source
inspection is bounded; graph coverage was unavailable and no whole-repository
absence claim is made.

## Live Caller-Owner Probe

The next audit used a separate result-cache namespace and the documented
in-process/thread diagnostic settings. The publication hook executed in the
analysis process; `STORAGE_AUDIT` records are in
`.cache/storage-live-{swaps,quicksort}.log`. Both generated functions passed
tail validation before this change, but neither reached an accepted unified
storage contract:

- Swaps: input census closed for all nine callsites. Return collection refused
  at memory live-outs because caller SSA was requested from the isolated callee
  project, which has no caller function (`function_not_found`).
- QuickSort: input census closed for five callsites, including four recursive
  edges. It hit the same wrong-project memory live-out lookup for RunMenu.

`interprocedural_storage_live_out.py` now selects the caller's project and exact
function boundary through the existing census-owned caller-context resolver.
The same resolver serves return-use and memory-effect consumers. Condition
facts use that selected project and cache separately for equal addresses in
distinct projects. Conflicting contexts explicitly refuse before SSA consumers.
No census/SSA reconstruction, alias inference or address repair was added to
CLI or Rewrite. Per-callsite collection remains in the existing live-out flow
owner; typed refusal construction remains with its contracts.

Positive isolated-project and conflicting-context tests failed before the fix
and pass afterward. Existing same-project and no-context paths still pass.
The changed caller-context test module is now explicitly in the default
pipeline. A cache test additionally prevents equal-address cross-project reuse.

Live after-probes (`.cache/storage-caller-{swaps,quicksort}.log`) pass validation
and no longer report unavailable caller SSA. Swaps retains its 18 proven pointer
effects through memory collection. The next real failure is **caller identity
disagreement** between return-use facts and the exact callsite census; it is
still refused, not hidden. Unified contracts for these functions are not done.

The source trace explains this disagreement:
`cli_function_discovery.py::_pre_entry_source_function_ranges_8616` starts
decoding at the first binary NOP-padding alias. The return-use program's direct
call index retains that range start, and
`callsite_summary.py::collect_caller_return_use_evidence_8616` passes it as the
caller's identity. Input collection instead consumes the census's recovered
function entry. For example, recursive QuickSort return-use facts name
`0x10cd4`, while input trials identify `0x10ce0`.

Next required mechanism: one Frontend-owned, binary-proven entry identity with
explicit decode-range/entry-alias evidence, consumed consistently by both
censuses. Verify the bytes and both producer paths before implementation; never
replace caller addresses merely by proximity or matching callsites. Distinct
entries with non-padding effects must remain distinct, and malformed/conflicting
alias evidence must refuse. Do this before designing accepted-contract worker
transport; copying the current conflicting identities would preserve the bug.

Binary verification through the MZ loader confirms these exact prefixes:
`0x108c0..0x108d0` is 16 NOP bytes, `0x10cd4..0x10ce0` is 12 NOP bytes,
and `0x102cc..0x102e0` is 20 NOP bytes. Each selected recovered entry starts
`55 8b ec b8`. These are diagnostic examples, never production allowlists or
permission to assume every entry has this prologue.

### Canonical Caller Identity Acceptance

Reason: two independently valid evidence streams cannot form one storage
contract while one identifies callers by decode-range starts and the other by
recovered entries.

DoD: a single Frontend owner records the independently established entry and
proven side-effect-free padding aliases separately from decoding bounds. Both
input and return-use inventories consume that identity, preserve exact callsites
and recursive edges, and survive clean-worker transport. Swaps' nine callsites
and QuickSort's five callsites must reach accepted unified contracts with closed
evidence; the same 20-function semantic/compile/behavior and routine pipeline
gates remain mandatory. Any additional positive-case refusal stays open work.

Definition of failure: guessing by proximity/prologue appearance, treating
non-NOP bytes or side-effecting alternative entries as equivalent, losing a
recursive call or its argument order, overwriting a typed conflict, or repairing
caller identities in Rewrite/CLI export. Negative controls must preserve
distinct meaningful entries and reject conflicting alias evidence.

Existing-owner caution: `callee_range_callsite_facts.py` already consumes
`frontend_function_boundary_index.py` and
`analysis_helpers.py::canonicalize_x86_16_padding_call_target_8616` for direct
targets. Do not invent a parallel inventory. The latter helper accepts 0x00 and
0xcc as padding as well as NOP: that discovery heuristic is **not** proof that
executing those bytes is side-effect-free. The new entry-equivalence proof must
not inherit that assumption. Check which supplied range inventory produced each
live caller identity before choosing the shared producer path.

Caller-owner slice acceptance: all 20 functions still validate, compile without
warnings and pass all 19 behavior cases; exported C is byte-identical to the
previous checkpoint. Default pipeline: 5,963 pytest passes in 298.33s, all four
QuickC fixtures and seven MS C round trips pass. This closes the wrong-project
lookup repair only. See the execution ledger for exact artifacts and remaining
global lint debt.

## Binary-Proven Caller Entry Identity

The next Frontend slice introduces `CallerEntryIdentity8616`: exact decoding
bounds, a canonical entry, and the contiguous 0x90 prefix proving equivalence.
Both decoded return-use indexing and argument-range collection consume this
owner. No prologue recognition, alignment assumption, 0x00/0xcc padding, source
labels or address allowlists establish identity. Instructions and exact callsite
coordinates remain unchanged. NOP-only, truncated and wrapping ranges do not
establish new aliases; malformed and conflicting witnesses refuse explicitly.

Return-use lookup, recursive-cycle checks and transitive wrapper traversal now
use the same target identity. A new negative test also exposed a missing-range
bug: readable callers could incorrectly prove that all calls discard a result
when another range could not be read. `range_census_complete` now prevents that
absence claim and returns UNKNOWN instead. This is distinct from closed
accounting, which may legitimately contain refusals.

Before/after evidence is in `.cache/caller-entry-before.log` (three failures),
`caller-entry-recursive-before.log` (two failures), and
`caller-entry-incomplete-before.log` (one failure). The focused changed-surface
gate subsequently passes 335 tests, plus scoped Ruff/MyPy/docs and startup
architecture. The separate callsite-summary MyPy and changed-code type/doc
ratchets pass; its pre-existing whole-file complexity warnings remain open.

Live probes, using a fresh result-cache namespace:
- `.cache/storage-entry-swaps.log`: all nine input callsites and 27 return/memory
  facts close; the unified contract is `published_accepted` and replay is
  `unchanged_accepted`. The earlier eight identity mismatches are gone.
- `.cache/storage-entry-quicksort.log`: all five input and return callsites
  close, including recursive identities. The next solver refusal is
  `passthrough_output_unresolved`, not a caller mismatch. It remains visible.
- Both focused functions pass tail validation. Generated C and behavior gates
  do not by themselves prove complete worker publication; final slice results
  are recorded in the execution ledger.

### Next: Explicit Discarded-Return Evidence

Source trace: `interprocedural_storage_return_trial_collection.py` counts an
UNUSED caller fact but appends the unchanged input callsite. Thus the shared
trial record does not distinguish a proven discarded result from absent return
collection. `FunctionStorageTrialJoin8616.direct_output_seed` intentionally
requires a non-empty output tuple, and recursive pass-through resolution refuses
without that seed. QuickSort is therefore still a required positive case.

Reason: resolve recursive procedures whose independent callers provably discard
their result without treating missing output evidence as a void signature.
DoD: retain explicit typed discarded-return evidence through collection,
joining, SCC resolution, publication and transport. Only a closed census with
appropriate independent evidence may establish an empty output contract;
recursive-only/no-seed, unknown, inconsistent and value-observing controls must
remain conservative. Prove live QuickSort acceptance with all five callsites
and unchanged argument order, then run the bounded acceptance gates.
Failure: merely changing truthiness checks to accept `()`, assuming absence is
UNUSED, discarding a live return, bypassing the existing solver, or claiming
the QuickSort contract accepted while its typed refusal remains.

This is the next 7.2 blocker; the canonical-entry mechanism is not closure of
all unified-contract or Step 12 obligations. Worker reconstruction of accepted
contracts and the remaining 7.1/7.3 obligations stay open.

## Explicit Discard Proof And Worker Findings

The discarded-return mechanism is implemented in Types/Lowering. Collection
retains `DiscardedReturnTrial8616` with the original typed observation and exact
callee identity; contradictory UNUSED/value-use observations refuse at the
collection boundary. The solver counts these proofs, preserves them in accepted
bindings, and permits an empty SCC seed only for a closed census with an
independent discarded-result witness. Missing, unknown, mismatched, recursive-
only and inconsistent cases still refuse. A value-observing caller keeps a
non-empty output even if another caller discards its result.

The atomic transaction checks proof retention and rejects forged empty seeds
before replacing the previous project payload. Positive collection-to-solver,
JSON-evidence reconstruction, lost-proof and corruption tests cover this path.
The new proof owner has typed/doc/lint gates and routine pipeline enrollment.

Live in-process/thread probe `.cache/storage-discard-quicksort.log` now reports
`published_accepted` and `unchanged_accepted`, five input and five return facts,
zero failures, and `validation=passed`. Its generated C differs from the prior
direct probe only in cast placement; no calls or control-flow operations change.
This result is **not yet normal clean-worker acceptance**.

A separate normal multi-process run installed a diagnostic publication observer
in actual clean workers, with an independent result-cache namespace. Per-process
ready records and `worker_evidence=true` prove that the observations came from
workers using transported parent evidence. Artifacts:
`.cache/storage-discard-clean-probe/*.jsonl`, `storage-discard-clean.{c,log}`;
the temporary observer is `.cache/storage_worker_probe/sitecustomize.py`.

Actual worker results:
- QuickSort: four of five input callsites materialize. RunMenu's call at
  `0x103bf`, caller `0x102e0`, refuses `caller_ssa_unavailable/function_not_found`.
- Swaps: one of nine input callsites materializes; the other eight fail with
  the same missing caller SSA. Both unified contracts remain `input_refused`.
- The normal whole-binary acceptance run still validates all 20 functions and
  emits byte-identical C through existing paths. Passing output gates therefore
  does not establish unified storage-contract parity. Do not hide these refusals.

### Next: Clean-Worker Caller Boundaries

Source-confirmed root cause: `callee_callsite_codec.py::_fact_record_8616`
serializes owner/address/summary but no caller boundary;
`_fact_from_record_8616` explicitly assigns `caller_function=None`.
`serial_clean_worker_evidence.py` schema 7 transports these records unchanged.
`interprocedural_storage_trial_collection.py` passes that missing function to
the semantic SSA registry. The worker's KB has its selected callee but not the
other callers. In-process ownership fixes cannot recreate data lost in JSON.

Reason: the production worker path must consume the same proven caller inputs
and return/memory effects as the accepted in-process path.
DoD: retain or reconstruct caller boundaries through a Frontend-owned, typed,
binary-validated contract; preserve exact entry/range/callsite identities and
evidence ownership across rebasing. Reuse existing Frontend reachability and
boundary/SSA inventories, with bounded reuse rather than a duplicate solver.
Record actual source caller boundary types before choosing the transport
representation. Verify normal workers publish accepted Swaps/QuickSort contracts
with all nine/five callsites, closed counters, matching argument order and the
same semantic/compile/behavior/default-pipeline gates.
Failure: guessing ends from nearby function addresses, trusting an unchecked
`.size`, copying mutable project/CFG objects, reconstructing semantics in CLI,
masking incomplete caller censuses, or accepting stale/mismatched binary evidence.
Include missing/invalid bounds, wrong binary/owner, rebasing and corrupted
callsite controls. JSON round-trip success alone is not sufficient.

Parent-boundary observation (September 20, `storage-boundary-probe.{c,log}`):
all 14 selected Swaps/QuickSort source callsites carry actual
`angr.knowledge_plugins.functions.function.Function` objects, not
`ExactFunctionRangeBoundary8616`. There are eight distinct caller entries;
their block address inventories survive in the parent but not the codec.
The installed angr `Function.size` implementation sums local block sizes.
It is not an address span, so `addr + size` is not an acceptable transported
end bound. The existing fallback in `project_callee_callsite_collection.py`
also uses this expression when no explicit caller ranges exist; audit that
consumer as part of this shared boundary repair, not just the JSON codec.

Implementation constraint: transport validated block extents/entry and binary
identity, then revalidate reachable instructions/edges in the evidence owner.
Reuse the existing Frontend boundary/SSA inventories; do not serialize mutable
angr functions or invent contiguous bounds from aggregate byte counts. Add a
discontiguous-block regression demonstrating why the size shortcut is invalid,
alongside actual fresh-worker accepted-contract checks. Observer code remains
an ignored diagnostic only; no production transport change is claimed yet.

This supersedes the earlier assumption that transported evidence might already
rebuild equivalent accepted contracts. The experiment now disproves that for
the production path. Steps 10-12 remain open until this and their other required
obligations are verified.

## Caller-Boundary Transport Implementation (September 20)

The transport mechanism above is now implemented. Frontend owns typed block
extents and byte digests, validates mapped bytes on the destination, and reuses
closed reachability inventories. Reconstructed blocks may split differently,
but cannot consume bytes in an unwitnessed gap. Callsite codec versioning is
coherent with worker schema 8 and program-callsite cache schema 3. A boundary
is attached only when it proves the specific caller entry and reachable
callsite; unavailable proof remains absent. Malformed or mismatched transported
proof fails explicitly before publication.

The first production trial exposed unreachable catalog callsites. Attaching a
function witness to those callsites was invalid; the producer now checks exact
membership. The decoder's rejection was retained. The failed trial was stopped,
not counted as acceptance. The second trial recovered QuickSort input SSA but
exposed a Semantics adapter that only read mutable angr graphs. A small typed
Frontend-edge adapter now feeds the existing terminal-path proof, with an
AX-clobber negative control. No return semantics were moved to the codec or CLI.

Fresh normal-worker observations in `.cache/storage-boundary-final-probe/`
confirm `published_accepted` and `unchanged_accepted` for both targets:
- QuickSort: five input and five return facts, zero failures.
- Swaps: nine input and 27 return/memory facts, zero failures.
The final normal CLI run exits zero with whole-tail validation clean across all
20 functions (`storage-boundary-final.{c,log}`). This closes the missing-worker-
caller-context defect, not the whole Task 7.2 acceptance inventory.

Focused verification: 24 boundary/codec/SSA/terminal-path tests pass; the scoped
check-files gate passes 100 tests plus Ruff, MyPy, type/doc, architecture and
ownership checks. Standalone typing/docs also pass for the touched legacy
semantic adapter and schema owners. Existing complexity debt still blocks
global quality-fast and whole-file Ruff on the legacy terminal-path owner.
The new owners are enrolled in typed/Ruff and routine pytest gates.

Acceptance export, compilation, behavior and default pipeline all pass:
20 validated exports, zero compiler diagnostics, 19 behavior cases, 6,020
routine pytest cases, four QuickC fixtures and seven MS C round trips. Exact
timing, source identity and lint limitations are in the execution ledger. The optional
raw-transcript behavior invocation failed because normalized stdout already
contains GP runtime union declarations, while the harness forcibly includes
another copy of that runtime header. The first diagnosis that extraction alone
lost a guard was incomplete: stdout's assembled declarations are already
unguarded. Use the existing structured per-function export
gate for acceptance; track transcript-extractor repair separately, not as a
semantic decompiler success or a waived failure.

The fallback caller-range collector now reuses the same Frontend witness rather
than `addr + function.size`. Two before-fix tests demonstrate truncation of
discontiguous code and guessed bounds without any block inventory. A third
test preserves authoritative explicit ranges. The scoped gate passes 103 tests;
20/20 whole-binary validation, zero-diagnostic compilation, 19 behavior cases,
6,023 default pytest cases, four QuickC fixtures and seven MS C round trips pass.
The supplemental scan does
not erase existing catalog call facts when a fallback boundary is unavailable.

Still open: complete the remaining Task 5/7 proof and feature obligations. Graph MCP
and coverage requests failed with Transport closed; the bounded source reads
and executable probes above are the evidence, not an exhaustive graph audit.
