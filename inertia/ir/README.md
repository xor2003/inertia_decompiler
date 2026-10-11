# IR evidence contracts

## Declared entry without a proven premise

`declared_entry_pipeline.py` distinguishes proven conditional entry input from
`UnprovedDeclaredEntry8616`. A valid declaration with unavailable entry proof
retains the authenticated raw IR, raw SSA and unresolved effects; it grants no
pruning, scoped-call enrichment or universal registry publication. The record
type fixes its premise status. Function diagnostics expose that status and the
scoped-view refusal under `x86_16_declared_entry`.

Malformed or changed declarations, native bytes and unreproducible boot evidence
remain errors. Continuing with raw input is not successful semantic validation.
Controls: `tests/ir/test_unproved_declared_entry.py` and the existing declared
entry attachment tests.

## Caller prefix fusion

`real16_fused_caller_prefix.py` transfers only the scalar prefix before the
first CALL while comparing the same rows to freshly imported native IR.
It binds the complete remaining block before the ordinary walker executes
CALL effects. Resumption preserves temporaries, memory, register lanes,
dirty families, direction and the machine-instruction entry snapshot.
Only canonical producers and full-block cutoffs qualify; foreign authority,
partial cutoffs and repeated-instruction geometry retain ordinary binding.
Late native mismatches revoke provisional materializations; resource work
is never rolled back and the shared deadline/work caps remain unchanged.
Controls: `tests/ir/test_fused_caller_prefix.py`.

## Immutable scalar dispatch authority

Static scalar/known-bits/native dispatch owns exact tuples of exact key-handler
pairs, with direct lookup in `frozen_dispatch.py` and no backing dictionary or
derived cache. Fresh fused-callee seals bind each tuple and lookup alias by
identity; replacement revokes fusion and retains ordinary binding. Dictionary
instrumentation is supported only on the ordinary route. Scalar normalization
also captures dictionary key/handler identities so mutable instrumentation
changes invalidate native caches. Tuple immutability freezes membership, not
callable internals; the existing function-identity checks remain mandatory.
Controls include operator escape, foreign-container refusal, changed handlers,
native late-mismatch priority and cache authority mutation.

## Temporary-normalization capture inputs

`real16_edge_feasibility8616.py` finishes a completed refinement round when
newly dead edges change neither the live call cone nor any predecessor meet
inside it. External-edge removal alone requires no further transfer. Internal
edges still trigger refinement even when all blocks survive. Selection consumes
the same deadline/work budget; exhaustion keeps only fully committed evidence.
The first fixpoint, snapshot callbacks and fresh downstream native/effect census
remain mandatory. This is convergence detection, not cached proof or effects.
Controls: `tests/ir/test_refinement_projection_convergence.py`.

`dead_temporary_capture_inputs.py` assigns retained condition operands,
register bindings, producer semantics and logical-memory address payloads to
their original producer blocks. Pending-source keys identify successors, not
producers. Ambiguous bounded ownership retains affected blocks; missing or
foreign ownership retains the entire surface with `UNKNOWN_REFUSE`.

`COMPLETE` establishes only metadata ownership. It does not authorize deletion:
the normalization owner must still prove complete temporary dependencies,
purity and totality. Payload objects remain unchanged; terminal evidence is
validated without inventing value dependencies. Controls live in
`tests/ir/test_dead_temporary_capture_inputs.py` and are enrolled in the
decompiler routine inventory.

`dead_temporary_surface_normalization.py` combines those payloads with live
anchors for the first original IR row at each instruction address. The shared
VEX import calls it after whole-function capture and before block-ownership
finishing; raw native census and ordinary import consume the same normalized
rows. Deadline-expired partial surfaces skip normalization. The block normalizer
in `dead_temporary_normalization.py` removes only uniquely bound dead pure-total
scalar TMP definitions; LOADs, calls, stores, architectural writes and unknown
dependencies remain. Decisions and the five evidence counts are retained in
the imported surface, and ordinary artifact summaries publish the aggregate.
All consumed normalization authorities participate in native-cache producer
binding. These transformations establish no whole-function equivalence verdict.

Predicate result widths come from the owning comparison/Boolean classifiers or
an authenticated scalar conversion to one bit. Only unique preceding TMP
definitions may supply this evidence to a later conversion; byte storage,
literal 0/1 and names never establish a Boolean width. Live conversion chains
and malformed or contradictory reads remain retained.

Dependency closure and totality are separate obligations. An exact unary
computation view exposes its owned operand even when its operation cannot be
proved pure-total by the scalar projection authority. Such a computation and
its producer closure must survive; only unrelated proven dead pure-total
definitions may disappear. Missing or malformed operand structure remains a
whole-block refusal. Names and compatibility expression strings never supply
missing dependencies or authorize deletion.

`vex_bit_source.py` owns `BitSourceProjection8616` and
`project_bit_source_8616`: bounded projection of one selected bit through proven
neutral bitwise operands. It preserves captured reads and refuses unsupported
operators, invalid definitions and exhausted bounds by retaining the original
atom. It does not claim whole-value equivalence.

Consumers include the frontend DF-direction helper. Historical
`angr_platforms.X86_16.ir.vex_bit_source` imports remain exact aliases, including
legacy pickle lookup. The remaining IR modules have not moved yet.

Focused controls:

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tests/ir/test_x86_16_vex_bit_source.py -q --tb=short --durations=5
```

## Raw boot census

The feasibility snapshot walker may omit a discarded block-exit replay only
under fresh canonical producer checks. The repeated-store owner supplies the
structural non-candidate predicate; the invocation owner supplies readonly
LOAD and inert terminal-CALL predicates. Only the exact selected stopping CALL
can be exempt, and a requested pre-CALL cut retains replay. Earlier calls,
branches, unknown effects and foreign memory/STORE/call observers remain
observable. Ordinary fixpoint transfers and native/effect census still execute;
omission publishes no state or proof. Classification consumes one work unit
even when replay is retained. Controls: `tests/ir/test_root_load_snapshot.py`
and `tests/ir/test_root_snapshot_observers.py`.

`real16_boot_entry_link.py` owns `RawBootEntrySurface8616`, an identity-bound
raw artifact/boundary pair. `real16_invocation_domain.py` owns its authenticated
boot census and replay; `entry_domain_call_preservation.py` requests that census
before recursive universal intake. The surface itself grants no proven coverage.
Published invocation records retain typed `entry_call_pool_advice` for replay
scheduling. READ selects independent replay; UNUSED skips a redundant static
eligibility scan; UNKNOWN keeps the charged scan. Advice grants no proof:
shared replay still admits both records, authenticates current inputs and
requires a fresh UNUSED receipt. Fresh READ/UNKNOWN results independently
replay the required record. The advisory field is excluded from semantic replay
equality and authority captures; altered advice cannot authorize stale effects.
Pending startup jumps must resolve to their retained successor under the live
state, and stores, calls and interrupts keep their ordinary proof obligations.
Raw artifacts never enter the universal proven-function registry.
An invocation domain with a retained failure rejects completeness before opening
a replay traversal: reporting an existing refusal must not renew proof budgets.
`raw_boot_blocked_prefix.py` retains an unavoidable, undeclared startup interrupt
only inside the current premise-resolution request. It authenticates native
prefix bytes and rechecks the source, mapped image, architecture, callsite index
and registry before reuse. Changed inputs and new requests retry; retained
failures never grant an invocation domain.

Explicit selectors unsupported by the storage-space model remain unknown;
register defaults or hints must never substitute DS/SS for an explicit CS
selector. The raw STORE census may prove a write span from its authenticated,
already evaluated native address temporary. It retains unknown alias identity,
checks agreement with any independently proven segmented span, rejects code
overlap, and commits the write to path memory. LOAD address recovery is unchanged.

Focused controls: `tests/ir/test_x86_16_boot_entry_link.py` and
`tests/ir/test_x86_16_invocation_domain.py`. A complete local census does not
establish compiler round-trip acceptance.

## Function-entry jump proof transport

`real16_initial_memory8616.py` separates initialized contents from authenticated
address ranges for reading native proven writes. Declared entries that disable
environment contents retain only explicit initialized spans. Their descendants
may still read bytes proved written in freshly authenticated environment/image
ranges; those ranges supply no original values. Unknown, tainted, unwritten or
outside-range data stays unknown. Controls:
`tests/ir/test_invocation_written_memory.py` and
`tests/ir/test_declared_function_entry_domain.py`.

Protected native ranges in `real16_invocation_domain.py` retain each distinct
`(address, size)` pair. Repeated fetches still decode and authenticate current
bytes; a separate admission counter preserves public `fetched_range_count`
and replay equality. Different sizes at the same address remain protected.
Speculative calls copy this footprint and keep their admissions and effects
detached from the published census. One synchronous feasibility operation
captures the closed caller decode interval once, charging native block extents,
IR block ownership and selected-call copying instead of expanded IR row visits.
The native and IR heads must agree; every native extent must fit the interval.
Its callback is bound to the selected instruction identities, original block
tuples and unchanged boundary coordinates. Captured spans are protective data,
not proof: every crossing includes the current fetched manifest and repeats
native/proof authentication. Gaps are conservatively protected as well.
Code/write overlap uses the exact interval
union and a charged sparse-write search or dense-byte walk; unknown writes and
tainted memory never authorize a call effect. Controls live in
`tests/ir/test_distinct_fetched_spans.py`,
`tests/ir/test_sparse_code_write_guard.py` and
`tests/ir/test_native_call_feasibility.py`. Operation-local capture, resource
admission and post-capture mutation controls live in
`tests/ir/test_caller_protective_footprint.py` and
`tests/ir/test_caller_protective_footprint_native.py`. Native boundary corruption,
exact budgets and preparation independent of IR expansion are covered by
`tests/ir/test_caller_native_range.py`.

`entry_jump_transport.py` produces the raw native function bundle and applies
the existing entry-domain proof for a single Clinic conversion. The frontend
consumes its typed admissions before SSA. This local proof does not resolve
caller/callee dependencies or publish a universal function lemma. Unsupported
control remains a refusal under the existing budgets.

## Request-local native lift reuse

Native import treats a recovered function's blocks as byte witnesses, not as
the final native block partition. The frontend boundary transport reconstructs
reachable instruction heads inside those authenticated extents before lifting.
This retains a branch target that a recovered graph merged into a preceding
block. Exact boundaries remain unchanged; missing or gapped witnesses cannot
authorize expansion into additional mapped bytes. The control is
`tests/ir/test_vex_native_boundary.py`.

`native_import_surface_cache.py` retains at most four raw lift surfaces and
256 blocks during one outer IR import. Equal reconstructed boundaries may
share lifting only when native bytes, decoded metadata, CFG, architecture,
engine settings and producer authorities still agree. Mutable captures are
copied; incomplete lifts and expired requests are not retained.

Every consumer reruns semantic finishing and proof against its current
boundary. Raw lifting does not consume the semantic function registry, so its
key does not serialize that registry. The finished-artifact cache in
`raw_boot_native_surface_cache.py` still authenticates registry contents and
boundary identity. Neither cache turns a retained refusal into proof.

`raw_boot_route_admission.py` bounds the initial record-free startup attempt.
It freshly decodes at most 512 bytes/16 linear blocks. A prior ordinary CALL
requires call-preservation evidence that this route never supplies, so that
attempt is skipped and ordinary resolution remains enabled. Requested calls,
branches, decode uncertainty and near-return continuations retain the existing
attempt. INT fallthrough remains possible. Later call-backed retries do not
consume this optimization decision; it proves no program unreachability.

## Flag CFG projection

`status_flag_cfg_projection.py` consumes a raw native import rather than running
universal caller/entry-domain proofs for optional flag suppression. Any retained
function or block refusal makes projected successors incomplete; all status
flags remain live at those exits. Callee overwrite summaries likewise require
a complete CFG. Native evidence is neither published as a universal proof nor
reused across activation of the flag-lift context.
