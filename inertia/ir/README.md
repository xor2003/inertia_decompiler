# IR evidence contracts

## CS-relative data addresses

Explicit CS-prefixed memory accesses retain `MemSpace.CS`, including indexed
loads. This identifies the address space; it does not establish the selector
value, immutable table contents, or indirect branch targets. Invocation and
known-bits memory evaluation require the proven CS lane and the ordinary
path-memory overlay. Missing/dirty selectors, unknown writes and tainted memory
remain unproved. Segment contracts retain the CS entry requirement. Unsupported
higher-level memory recovery must refuse rather than substitute DS or SS.
Controls: `test_native_cs_load_retains_selector_and_path_memory_authority` in
`tests/ir/test_x86_16_vex_logical_memory_accesses.py` and the CS cases in
`tests/ir/test_x86_16_unary_address_capture.py`.

## Native feasibility row maps

LOAD and interior-CALL maps may skip whole-block binding only when a scan of
the full source block finds no eligible owned instruction. A nonempty candidate
set still requires the existing native block/prefix binding; map rows are read
after binding and each consumer retains its own freshness checks. Unknown row
objects produce no facts. Do not narrow the prefilter using unverified native
lengths or address cutoffs, extend proof lifetime, or change work charges.
Controls: `tests/ir/test_native_feasibility_map_binding.py`.

## Declared function-head preparation

Preparing the declared head of a refusal-free raw function does not require
proving selector preservation through every call in its body. Authenticate the
head's entry state, source and native CFG normally, and leave body-call effect
obligations to their consumers. Any retained artifact/block refusal keeps the
existing selector survey, including pending selector-window transformations.
No call-preservation facts are fabricated. Controls:
`tests/ir/test_declared_head_entry.py`.

## Unchanged call-containing control graphs

A complete unchanged native CFG may be consumed under its authenticated entry
without inventing a transformed jump or proving call effects. Its application
remains `EMPTY`, all raw CALLs survive, and control-only projections report
`NOT_REQUESTED` with no materialized target facts. Explicit call-target requests
still use their separate admission owner; missing authority remains unproved.
Byte/source/entry mutation, open successors and expired proof budgets refuse.
Controls: `tests/ir/test_scoped_identity_calls.py`.

## Known scalar comparisons

Invocation transfer preserves comparison results when both operands are known,
using the existing scalar operation-width table and known-bits evaluator.
Signedness and operand truncation belong to those canonical owners; unsupported
operators and unknown operands remain unknown. The result is a one-bit
predicate, not an operand-width integer. Controls:
`tests/ir/test_real16_scalar_comparison.py`.

## Nested call construction

Comparing a native entry-only chained scope with itself must not replay its
declared/raw root parent before the child's own mandatory parent replay.
Keep structural provenance and depth gates, then authenticate the child; its
native entry consumer forces the current parent derivation after callbacks.
Other chain forms retain their ordinary admission. No verdict survives this
operation and changed bytes, parent captures or missing links still refuse.
The caller-state consumer rereads the retained frame after native callbacks;
an earlier snapshot must agree with its current value before state transport.
Controls: `tests/ir/test_self_chained_scope_replay.py`.

Construct a nested caller prefix after the callee intake and native binding
callbacks, then pass its fresh derivation directly to the callee entry. Building
the callee must not reconstruct the same caller prefix again. Keep the original
consuming scope authenticated, preserve prior-call evidence, and refuse changed
inputs, cyclic dependencies and exhausted budgets. Later public completeness
checks remain independent; this operation-local transfer is not a retained cache.
The regression must exercise the production callsite route, count ancestor
derivations without replacing producers, and compare total charged work.

## Prefix profitability advice

The structural cost estimate stops scanning block headers once its lower bound
already exceeds the work that continuation could save. This early result can
only reject optional reuse; successful continuation still requires the complete
structural cut and fresh native/source checks. Performed header visits remain
charged, and resource exhaustion remains a refusal. Controls:
`tests/ir/test_real16_prefix_cut.py`.

## Selector proof preparation

Conditional native callees retain their exact invocation proof in selector
induction; a popped near-return frame never becomes a universal summary.
Guarded bodies use authenticated reachable edges while retaining the complete
raw byte census. A detached snapshot visits each proof/scope node once per
operation, including shared prior calls; a new operation always starts fresh.
Native callbacks are followed by a snapshot seal, so changed frames, entries,
bindings and prior proofs refuse. Controls: `test_scoped_selector_callee.py`
and `test_scoped_selector_seal.py` in `tests/ir/`.

Repeated universal callees share their segment-effect result within one
machine preparation. Each CALL retains its own decoded target and selector
check. The first native surface remains bound through final validation;
conditional callee results never enter this table. Control:
`tests/ir/test_selector_callee_reuse.py`.

Selector induction authenticates the native boundary and captures its source
snapshot before preparing decoded instructions and callees. Full effect
classification runs only if that preparation succeeds; an already-refused
optional route cannot spend shared work on an unused survey. Existing budget
and deadline admission still precedes preparation. Successful routes require
complete classification and final source/authority revalidation, including
changes made by callbacks. Controls:
`tests/ir/test_declared_selector_survey_projection.py`.

## Discarded CALL snapshot replay

The root census can omit a second transfer of an ordinary CALL-only block
when the owned handler's current implementation confines its result to the
discarded snapshot state. The fixpoint transfer and subsequent real call/effect
census still run. Branch observations, requested pre-CALL captures, interrupts,
unknown effects, foreign initial-memory readers and external or rebound handlers
retain replay. The policy is
checked when consumed, defaults to observable replay, and stores no callee
result. Work charges count only performed work; existing limits remain.
Controls: `tests/ir/test_call_snapshot_omission.py`.

## Native graph encoding

`source_graph_binding.py` is the authoritative pure-Python-syntax implementation.
Build its optional Cython extension with
`python tools/dev/build_cython_source_graph.py`. Ordinary imports select the
verified extension when available; `INERTIA_SOURCE_GRAPH_BACKEND=python` selects
interpretation and `cython` requires a matching build. Source, ABI and artifact
digests are checked by `inertia.native_bundle`, shared with the mandatory native
lifter. Compilation does not change graph equality or proof obligations.
Loader controls run in `tests/ir/test_source_graph_native_backend.py`.

## Branch observations from pure callee transfers

An owned callee feasibility walk may record a terminal branch's edge verdict
while evaluating that block, instead of executing its instructions a second
time for a snapshot. Only a no-op service handler and read-only owned LOADs
qualify. Generic observable callbacks, CALL/repeat handlers and requested CALL
cuts retain fresh snapshot replay. The default API policy remains observable.
Each changed block entry replaces its provisional verdict; only a converged
round can publish it. Limits and complete native/code-byte checks remain.
The collector retains integer edges, not register/tmp maps or cross-request
proofs. Controls: `tests/ir/test_branch_transfer_snapshots.py` and
`tests/ir/test_branch_transfer_snapshot_loops.py`.

For larger pure callee graphs, the first transfer may evaluate a straight
entry chain before visiting an error-path loop. The head must have no in-scope
predecessor; every next block must have exactly the preceding block as its
only predecessor and exactly one proven live incoming path. A join, backedge,
unknown branch, or call-cut boundary stops this walk. Its edge candidates only
restrict the local transfer; exhaustion or lack of convergence publishes no
new candidate. Native byte coverage, subsequent state/effect simulation, and
the shared work/deadline limits remain mandatory. Small callees and observable
callbacks retain their existing path. This is not loop unrolling or an assumed
loop invariant.

## Scoped native callee copies

A current callee CFG projection can limit detached native IR copies to its
live blocks. This is an allocation optimization only: the complete raw byte
census remains protected against caller writes, and path simulation still
derives its own reachability and binds every executed row to native IR.
Missing native evidence for a live block refuses; a selection never proves
that the omitted block is dead. Ordinary callees retain complete copies.
Controls: `tests/ir/test_forward_declared_call_scope.py`.

## Detached native copies

The request-local native cache retains exact raw-surface variants separately.
Conditional return inputs remain part of the complete source key; alternating
variants of one address do not evict each other merely for sharing an address.
The existing four-record and 256-block limits count all variants together.
Every insertion, including reinsertion after a reentrant copy or fact callback,
uses the same bounded retention path. Census projections select the matching
raw variant and still authenticate their own fetch/producer key. Retention
never replaces fresh scope, source or semantic proof checks.
Controls: `test_native_import_surface_cache.py`, `test_native_fact_rebind.py`
and `test_native_census_projection.py` in `tests/ir/`.

Native import copies preconstruct exact owned IR nodes and scalar normalization
decisions in the ordinary deepcopy memo. Every field, including provenance fields
excluded from equality, must survive. Copies remain detached from their source,
and references shared across surface fields must resolve to one copied node.
Typed IR clones recursively detach their fields; normalization decisions qualify
only with exact integer and enum fields. Subclasses, malformed containers and
unknown payloads retain generic copying; cyclic references must
terminate and preserve their topology. Copier helpers participate in the
existing native source identity, so changing a helper invalidates retained facts.
This optimization changes neither proof authority nor global cache limits.
Controls: `tests/ir/test_native_copy_memo.py` and
`tests/ir/test_native_surface_copy.py`.

## Conditional prefix source bindings

An invocation prefix may explicitly retain raw source identities for scoped
near-return helpers. These identities authenticate bytes and lift inputs only;
they do not authenticate a return premise or callee effects. Default raw-cache
consumers still receive no conditional binding. Prefix consumption must freshly
authenticate every earlier CALL under its exact scope, rebind native facts, and
repeat conditional CALL authentication after callbacks before accepting moved
state. A changed premise identity must refuse even when serialized lift inputs
are unchanged. Different conditional sources at the same address conservatively
decline reuse and retain the ordinary census. Completed-artifact caching remains
disabled for conditional bodies. Controls:
`tests/ir/test_conditional_prefix_binding.py` and
`tests/ir/test_native_census_projection.py`.

Forced replay at an identical CALL cut must reject corrupted retained final
registers, memory, counters, or source bytes. Untrusted retained data may fall
back to ordinary derivation; changed executable bytes invalidate the premise.
Identical-cut replay currently performs the ordinary fresh derivation: the
experimental shortcut cost more on the actual nested-call witness and was removed.
Controls: `tests/ir/test_same_callsite_prefix_integrity.py`.

## Structural prefix work

CALL-cut admission collects block and edge censuses once and supplies them to
the shared CFG agreement owner. That owner checks the same root, exact block
and edge membership, endpoint closure and entry reachability. An optional work
consumer charges before allocation and traversal; unbudgeted callers retain
their original semantics. Global CALL ambiguity and duplicate/missing edges
still refuse, including outside an absorbing cut. Prefix-selection advice must
remain a lower bound on the current measured structural work. Controls:
`tests/ir/test_real16_prefix_cut.py` and `tests/ir/test_x86_16_ir_boundary_cfg.py`.

## Selector proof refusal and shared work

Declared-selector phase A retains the decoded fetch census but stops resolving
additional callees after the first closure or resource refusal. It returns no
prepared machine and grants no invariant authority. Continuing an already
refused whole-surface attempt would consume the bounded ledger needed by later
invocation-local proofs. Successful phase A still resolves every call, and
consumed sources retain their freshness obligations. Controls:
`tests/ir/test_declared_selector_survey_projection.py`.

A receipt whose collected evidence already forces refusal skips final native
surface sealing. It retains the original typed obligations, diagnostic counts,
and the work actually performed; it grants no selector authority. Every
potentially positive receipt still rebinds consumed native surfaces and checks
current authority after producer callbacks. Budget and private-index checks
remain mandatory on both paths. The same regression module checks refusal
savings, successful sealing, and rejection of a stale positive candidate.

## Declared application data and native code

The default whole-image MZ range authorizes instruction decoding; it does not
prove that every loaded byte is immutable code. Declared application-entry
memory may supply writable module data. The invocation owner protects the
complete authenticated root extent and checks the original declaration against
every fetched native instruction, including chained and interior callees.
These checks use bounded interval overlap under the census work/deadline limits.
They inspect declared spans directly, so joining or transporting a path-memory
ledger cannot erase an overlay into future code. Source/native authentication,
unknown undeclared data and runtime STORE protection remain mandatory.
Controls: `tests/ir/test_declared_function_entry_domain.py`.

Target coordinates and callee effects are separate obligations. A universally
proved near-CALL target must not prevent refinement of an incomplete callee
under an authenticated declared caller entry. The complete in-flight record
pool supplies preceding call effects; each retry still authenticates native
bytes, the exact transporting edge and the caller/callee scopes. Such results
remain conditional and must not enter the universal artifact registry.

Replaying an admitted callee must consume its authenticated control projection
as well as its raw effects. A native popped-return JMP whose exact terminal is
projected to RET under the consuming call scope is a return during that replay.
This permission lasts only for that callee simulation, retains native byte/row
validation, and does not clear other pending jumps or external-service calls.
Missing or stale projections refuse; raw code and the universal registry remain
unchanged. Repeated calls must preserve this distinction.

Scoped reachability contract: a native return-domain proof may exclude a callee
branch only under its exact authenticated incoming call. Recompute reachability
over the entire raw CFG after removing its proven-infeasible edges; require the
result to equal the domain's censused path and to close at the proven return.
A backward return cone alone does not establish global unreachability. Retain
all raw blocks/instructions and byte authentication; the projection explicitly
records unreachable blocks. Coverage, segment-state predecessors, call census,
and return census must all consume this same conditional partition. Unknown or
reachable external calls remain obligations. Changed source, entry, or dead-edge
records revoke the projection. This is not universal DCE or registry publication.

## Atomic conditional selection

The VEX importer retains fully bound atomic ITE expressions as
`SELECT1/8/16/32/64` instructions. Arguments are `(guard, true_value,
false_value)`; the guard's low bit selects the arm. VEX must establish an
I1 guard and equally typed arms. Unbound, nested or unknown operands retain
the existing explicit UNKNOWN result; byte storage alone never proves I1.

`scalar_instruction_effects.py` owns selection shape and result widths.
Selections write only their explicit temporary destination. Their three
inputs remain SSA dependencies. Dead-temporary normalization may remove a
selection only after proving input totality and deadness; live and unknown
computations remain. The exact invocation evaluator selects an arm only when
the low guard bit is known. The known-bits evaluator additionally joins bits
proven equal in both arms when the guard is unknown. Both mask the result to
the semantic width and retain captured TMP identity across register writes.
Other numeric/provenance consumers continue to return unknown, never treat
the guard as the selected value. Tests:
`tests/ir/test_x86_16_vex_wrtmp_result_width.py`, `tests/ir/test_select_numeric.py`.

`select_normalization.py` simplifies selections only when block-local known-bit
execution proves the guard's low bit. Entry registers and memory are unknown;
environment services supply no assumptions. Unique preceding definitions and
complete external capture ownership are required. `SELECT1` keeps an explicit
one-bit projection of the chosen value. Unknown guards retain the selection;
blocks without selections bypass abstract execution. Surface normalization
retains destination/capture identity, then applies its existing rooted deletion
proof. Selection rewrites publish separate five-field evidence counts; they
do not establish whole-function validation. Controls:
`tests/ir/test_select_normalization.py` and
`tests/ir/test_dead_temporary_surface_normalization.py`.

`canonical_patterns.py` owns the named SELECT rule's typed match evidence,
verified action, decisions and recursion guard. A proof binds the source row,
width, known guard bit and chosen arm; the action rechecks them before changing
IR. Unknown or stale evidence keeps the original row. Pattern decisions share
the surface normalization report and authenticated producer closure.

Use `CanonicalPatternConfig8616(disabled=frozenset({"select_known_guard"}))`
for explicit policy, or set `INERTIA_DISABLE_CANONICAL_PATTERNS=select_known_guard`
for the native import path. Unknown names raise `ValueError`. The native fact
cache binds resolved policy values as well as producer identities: unchanged
policy reuses facts, while policy changes invalidate retained results. Controls
in `tests/ir/test_canonical_patterns.py` cover forged proofs, rule disabling,
recursion, producer replacement and policy changes during cache requests.

## Canonical source graph

`source_graph_binding.py` validates and encodes every owned graph field.
`source_graph_json.py` emits its canonical JSON with the existing schema and
exact stdlib bytes. The optional native codec handles compatible ASCII payloads;
Unicode, DEL and unsupported subclasses retain stdlib encoding. Missing codec
packages use stdlib; broken installations raise their original error. This
changes serialization cost, not source-digest or proof authority.

## Fresh outgoing CALL census

`near_call_census.py` prepares all outgoing CALL preservation records together.
The caller graph is captured before callbacks and freshly reconciled after them;
callee checks precede final native observations. Exact CALL identities are checked
again before promotion, so missing, duplicated or callback-replaced entries refuse.
Staged records grant no authority. Target gates, callee projections and record
materialization use the same owners as standalone proof and scope consumption.
Deadline expiry stops subsequent graph work. Controls: `tests/ir/test_near_call_census.py`.

Admitted jump applications retain unchanged non-CALL instruction identities.
Rewritten jumps and CALL instructions remain distinct effective objects; an
effective CALL must not inherit the original instruction's identity binding.

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

## Clinic input handoff

Clinic passes its identical retained conditional entry input to the fresh
structuring codegen before validation initializes IR. The handoff binds the
original Clinic partition receipt, project, function, source graph and entry
identities. It grants no proof authority and performs no full native replay.
The ordinary IR consumer authenticates current native evidence before reuse;
it rejects a different requested function or changes to body/incoming-call
bytes. A Clinic without a retained input keeps the ordinary unscoped route.
Controls: `tests/frontend/test_x86_16_clinic_entry_handoff.py`.

## Retained native entry in the structuring prefix

The synchronous structuring prefix may attach an already-retained native
entry's raw bundle after checking its source membership and identities.
Attachment grants no proof authority and publishes nothing to universal
registries. Indexed-address processing runs before the existing call-Semantics
consumer authenticates the scope. The prefix requires a fresh semantic
projection bound to the retained entry; an early return or replacement of
source authority cannot count as successful consumption. Standalone IR
preparation and attachment retain their full authentication.
Controls: `tests/structuring/test_native_scoped_prefix.py`.

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

Fresh near-call scoped views use one synchronous proof/application operation
owned by `entry_jump_domain.py`. It authenticates the scope before proving and
again after application admission and any call-target solver. Only the final
check permits the paired proof/application result to leave that owner. Both
applied and empty results retain this check, including the original binding
digest, function root, scope and admission identities. Retained proofs and
standalone consumers still perform their own authentication; this operation
does not introduce reusable cached authority. Ordering, callback mutation and
standalone behavior are covered by `tests/ir/test_fresh_near_call_scope.py`.

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

Semantic consumers rerun finishing and proof against their current boundary.
Raw census projections copy only requested blocks and terminal prefixes, even
on their first query. The private projection records whether its block inventory
is complete and which blocks contain only a prefix. A request for missing blocks
or additional rows performs a fresh authenticated fetch; incomplete rows cannot
satisfy a whole-block comparison. Returned rows remain detached from the private
projection. Work accounting includes the full block-header index and only the
rows actually copied. Controls: `tests/ir/test_native_prefix_copy.py` and
`tests/ir/test_native_census_projection.py`.
Growing a partial projection preserves its source-key identity only after a
fresh key compares equal, so collecting more rows does not invalidate an
otherwise unchanged caller prefix.

The raw-lift cache may retain conditional return inputs. Its key includes both
the owned continuation record projection and the actual return-block set used
by the lifter. This is no invocation authority: conditional census selections
carry no prefix-replay source binding, and each scoped call still authenticates
its current premise. The completed-artifact cache continues to reject these
conditional boundaries. Controls include replaced return projections and real
changed-helper-byte refusals in `tests/ir/test_forward_declared_call_scope.py`.
Source-only raw rebind compares the normalized native blocks and refusals
without constructing discarded semantic summaries. Scoped CFG consumption
opens the same bounded raw-import request as view construction, so nested
rechecks share lifting while each proof still runs; records expire on exit.
Raw lifting does not consume the semantic function registry, so its
key does not serialize that registry. The finished-artifact cache in
`raw_boot_native_surface_cache.py` still authenticates registry contents and
boundary identity. Neither cache turns a retained refusal into proof.

Scoped boundary coverage compares current caller facts with the request's
private native facts before constructing another full native artifact. This
route requires the canonical census importer and finishing producers. Missing
or stale records and replaced producers use the ordinary census import;
changed caller facts refuse. The no-effect instruction census and the final
before/after graph and boundary checks still run. Controls live in
`tests/frontend/test_x86_16_scoped_ir_native_resolution.py`.

`raw_boot_route_admission.py` bounds the initial record-free startup attempt.
It freshly decodes at most 512 bytes/16 linear blocks. A prior ordinary CALL
requires call-preservation evidence that this route never supplies, so that
attempt is skipped and ordinary resolution remains enabled. Requested calls,
branches, decode uncertainty and near-return continuations retain the existing
attempt. INT fallthrough remains possible. Later call-backed retries do not
consume this optimization decision; it proves no program unreachability.

## Scoped native graph authentication

A scoped native seal captures the caller graph before callbacks and freshly
captures it again afterward. Within that one operation, its first immutable
snapshot may be compared directly with the request's authenticated native
facts; a third encoding of the same caller is unnecessary. The final seal
still requires pre-callback, native and post-callback graphs to agree, and
checks boundary identity, source bytes and the instruction census. A retained
CFG projection never replaces post-callback scope authentication. Missing
native authority falls back to guarded import. Controls:
`tests/ir/test_scoped_native_snapshot_rebind.py` and
`tests/ir/test_x86_16_segment_effect_closure.py`.

## Flag CFG projection

`status_flag_cfg_projection.py` consumes a raw native import rather than running
universal caller/entry-domain proofs for optional flag suppression. Any retained
function or block refusal makes projected successors incomplete; all status
flags remain live at those exits. Callee overwrite summaries likewise require
a complete CFG. Native evidence is neither published as a universal proof nor
reused across activation of the flag-lift context.

## Conditional callee import routing

A native boundary with a typed near-call frame premise and proven return
continuations enters through `real16_native_census_import_8616`. The guarded
import retains pending markers and suppresses universal call/entry discharge;
only the later scoped closure can prove its effects. It never publishes a
conditional helper into the universal registry. Ordinary RET bodies retain
the ordinary importer and publication rules. Controls:
`tests/ir/test_conditional_callee_import.py`.

## Nested conditional callee composition

A declared caller may retry a dependency-incomplete ordinary callee under its
authenticated entry. Its ordinary native body keeps canonical registered CFG
coverage; the effect closure remains conditional. A nested CALL derives its
caller prefix from the exact retained chain and completed prior nested proofs,
then binds its encoded target and constructs a distinct callee chain. Prior
proofs cannot discharge themselves, and every live dependency is still required.
Forward target binding retains the freshly checked caller invocation: a target
that is unconditional can still enter a conditionally returning helper.
The segment-state solver accepts an exact, current, refusal-free chained body
without inventing an empty rewrite view. Pending bodies still require their
conditional projection and never publish into the universal registry. Context
revocation after nested replay returns refusal before calling the state solver.
Controls: `tests/ir/test_nested_declared_callee_import.py`.

## Bounded code-write exclusion

`real16_persistent_bytes8616.py` maintains conservative address bounds during
owned writes to its immutable-root facade. Copy/adopt share these bounds;
foreign roots and non-integer keys leave them unknown. Bounds describe stored
addresses only, never invocation authority or byte-value equivalence.

`real16_scratch_protection.py` combines those bounds with a charged unknown-byte
scan. The code-write guard still walks every protected input span. Only disjoint
complete bounds omit union merging and membership queries; overlapping or
unknown bounds retain the exact checks. Foreign span operators disable this
shortcut even for discarded zero/negative extents. Deadline and work exhaustion
remain refusals. Controls: `test_persistent_byte_envelope.py` and
`test_written_address_envelope.py` in `tests/ir/`.

Invocation ordering can omit its second heap walk when the existing charged
scan establishes strictly increasing edges. Backward edges and cycles retain
the original deterministic heap traversal and budgets. This is graph ordering,
not a proof of executable effects; `tests/ir/test_invocation_order.py` checks
both routes and their resource boundaries.

Within one dependency traversal, an unsuccessful owned callee-order attempt
can select the ordinary bounded fixpoint on later visits. This bounded advice
retains neither a positive order nor graph/effect proof. Changed geometry still
uses the ordinary solver; native instruction authentication, shared/local work
and deadlines remain enforced. Custom ordering callbacks remain observable,
and advice expires with the traversal. Controls:
`tests/ir/test_callee_order_advice.py`.

Native census projections grow within their freshly authenticated raw source
inventory. Already-private full blocks remain private; new or widened blocks
are copied, and every consumer still receives a detached copy. Retained and
selected-header walks are charged alongside newly copied rows. Truncated
prefixes never satisfy full-block requests. Inventory completeness comes from
the fresh raw address set, and growth cannot exceed its 256-block bound.
Controls: `tests/ir/test_native_projection_growth.py` and
`tests/ir/test_native_projection_growth_controls.py`.

## Call stack coordinates

`call_stack_coordinates.py` owns the immutable seven-slot callsite coordinate
contract. `None` means missing evidence. Return-frame width, RET-immediate
purge, caller cleanup, linked-return extra, caller-visible delta, argument top
and callee-body SP transfer remain independent. A plain RET cannot establish
a zero call delta; a zero argument-count hint cannot prove an empty region.

Semantics authenticates physical call identity, retained source and covered
callee-body transfers; Alias consumes only the checked SP projection. A present
invalid coordinate refuses instead of falling back to an independent legacy
number. Native copies preserve source authority while detaching mutable graph
payloads. Serialized graph bindings include finite coordinate data and proof
readiness without serializing project objects. Controls:
`tests/semantics/test_call_stack_coordinates.py`,
`tests/semantics/test_callee_stack_effects.py` and
`tests/ir/test_call_stack_coordinate_transport.py`.

## Function lifecycle and cache boundary

`function_lifecycle.py` owns function-wide producer evidence, typed readiness
verdicts and refusals. `IRFunctionArtifact.lifecycle` and
`SSAFunctionArtifact.lifecycle` bind to the same state for their accepted raw-IR
source generation. `lifecycle_stage` labels the immutable projection;
`lifecycle.state.maturity` is the last consumer-validated contiguous prefix.

Direct IR and SSA registry lookups that observe changed, unavailable or
conflicting source evidence also revoke the retained lifecycle prefix with
the corresponding typed IR-stage refusal. This observation neither creates lifecycle state nor binds a new
source generation; retained IR and SSA handles continue to share their original
state and its refusal.
Every consumption still rechecks live source, body and producer evidence.
A cached observation never grants permission to skip those checks.

An accepted new source generation receives a new state. Retained old IR/SSA
views keep their original source identity and a typed stale refusal; they
cannot borrow the new generation's maturity. Producer replacement or removal
revokes dependent observations without inventing successful evidence.

`to_dict()` transports lifecycle diagnostics, not restore authority. Function
IR/SSA cache schema 5 persists raw IR with a fresh empty lifecycle and an IR
projection label. Decoding discards serialized lifecycle claims again and
rebuilds SSA sharing the fresh handle. Runtime publication reattests the source.
Readiness describes evidence currency; it does not establish tail-validation
equivalence by itself.

## Authenticated entry constant seeds

`IRConstantFlow8616.seed_register_constants_8616` merges externally proven
register values through their shared storage lanes. Agreement is checked only
on overlapping known bits. A contradicted bit stays unknown throughout the
seed batch, even when a later wider view supplies it again; compatible and
nonoverlapping bits remain available. These are numeric facts, never
SP-relative coordinates. Authentication remains the caller's responsibility.
Controls: entry-seed cases in
`tests/ir/test_x86_16_ir_constant_flow_refusals.py`.

`scoped_call_stack_coordinates.py` owns the dual-scope per-call SP carrier:
`IRScopedCallStackCoordinates8616` retains the universal physical coordinate
record plus the Semantics scoped call effect, projecting
`net_sp_delta_for(caller_scope, callee_scope)` only after both entry domains
re-authenticate and the physical CALL source/frame still binds. It never
publishes a context-free scalar; `IRCallStackEffect8616.scoped_coordinates`
carries it as an optional sibling without touching `net_stack_delta`,
`current_net_stack_delta` or `has_proven_sp_delta`. Controls:
`tests/ir/test_scoped_call_stack_coordinate_transport.py` and
`tests/semantics/test_scoped_call_stack_coordinates.py`.

Scoped coordinate access must recheck agreement with the retained call effect
and replay the universal coordinate source and its closed evidence census on
every projection. A frozen record replaced with another frame width, source,
callsite or census is not authenticated by the original effect. Native effect
schema comparison includes `scoped_coordinates`: seeded detach preserves the
same carrier as live authority, and native binding rejects removed or replaced
carriers rather than treating serialized values as authority. Scope replay is
performed by the explicit consumer accessor, not recursively inside native
structural equality. Controls: accessor-tampering cases in
`tests/semantics/test_scoped_call_stack_coordinates.py` and scoped native-copy
cases in `tests/ir/test_scoped_call_stack_coordinate_transport.py`.
