# Decompiler Evidence And Consumer Owners

Detailed per-module evidence, ownership, and consumer facts extracted from
[`decompiler-map.md`](decompiler-map.md). The map stays navigational; consult
this guide for the semantic evidence and consumers behind each layer owner
before editing.

`frontend_block_partition.py` normalizes bounded decoded CFGs before publishing
an exact function boundary. A prefix may transfer to a known aligned suffix
only when instruction extents, loaded bytes and terminal edges agree; otherwise
the original blocks and edges remain with a typed refusal. IR import consumes
those exact Frontend extents so neither branch edges nor logical-memory
captures acquire duplicate owners. Out-of-range terminators and mid-instruction
entries cannot turn missing evidence into a closed boundary.

Typed branch evidence is an IR/frontend fact even when angr returns a cached
IRSB. `X86_16/ir/condition_cache_relift.py` owns the temporary exact-byte
publication bridge: an empty condition cache is complete only when a typed
pending `ConditionSource` still owns that block; otherwise the custom lifter is
run under isolated state and must close all five evidence counters. Lowering may
transfer the resulting `ConditionIR`, but must not recreate operands or branch
meaning. The eventual replacement is direct cross-block condition-source
provenance in `IRFunctionArtifact`, after which the cache bridge can be removed.
Stored call-return ownership is specified in [`stored-call-return-contract.md`](stored-call-return-contract.md).
`ir/vex_import.py` owns temporary-result widths from the actual VEX
expression/type environment. Destination, instruction and retained result
consume that width; operand views keep their independent widths. A comparison
predicate occupies one byte even over wider operands. Unsupported value
semantics remain UNKNOWN without discarding known result-type facts. The
Binop and generic-WrTmp result-width regressions are enrolled in importer
ownership and the fast pipeline; this is not emitted-C or callee proof.
Selector returns have two owners: Structuring's
`structuring/single_branch_return_orientation.py` maps a no-else return body to
its edge from target-return expressions and CFG reachability; Tail Validation's
`tail_validation_selector_returns.py` fingerprints condition and both outcomes.
Only swapping outcomes makes inverted conditions equivalent; neither owner may
infer from rendered C or repair semantics in Rewrite.
Indexed segmented addresses are IR facts. `IRAddress.base_values` retains exact
versioned terms; `X86_16/ir/indexed_address_evidence.py` traces each supported
term to SSA and stable stack storage, producing a typed fact or refusal. Alias
owns storage identity in `alias/indexed_address_projection.py`, access roles,
copy endpoint identity, and the closed discovered-function census in
`alias/indexed_address_program.py`. `widening/indexed_global_object_layout.py`
alone joins proven byte/word views and whole-value copy families; Lowering only
consumes its closed artifact and materializes accepted objects. The CLI module
`inertia_decompiler/indexed_alias_program_context.py` transports a complete
discovery catalog into Alias once and never classifies semantic evidence.
`lowering/global_object_program_requirement.py` owns that typed need decision from local Alias roles and proven outgoing pointer-call sources; CLI only sequences it.
Legacy instruction-backed collectors are per-function rendering/parity debt, not an alternate project-layout owner. The read-only parity modules in Lowering may
report divergence but never select evidence or change C; the inventory script
isolates the executable from sidecars and reports non-library functions.
Near-offset call arguments follow the same chain: IR owns exact affine proof,
and Lowering joins it with callee-owned pointer output evidence atomically.
The callee pointer collector records a BP-argument carrier used in an indexed
effective address as `ambiguous_indexed_stack_offsets`, separate from displaced
uses. An indexed carrier alone does not prove which register is the pointer
base; input-trial classification refuses it until independent Alias/Widening
evidence resolves that ownership. The evidence codec preserves the distinction
across clean-worker transport.
`ir/stack_argument_modular_use.py` proves only a stable SS:BP word's
sign-insensitive bit-pattern use through a closed straight-line SSA path and
an exact AX or DX return carrier. It requires exact CFG, logical reads, SSA definitions, and
preserved pre-read call effects; signed operations and unknown uses refuse.
It neither recovers the source C signedness nor authorizes changing a return
type or scaled pointer expression. Lowering must join it with independent
pointer and expression evidence before atomic materialization.
`ir/stack_argument_scaled_return.py` joins two proven SS:BP word uses with
an exact SSA affine return path. Its typed result proves only 16-bit offset
arithmetic `AX = base + 2 * index` and exact logical LOAD-site identity;
its separate far-result fact also binds DX to an adjacent input segment word
at the same return. Pointer typing, source signedness, and generated-C
publication remain Lowering obligations.
The scaled result retains the original `ScalarAffineExpression8616`; its
coefficient roles can be bound to the exact base/index storage identities.
`near_scaled_return_candidate.py` exposes only that same closed IR value and
refuses reversed inputs or a refused candidate, never a separately rebuilt sum.
Return storage trials retain the complete `ReturnPointerUseEvidence8616`, not
just a dereference width. Address consumers must require its exact caller,
callsite and witness binding; an omitted legacy proof does not establish a space.
`c_runtime_header.py` owns explicit near-offset/byte-add representations. They
preserve modular16 and null, with distinct supplied source/result segments.
Portable operands require a live guest-memory view; unrelated native objects
abort. Native DOS results require the proven native near-data segment. These
primitives are not yet connected to scaled-return publication: input-space,
callee segment preservation and C-AST congruence remain independent obligations.
`ir/direct_call_segment_entry.py` consumes an Alias-proved local SS-to-DS
stack copy and one exact direct-call index entry to prove live DS=SS equality
at the call without inventing a numeric segment value. It requires matching
closed Frontend/IR CFGs and a single in-block interval free of intervening
calls or segment clobbers; unrelated branches and callers are not ambiguity.
Foreign code-segment low-word aliases and incomplete indices refuse. This
candidate publishes no function-entry state, call-preservation effect, or
pointer type; those separate interprocedural obligations remain required.
The Alias restore must still own a matching DS destination in the consumed IR;
a missing destination or a later DS write at the same machine-instruction
address refuses. Instruction-level address grouping must not hide ordered
effects or allow stale Alias evidence to assert an equality.
Its acceptance gate in `ir/direct_call_segment_entry_binding.py` additionally
requires the exact raw IR object registered on the caller's project and the
same object's in-process Alias source lineage. Equal addresses, equal-content
artifacts and diagnostic serialization are not ownership. Registry lookup
does not create state on refusal; missing and corrupt registrations have
distinct typed reasons. These facts still publish no callee entry state or
pointer type, and do not prove decoded-index freshness or call preservation.
The retained proof's `complete` property additionally requires closed counters,
the exact SS-save/DS-restore roles, and ordered addresses inside its call block;
the producer rejects an internally incomplete PROVEN result. This structural
check does not replace the project-owned IR/Alias lineage requirement at a
future consumer.
`lowering/far_return_pointer_use.py` separately proves an immediate caller
DX:AX to ES:BX transfer and a closed logical segmented access through one
exclusive post-call CFG edge. It records access width, not an input pointee
family; its typed refusal never changes a return prototype or emitted C.
The frontend direct-call index keeps exact 20-bit immediate far targets apart
from near-call low-word identities, so the caller-return-use census reaches
far callers without admitting a different segment's call as evidence. That
AX-use census does not replace the paired DX:AX Lowering proof.
`lowering/far_return_pointer_census.py` joins every included direct caller to
one exact paired-use witness whose CALL target matches the census target,
refusing open, missing, duplicate, unrelated, or unproven sites. This gate does
not publish a return type or C expression;
independent pointee and guest-address proofs remain necessary.
Its `collect_far_return_pointer_census_8616` entrypoint obtains the direct-call
census, proves the callee's DX:AX terminal storage from binary paths, builds
each exact caller's Semantics SSA, resolves physical CALL_OUTPUT definitions,
and joins paired uses without source/sidecar semantics. Supplied ranges only
bound code discovery. The returned contract remains a caller-use census: it
does not retain a callee expression or authorize C return publication.
`lowering/far_return_expression_binding.py` is a mutation-free candidate
binding: it rechecks the scaled-return IR access keys against closed logical
memory, exact SS:BP word projections, and the selected C runtime, then builds
`SEG_PTR` or `MK_FP` with an explicit 16-bit offset result. Signed source
words first receive unsigned bit-pattern views. It neither proves a pointee
family nor updates the function or any callsite.
`lowering/interprocedural_storage_simtypes.py` can project an exact DX:AX
pointer-class return to the owned FAR SimType only when an independent pointee
type is supplied; downstream access width alone refuses. Existing generic
32-bit pointers and distinct equal-width pointee families refuse rather than
being treated as matching FAR declarations. This type projector is not yet an
atomic far-return publisher.
Semantics may prove BP preservation across an exact near `E8` callsite whose
decoded target is a mapped, real one-instruction `RET` body, while synthetic
stubs and other bodies still
require separate evidence. This lets IR retain otherwise closed argument-use
facts without promoting offset arithmetic to a pointer return.
Terminal stack-cleanup Semantics visits each entry-reachable CFG block once;
distinct decoded returns and incomplete edges are the counted facts. A shared
branch suffix must not multiply one return fact by its number of incoming
paths, while every reachable unknown edge still refuses the proof.
For split-word callback values, IR's
`ir/logical_word_read_reaching_value.py` traces each logical word READ through
exact byte SSA STORE versions and immediate memory-phi predecessors to proven
constant logical WRITEs. It refuses absent writers, incomplete predecessor
censuses, and mixed byte writers. This is a Value proof only: it does not
establish a four-byte Alias object, a function-pointer type, or a rewritten C
call. Lowering may join words only after those separate obligations are proven.
`lowering/far_callback_call_value.py` joins the two exact PUSH-site READs with
the callee's decoded far-callback ABI and retains offset/segment pairs per CFG
predecessor. `lowering/binary_far_callback_targets.py` separately checks each
pair against a closed far-return code entry in the loaded DOS image. Neither
fact alone authorizes publishing a widened caller object. The
`lowering/far_callback_call_materialization.py` consumer atomically binds those
proofs to one typed C callback argument, `(4,2)` logical call shape, callee
prototype, and both forward declarations. It preserves the two separate BP
word stores; later DCE still needs its own proof. Structuring's typed path
selector chooses the target on every call predecessor, and callsite prototype
seeding carries a JSON-safe typed physical-interface provenance record so an
owned three-word seed can be refined without overriding an unrelated explicit
prototype. The consumer replays after structured AST regeneration.
Target projection, object grouping, type proof, and direct/indirect ownership
are specified in `reference/pointer-parameter-output-pipeline.md`.
Alias accepts only unambiguous unscaled pointer-relative or scaled global forms; IR owns exact LOAD-to-STORE SSA lanes, Alias endpoint/index identity, and Widening families and bounds without defaults or numeric proximity.
Loop bounds follow the same chain: IR carries exact-byte conditions into SSA and owns immutable CFG, dominators, single-entry loops, and byte-backed zero/plus-one induction writes; Alias owns canonical index identity, and Widening maps one segmented layout before proving an extent. The final Widening layout/range bundle is serialized atomically through the project cache and clean-worker transport. Types/Lowering may only strengthen an existing declaration with an accepted exact range and matching indexed identity; dynamic bounds such as SORTD InitBars, external entries, ambiguous overlaps, missing names, and declaration conflicts remain typed refusals.
For interprocedural global-memory outputs, Semantics owns terminal stores, Alias
owns segmented ranges, Widening owns exact caller-load views, and Types/Lowering
owns CFG/use trials. Contained views require an exact offset into one maximal
range; crossing or ambiguous views refuse. Function contracts keep all views
under that Alias object, reserve `outputs` for register/sequence returns, and
validate matching effects and `LIVE_OUT` trials before atomic publication.

## Initial Entry-Stack Byte Values

`alias/entry_stack_bytes.py` proves only immutable SS byte reads relative to
entry SP in the initial invocation of one unique entry-block prefix. Its bounded
`entry_stack_pointer_snapshots.py` extension consumes the shared snapshot owner
instead of creating a second frame-coordinate engine. Typed facts retain the
exact raw IR object and producing LOAD sites; equal addresses, hashes or
diagnostic serialization do not establish source ownership. Reentry, unearned
producer views, unknown effects and unproven segment identity remain refusals,
with all five evidence counters retained.

The byte proof does not close a function's CFG, caller frame, callee effects or
return behavior, and establishes no DS=SS relation, pointer type or C expression.
Any word Value recomposition belongs to Widening after Alias proof and needs
independent, definition-preserving bit/width evidence; adjacent byte addresses or
temporary identifiers alone are insufficient. It does not authorize replacing
captured values with a later memory read or deleting any unproved code.

`widening/entry_stack_word_values.py` consumes the exact Alias byte owner,
replays its evidence, and builds SSA from that owner's raw entry block. It proves
one selected 16-bit definition through exact scalar bit provenance, not a new
memory access. `entry_stack_word_bits.py` transports bits; the declarative
`entry_stack_word_value_contracts.py` owns verdicts, refusals and counters.
Conversion/operation metadata comes from the shared IR projection owner.
Malformed storage views, unearned decorations, unsupported operators, gaps and
wrong bit lanes refuse. Register-family writes invalidate sibling evidence;
CALL and unknown effects invalidate current register values, not immutable TMP
captures. Register reads tagged with a TMP need a separate capture projection
and currently refuse. Materialized counts are word facts, not emitted C.
Repeated TMP producer IDs refuse until a unique versioned lineage is proven;
descriptive names or matching numeric versions cannot disambiguate them.
This API is not yet a whole-function/pointer/materialization consumer: caller,
callee, return, CFG and memory-liveness obligations remain independent.

`ir/scalar_instruction_effects.py` owns typed architectural-register clobber
classification separately from scalar value equality. Comparison spellings
come from the actual custom emitter; the stock VEX registry is not exhaustive.
Malformed widths/destinations and unknown effects refuse. IP-only control
effects preserve unrelated data registers, not a prior IP value, flags,
segments, CFG closure or callee effects.
The canonical entry-word value owner consumes the same clobber decision:
closed non-data effects retain data-word provenance, IP writes kill the IP
family, and unknown/CALL effects invalidate current registers. Immutable TMP
captures remain values; this does not infer a new load or full control scope.

`widening/entry_word_transport.py` consumes the canonical Alias/Word evidence
and transports one word to one exact MOV definition over a known acyclic
target cone. Its typed scope is conditional; retained off-cone exits may
reenter and are never full-frontier proof. Contract, CFG meet, transfer state
and register snapshots have separate typed owners. Snapshots require exact
block-local producer/view/version coherence; duplicate producers invalidate
both the word and capture projections. All primary counters describe one
requested relation; instruction observations are separate traversal metrics.
Materialized word relations are not generated-C, return or frame acceptance.

## CALL Target SSA Uses

`ir/ssa.py` rewrites a CALL's destination as an input target using pre-call
definitions and captured versions. It creates no target binding; explicit later
outputs still define their own versions. This does not prove callee preservation,
return effects, or a closed call frontier. Those effects require separate evidence.
`ir/scalar_definitions.py` keeps the same rule in raw and SSA indexes: target
reads are not producer records, and manually supplied CALL records are not
complete definitions. Captured TMP producers remain unique unless an actual
defining operation conflicts; no CALL preservation claim follows.

## Shared Scalar Read Projections

`ir/scalar_value_projection.py` owns backend operation decoding and the typed
identity, earned-redecoration and explicit-conversion decisions used by
`ir/constant_flow.py`. Conversion source and target widths must both agree;
there is no implicit widening or truncation. Register+register addition retains
its operand-name decoration, and a different decoration refuses. The projection
API describes supplied metadata; it does not prove producer existence, honest
production, dominance, Alias identity or a memory object. Consumers retain those
proof obligations. Arithmetic and known-bit transport stay in the local flow
owner; later consumers must reuse the shared metadata decision rather than
invent another conversion table. Refused reads publish no new definition; their
private allocation counters need not match discarded baseline work, but retained
immutable identity relations and observable values/refusals must remain stable.

## Multi-component Affine Addresses

`ir/affine_indexed_address.py` replays the exact normalized access and each
captured register component through the scalar affine owner. It retains modular
displacement, distinct loaded values, coefficients and definition paths without
assigning pointer or induction roles. Corrupted capture identities, missing
components and unsupported component operations refuse atomically. Receipt
counts and all retained component provenance must match replay before values
are exposed. This is an IR decomposition, not Alias identity, a range,
load-stability proof, physical segment disjointness or binary CFG coverage.
`ir/scalar_affine_trace.py` consumes the shared scalar projection decision:
only exact earned decoration passes unchanged; unsupported decoration and
unproved conversions refuse instead of borrowing a captured producer's value.

`ir/affine_induction_role.py` consumes the full address decomposition and selects
one loaded term only when a supplied unique natural loop, dominating zero
initializer, latch increment and strict continued typed guard agree on its
canonical stack identity. Every residual term remains unclassified. The receipt
replays selection and capture identities, refusing ambiguous terms or incomplete
guard/write/CFG evidence. This is a role prerequisite, not a range: other writes,
pointer aliasing and bound/load stability still require a separate lifetime
census. The existing single-register range lane is not silently broadened by it.

Storage-prototype preflight in `lowering/interprocedural_storage_prototype_types.py`
refuses pointer retyping when an affected canonical argument still occurs in
retained numeric binary arithmetic. The typed failure is
`POINTER_ARITHMETIC_UNPROVEN`; argument variables, metadata, prototypes and
replay snapshots remain unmutated. Accepted interface storage classes do not
prove pointer-byte-offset arithmetic. Independent address/segment/representation
Lowering must consume or replace that arithmetic before promotion is possible.
Unrelated arithmetic and header-only declarations are unaffected. This guard
does not grant pointer-return, pointee-family or end-to-end call ABI acceptance.
