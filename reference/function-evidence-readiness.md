# Function evidence readiness: ownership and acceptance

Cross-call evidence requirement: stable local tail snapshots can coexist with
an incorrect architectural SP input at a call. The Alias position proof distinguishes
caller-before, callee-entry and caller-after SP; it is not a C ABI binding or
validation pass. The required runtime input, actual emitted binding and source
position must be checked together before a generated caller/callee pair is accepted.
See [the remaining stack-input obligations](p0-call-return-stack-effects.md).

Status: integrated into the main worktree; bounded native, cache and lifecycle
controls pass. Full acceptance remains open while repository gates are checked.
This is the lifecycle contract from the six-area transfer plan in
`decompiler-evidence-improvements.md`.

## Owned function state

The function must expose a typed lifecycle stage and typed refusal through its
owned IR contract. A disconnected project/pipeline ledger, a producer label,
or a diagnostic string does not satisfy this requirement. The state must
remain coherent in IR, SSA, later projections, serialization, cache restoration
and diagnostics. Keep one authoritative owner; other layers derive from it.
Immutable raw IR and later stage publications may have different lifetimes,
but they must refer to the same source generation and exact consumed bodies.
A cache cannot restore a later maturity merely because its metadata names it.

The ordered stages remain IR, Alias, Widening, Types, Structuring and Rewrite.
Each real producer publishes completion or a typed non-result, and each
consumer checks its actual prerequisites. No applicable facts is a valid
completed result when supported by a closed evidence census; it is different
from missing evidence. Method entry or method return alone proves neither.
Rewrite performs cleanup, naming and formatting only.

Internal Structuring rendering consumes the exact current Types publication
under a process-local producer lease. Rewrite rendering similarly retains its
checked Structuring input. A lease alone publishes nothing. Inner cleanup may
explicitly request Rewrite completion through
`record_function_rewrite_completion_8616`; the matching producer snapshots the
actual final AST only after its body returns normally. This includes final
naming, regeneration and validation work performed by the outer producer.
Before publication, it rechecks both the identical consumed Structuring record
and that record's current prerequisites. Exceptions discard pending requests;
duplicate requests and foreign or inherited producer authority refuse.
Standalone completion still records the actual output at the call boundary.
Foreign generators, replaced input evidence, expired contexts and other processes
retain the final Rewrite requirement. A render failure after an AST mutation
must propagate; returning previously rendered C would expose stale semantics.

Late semantic materialization remains a stage-order defect, even if its owner is
Types/Lowering: invoking that owner from CLI after Rewrite publication changes
the consumed output. The live-AST guard must keep refusing this change. The
current real-function investigation still observes late argument-width/type
reconciliation after the producer; delayed publication is not authority to hide
it or to re-certify an arbitrary mutation.

Segment input versions are immutable values even when the architectural
register later changes. Lowering consumes exact identities from the native
alias input registry, which excludes written and phi versions, together with
proven segment-entry state. Before projecting a local write onto mutable
runtime state, retain each observed input version once at function
entry and keep its uses bound to that local snapshot. Register names alone
cannot authorize this capture. Account for captured inputs in the same closed
materialization census as the architectural projection.
An input-registry entry alone does not prove origin across CALL: a callee may
change a segment without a local assignment. A required snapshot crossing
such a boundary must refuse unless independent origin evidence is available.

Native consumption requires the target stage and every prerequisite to have
current producer evidence. A missing producer is the typed
`STAGE_NOT_PRODUCED` refusal. `UNTRACKED` may describe a diagnostic lookup,
but cannot admit native consumption. A producer checks its prerequisites on
entry and publishes its own completion after producing its actual artifacts.
Raw SSA cannot stand in for Widening outputs, and a terminal-return render
projection cannot stand in for the Types/Lowering result or final structured AST.

Every actual producer output must participate in its readiness evidence. An
unsupported output cannot be silently omitted from the saved fingerprint set.
Return a typed `UNKNOWN_REFUSE` rather than claiming `CURRENT` for that producer;
keep the generated code and expose the cause. An unchanged real producer
aggregate must remain eligible, while in-place mutations of supported evidence
must invalidate consumers. Exercise these obligations on actual Alias and
Widening artifacts, not only small model fixtures.

A native AIL virtual variable retained inside a C dirty-expression node is
observable output data. Its index, variable identifier, bit width, category,
original identifier and tags all participate in the AST version. Immutable
native fields are checked by replacing the expression; writable fields and
tags are checked through in-place mutation. Native byte serialization alone
does not establish complete metadata: unsupported tag values can be replaced
with null by that serializer. Unknown tag objects therefore remain explicit
`FIELD_UNSUPPORTED` refusals in the structural observer.

Call-stack serialization counts retained Alias transfer data without rerunning
the transfer proof for every coordinate slot. That retained data is not current
authority. A fresh coordinate observation still reproduces its source and
checks the independent physical call/body proof. Canonical serialization shares
that immediate observation between its scalar SP projection and coordinate
record, then discards it. Each later observation must detect source mutation;
retaining the observation as a proof cache would violate this contract. Boolean
readiness queries must not serialize an invalid argument layout merely to
report a refusal.

Only an accepted Alias/call publication can supply a retained transfer value
to the coordinate census. Partial return transfers from a refused body remain
failure details. In particular, disagreeing returns must leave a closed ledger
of known fields and typed refusals without granting SP authority.

Traverse the complete finite provenance graph, rather than dropping fields or
truncating it at an arbitrary nesting depth. Encode enum identity and value
explicitly and use canonical owned IR/SSA/value encodings. Identity may detect
cycles and shared references during one observation, but must never enter a
content fingerprint. Discard traversal memoization after each observation so
later in-place changes remain visible. Unsupported cyclic boundary objects
remain typed non-results; they do not authorize pruning or guessed completion.

## Source and body authority

Local declaration retirement belongs to Postprocess before the final Rewrite
snapshot. The canonical scalar cleanup inventories body and parameter references
and consumes existing alias identities; it keeps unknown types, arrays,
pointer declarators and opaque code. The CLI reuses this owner so late cleanup
does not introduce a different declaration policy. DCE deletion-key retirement
remains a separate operation backed by actual eliminated definitions.

Internal Rewrite rendering uses a scoped producer lease after a checked
Structuring handoff. Each internal render rechecks the complete Structuring
input prefix, then applies Types contracts to the pending output. The immutable
consumed AST snapshot is not compared with the changing producer output.
Final rendering requires the completed Rewrite publication and actual AST
equality. The lease is tied to one project, function, generator, input version
and process; leaving the scope also revokes copied execution contexts. It is
held in a context variable rather than serialized artifact or codegen metadata.

The native producer's actual CFG knowledge base owns its function boundary.
An explicitly supplied `cfg.kb` may differ from `project.kb`; a builder attestation
therefore retains the live function manager it consumed. Re-observation queries
that manager without creating a function, then reads the current graph and
loader bytes. Removing the bound function is a refusal even when a competing
default-KB frame exists. The manager reference is runtime authority and is not
part of a serialized source revision or an artifact fingerprint.

A source revision binds the observed binary/control boundary, architecture
state and actual producing implementation. Module/qualified names, environment
labels and object identities cannot substitute for implementation content.
Use the canonical existing architecture/source authorities rather than
maintaining an additional definition in a higher layer. IR cannot import CLI.

An owned build boundary binds the exact consumed input and exact produced
artifact body to its source generation. Publication checks an existing binding;
it cannot manufacture source-body proof by observing the current project.
Copying a revision, removing a revision, or replacing a parent digest must not
make a foreign body current. A derived artifact requires actual derivation
evidence for that output, not just the name/digest of an authentic ancestor.

If source observation becomes unavailable, earlier binary-current proof is no
longer current. Keep independent, genuinely supported model/artifact proof
routes explicit in their own scope; never relabel an arbitrary unbound body
as current binary evidence. Looking up already registered evidence must not
relift the binary just to inspect its status.

## Evidence dependencies

Record the actual consumed and produced owned evidence. Each dependency must
identify a particular producer output using the same canonical representation
on both sides of the comparison. A digest of an individual input and a digest
of the whole output collection are not interchangeable.

Readiness must detect replacement and in-place mutation, including changes to
call effects and types when instruction bytes remain unchanged. Re-recording
the same mutated object must also invalidate its dependents. An identity
fallback or an unchanged stored digest cannot establish this property.
Unsupported evidence yields a typed non-result, never a guessed fingerprint.

IR and SSA body attestation encodes shared instruction expressions as a finite
canonical DAG. It must not expand every path through a shared expression into
a tree. SSA block order, instruction groups, definition targets and provenance,
versions, definition coordinates and refusals remain part of that digest.
Artifact owners share their non-block payload with diagnostic serialization so
the body projection cannot silently omit a newly added owned field. Lifecycle
authority and source attestation are excluded from the body payload itself.

No-effect instruction censuses may reuse immutable exact-byte relift facts
within a bounded block cache. Reuse requires matching architecture semantics,
block address, extent and every decoded byte; each census still checks the
current loader bytes and bound block provenance. Cached lift facts confer no
coverage or readiness authority. The cache retains at most 128 blocks, each
at most 4096 bytes and 2048 statements; larger working sets remain correct
when evicted. Native multiblock coverage must reuse a warm modest working set
and must refuse when even a late block's current bytes change.

Earlier stale/refused evidence blocks dependent stages. Every semantic
improvement retains a closed raw/normalized/classified/materialized/failure
census with documented units; classified facts cannot silently disappear.
Refusal preserves semantically live code and its cause. Successful C parsing
or compilation does not excuse call loss or failed equivalence.

## Verified restoration

A persisted bundle must bind the exact saved bodies, current binary source,
architecture and actual producer scope. Restoration verifies these bindings
and reacquires canonical authority at an explicit restoration boundary.
Dropping source metadata and publishing the body as an observed success is
not restoration proof. Test genuinely separate save/restore processes, a
valid cache hit, altered bodies, changed source, and changed producers.
Cache integrity here concerns coherent reuse of owned build output, not a
new authentication system against an attacker controlling the filesystem.

## Required acceptance evidence

The existing four stale-source/unknown-source/architecture/copied-revision
controls must stay green. The six additional parent controls must turn green
without weakening their assertions:

1. Mutating a real type object invalidates a dependent stage.
2. An unchanged explicitly consumed producer output remains eligible.
3. Losing live source observation cannot leave binary evidence current.
4. Replacing a producing callable while retaining its names changes scope.
5. An unstamped foreign instruction body cannot reach native lowering as
   current evidence.
6. A foreign SSA body with an authentic but unrelated parent digest cannot
   reach native lowering as current evidence.

Also exercise real producer/consumer hooks across all six stages, genuine
positive binary cases, in-place changes without re-recording, same-process
lookup without relifting, derived partial-scope artifacts, and cross-process
cache restoration. Check typed lifecycle/refusal transport and diagnostics.
Synthetic ledger tests supplement these controls; they cannot replace them.

Explicit `ExactFunctionRangeBoundary8616` inputs are legitimate native sources
even when the function manager has no entry. The canonical source revision must
carry a typed `CURRENT_FUNCTION` or `EXACT_RANGE` scope and, for an exact range,
its exclusive end. Bind the actual boundary the producer consumed, including
when a manager entry shares its head. Reconstruct the exact native inventory
from current bytes at reuse; a saved block list alone is insufficient. Only an
exact builder-body attestation may select this explicit scope. Copying scope
metadata into a foreign body must remain a refusal. IR, SSA, stage evidence,
serialized revisions and cache keys must retain the same scope; scope changes
invalidate reuse even when the byte inventory happens to match. Cache
restoration must compare this scope with the live consumer request; persisted
metadata cannot choose another valid scope for that request. Cover both source
kinds with fresh-process save, restore, changed-byte miss and foreign-generation
refusal, and retain a red/green control for different scopes over identical bytes.
An address-only lookup that loses that scope must not turn genuine native
production into a model path or silently disable source checks. Acceptance must
include successful explicit-range publication and the existing native scoped
entry tests, alongside refusal after genuine source loss and foreign-body
controls. Passing one side of this pair does not establish source coherence.

For any claim that a particular function is fixed, apply the repository's
focused before/after regression, semantic equivalence and call-preservation
acceptance contract. Broader repository failures must remain visible and
classified separately from the bounded results.

## Conditional CFG observations

A near-return continuation factory authenticates its independently supplied
entry before retaining a view. Projection consumption authenticates the offered
entry against the retained entry again, then checks exact call-row, callsite
index, raw artifact and boundary identities without replaying that same entry
a second time. The structural predicate cannot authorize evidence by itself.
Freshness remains independent at each producer/consumer boundary; no replay
result or caller-supplied authentication flag is reused across callbacks.
A projection producer that changes the native input, environment or retained
scope must leave no consumable projection. Tests retain both a complete
universal helper and a pending return-word helper requiring its actual near-CALL
frame, so improving unconditional CFG recovery cannot disable scope testing.

Caller-prefix retries select required CALL records through the census owner's
CFG ancestry relation and stop before the target instruction. Raw-boot and
registered-caller retries share this selector and their existing bounded
resolution session. Selection grants no coverage for omitted calls: the
independent prefix replay still refuses any necessary call lacking evidence.
Numeric address order cannot identify the prefix across backedges or loops.

Registered universal boot IR and raw boot intake share the same request-local
missing-service prerequisite owner. Retention requires a classified service
refusal, a source-bound boot body, no incoming caller alternative or declared
service, and an exact contiguous native entry prefix ending at the refused
INT with no preceding control transfer. Registered evidence must still be the
identical project-owned universal artifact; scoped or foreign bodies refuse.
Reuse rechecks source, index, architecture, registry identities and current
image bytes, and expires with the shared request budget. It grants no domain
or CALL preservation and cannot turn a refusal into successful evidence.

Native STORE replay accepts a physical span from either its already evaluated
address temporary or an independently proven segmented address evaluated from
the instruction-entry register snapshot. The latter is not a reread of later
register state. Absence of both proofs refuses. A known capture proves the
physical write span when segment state is unavailable; it introduces no
segment alias. Independently known segmented spans must agree with that
capture. CS, DS and SS follow the same rule.

Fused-transfer cache keys read typed dependency namespaces owned by path
memory, scalar classification, edge feasibility and fused transfer. These
protocol views retain the helper references actually held in each consumer's
module; the canonical definition elsewhere cannot substitute for a changed
consumer binding. Reading this metadata invokes no accessor callback. Changed
bindings invalidate cache reuse, while a fresh independent replay may still
prove paths that never consume the changed helper.
