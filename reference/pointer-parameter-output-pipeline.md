# Pointer-Parameter Output Pipeline

Semantics owns each exact direct STORE and each versioned indirect STORE site,
segmented relative range, and terminal-path disposition. An indirect STORE in
the same segment neither disproves an independently proven direct STORE nor
proves that the two effects are disjoint. Semantics must retain the direct fact;
Alias and interprocedural Lowering own the relationship between the effects.
Alias may bind an indirect base only when every STORE site resolves to one exact
positive-BP parameter source. Competing or unknown sources refuse atomically.

Widening joins touching or overlapping lanes only when parameter ownership,
segment, and terminal-path coverage agree. Gaps and adjacent lanes with
different coverage remain separate views; overlapping incompatible coverage
refuses. Adjacency does not prove a pointee type, array, struct, or extent.

Types/Lowering maps each view to one exact logical callee input and publishes
that contract before legacy input collection.
IR now traces a call argument's 16-bit near-offset arithmetic as an exact
modular affine expression with stack-source ranges, coefficients, and SSA
definition paths. Types/Lowering cross-checks that proof against the structured
callsite source and retains the physical outgoing byte definitions. The offset
expression alone has no segment or pointee width.

The caller-target Lowering publisher separately joins that exact near-offset
expression with the callee output view's proven segment, relative offset, and
width for every direct callsite. Publication is all-or-nothing per callee;
missing expression provenance, carry-dependent arithmetic, target or width
conflicts, unmatched parameter storage, incomplete callsite census, and
publication conflicts remain typed refusals. The published target is evidence
for later object/effect materialization, not a pointee-type decision. A dynamic
target must not be misrepresented as an exact direct
`StorageIdentity8616.MEMORY`.

The interprocedural storage collector partitions those targets by exact
caller/callsite and retains them as `pointer_effects` alongside, but distinct
from, direct Alias-owned memory effects. Types/Lowering groups all views for one
callee output source into a `PointerParameterMemoryOutputObject8616`. The
accepted function contract carries those objects and their original effects;
it does not fabricate scalar `LIVE_OUT` trials for dynamic targets. Atomic
publication revalidates every source, view, callsite identity, and retained
effect and rejects duplicate, missing, conflicting, or orphaned projections.

Rendered C, assembly text, names, sidecars, and postprocess output are never
evidence for this pipeline.

Near-pointer return projection has a separate address-representation gate. A
callee's proof that `AX = (base + scale * index) mod 65536` establishes an
offset computation, not a C pointer expression: its input may still have
unknown pointee width, and the input offset must be bound to a proven SS/DS
address domain at each caller. On portable-flat C, ordinary pointer addition
does not guarantee 16-bit wrap; `PTR_U16` extracts host pointer bits, not a
guest offset; and `SEG_PTR` requires an independently proven segment. Types
must retain a typed refusal unless the caller binding, pointee width (if a
typed pointer is projected), modulo arithmetic, and both target runtimes
agree. Any accepted return type and expression must be committed atomically
and replayed after Structuring regeneration, then validated with boundary and
segment-distinguishing inputs. Downstream dereference width alone must not be
back-propagated as the callee input's pointee width.

For far DX:AX results, Lowering may prove caller use only when exact
CALL_OUTPUT pieces flow through an exclusive straight-line successor into
independent DX-to-ES and AX-to-BX copies, with no clobber before a complete
logical ES:BX access. This evidence records the access width but does not
establish the input's pointee family, array extent, or a representable C
return expression. Function and callsite pointer declarations must remain
unchanged until those separate obligations and the full caller census close.
The direct-call census decodes an immediate far CALL as one exact 20-bit code
target, separate from the legacy near-call low-word identity. Its bounded AX
scan can pass an exact DX-to-ES copy without treating that copy as AX use;
the independent Lowering proof above must still establish the complete paired
DX:AX use at each caller. A complete direct-call inventory alone is neither a
four-byte return-type proof nor permission to publish a C pointer.
The Lowering caller-census join requires one exact paired-use proof per included
direct callsite and refuses open, missing, duplicate, extra, mismatched, or
unproven witnesses. Its closed five-stage counts are diagnostic evidence only;
the join does not change function or callsite declarations. Each paired-use
proof now binds the exact typed CALL target to its CALL_OUTPUT provenance, and
the join requires that target to equal the direct-call census target. Foreign
targets refuse; alias-normalized equivalence requires its own proof before
publication.
The Lowering collector now obtains the direct-call census itself, checks the
callee's DX:AX terminal carrier from binary paths, and resolves each caller's
exact SSA CALL_OUTPUT pair before this join. Its result remains a nonpublishing
caller-use fact; a guest segment:offset return expression, independently proven
pointee family, and atomic function/callsite contract update are still required.
An additional Lowering preflight now binds the callee's proven BP-word IR
inputs to canonical structured C variables and constructs a candidate
`SEG_PTR`/`MK_FP` expression with explicit 16-bit offset wrap. It casts signed
input words to unsigned bit-pattern views before C shifting or segment-macro
evaluation; otherwise a negative signed word could have undefined or
sign-extended host behavior. The candidate is not installed in C. The FAR
SimType projection independently refuses without a supplied pointee family
and rejects width-only matches against existing generic pointers or distinct
pointee types. No caller-owned object-family proof or atomic publication has
been added, so neither preflight makes a pointer-return acceptance claim.
