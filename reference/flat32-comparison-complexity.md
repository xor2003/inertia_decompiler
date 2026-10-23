# Reducing flat32 comparison complexity

Objective: compare more than 80% of original functions across the MSC8 PE stages,
as explicitly reset by the user on 2026-10-12, with conditional results separate.
The original manifest remains the denominator. Every accepted coverage improvement
must add newly proved original functions; moving to another refusal is insufficient.
For repeated blockers, select a complete native-function cohort and resolve its
remaining obligations together before reporting the technique as a coverage gain.
Budget increases, renamed refusals and unit-test totals are not coverage gains.

Use the reviewed ABI catalog for the current coverage run. Retain old-catalog
runs for controlled implementation comparisons, but do not mistake them for
the best currently supported scope. Publish changed premises with verdict deltas.

## Accepted coverage increase: explicit entry memory ranges

The v63/v64 implementation adds six conditional native proofs: CL fd_handle
and fd_set_textmode, C23216 fd_handle, C33216 fd_handle and fd_set_textmode,
and C1XX3216 fd_set_textmode. Each failed
before the explicit table-count range and proves afterward; no new unconditional
proof is claimed. The common mechanism is a typed predicate on root input memory,
not deleting stores or constraining descriptor arguments to test cases. Native
changed-errno controls both fail. Initializers equal 64 but do not prove the
live-entry invariant; range, ABI, private-frame, ESP and relocation assumptions
remain published. Range constraints do not apply to later stores or loop cuts.

C33216 additionally requires the existing `--global-alias-source` option to bind
candidate `_err_id` to the original address-encoded label. With that option held
constant, removing the memory range changes both proofs back to failed.
Whole-CL v64 exposed a crash while serializing a non-concrete scalar model value.
The witness fix retains exact differences and reports incomplete scalar evidence
without inventing a value. Full v65 now completes: 3 passed, 69 conditional,
5 failed and 228 refused over 305 original CL functions, versus 3/64/8/230 in
the prior complete reviewed-catalog run. No unconditional gain is claimed.

## Allocator proof milestone (v74; full-corpus gate pending)

CL `sub_1D5C0` and `sub_210C0` now prove conditionally as complete native
functions. The positive v74 pair takes 7.746 seconds; both zero-return PE
mutations are rejected as opaque external countermodels. Removing the explicit
external stack frame yields two composition-budget refusals, not a concrete
Windows counterexample. Final focused regressions: 205 passed; scoped MyPy over
eight owners and startup architecture checks pass. Full CL v74 confirms 3 unconditional and 71 conditional functions of 305.
It exposed a publication regression hiding five existing counterexamples as
refusals; v76 repairs exact-map admission for counterexamples. A native seven-root
check now gives 5 failed and 2 conditional with no refusals. The corrected full
CL rerun and general pipeline remain pending; no unconditional gain is claimed.

The shared treatment combines four independently explicit mechanisms:
- Singleton entry-memory ranges seed a side-local root execution view, retaining
  canonical predicates. Later writes and arbitrary loop cutpoints stay live.
- Exact forced path equalities simplify expressions before a bounded solver.
  Positive disjunction arms never become assumptions.
- `preserved_memory_ranges` frames only the external transition over declared
  inclusive physical intervals. It proves neither pointer freshness nor
  allocation success and does not suppress subsequent native stores. The same
  physical coordinates must describe the region on both sides.
- IAT slot identities come from loaded DLL/export metadata. Every slot is
  relocated before adjacent byte ranges are combined. Normalizing just the
  endpoints of a physical IAT interval is incorrect when imports are reordered.
  Publication independently re-derives the map and retains exact-map admission.

Array equality now uses an unconstrained fresh address when a shared finite
store footprint is unavailable. This is exact extensional disequality, not a
sampled set of addresses; selecting from lambda-backed memory exposes scalar
byte expressions to Z3. Changed boundary bytes remain counterexamples.

Premises remain visible: callback DWORD 0x27b70 equals zero at root entry,
ESP lies in 0x7f000..0x80000, private frame is 28 bytes, and HeapAlloc has the
returned-region contract with external preservation of 0x7efe4..0x8000b.
Initializer bytes alone do not establish the callback premise. The corresponding
ABI and external declarations are in the reviewed CL catalogs.

## Measured bottlenecks

Frozen CL v58 sub1BA28 diagnostic:257 block visits,200 in error_map across two
uncached calls. Generic leaf reuse in v59 reaches more calls under the same cap;
it builds error_map once (145 generic block visits), then substitutes the template.
The native eight-root v59 cohort still has8refused and no coverage gain.
A prior return query reduced783 assignments to a constant through exact store
forwarding/disjoint-write elimination. This removes one solver bottleneck but
cannot remove path enumeration, repeated expansion or loop proof obligations.

Frozen CL v61 whole-manifest check: 305 functions, 3 passed, 62 conditional,
10 failed, 230 refused; every function status matches v55 on identical input
and auxiliary catalogs. Runtime was 400.79s versus 291.28s for v55. This single
comparison demonstrates no end-to-end speed or coverage improvement. All 1873
source/input paths were verified; the source snapshot stayed unchanged.
The first v61 run exhausted /home while writing JSON and is incomplete evidence;
the accepted complete report came from the retry in /tmp.
The selected refusal frontiers are now: loop induction52, import-target
preservation46, inline-depth22, CFG-shape21, return-target mismatch18 and
missing mapping15. Import preservation was61 in v55; reaching a later blocker
did not complete any additional function. These counts select one reported
frontier per function, not every potentially overlapping underlying cause.

The common-call regression retains one call expansion after eight diamonds.
A sys.monitoring diagnostic of its join guards (producer identities unchanged)
found up to 7906 tree occurrences but only 102 unique DAG nodes, depth22. Keep
DAG sharing through substitution/serialization; measure Boolean guard reduction
before adding it. Neither the occurrence count nor this synthetic example alone
establishes a native-function bottleneck or a whole-program performance gain.

## Implementation order

1. Generic leaf templates (implemented): build closed internal bodies once,
   substitute actual caller inputs, replay checking obligations, prove every
   return. Never cache root-bound state by entry. Failed proposals are attempted
   once and retain contextual fallback. This saves repeated execution work;
   substitution still traverses the template and does not eliminate its SMT body.
2. Join before continuing (implemented for admitted closed DAGs): extend the existing DAG composer to calls by extracting
   a one-call state transition from the recursive continuation. At each join,
   merge exact guarded states once before composing the suffix. Preserve incoming
   reach guards, external checks, obligations, return proofs and all memory.
   Cycles require their existing induction owner. A diamond-chain regression must
   show bounded block work without changing trace order or assuming equal states.
3. Relational callee certificates: after proving a pair of bodies, use a common
   transition at their paired call sites. Validate the precondition and relation
   of all inputs read by the callee, including relevant memory and architectural
   state. Preserve the output relation, written memory, external-event ordering,
   exceptions and termination contract. A proof of one projected ABI output does
   not certify full machine-state equality. Cyclic call dependencies require an
   SCC induction proof; never assume a callee equal because its caller needs it.
4. Precise memory footprints: separate the bytes actually read/written by a
   transition from retained memory. Use proved address intervals or object
   provenance; unknown aliases keep the complete query. External API contracts
   are explicit premises, not inferred from a symbol name. Optional writes must
   retain old output bytes on no-write/failure paths; an unconstrained fresh value
   depending only on scalar arguments does not model that relation correctly.
5. Loop relations: compare loop-carried state at paired boundaries and prove
   initialization, preservation and exits, including progress/termination where
   required. Handle unequal iteration grouping through the existing macro-step
   owner. Do not prove bounded samples and claim an unbounded loop equivalent.

## Certificate and cache boundary

A reusable equivalence needs source/binary digests for both sides, proof scope,
ABI/output contract, constant normalization, memory relation, input predicates,
external contracts and checking obligations. Dependencies must be explicit and
acyclic unless jointly proved. At each call discharge the predicate in the actual
caller state. Conditional premises stay attached to all consumers. A cutpoint
countermodel alone is not a reachable original-function mismatch.

Common instructions or SSA subgraphs can be shared by congruence once their
required input relation is established. Matching opcode bytes identify a common
operation, not equality of unrelated operand states. Backward slicing must retain
all dependencies of observed memory, returns, external events and exceptions.

## Next experiments and their actual acceptance criteria

The next substantial reduction is paired relational comparison. Independently
expanding both functions first can duplicate the same expensive computation
before the equality solver sees it. Extend the existing region/cutpoint and
callee-lemma owners so a paired transition discharges only the outstanding
relation. Do not create a separate comparison framework.

1. **Backward demand through a common suffix.** Start with the declared observable
   outputs, then propagate their equality requirement backwards through identical
   transitions. An unconditional constant assignment removes the old destination
   from that requirement; `leave` removes the old stack pointer but introduces
   frame-pointer and saved-frame memory dependencies. A near return has the same
   transition on both sides without a new semantic premise. The enclosing proof
   still needs the return address and observed final stack state related. Test
   overwritten-input differences as positive controls, and changed return slots,
   saved frames, guards and visible stores as negative controls. Measure the
   number of live boundary terms and solver assertions, not stripped byte count.
2. **One shared result for a proved pair of callees.** A reusable pair certificate
   can replace both expanded bodies with corresponding results and effects after
   its actual input/memory relation is proved. This goes beyond a generic template:
   the expanded callee formula disappears from the caller query. First restrict
   to closed nonrecursive scalar callees, then add proven memory footprints.
   Require a real caller that formerly hit a work limit to become proved under
   unchanged budgets; reject changed arguments, hidden memory reads and lost
   writes. A common opaque result without the certificate is an assumption.
3. **Frame memory locally.** Carry equality of untouched memory separately and
   compare the finite modified footprints. Discharge read-after-write and
   disjointness facts before sending whole arrays to SMT. If an address can alias
   an import slot or return slot, keep that obligation; equal initial data layout
   does not establish preservation after earlier writes. Count residual symbolic
   loads/stores and repeat the pointer-alias negative controls.
4. **Synchronize external calls as events.** At matching call sites, prove the
   import identity, arguments and relevant memory relation, then use the same
   admitted external contract with related nondeterministic outcomes. Preserve
   order and count of events, optional writes and failure paths. Merely invoking
   the same API twice does not make its two independent results identical.
5. **Use cheap matching only to propose proof boundaries.** Hash decoded operations
   or normalized SSA DAGs with widths, endianness, decode mode and verified address
   mappings. Check actual structures after a hash hit. Direct relative targets,
   RIP/EIP-dependent operations and embedded pointers require binding, not just
   identical bytes. Unmatched parts retain semantic comparison; matching alone
   never promotes a verdict.

Straight-line boundary transfer and DAG scheduling can reduce traversal work
without making all solver work linear. Merged memory and guards can still grow;
loop invariants, aliasing and differing iteration grouping remain separate proof
obligations. Report traversal, expression size and elapsed time separately.

## Acceptance

Use real original/rebuilt function pairs plus mutations of return values, memory,
call arguments, output pointers, guards and event order. Compare identical commands,
input catalogs and unchanged limits on frozen sources. Record whole-function
verdicts, actual block/term/query work and elapsed time. Faster isolated queries
or a later refusal are useful diagnosis, not completed function coverage.

Current ownership: call execution/scheduling own template reuse; DAG composition
owns joins; relational region/macro proof owns cutpoints; SSA read reduction owns
literal auxiliary memory simplification; external-call contracts own API effects.
Extend those owners rather than add a second comparator framework.

## Cross-stage allocator transfer (v75)

The same machinery gives three further conditional native proofs:
C23216 `sub_5CD10`, C33216 `sub_3A7C0`, C1XX3216 `sub_794D0`.
All three reject both a missing callback-entry premise and an isolated PE
zero-return mutation. Callback coordinates and stack domains are stage-specific,
not inferred from image initializers. The reviewed ABI/external catalogs retain
the exact premises. Together with CL this is five new conditional proofs across
four PE images. Caller `sub_1A3F5` still exceeds the composition budget; optimizing
its relational composition is pending, and a stronger allocator assumption is
not yet justified by that timeout alone.


### CL caller proof: exact compact stack projection (2026-10-13)

Integrated `sub_1A3F5` improvement after native staged proofs v90/v91/v92:
previous `compose_budget_exceeded` becomes CONDITIONAL under the unchanged
explicit callback-zero, entry-ESP, external HeapAlloc frame and private-stack
lifetime premises. Latest staged receipt: CL-caller92,21.837s,1880 source/input
paths checked. Count ONE new original function; no unconditional gain.

Contiguous excluded stack bytes are coalesced without filling holes; long
repeated-byte stores use exact modular Lambda fills, including address wrap.
Lambda array sorts receive exact fresh-index disequality checks. Final outputs
are proved independently with every original assertion and the original shared
deadline; exact read-over-write and conditional-select simplification is local
to each query. No allocation-success/freshness premise is added.

Main-tree focused acceptance:73 tests passed in68.60s; scoped lint passed.
Staged MyPy passed. Mutated store-zero-to-one PE was rejected as opaque external
countermodel (not a concrete mismatch); removing callback premise was refused.
Main-tree 305-function CL acceptance is pending; do not extrapolate the staged
single-function gain to whole-PE coverage. Native-constants relocation loop
regression remains failing. The older required pipeline completed its general
unit phase with198 failures/15469 passes/1xfail, then was deliberately stopped
before remaining phases to integrate this slice; it is not a green full gate.


### Full CL94 acceptance (2026-10-13)

The integrated compact-memory/output-query slice preserves every prior CL
proof and adds ONE conditional original function,sub_1A3F5. Full305 original
functions:3passed,72conditional,5failed,225refused. Verified1880 input/source
hashes; receipt current-full-CL-reviewed94-receipt.json. Delta againstCL74 has
one gain and zero losses. The five mismatches were formerly mislabeled refusals
by the separate import-admission issue; they are not additional proofs.

Measured full runtime738.59s versus486.50s forCL74: the end-to-end runtime has
increased and no overall speedup is claimed. Unconditional/conditional coverage
remain separate; >80% of all6786 original functions is still unachieved.
CL93 used the point-override external catalog in error, losing42 import proofs.
CL94 restores the full305-root catalog and overlays the canonical overrides;
only changed actual external contract is sub_1A3F5/HeapAlloc.

The old required pipeline is interrupted after198 unit failures. Main focused
73 tests, lint and scoped MyPy passed. A new isolated loop experiment moves
native-constant inference before the unrestricted graph check: the previously
failing relocation linked-list test passes in6.88s (20s budget), both mutated
variants are rejected. This experiment is not integrated or counted as native
coverage until new original PE functions are proved.

Fresh peer-loop98/99 controls subsequently tested seven original roots across
C13216, C1XX3216, Q23 and LINK: both the current engine and early-constant
variant proved four conditionally and refused three. The variant remains
unintegrated. These controls also show that historical refusal lists are stale;
always reproduce a current baseline before crediting an improvement.

Peer-loop104 adds one conditional C13216 original function, sub_23934
(nth_pooled_string). Its reviewed catalog declares a 32-bit return and zero
private stack bytes. Root EDX is outside that explicit ABI observation; internal
loop dependencies and all memory remain subject to the induction proof. The
same function refuses without this contract (peer-loop98 baseline). A copied
candidate with ADD EAX,2 changed to ADD EAX,3 is rejected (peer-loop103), with
EAX and memory transition mismatches. Canonical-catalog native proof completed
in12.720s; source/input hashes and compressed report are recorded in
`.cache/ssa-capability-audit/C13216-peer-loop104-abi32-receipt.json`.
Existing relocation premises remain explicit. This is one conditional gain,
zero unconditional gains, and does not establish whole-corpus coverage.

Peer-loop108 adds sub_238F0 (fnptr_tail) under the same explicit 32-bit return
observation with zero private stack bytes. A joint canonical-catalog rerun
proves both it and sub_23934 conditionally in22.231s. The current baseline
refuses sub_238F0; a copied candidate returning2 instead of1 is rejected with
an EAX mismatch (peer-loop107). Thus the two catalog additions provide two
conditional original-function gains; no unconditional gain is claimed.
Evidence is in the corresponding C13216-peer-loop108/107-abi32 receipts.

An isolated attempt to generalize low-bit register demands to all GPRs did not
prove next_entry/sub_4073C: its remaining ESI mismatch is at a return, whose
observation must stay exact. The experiment is not integrated. Register
liveness cannot replace required memory-alias or restored-state invariants.

Peer-loop113 also proves C1XX3216 sub_202C8 (argument_seek) conditionally with a
reviewed 32-bit return and zero private stack bytes. Fresh no-contract baseline
109 refuses; the canonical-catalog proof completes in11.907s. A copied candidate
adding3 instead of2 to the returned pointer is rejected (112). The reviewed
61-root peer cohort now has7 conditional proofs versus4 in its fresh baseline;
54 remain refused. This selected cohort is not the full6786-root corpus.
The receipt-hashed ledger is `.cache/devin-x87/peer-loop116-cohort-summary.json`.

Diagnostic profiling114/115 found375 repeated literal-false SMT queries among
472 solver checks on one unresolved native root. Exact simplification already
discharges those equalities. Isolated stage116 skips the unnecessary check,
preserving the original domain and deadline;46 focused tests and lint pass.
Full305-root CL117 is the pending coverage/performance acceptance experiment;
the optimization is not yet integrated or credited with any coverage gain.
