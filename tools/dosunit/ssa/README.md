# SSA operator interpretation

`z3_ops.py` owns interpretation of operators over supplied Z3 terms,
including integer widths, byte-array memory effects and summary functions.
It does not import Z3 until a caller supplies the backend module.

Document constant normalization, solver admission, deadlines and verdict
policy remain outside this owner. Lazy x86 flag semantics use the existing
authoritative condition contract. Preserve unsupported-operation refusals;
do not approximate unsupported behavior to obtain equality.

Legacy engine helper imports alias these exact objects during migration.
Boundary controls cover import isolation, legacy identities, 16/32-bit
memory roundtrips and deliberately corrupted stores.

`translation.py` owns serialized term and assignment translation through
`TranslationContext`. Each context explicitly carries its document, inputs,
assignment index, memo cache, backend and constant-normalization policy.
Different output normalization domains require separate caches. The legacy
engine translation entry points construct this context; operator recursion
no longer imports or calls back into the engine.

`composition.py` owns block-output substitution, exact named scalar/array
binding, shared-DAG equality and guarded state merging. Existing deadline
checks remain at the same work boundaries. Keep comparison caches scoped to
live terms; the merge owner pins compared roots to prevent recycled identities.
When both branches store equal-width values to the same address over identical
memory, merging factors the store and selects only its value. Different arrays,
addresses, widths or endian operators retain the complete conditional arrays.

`guard_composition.py` constructs one-bit AND/OR guards with exact constant,
identity, complement and reconvergence rules. A pair of complementary branches
with the same incoming guard reduces to that incoming guard; its Boolean dual
is handled as well. Only shared live operand objects are matched, in constant
work independent of their depth. Distinct predicates and wider operands retain
the unreduced operation. DAG composition uses this owner to avoid carrying the
history of branches that have already rejoined; memory and call effects remain
in the state merge and are not removed by guard reduction.

`materialization.py` owns deterministic serialized assignment references,
shared-term memoization and input discovery through references. Neither module
imports the engine, architecture setup or a solver. Legacy engine helpers alias
these owners. Array `mem` binds program `memory`; other arrays bind their exact
names, and unbound arrays remain explicit inputs. A missing assignment or
expired deadline retains its existing refusal.

`identity.py` owns literal SSA and machine-code identity admission over an
explicit `ComparisonPolicy`. It has no backend or engine dependency. With
explicit-only comparison, normalization maps require solving even if raw
expressions or machine-code hashes match. The legacy engine helpers alias
these exact functions. Layout inference and proof orchestration remain in
the engine; their per-invocation policy comes from `../contracts/comparison.py`.

`flag_scan.py` distinguishes reachable abstract flag helpers from incomplete
expression coverage. It visits shared compound nodes once with a bounded DFS.
Dangling/cyclic references and exhausted scans remain incomplete; the comparator
reports `x86_flag_scan_incomplete`, not invented `uninterpreted_x86_flags`
evidence. An independently complete, helper-free mismatch still fails.

`x86_lazy_conditions.py` also owns complete CF/PF/AF/ZF/SF/OF materialization
for COPY, ADD/SUB/ADC/SBB and INC/DEC with concrete VEX operation selectors.
The Z3 evaluator and abstract-flag refusal scan share this admission contract.
Logical AF is undefined: LOGIC, shifts, rotates, multiplication and unknown
selectors remain abstract for the complete-flags helper. This does not widen
those operations merely because their CF or Jcc projection is already exact.

Unknown i386 flag helpers retain uninterpreted semantics but have architectural
result ranges: CF/condition are0..1; complete arithmetic flags occupy0x8d5.
This bound applies only to the known helper names with32-bit operands/results
and their required arities. It supplies no value assumption or exact-thunk
admission. SAT involving the remaining unknown semantics still refuses.

Abstract flag projections share one unknown arithmetic word for identical
thunk dependencies. CF reads bit0; a known Jcc condition0..15 uses the COPY
predicate interpretation of that word. Unknown selectors stay abstract, and
exact arithmetic paths retain priority. This enforces cross-helper consistency
without selecting incoming flags or canonicalizing cached callee state.


Dword SHL32 and SHR32/SAR32 have exact carry-only contracts (VEX selectors
24 and 27). CF is bit31 or bit0 of dep2, respectively. Dependency projection
drops unused operands; branch and complete-flags admission remain separate.
Zero-count preservation stays in the lifted control/data expressions. Byte and
word shifts still need count-sensitive definedness before CF can be admitted.


Flat32 nonempty REP SCAS/CMPS summaries select the exact width-specific SUB
thunk with zero cc_ndep; SCAS retains its accumulator dependency. Zero-count
guards preserve incoming flags. Other scan outputs remain abstract.
Flag evaluation additionally admits one conditional choice between two concrete
supported operation selectors. Both arms must have exact semantics; an unknown
arm retains conservative refusal. Flat32 REP admission also covers one operand
override (0x66) before or after the repeat prefix: word elements retain32-bit
counter/index state. Address/segment overrides and repeated prefixes still
retain native IR. Real16 override admission is unchanged.


repeat_counted.py owns completed flat32 MOVS/STOS counter and index arithmetic:
ECX becomes zero and indices advance modulo32 bits by count*width*direction.
The repeat memory summary retains all relevant inputs but drops arithmetic flag
dependencies; output flags remain preserved and observable. Zero-count guards
still apply. Exact memory contents and arbitrary scan lengths remain separate
obligations; this arithmetic does not imply stack preservation.


z3_repeat_memory.py evaluates flat32 counted REP byte/word/dword copy/store memory
for constant counts0..16. It preserves per-element read-before-write ordering,
inter-iteration overlap and modular addresses. Counts outside the bound remain
abstract instead of being shortened. The expansion can increase comparison
cost; native acceptance must check its effect on composition deadlines.

`ssa_output_lemmas.py` can search individual scalar counterexamples after an
array equality query is inconclusive. It checks at most eight nonidentical
scalar outputs, with500ms per probe and a shared cap of one quarter of the
remaining deadline, at most4s. Only SAT can terminate this search successfully.
UNSAT or unknown for a subset never proves the complete comparison or removes
outputs from its fallback query. Input constraints and proved array substitutions
are preserved; each temporary query is popped before returning its model.


`ssa_shared_subterms.py` proves scalar identities after replacing identical
non-leaf bitvectors on both sides by shared arbitrary values. This is a stronger
query: an abstract SAT/unknown result is never a concrete counterexample.
`ssa_modular_scalar.py` provides an exact integer-polynomial proof lane for
addition, constant multiplication and concatenation. Every intermediate width
truncates modulo its power of two; a truncation is removed only when modular
congruence proves it invisible after the surrounding constant multiplication.
Unsupported terms remain arbitrary bounded atoms, and the complete output query
still observes memory, flags and all declared registers. Both lanes consume the
existing caller deadline and only discharged equalities refine later queries.

Recognized scalar and memory operators validate operand count before backend
evaluation. Binary arithmetic, comparisons, shifts and wide multiply require
two operands; unary operators require one; ITE requires three; loads require
two and stores three. CONCAT requires at least two operands and remains
variadic. Wrong counts raise `DosUnitError` with operator and counts instead
of dropping trailing operands or exposing backend indexing errors. Summary
operators retain their separate contracts. Regression coverage includes a
complete comparison that must reject malformed `or(0,0,1)` rather than prove
it equal to zero (`test_ssa_operator_arity.py`).

Bound root-domain obligations may mark `literal_constants: true`. Their
predicates are evaluated without code/global constant normalization; all
other obligations retain their existing interpretation. This is used for
argument offsets, buffer lengths and stack extents, whose meaning must not
change when code/data addresses move. Domain satisfiability remains mandatory.

`obligation_codec.py` stores shared bound predicates as a self-contained DAG.
The record retains its metadata and adds `predicate_encoding:
"inline_ssa_dag_v1"` and a topologically ordered `predicate_assignments` list;
`predicate` becomes a local reference or inline leaf. References never borrow
the enclosing function's assignment namespace. The decoder restores shared
nodes and rejects dangling/forward references, duplicate IDs and unknown
encodings. Solver input discovery, literal normalization policy and nonempty
domain checks apply equally to decoded and inline predicates. Completed call
reports compact x87 conditions only after the solver result is established;
encoding neither removes conditions nor changes a verdict.

Array-output lemmas may compare the finite union of written addresses when
both arrays are Store/If expressions over an identical base array. Every
branch and possible alias is retained. Different bases, multidimensional
stores or exhausted scan limits keep the full extensional array query.
No memory-initialization premise is added by this reduction.

Scalar output lemmas first try exact read-over-write expansion when it changes
the simplified terms, then try shared-subterm abstraction. The fallback retains the
original address constraints and every alias, accepts only UNSAT, and consumes
the existing scalar-lemma deadline with a maximum 500ms query.
Proved equalities are consumed as expression substitutions rather than redundant
solver assertions. Reasserting a discharged whole-array equality can reintroduce
the expensive array problem that its finite-store proof already eliminated.
Discharged scalar outputs are removed from the residual comparison rather than
substituted into other outputs. This avoids expanding saved-register inputs back
into large read expressions. Every undischarged output remains in the query.
Exact read queries copy all active assertions into an isolated solver so earlier
array queries do not contaminate their search state; deadlines are unchanged.

Block composition balances bounded same-width integer ADD chains. It preserves
ordered operand multiplicity and literal leaves, including later normalization;
no constant folding or width-boundary crossing is performed. Existing pairs
retain DAG sharing. A bounded scan leaves oversized diamonds/cycles unchanged.
This reduces loop-state depth without raising expression or execution budgets.

`literal_read_reduction.py` simplifies auxiliary return-address queries before
Z3 translation. It forwards whole same-endian stores and skips writes whose
byte regions are proved disjoint by circular relative offsets or explicit
unsigned input intervals. Unknown aliases and partial overlaps remain intact.
It consumes the original return-query deadline. This owner is restricted to
literal-address queries without relocation normalization; it must not rewrite
ordinary normalized comparison documents. Original constraints and obligations
remain in the final proof, and no memory contents are assumed.

Root-bound call composition now attempts generic summaries for closed internal
leaves before repeated contextual expansion. The cached template retains all
register, memory and checking-obligation outputs; each caller substitutes its
own inputs and still proves its return target. Failed proposals consume the
original budget, are attempted only once, and fall back to contextual execution.
External calls, I/O, traps and nonlocal transfers remain with their existing owner.

The DAG execution view partitions overlapping lifted blocks at discovered
instruction entry boundaries, preserving the original CFG for induction and
matching. Its composer joins states before returning direct/import
calls, delegates complete call effects to the execution owner, then composes the
shared suffix once. Incoming reach guards, IAT checks, return proofs, external
history and all memory effects remain. Cycles, unresolved indirect calls, native
summary obligations and nonlocal transfers keep their existing path owner.

Unread dependency projection commutes through stores and closed pointwise
choices. Its free-index check memoizes shared Z3 subexpressions by both AST
identity and binder depth, retaining each AST until the projection completes.
This prevents repeated DAG walks without transferring a closedness result
between different binder scopes. No actual program-memory state is masked.

Flat32 REP SCAS/CMPS nonempty summaries exclude incoming lazy arithmetic
flags: each iteration overwrites them before the repeat condition is tested.
Direction remains an input. The zero-count guard restores the entire incoming
state, including flags. This projection does not apply to the real16 combined
flags carrier. Native regression controls cover byte/word/dword scans, zero
count with observable LAHF, and opposite directions.
