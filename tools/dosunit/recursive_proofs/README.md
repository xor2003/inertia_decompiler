# Binary-derived recursive proof components

These components check local obligations for a matched recursive real-mode
component. They do not yet establish whole-binary equivalence. The public
`compare-binary16` command retains its existing shared arbitrary input-memory
contract; this package's initialized MZ domain is a separate contract.

`real16_image_bound_domain.prove_image_bound_real16_domain` connects immutable
MZ bytes, initialized loaded-memory relations, bootstrap effects and proposed
joint transitions. A proposal supplies no semantic proof. The native binder
independently decodes the actual bytes and checks the proposed effects.

`loaded_byte_relation_proof.seed_loaded_array` constructs the actual literal
loaded bytes over arbitrary background memory after revalidating the snapshot.
It supports the declared real16 and flat32 physical array contracts. This
constructor is for loader initiation; later cutpoints must retain live memory
and prove the needed dynamic invariant. Relative XOR transport by itself does
not constrain a free input array to contain those literal loaded bytes. This
helper supplies the loader seed used by `real16_fetched_code_invariant`.
That owner binds every exact fetched span to immutable loaded bytes, establishes
the absolute code predicate and consumes each universal store-prefix witness.
Missing requests, spans, consumers, model identity or ledger rows refuse closure.

`real16_image_bound_joint_proof.check_image_bound_real16_joint` consumes that
receipt, proves every fetched store prefix and its absolute loaded-code invariant,
original operand segment scope,
physical byte bounds, source-bound native control coordinates, actual entry frame,
full native transition and both
sides' finite stack-frame invariant. It retains complete dispatch and atomic
lockstep progress without assuming any recursive callee summary. The ghost
stack frontier saturates at actual modular wrap and preserves physical aliases.

The control-coordinate prerequisite independently checks full loaded near16
JMP/CALL/conditional destinations against WORD-wrapped architectural targets.
RET compares control with the actual pre-terminal SS:SP word. Bootstrap uses
its real constant CS; component cutpoints use the separately derived scalar
domain. Target-set evidence does not establish branch guards or reachability.
Known high-address/wrap mismatches stay refused until the frontend and its
consumers can be repaired together without losing direct-call capability.

The report removes `CALLER_ENTRY` and `CODE_MEMORY` after all composed obligations
succeed. `FAULT_DOMAIN`, `ADDRESS_MODEL` and `ENVIRONMENT` remain
explicit requirements. Successful local premises yield `CONDITIONAL`, with
`binary_equivalence_proved == False`; no consumer may promote this to
`validation=passed`. Code-prefix or address geometry evidence alone cannot
close all of those requirements.

Every nested producer shares the original absolute deadline. A typed child
resource refusal remains `DEADLINE` through code, entry, native and joint controllers.
Partial child receipts, required rows and fact counters remain in the report.
Incomplete, duplicate, stale, vacuous or unsupported evidence grants no proof.

Semantic source identities read fresh bytes at every independent boundary.
A capture may share one native fingerprint inside one nested hash traversal;
it must not cache identities across proof boundaries. Source path-key creation
preserves pathlib keys and outside-root errors without caching files, source
sets, timestamps or digests. Namespace promotion changes model identities and
invalidates old receipts.

Controller accounting tests run in the curated fast lane. Actual MZ-byte joint
and refusal controls run in the `binary-relational` default/expanded lane;
these include real SSA/Z3 and keep the 120,000 ms joint proof budget. Concrete
execution, architectural fault/event closure and both flat32 adapter acceptance
are separate obligations in `reference/binary-behavior-equivalence-plan.md`.
