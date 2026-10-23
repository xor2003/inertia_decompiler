# Types and lowering

This package owns typed storage and object materialization, argument and return
lowering, and generated C representations. Alias and widening evidence comes
from their owning layers.

`entry_stack_pointer_capture.py` owns one immutable entry-SP scalar per function
activation. Return materialization and prospective call-input lowering share
its local and source-use census. Every retained use must reproduce from the
current codegen IR publication; the actual initializer, scope and single write
must also verify. The marker is evidence to check, not authority to trust.
`numeric_stack_pointer_returns.py` consumes this owner for exact return values.
The runtime call-input consumer is still tracked as open in
[`p0-call-return-stack-effects.md`](../../reference/p0-call-return-stack-effects.md).

Private tests live in `tests/lowering/`; shared behavior tests live in
`tests/integration/`. Import these owners directly.

Register-version capture consumes proven definition/use identities. Each
selected definition evaluates its RHS once into a typed local and then
publishes that local to the original architectural register. Dependent RHSs
see prior captures before pointer-to-offset projection. Preparing N captures
visits their individual RHSs and uses one full-function replacement walk;
publication destinations remain outside that replacement. Branch dominance,
unknown effects, evidence counters and idempotence retain their existing
contracts. `test_x86_16_gp_register_versions.py` covers these requirements.

The read-order owner in gp_register_read_order.py distinguishes pure assignment
operand reads from the destination store. GP entry placement uses separate
read/store phases only for that proved shape. Calls, nested writes and control
constructs remain atomic; shared expression nodes use their latest occurrence.
Register identity and live-in evidence are still required independently. The
compiled boundary and refusal controls live in test_gp_entry_read_order.py.

Call-input lowering publishes immutable status, refusal and census records through
`inertia.pipeline.call_stack_input_outcome`. Binding and argument semantics remain
in Lowering. Postprocess reads this publication without importing semantic
materializers: a refused Alias call-position proof prevents rollback cleanup
retries from attempting to supply that proof. The original C tree and refusal
remain intact. Backends without a publication return no observation; malformed
publication values raise instead of silently becoming absent evidence.


`access_profiles.py` groups existing access-trait evidence into typed profiles,
induction candidates, and storage naming hints. `storage_objects.py` owns the
resulting typed records and refusal artifacts. These modules consume existing
identity/evidence; they do not establish storage identity from names. Import
them directly from `inertia.lowering`. CLI compatibility exports resolve to the
same canonical objects, and decompilation cache provenance includes both source
files. The bucket decoder returns its validated integer count together with
the decoded key, offset, and width, so consumers retain the checked type.

`ScopedCallPositionAuthority8616` (entry_stack_pointer_capture.py) is a
read-only projection over one retained `ScopedCallStackPositionResult8616` —
the scoped sibling of a plain `CallStackPosition8616`, never a decorated
scalar. Its `position` mirrors `result.proof` and cannot be assigned, and
equality/hash bind artifact, call, carrier, both scopes and context
identity, so equal offsets never merge distinct authority. Every scoped use
revalidates through `is_current_for` against the OFFERED
`ScopedCallStackContext8616`: the exact callsite binding must carry the
retained carrier, a fresh Alias replay must reproduce the retained
position, and an offered context other than the retained one must
independently reprove — empty, partial or foreign binding sets refuse.
`lower_call_stack_inputs_8616`/`apply_call_stack_input_lowering_8616`,
capture prepare/observe, `run_call_stack_input_aware_lowering_8616` and
`validate_scoped_call_stack_inputs_8616` all require explicit
`scoped_context`/`scoped_caller_scope`; without them every scoped call
refuses atomically before any AST edit and before any consumer callback.
Ordinary AST copy/deepcopy retains the live authority handle in-process;
the structured-AST snapshot encoder publishes only an explicit
`scoped_call_position` diagnostic (position plus scope restriction) that
cannot re-enter as authority. `validate_scoped_call_stack_inputs_8616`
returns a distinct `ScopedCallStackInputValidation8616` verdict sharing
only the neutral observation base — a scope-restricted report, never a
universal pass.
Controls: `tests/lowering/test_scoped_call_stack_inputs.py`.
