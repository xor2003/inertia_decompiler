# Alias analysis

`call_stack_positions.py` derives source-bound caller-before, callee-entry and
caller-after SP offsets through the canonical stack solver. Its proof consumes
the existing IR frame/effect contract; it does not replace that contract or
authorize a generated-C call-input binding. Consumers must freshly reproduce a
saved proof. The runtime obligation is tracked in
[`p0-call-return-stack-effects.md`](../../reference/p0-call-return-stack-effects.md).

`stack_pointer_snapshots.py` owns entry-SP coordinates captured into temporaries
and live word-register copies. `stack_restore_state.py` freezes those register
coordinates in the canonical CFG must-state; joins retain a coordinate only
when every incoming path proves the identical value. The existing stack solver
consumes that state across blocks rather than starting another dataflow pass.
`register_constants` carries proven numeric register words through the same
join; constants stay a separate fact kind from SP-relative coordinates.

`scoped_callee_stack_pointer.py` proves a callee's returning-SP transfer under
one authenticated invocation domain. It consumes
`IRBoundaryCoverageResult8616.complete_for(scope)`, the projection's live
effective blocks, and entry register facts transported by the retained call
chain or entry declaration, then runs the shared must-state solver on that
scoped graph. The result stays scope-bound (`complete` is always false) and
every accessor re-authenticates scope provenance, retained coverage, and a
fresh solve; unreachable pending markers on the shared artifact are never
removed. Native controls live in
[`test_scoped_callee_stack_pointer.py`](../../tests/alias/test_scoped_callee_stack_pointer.py).

Only exact, undecorated word-register MOVs preserve a live coordinate. Narrow,
wide, versioned or unknown writes invalidate the affected storage family.
CALL and interrupt boundaries invalidate general-register coordinates because
an SP effect alone does not prove register survival. Immutable temporary
captures remain distinct from live storage. Unknown coordinates refuse; this
contract neither flattens memory spaces nor changes the stricter entry-prefix
producer-evidence API.

Binary callee proofs and independent execution checks are in
[`test_callee_stack_effects.py`](../../tests/semantics/test_callee_stack_effects.py).
Alias refusal/join controls are in
[`test_general_register_stack_coordinates.py`](../../tests/alias/test_general_register_stack_coordinates.py).
Other storage-identity and register-source owners live here; widening and
lowering consume their evidence through direct canonical imports. Tests live
in `tests/alias/`.

`scoped_call_stack_context.py` binds each exact callsite to its retained
`IRScopedCallStackCoordinates8616` carrier plus caller/callee domains — an
explicit overlay outside the raw artifact. `scoped_call_stack_positions.py`
consumes it through the shared must-state solver: a `call_deltas` overlay
applies the callee's caller-visible SP effect at the exact CALL instruction
(downstream instructions see the real post-call SP) while BP and stack-byte
proofs stay unproven. `position_for(caller_scope, callee_scope)` re-runs the
proof under the offered domains; `complete` is permanently false. Controls:
`tests/alias/test_scoped_call_stack_positions.py`.
