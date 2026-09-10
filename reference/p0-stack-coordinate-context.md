# Stack Coordinate Context And Saved-Frame Evidence

## Verified Context Defect (2026-09-09)

The direct-stack-update resolver used the active codegen registry for its
variable inventory, but `_stack_cvar_identity_8616` used each C variable's own
codegen registry during the AST fallback. A reused snapshot variable can point
to an older context. The fallback could therefore reselect a variable which
the active registry had already mapped to a different machine-BP slot.

The resolver now uses the active registry in both paths. This is a Lowering
consumer correction; Alias identity is neither guessed nor changed, and frame
removal checks are untouched. Eight regression cases cover byte/word storage,
AST-only/inventory-plus-AST candidates, and current/snapshot contexts. All four
snapshot cases fail before the repair; current-context cases already pass.
Before: 4 failed, 7 passed, 9.14s. After, with adjacent coordinate and segmented
stack tests: **110 passed**, seven dependency warnings, 10.85s. Scoped Ruff
(`--fix`), MyPy and Pyright pass. The test module is admitted to the routine
pytest and Ruff lists; it previously was not selected there.

Logs: `/tmp/inertia-stack-coordinate-context-{before,after,mypy,pyright}.log`.
Broad gates have not been rerun after this candidate. The preceding green fast
gate and failing default pipeline belong to the byte-cast checkpoint, not this
new revision. No commit/push or full-goal acceptance is claimed.

## Actual MSC6 Function Evidence

A fresh-cache, in-process `byteops_unsigned` probe observes saved-BP carriers
at entry instruction 0x1000, VEX statement indices 17 and 20. They are byte
variables, not one word variable. The late prologue classifier refuses them.
The low-byte native variable has raw offset -2 and later receives a BP -2 / SP
-2 projection and the name `a`. That is evidence to trace, not permission to
delete its assignment. The observed C variables use the active codegen context:
the snapshot defect above is **not** the cause of this function's symptom.

Before/after fresh C is byte-identical, SHA-256:
`344eba6a324673d5753aca66fb82d586bdaf995c1b285d39df3f28e9132d0aa8`.
Both runs exit 0 with `validation=passed` and clean whole-tail validation.
Artifacts: `/tmp/inertia-frame-context-{probe,after}.{c,log}`.

## Next Investigation

Reason: byte-oriented execution must not silently change the identity or width
of one logical saved-frame access. Trace `IRLogicalMemoryAccess8616` and its
exact execution slices into native AIL and stack-variable creation. Keep the
existing byte-safe `access.py` and optimized lifter execution methods intact.
DoD: a binary-derived regression proves saved BP and local storage remain
distinct, with complete logical-access provenance and correct numeric stack
behavior. Definition of failure: inferring coordinate domains from coincident
offsets/names, treating paired byte assignments as dead without use proof,
loosening the late frame guard, or restoring unsafe wide execution accesses.
An early adapter repair is a candidate direction, not yet a proven solution.
