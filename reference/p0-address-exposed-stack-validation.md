# Address-Exposed Stack Validation

## Reason And Contract

Before removing private BIOS stores, the validator's observable-stack policy
was checked. The existing live-out exclusion for BP+0 and positive BP slots
overrode explicit address exposure. A caller could pass `&slot` to a callee,
lose the initializer, and still receive an unchanged summary. A second probe
showed changed initializer values were also invisible: write summaries retained
locations but not values.

DoD: explicit address exposure preserves the write at negative, zero and
positive offsets; deleted and changed initializers produce validation deltas;
the new effect survives summary serialization and generic comparison; ordinary
by-value observations keep their existing policy; routine gates are measured.
Definition of failure: accepting those mutations, inferring private lifetime
from missing observations, ignoring the new field in comparison, or putting
it on a delta-suppression allowlist merely to pass corpus tests.

## Implementation And Scope

Tail Validation owns the repair. `StackObservedLocations8616` retains separate
value-read and explicitly address-exposed location sets. Typed C `Reference`
nodes encountered at observable uses publish exposure of their operands.
That evidence overrides the legacy frame/argument-location exclusion.

The summary's new `exposed_stack_values` observable retains deterministic
location/value fingerprints for these stores. `as_dict` includes it and the
shared observable-field inventory compares it. It is not a new semantic
recovery rule in Rewrite, and it does not delete or alter generated C.

This is direct structured-address observation in live-out mode, not general
pointer-alias/escape analysis or a private-frame lifetime proof. Like existing
effect summaries, the fingerprints are a set; this does not prove ordering
between identical writes, full machine equivalence, or every transitive alias.
BIOS strict compilation remains open and no BIOS stores were deleted.

## Verification

Initial deletion probes: two failed, one passed (8.83s). After preserving
exposure, the three value-corruption probes still failed, confirming the
second gap. With value fingerprints: all 287 focused tail-validation tests
pass (8.79s), covering both deletion and value changes at offsets -4, 0 and +4.
The regression checks the serialized observable and its removed delta too.
Tests are in Make, the routine pipeline and changed-file ownership.

Scoped MyPy and Pyright pass. Ruff passes for the policy, new tests, ownership
manifest and pipeline module; the large tail-validation module retains 85
legacy Ruff findings, not suppressed here. Verification was observed at
19:17 CEST on 2026-09-10; the exact investigation start was not captured.
Routine quality and default gates were then running with source held stable.
Logs: `/tmp/inertia-stack-escape-before.log`,
`/tmp/inertia-stack-escape-values.log`, `/tmp/inertia-stack-escape-value-after.log`,
`/tmp/inertia-stack-escape-final-mypy.log`, `/tmp/inertia-stack-escape-pyright.log`,
`/tmp/inertia-stack-escape-gates.log`.

Routine gates completed before 19:25 CEST: fast pytest reports 3,637 passed,
one known BIOS strict-C failure in 159.84s; default pytest reports the same
counts in 141.34s. All three executable quality guards and both default
executable lanes, including MS C round trips, pass. The new observable remains
enabled throughout those runs. Make remains red for the known BIOS failure
and global Ruff debt. This is not a refreshed full-suite result.
