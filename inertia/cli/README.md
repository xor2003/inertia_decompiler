# Decompiler commands and orchestration

This package owns command handling, function discovery, cache access, fallback
selection and reporting. Semantic recovery belongs to the decompiler layers.

Run `python -m inertia.cli.cli --help` or the repository's `decompile.py` entry
point. `inertia_decompiler` retains historical import and command aliases.

Private tests belong in `tests/cli/`; tests spanning several layers belong in
`tests/integration/`.

For an authenticated declared function entry, the direct indexed-Alias preflight
returns `DECLARED_ENTRY_DEFERRED` before requesting universal SSA. Declared-entry
preparation owns the subsequent scoped proofs. Deferral carries no program or
global-object requirement evidence, and never publishes scoped artifacts into
the universal registry. Ordinary requests retain the universal preflight.

Declared-function intake starts from authenticated explicit extents and indexes
their direct near-call descendants using existing frontend boundary producers.
All roots/descendants share the same instruction and attempted-boundary caps.
Unclosed, out-of-image, far, or budget-exhausted targets stay pending; indirect
calls supply no invented target. These rows establish decoded caller evidence,
not startup reachability or callee entry state. The traversal does not enter
unrelated CRT startup. Controls: `tests/cli/test_declared_entry_descendants.py`.

Exact-region publication installs lookup aliases in project and CFG function
inventories while preserving the function's originating manager. Native consumers
resolve the correct CFG through that manager's knowledge base. Publication must
invalidate the derived transition-graph cache and propagate invalidation errors.
The [native regression](../../tests/cli/test_x86_16_exact_region_function_owner.py)
checks ownership, tail validation and executed generated C across publication.

Validated cache and clean-worker results may carry only a parent-side function
identity, without the worker's live prototype authority. Transport preserves
the accepted body and leaves an
absent scalar-interface receipt absent. It must not reconstruct a prototype
from the identity or rendered C. Retained scalar receipts still require exact
accepted-payload, source and producer-generation authentication, including on
cache hits; a stale receipt is refused.
