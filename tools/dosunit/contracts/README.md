# SSA contracts

`ssa.py` owns immutable `SsaExpr` trees, their ordered structural identity,
and `LowerFailure` refusal evidence. Import these contracts directly here;
they require no angr, VEX or Z3 setup.

The legacy `straightline_ssa` imports remain aliases to the same classes,
including lookup of historical pickles. Preserve field order, defaults,
exception behavior and `key()` representation when changing this owner.
Memory expressions retain width zero; this extraction adds no validation.

Boundary controls: `tools/dosunit/tests/test_contract_boundaries.py`.
Solver operators belong in `../ssa/`; lowering and document proof policy
remain in their existing owners during migration.

`registers.py` defines `RegisterReader`, the architecture-specific register
read contract passed explicitly through recursive VEX expression lowering.
Flat32 expression reads use this contract without installing global register
state. `RegisterArchitecture` also supplies initial widths, writes, enclosing
write targets, control width/name and the statement-retention policy to block
lowering. Explicit block calls preserve that owner through dirty-I/O reads,
final control projections and serialized input widths. Whole-function/region
and driver installation remain transitional.
The optional expression-lowering contract retains architecture admission
policy alongside register effects; dirty-I/O arguments use that same policy.
PE32 terminal walks now consume this state without installing global seams.
Whole-function VEX scans also accept this architecture, retaining it through
repeat-string summaries, internal cutpoint outputs and input serialization.
The document-lowering API exposes the architecture and existing image-project
argument explicitly. AIL lowering does not yet accept this architecture.
Recursive PE32 proposals and independent native byte binding use that same
explicit architecture. Their model seals fingerprint its register contract;
the obsolete shared register-installation context has been removed.

`comparison.py` owns immutable `ComparisonPolicy` and typed
`LayoutNormalization`. The default preserves real16 layout inference and
historical identity admission. `EXPLICIT_COMPARISON_POLICY` leaves declared
constant maps intact, disables inferred layout maps, and defers identity to
solving whenever either side rewrites constants. The public comparison API
threads the policy through pair comparison, callee retries, region transitions
and connectivity; its report serializes the selected policy. MSC/BC5 drivers
pass the explicit policy, including matched-CFG and scratch-frame retries.
They no longer install layout or identity callbacks process-wide.
With a literal-identity policy, raw region signatures cannot bypass declared
maps. Region transition proofs consume each block's maps; if that lane cannot
prove equality, ABI composition refuses with the typed
`ComparisonRefusal.REGION_NORMALIZATION_REQUIRES_BLOCK_PROOF`, because its
current summaries do not preserve per-block normalization domains. A region
shortcut must never override a solver mismatch by dropping that evidence.

`scanning.py` owns `SuccessorRangeAdmission`, an explicit callback over loaded
image evidence. The document and function lowering APIs carry it into the
scan context. It admits discovery extensions only after the existing typed
`SuccessorRangePolicy` allows extension; declared-only ranges remain closed.
MSC passes its bounded callback and BC5 passes its executable-section callback.
Their installation contexts no longer replace the engine's range callback.

Explicit architecture document/block calls select the authoritative
context-aware function and finisher implementations. The historical
`_lower_function` and `_finish_irsb_lowering` facades remain patchable only for
legacy calls without architecture state. Recursive PE32 drivers no longer
need an inner region installation to undo an enclosing leaf finisher patch.
