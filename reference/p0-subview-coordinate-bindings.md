# Widening Subview Coordinate Bindings

## Root Cause (2026-09-09)

A bounded assignment-destination trace identifies the first incorrect rewrite:
`materialize_contained_stack_subviews_8616` changes saved-frame byte destinations
to the local word. `resolve_stack_object_view_8616` used native variable offsets
as machine-BP ranges, despite explicit coordinate bindings already being present.
Thus native offset -2, bound to BP+0, matched a local at BP-2.

The corrected trace confirms initial materialization is sound: saved-frame
variables bind 0/-2 and 1/-1, while the local word binds -2/-4 (BP/native).
The earlier negative projector trace was unreliable: its observer requested a
registry accessor from the wrong module. The corrected observer shows normal
new-slot projections. Do not fix that projector based on the superseded trace.

## Repair

Subview range resolution now consumes explicit bindings for exact variables or
clones with matching durable identifier and range. Owner selection, direct
views, widened reads and recomposition containers use the same coordinate
reader. The Alias/Widening artifact still proves ownership; a coordinate binding
does not create a storage fact. Missing bindings retain existing behavior.

The focused reader is in `widening/stack_subview_coordinates.py`. Its read-only
Protocol describes the existing registry API; it introduces no Widening import
of Lowering and no competing registry or name-based identity recovery.
The previously >350-line proof module shrinks as the range helper moves out.

## Evidence And Limits

- Before: eight coordinate tests fail (8.11s), both saved-frame false positives
  and genuine local-view false negatives, including identifier-preserving clones.
- After: 39 subview tests pass (9.93s). Scoped Ruff --fix, MyPy and Pyright pass.
- Routine test, lint and architecture ownership lists include the new modules.
- Fresh byteops still retains EBP; direct decompilation exits 0 with
  validation=passed and whole-tail clean. This is not a byteops fix claim.
- At this intermediate revision, the disabled native-anchor experiment improved from four smoke failures to
  one: three annotation tests pass, but ENTER now returns the saved-frame byte
  instead of the local containing 1. Do not enable it until return-coordinate
  consumers are repaired and validation/compiled behavior agree.
- The subsequent [native return repair](p0-native-return-preservation.md)
  resolves that observed return substitution. The combined diagnostic now
  passes all four smoke cases; native-anchor integration remains undeployed.
- Combined `quality-fast` passes 3,101 tests (170.07s), configured checks and
  three executable guards. The subsequent default pipeline passes 3,101 unit
  tests and QuickC; MSC6 remains 5/7 with the same two register rebuild failures.
- Logs: `/tmp/inertia-subview-coordinates-{before,after,mypy,pyright}.log`;
  `/tmp/inertia-anchor-variable-identity-verified.log`;
  `/tmp/inertia-anchor-assignment-probe.log`;
  `/tmp/inertia-anchor-after-subview-fix.log`.

## Acceptance

Reason: raw native offsets must not override published machine storage identity.
DoD: coordinate/refusal tests and existing subview behavior pass; exact calls,
memory effects and returns survive; quality-fast and default pipeline agree.
Default pipeline MSC6 acceptance remains open. Failure: rebind saved-frame storage to a local, derive
identity from names, discard unknown effects, or enable the unsafe experiment.
Next: integrate explicit native-anchor provenance after the default gate;
preserve untagged references rather than restoring unconditional rebasing.
