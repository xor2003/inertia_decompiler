# Widening

This layer joins Alias-proven register and storage slices, recovers global
layouts, and retains carry/borrow and segmented-memory evidence. Types/Lowering
consumes those facts; it must not infer missing storage identities.

`pair_type_contracts.py` owns named logical pair types and operation legality.
Type identity includes total width, low/high layout and signedness. Arithmetic
kind and segmented source space remain operation evidence. Unknown signedness
stays unknown; a logical pair does not change the scalar ABI or establish a
recovered program structure or flat far pointer.

Construction and subsequent authorization use the same half invariants.
Combining requires a consistent paired value; split or unpaired evidence never
authorizes retiring the original carriers. Lowering binds the retained pair to
the live operation, storage versions, exact SS/BP ranges and call provenance
before materializing or accepting a dedicated assignment as authoritative.

The permanent contract regressions are in
`tests/widening/test_pair_type_contracts.py`; materialization and refusal tests
also cover the actual Lowering and legacy ownership paths. This contract does
not establish general split-transform recovery for every wide operation.
