# Widening

The existing alias-proven widening modules live here. They join register and
storage slices, recover global layouts, and preserve carry/borrow and segmented
memory evidence. Their interfaces and algorithms are unchanged by the move.

Private tests move into `tests/widening/`. Shared decompiler integration tests
remain in their existing cohort until that test move. Historical
`X86_16/widening/` module imports alias these owners.
