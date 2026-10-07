# Alias analysis

The existing storage-identity, register-source and stack-alias modules live here.
Their implementations retain the same data contracts and proof rules. Widening
and lowering consume their evidence through ordinary imports.

Private tests move into `tests/alias/`. Historical `X86_16/alias/` modules alias
these owners; its package keeps the existing public export surface.
