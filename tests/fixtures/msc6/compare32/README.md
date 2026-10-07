# MS C Compare32 Regression Input

These are durable test inputs, not temporary build outputs. Copied byte-for-byte
from the existing `examples/build_msc6/COMP32.*` artifacts on 2026-09-07.
`sha256.json` records their identities. The corresponding compiler-example
owner is `scripts/build_msc6_examples.py`, construct `compare32`.

The fixed-address decompiler regressions must not depend on an ignored local
build directory or a DOS compiler installed on the pytest host. The C source
is retained for inspection. COD/MAP evidence supports the named-function test;
sidecar-free tests copy only the EXE into their isolated directories.

This fixture is not a replacement for the MS C build/decompile/recompile/run
pipeline. Do not replace these bytes with a fresh compiler output without
reviewing instruction addresses and the matching test assertions. Reproducible
rebuilding of these exact historical bytes has not been established here.
