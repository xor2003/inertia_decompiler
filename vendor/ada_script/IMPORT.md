# ada_script source import

This directory preserves the tracked code, tests and documentation from
`https://github.com/xor2003/ada_script` at the revision recorded in
`UPSTREAM.json`. Its per-file SHA-256 entries make the imported snapshot
auditable. Game binaries, IDCs for local games, databases, generated listings,
caches and local environments were not imported. Agent-specific instruction
files were omitted; this repository's instructions govern the integration.

The original flat-module CLI remains `vendor/ada_script/ada.py`. The supported
Inertia entry point is the repository-root `ada.py`, implemented in
`tools/ada_script/`. Use that entry point for shared signature matching and
explicit output directories. The snapshot is not a replacement for Inertia's
loader or semantic IR.

Legacy upstream code is retained unchanged, including its typing, error
handling and heuristic-analysis debt. New integration code is typed, linted
and tested independently; importing the snapshot is not a claim that the
legacy code meets all Inertia semantic acceptance gates. Some upstream tests
contain stubs; they are not correctness evidence for this integration. Real
binary-to-ASM/LST controls live in
`angr_platforms/tests/test_ada_signature_integration.py`.

The source checkout did not contain a tracked LICENSE file. Its provenance is
preserved here; no license grant is inferred from its inclusion. See the
repository's third-party notices before redistribution.
