# ADA source provenance

The analyzer and tests were imported from https://github.com/xor2003/ada_script
at the revision in `UPSTREAM.json`, then integrated into `tools/ada_script`.
The recorded SHA-256 values describe the original upstream snapshot, not current
files. Package-qualified sibling imports replace flat imports and path mutation.
The integrated CLI supersedes the original standalone `ada.py`; its implementation
is removed. `UPSTREAM_README.md` preserves the original upstream documentation.

The package CLI retains shared signature matching, IDC/runtime input, optional
Capstone/Rizin backends and exact instruction encodings by default. It remains
an independent disassembly tool, not Inertia's semantic loader or IR. Upstream
heuristic, typing and error-handling debt remains visible; upstream stub tests
are not correctness evidence. Cross-tool controls live in
`tests/integration/test_ada_signature_integration.py`.

Game binaries, local IDCs, databases, generated listings, caches and environments
were excluded. The source checkout had no tracked LICENSE; provenance does not
imply a license grant. Consult the repository's third-party notices.

Historical Make/pytest/tool configuration is preserved as `UPSTREAM_Makefile`,
`UPSTREAM_pyproject.toml` and `UPSTREAM_pytest.ini`; repository configuration governs
checks. Private tests now live in `tests/`.
