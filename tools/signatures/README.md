# Shared signatures

Optional library identification for ADA and the decompiler. Signature matches
provide labels and classification; they do not prove argument types or semantics.

Public configuration API:
`flair_paths.resolve_flair_root(Path | None) -> Path` and
`signature_matching_policy.signature_matching_disabled() -> bool`.
The default assets remain at repository `flair_startup/`; explicit paths take
priority over `INERTIA_FLAIR_ROOT`. `INERTIA_DISABLE_SIGNATURES` disables matching.
Neither configuration module imports the decompiler.

Parser/catalog API lives here: `omf_pat.PatModule`, `omf_pat.parse_pat_file`,
`omf_pat.match_pat_modules`, `signature_catalog.build_signature_catalog` and
`signature_catalog.match_signature_catalog`. `pat_literal_filter` only rejects
impossible matches; surviving hits still need the matching backend.

The package command `python -m tools.signatures ROOT --output CATALOG.pat`
imports PAT/OBJ/LIB inputs into a deduplicated catalog. `inertia-signatures`
is the installed console command; `scripts/build_signature_catalog.py` remains
a compatibility command. Input compiler assets remain external. Output catalogs
and caches belong in explicit output roots, not the package.

Do not introduce proof or argument-recovery semantics into this tool.

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/signatures/tests tests/integration/test_signature_matching_policy.py -q --tb=short
```

`pickle_cache` owns the local cache decoding boundary. It maps historical
`omf_pat` serialized globals to `tools.signatures.omf_pat` without restoring
root import aliases. Both the PAT cache and compiler catalog bundle reader use
that boundary. Missing files are cache misses; known IO, malformed-pickle and
class-lookup failures produce diagnostics and allow rebuilding from PAT input.
Unexpected reconstruction errors propagate with their original cause. Cache
fingerprints include the decoder alongside the parser and literal filter.

Positive example: an explicit Flair root is returned unchanged. Negative example:
a signature match must never turn a refused semantic comparison into a proof.
Component metadata: [signatures.json](../../reference/components/signatures.json).

Private parser/catalog tests live in `tests/`. Cross-tool ADA/decompiler tests
live in `tests/integration/` and retain their multiple component labels.
