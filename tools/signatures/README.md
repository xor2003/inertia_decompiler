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

Generic cache storage currently remains in `inertia_decompiler.cache`;
extract that boundary during core/cache migration rather than copying it here.
Do not introduce proof or argument-recovery semantics into this tool.

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/signatures/tests tests/integration/test_signature_matching_policy.py -q --tb=short
```

Legacy root `omf_pat`, `signature_catalog`, `pat_literal_filter` and CLI
configuration imports alias these exact modules, preserving shared state and monkeypatches. Remove
aliases only after existing consumers migrate. Catalog and sidecar fingerprints
include canonical configuration sources so their changes invalidate cached data.

Positive example: an explicit Flair root is returned unchanged. Negative example:
a signature match must never turn a refused semantic comparison into a proof.
Component metadata: [signatures.json](../../reference/components/signatures.json).

Private parser/catalog tests live in `tests/`. Cross-tool ADA/decompiler tests
live in `tests/integration/` and retain their multiple component labels.
Old pickle globals resolve through the root aliases; cache fingerprints use the
canonical parser sources rather than compatibility wrappers.
