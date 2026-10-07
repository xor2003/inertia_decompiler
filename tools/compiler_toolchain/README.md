# Compiler build and coverage tooling

Runs explicitly selected compiler cases through compilation, decompilation,
recompilation and execution. A successful round trip proves the selected
observations; it does not automatically prove every claimed feature witness.

Public contracts: `compiler_coverage_manifest.CoverageManifest`,
`compiler_profile.CompilerToolchain`, `compiler_coverage_result.CoverageOutcome`.
`compiler_coverage_runner.run_source_case` runs one bounded case;
`compiler_coverage_suite.run_suite` selects manifest cases and writes a summary.
Invalid identities, missing evidence and exceeded budgets retain distinct typed
outcomes. Decompiler and comparator semantics stay with their existing owners.

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.compiler_toolchain --help
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.compiler_toolchain --manifest examples/compiler_coverage/pilot.json --out-dir .cache/compiler-coverage/example
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/compiler_toolchain/tests -m 'not requires_kvm' -q --tb=short --durations=5 -n 2
```

The installed command is `inertia-compiler-coverage`. Legacy `scripts.compiler_*`
imports and runner/suite/Csmith commands alias their canonical modules, retaining
monkeypatch and class identity. Remove aliases only after actual consumers migrate.

The QuickC fixture importer is `import_ultra_quickc_fixtures` in this package.
Run `python -m tools.compiler_toolchain.import_ultra_quickc_fixtures --help`.
The historical script remains supported; its private tests live beside the
importer. Compiler execution and fixture selection are unchanged by the move.

Inputs: explicit JSON manifests, source fixtures, profile registries and external
compiler/runtime binaries. Outputs: isolated case artifacts, logs, provenance and
structured reports. Shared compiler/decompiler source manifests remain at `examples/compiler_coverage/`
and `examples/msc6_constructs/`; private temporary fixtures live in the tests; do not
copy proprietary compilers or generated artifacts into this package.

Dependencies: shared process measurements in `tools.dev.process_metrics`, optional
signatures, and the native orchestration owner `build_msc6_examples.py` here.
The legacy build script aliases it; generic decompiler batching remains in its
existing CLI owner. The builder still needs decomposition during the large-owner
step; this move introduces no semantic recovery or duplicate runtime.
Case implementation fingerprints include these migrated owners, so old receipts
must be regenerated. Test lanes retain explicit native/process budgets; no glob
promotes mixed runtime tests into the fast ownership lane.

Positive example: a pinned case runs only with its selected toolchain profile.
Negative example: an environment/source identity change refuses a previously
passing report rather than accepting stale evidence. Native KVM acceptance is
separate from static and mocked runner tests.

Component declaration: [compiler_toolchain.json](../../reference/components/compiler_toolchain.json).
