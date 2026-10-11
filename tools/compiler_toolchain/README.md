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

The default registry selects `/home/xor/kvikdos/kvikdos` for compilation,
linking and execution under MS C 5.1 and Borland 3.1, in small and large models.
All four profiles have fresh native probes (2026-10-10, runner SHA256
`3d75ba5d623b…`). Borland 3.1 profiles explicitly select
`kvikdos_dpmi_mode: off`: this runner's automatic DPMI handling makes their
compiler/linker print help without producing artifacts. MS C 5.1 retains
`auto`. The typed mode applies to compilation, linking and execution, must
agree with the measured probe, and participates in frozen-context fingerprints.
Changed runner bytes require another probe and a new frozen context. This execution path requires
KVM. Captured DOSBox entry environments remain bound to DOSBox, even when
kvikdos produces identical executable bytes.

For a single schema-2 case with measured DOS entry evidence, pass
`--real16-declared-input entry.json` to the coverage suite. The suite forwards
it through the build harness to the decompiler and every clean worker; the CLI
authenticates its binary hash, load coordinates and declared service contracts.
The runner fingerprints the declaration and rejects changes during execution.
The option requires an exact case selection and does not increase proof budgets
or permit fixture fallback. A declaration is an explicit environment premise,
not a successful round trip.

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.compiler_toolchain --help
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.compiler_toolchain --manifest examples/compiler_coverage/pilot.json --out-dir .cache/compiler-coverage/example
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/compiler_toolchain/tests -m 'not requires_kvm' -q --tb=short --durations=5 -n 2
```

The installed command is `inertia-compiler-coverage`. Import compiler tooling
from `tools.compiler_toolchain`; historical `scripts.compiler_*` aliases have
been removed.

The QuickC fixture importer is `import_ultra_quickc_fixtures` in this package.
Run `python -m tools.compiler_toolchain.import_ultra_quickc_fixtures --help`.
Its private tests live beside the importer. Compiler execution and fixture
selection are unchanged by the move.

Inputs: explicit JSON manifests, source fixtures, profile registries and external
compiler/runtime binaries. Outputs: isolated case artifacts, logs, provenance and
structured reports. Shared compiler/decompiler source manifests remain at `examples/compiler_coverage/`
and `examples/msc6_constructs/`; private temporary fixtures live in the tests; do not
copy proprietary compilers or generated artifacts into this package.

Dependencies: shared process measurements in `tools.dev.process_metrics`, optional
signatures, and the native orchestration owner `build_msc6_examples.py` here.
Generic decompiler batching uses `tools/dev/batch_decompile_procs.py`.
Focused binary-target attempts retain fresh conditional C receipts through
`conditional_function_receipt.py`. Transport checks the unchanged source image,
selected entry, phase premises and all payload hashes. A bound receipt remains
conditional evidence: exit 5 and the legacy acceptance boolean stay unchanged.
Batch transport and complete-case acceptance require their own evidence.
The builder still needs decomposition during the large-owner
step; this move introduces no semantic recovery or duplicate runtime.
Case implementation fingerprints include these migrated owners, so old receipts
must be regenerated. Test lanes retain explicit native/process budgets; no glob
promotes mixed runtime tests into the fast ownership lane.

Positive example: a pinned case runs only with its selected toolchain profile.
Negative example: an environment/source identity change refuses a previously
passing report rather than accepting stale evidence. Native KVM acceptance is
separate from static and mocked runner tests.

To declare an observed real-mode entry environment, use the explicit native
DOSBox debugger adapter:

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 DISPLAY=:111 SDL_VIDEODRIVER=x11 SDL_AUDIODRIVER=dummy SDL_RENDER_DRIVER=software \
  .venv/bin/python -m tools.compiler_toolchain.capture_real16_entry capture \
  --source /absolute/path/PROGRAM.EXE \
  --native-exe /home/xor/inertia_player/libdosbox/build_gdb/dosbox \
  --gdb /usr/bin/gdb --config /absolute/path/dosbox.conf \
  --target-stem PROGRAM --out-dir .cache/program-entry --timeout 60
```

Choose a working display and a configuration that runs that exact executable
with `core=normal`. The native build must expose the custom entry hook and CPU
debug symbols; missing symbols refuse. Use a fresh output directory. The tool
stops before the target's first instruction and authenticates full-width
registers, segments, loader coordinates, relocated source bytes, flags and guest
memory. It retains hashes, the debugger log, `capture.json`, `memory.bin`, a typed
`report.json`, and the canonical `environment.json`. `convert` mode can replay
authentication with explicit `--capture-json` and `--memory` inputs.

The manifest declares observed inputs; capture does not prove program behavior
or invent DOS service policies. Declare services separately through existing
dosunit contracts. For decompiler intake, wrap the manifest and explicit service
sites in the source-bound declaration described in `../dosunit/catalog/README.md`
and use `--real16-declared-input`. Capture uses GDB and live DOSBox memory,
without KVM.

Component declaration: [compiler_toolchain.json](../../reference/components/compiler_toolchain.json).
