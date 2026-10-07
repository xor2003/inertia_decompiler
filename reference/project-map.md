# Project Map

This is the fast startup map for agents. Read `AGENTS.md` first, then this file, then the domain-specific reference file for the code you are changing.

## Domains

- `inertia/` owns the migrated decompiler layers: `ir/`, `semantics/`,
  `alias/`, `widening/`, `lowering/`, `structuring/`, `postprocess/` and
  `validation/`. Their private tests live under the corresponding `tests/`
  directories. See `reference/decompiler-map.md`.
- `inertia/frontend/x86_16/` owns the VEX lifter, native-backend verification,
  DOS SimOS, interrupt contracts, architecture registration/register layout,
  control-coordinate contracts, MZ/NE loaders and optional NE resources.
  Frontend adapters import these owners directly. Start with `inertia/frontend/x86_16/README.md` for this boundary.
- `inertia/cli/` owns CLI orchestration, fallback/reporting, cache, sidecar
  loading and user-facing command behavior. It must not become the owner of
  decompiler semantics.
- `tools/debugger/` owns RSP client, TUI/widgets and backend launch
  orchestration. Run `inertia-debugger`.
- `tools/dosunit/` owns the DOS unit harness and SSA/Z3 machinery; `dosunit.py`
  is its command entry. Existing machinery is grouped under `contracts/`,
  `ssa/`, `compare/`, `architectures/`, `catalog/`, `runtime/` and `reporting/`.
  `tools/comparator/` owns comparison drivers/profiles.
  Use `reference/dosunit-execution-spec.md` and related DoD files before changing semantics.
- `tools/ada_script/` owns annotated DOS disassembly, runtime-trace import
  and shared signature naming, including the imported analyzer implementation.
- `tools/signatures/` owns catalogs and OMF/PAT import/export;
  `tools/signatures/signature_catalog.py` owns catalog contracts.
  `signature_catalogs/` holds evidence inputs.
- `tools/dev/test_pipeline.py` owns the curated project pipeline. Its fast tier runs local budgeted binary controls and focused units; default and expanded tiers add external compiler/decompiler smoke lanes.
- `tools/compiler_toolchain/` owns compiler fixtures and build/coverage
  commands. `tools/dev/` owns pytest, profiling and development support.
  Private tests live beside their tools.
- `examples/msc6_constructs/` contains source examples for the MS C tiny full pipeline. `examples/build_msc6_tiny/` and `examples/build_msc6/` are generated outputs.
- `reference/` contains the long-form contracts, plans, diagnostics, and handoff files.

## Decompiler Order

Keep semantic fixes in the earliest correct layer:

```text
IR -> Alias -> Widening -> Types/Lowering -> Structuring -> Rewrite
```

Rewrite and `decompiler_postprocess_*.py` are cleanup bridges only. Do not add alias, type, condition, call-argument, signature, or memory recovery there. `tools/dev/check_decompiler_architecture.py` enforces this and is executed in the main decompiler startup path.

## Startup Reading

- General work: `AGENTS.md`, then `reference/project-map.md`.
- Repository organization: [project-structure-plan.md](project-structure-plan.md)
  records destinations and the remaining file-move checklist; `tools/dev/`
  supplies component declarations and bounded task context.
- Find a task owner and its tests with
  `tools/dev/agent_test_focus.py --files <paths> --context --json --json-only`.
  Edit `reference/components/*.json` for migrated ownership, then regenerate
  its compatibility views with `python -m tools.dev.component_catalog_cli --write`.
- Choosing reconstruction tools: `reference/dos-c-reconstruction-toolchain.md`
  orders instruction matching, concrete oracle tests, SSA/Z3 proofs and runtime acceptance.
- Decompiler work: add `reference/decompiler-map.md` and `reference/agent-rules.md`.
- DOS execution work: add `reference/dosunit-execution-spec.md` and the matching DoD file.
- SORTDEMO/SORTD work: read `SORTD_GHIDRA_PLAN.md`; its per-step DoD and
  bounded-worker memory rule are mandatory for executable-only work.
- Telemetry/performance work: read `reference/telemetry.md`.

## Fallback Discovery Flow

Use this flow when `codebase-memory-mcp` is unavailable or its transport is
closed:

1. Read `AGENTS.md`, then `reference/project-map.md`.
2. For decompiler changes, read `reference/decompiler-map.md` and
   `reference/agent-rules.md`.
3. Inspect the owning layer before editing: `inertia/`
   for decompiler core, `inertia/cli/` for CLI/fallback/reporting,
   `tools/dev/test_pipeline.py` for curated gates, and
   `tools/compiler_toolchain/` for MS C tiny examples
   (`tools/compiler_toolchain/build_msc6_examples.py` owns the build command).
4. Use `rg`/`rg --files` only after the map identifies the likely owner.
5. Run `make check-files PYTHON=./.venv/bin/python FILES="..."` while editing
   so focused linters, the changed-file module/doc/type/dot-access ratchet,
   architecture/context guards, ownership-manifest validation, and owned tests
   run together, then the broader target named by the owning domain.

## Checks

- `make architecture-check PYTHON=./.venv/bin/python` runs the full decompiler architecture and agent-guide guard; `architecture-check-fast` runs the startup-critical wrong-layer and semantic-recovery subset.
- `make agent-context-check PYTHON=./.venv/bin/python` reports whether the
  codebase-memory MCP graph is available to the agent and prints the fallback
  discovery flow above when it is not confirmed available.
- `tools/dev/check_decompiler_architecture.py` tracks legacy `Responsibility:` header debt explicitly; remove entries from those lists as soon as the owning module docstring is fixed.
- `tools/dev/check_decompiler_architecture.py` requires every inertia module to be in the promoted typed/ruff gates or explicit promotion debt; it also distinguishes full promoted typed files from Pyright-only partial promotions, which must remain explicit full-promotion debt until Ruff/docs/dynamic-attribute cleanup is complete.
- Full-promotion debt files stay out of `QA_TYPED_FILES` and `QA_RUFF_TARGETS`; only Pyright-only partial promotion debt may appear in `QA_TYPED_FILES`.
- `make test-ownership-check PYTHON=./.venv/bin/python` validates that changed-file ownership rules point at existing pytest targets.
- Ownership-manifest tests are fast-only; slower/default/expanded coverage belongs in `tools/dev/test_pipeline.py` tiers.
- `make quality-fast PYTHON=./.venv/bin/python` runs linters, the changed-file module/doc/type/dot-access ratchet, startup architecture/context checks, ownership-manifest validation, and the fast decompiler gate for regular local checks.
- `make quality-hard PYTHON=./.venv/bin/python` adds the full repository
  architecture scan and remains the mandatory pre-PR/incremental gate.
- `make test-pipeline-fast PYTHON=./.venv/bin/python` runs the fast curated pipeline tier used by `quality-fast`. Its `binary-budgeted` phase runs transitive-call controls with at most two workers before `unit-focused` uses the requested pool. Proof budgets stay unchanged; local checks still require no external compiler/decompiler lane.
- `make test-pipeline PYTHON=./.venv/bin/python` runs the curated pipeline and writes `.cache/frontend/test_pipeline/summary.json`.
- `make test-pipeline-expanded PYTHON=./.venv/bin/python` runs the expanded curated tier, including the executable-only sidecar-free SORTD ratchet and the long SORTDEMO status lane.
- `make msc6-examples PYTHON=./.venv/bin/python` runs the MS C tiny compile, decompile, recompile, return-code, and exit-code lane.

Run changed-file checks periodically while developing, `quality-fast` regularly, `test-pipeline` before claiming a decompiler improvement, and `test-pipeline-expanded` for broad status/audit work.

## External Contracts

- `libdosbox` memory contract: `m2c::m` is the translated-program live DOS memory view, not an independent zero-filled compatibility buffer. If live memory is unavailable, use DOSBox memory APIs only as a temporary workaround.
- Compiler sidecars, COD, LST, MAP, and signature catalogs are optional evidence. They may provide labels, bounds, names, or known library matches, but they must not be required for argument values, types, control-flow semantics, stack recovery, memory modeling, or validation success.

## Knowledge Graph

Understand-Anything may be used for architecture exploration with `--no-auto-update`. Its config lives at `.understand-anything/config.json` and must keep `autoUpdate` disabled so ordinary agent work does not mutate graph state unexpectedly.
