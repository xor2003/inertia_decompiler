# Project Map

This is the fast startup map for agents. Read `AGENTS.md` first, then this file, then the domain-specific reference file for the code you are changing.

## Domains

- `angr_platforms/angr_platforms/X86_16/` owns the 16-bit x86 decompiler core: frontend, IR, semantics, alias, widening, lowering, structuring, postprocess cleanup, and tail validation. Use `reference/decompiler-map.md` before changing this area.
- `inertia_decompiler/` owns CLI orchestration, fallback/reporting, cache, sidecar loading, debugger helpers, and user-facing command behavior. It must not become the owner of decompiler semantics.
- `dosunit.py` owns the DOS unit execution harness. Use `reference/dosunit-execution-spec.md` plus the related `reference/dosunit-*-dod.md` files before changing execution or equivalence logic.
- `ada.py` and `tools/ada_script/` integrate annotated DOS disassembly and shared
  signature naming. `vendor/ada_script/` is the pinned upstream snapshot, not
  the semantic IR owner; see `tools/ada_script/README.md`.
- `signature_catalog.py`, `omf_pat.py`, `signature_catalogs/`, and `scripts/build_signature_catalog.py` own compiler/library signature catalogs and pattern import/export. They are evidence inputs, not proof of general decompiler semantics.
- `scripts/test_pipeline.py` owns the curated project pipeline. Its fast tier is unit-focused only; default and expanded tiers own external compiler/decompiler smoke lanes.
- `scripts/build_msc6_examples.py` owns the MS C example build/decompile/recompile/run lane.
- `examples/msc6_constructs/` contains source examples for the MS C tiny full pipeline. `examples/build_msc6_tiny/` and `examples/build_msc6/` are generated outputs.
- `reference/` contains the long-form contracts, plans, diagnostics, and handoff files.

## Decompiler Order

Keep semantic fixes in the earliest correct layer:

```text
IR -> Alias -> Widening -> Types/Lowering -> Structuring -> Rewrite
```

Rewrite and `decompiler_postprocess_*.py` are cleanup bridges only. Do not add alias, type, condition, call-argument, signature, or memory recovery there. `scripts/check_decompiler_architecture.py` enforces this and is executed in the main decompiler startup path.

## Startup Reading

- General work: `AGENTS.md`, then `reference/project-map.md`.
- Choosing reconstruction tools: `reference/dos-c-reconstruction-toolchain.md`
  orders instruction matching, concrete oracle tests, SSA/Z3 proofs and runtime acceptance.
- Decompiler work: add `reference/decompiler-map.md` and `reference/agent-rules.md`.
- DOS execution work: add `reference/dosunit-execution-spec.md` and the matching DoD file.
- SORTDEMO/SORTD work: read `SORTD_GHIDRA_PLAN.md` before touching ReInitBars,
  SwapBars, HeapSort, or the executable-only comparison baseline.
- Executable-only SORTD work: follow `SORTD_GHIDRA_PLAN.md`; its per-step DoD
  and bounded-worker memory rule are mandatory.
- Telemetry/performance work: read `reference/telemetry.md`.

## Fallback Discovery Flow

Use this flow when `codebase-memory-mcp` is unavailable or its transport is
closed:

1. Read `AGENTS.md`, then `reference/project-map.md`.
2. For decompiler changes, read `reference/decompiler-map.md` and
   `reference/agent-rules.md`.
3. Inspect the owning layer before editing: `angr_platforms/angr_platforms/X86_16/`
   for decompiler core, `inertia_decompiler/` for CLI/fallback/reporting,
   `scripts/test_pipeline.py` for curated gates, and
   `scripts/build_msc6_examples.py` for MS C tiny examples.
4. Use `rg`/`rg --files` only after the map identifies the likely owner.
5. Run `make check-files PYTHON=./.venv/bin/python FILES="..."` while editing
   so focused linters, the changed-file module/doc/type/dot-access ratchet,
   architecture/context guards, ownership-manifest validation, and owned tests
   run together, then the broader target named by the owning domain.

## Checks

- `make architecture-check PYTHON=./.venv/bin/python` runs the full decompiler architecture and agent-guide guard.
- `make architecture-check-fast PYTHON=./.venv/bin/python` runs the startup-critical
  wrong-layer and semantic-recovery guard for the focused development loop.
- `make agent-context-check PYTHON=./.venv/bin/python` reports whether the
  codebase-memory MCP graph is available to the agent and prints the fallback
  discovery flow above when it is not confirmed available.
- `make check-files PYTHON=./.venv/bin/python FILES="path/to/file.py ..."` runs focused linters, the changed-file module/doc/type/dot-access ratchet, startup architecture/context guards, ownership-manifest validation, and relevant tests for active files.
- `scripts/check_decompiler_architecture.py` tracks legacy `Responsibility:` header debt explicitly; remove entries from those lists as soon as the owning module docstring is fixed.
- `scripts/check_decompiler_architecture.py` requires every X86_16 and inertia_decompiler module to be in the promoted typed/ruff gates or explicit promotion debt.
- `scripts/check_decompiler_architecture.py` also distinguishes full promoted typed files from Pyright-only partial promotions; Pyright-only files must remain explicit full-promotion debt until Ruff/docs/dynamic-attribute cleanup is complete.
- Full-promotion debt files stay out of `QA_TYPED_FILES` and `QA_RUFF_TARGETS`; only Pyright-only partial promotion debt may appear in `QA_TYPED_FILES`.
- `make test-ownership-check PYTHON=./.venv/bin/python` validates that changed-file ownership rules point at existing pytest targets.
- Ownership-manifest tests are fast-only; slower/default/expanded coverage belongs in `scripts/test_pipeline.py` tiers.
- `make quality-fast PYTHON=./.venv/bin/python` runs linters, the changed-file module/doc/type/dot-access ratchet, startup architecture/context checks, ownership-manifest validation, and the fast decompiler gate for regular local checks.
- `make quality-hard PYTHON=./.venv/bin/python` adds the full repository
  architecture scan and remains the mandatory pre-PR/incremental gate.
- `make test-pipeline-fast PYTHON=./.venv/bin/python` runs the fast curated pipeline tier used by `quality-fast`; it must stay unit-focused so regular local checks do not depend on slow external compiler/decompiler lanes.
- `make test-pipeline PYTHON=./.venv/bin/python` runs the curated pipeline and writes `angr_platforms/.cache/test_pipeline/summary.json`.
- `make test-pipeline-expanded PYTHON=./.venv/bin/python` runs the expanded curated tier, including the executable-only sidecar-free SORTD ratchet and the long SORTDEMO status lane.
- `make msc6-examples PYTHON=./.venv/bin/python` runs the MS C tiny compile, decompile, recompile, return-code, and exit-code lane.

Run changed-file checks periodically while developing, `quality-fast` regularly, `test-pipeline` before claiming a decompiler improvement, and `test-pipeline-expanded` for broad status/audit work.

## External Contracts

- `libdosbox` memory contract: `m2c::m` is the translated-program live DOS memory view, not an independent zero-filled compatibility buffer. If live memory is unavailable, use DOSBox memory APIs only as a temporary workaround.
- Compiler sidecars, COD, LST, MAP, and signature catalogs are optional evidence. They may provide labels, bounds, names, or known library matches, but they must not be required for argument values, types, control-flow semantics, stack recovery, memory modeling, or validation success.

## Knowledge Graph

Understand-Anything may be used for architecture exploration with `--no-auto-update`. Its config lives at `.understand-anything/config.json` and must keep `autoUpdate` disabled so ordinary agent work does not mutate graph state unexpectedly.
