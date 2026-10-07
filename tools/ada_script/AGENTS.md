# ADA assembly tooling

The root `AGENTS.md` remains authoritative. Start with [README.md](README.md).

## Owners

- `cli.py`: input admission, options and pipeline orchestration.
- `contracts.py`: typed database view shared by orchestration and rendering.
- Analyzer, loader, database and backend modules: the integrated upstream implementation.
- `map_writer.py`: function/segment listing projection from database evidence.
- `signatures.py`: library-name evidence and conflict dispositions; shared PAT
  matching belongs in `tools/signatures/`.
- `__main__.py`: package command; `cli.py` also supports direct module execution.

Preserve exact instruction bytes by default. Mnemonic output is an explicit
inspection mode, not binary-equality evidence. Runtime traces refine analysis;
they never establish complete static semantics. Library labels must not replace
bodies or authorize semantic recovery. Preserve explicit user names and refuse
ambiguous matches and unsupported executable formats.

## Validation

The cross-tool signature controls live in
`tests/integration/test_ada_signature_integration.py`; do not duplicate them as
private tests. Run that focused module with `PYTHON_JIT=1`, nice 10 and at most
six aggregate test workers. Python edits also require scoped `lint-iteration`.
Analyzer changes require analyzer-specific controls as well as integration checks;
a naming regression alone does not verify disassembly or rebuildability.
