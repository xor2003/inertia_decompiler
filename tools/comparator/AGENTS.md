# Comparator work

This supplements the repository `AGENTS.md`; its proof and execution rules apply.
Start with [README.md](README.md), then read the owner selected for the task.

## Ownership

- `catalog.py`, target catalogs: function coordinates and correspondence evidence.
- `profiles.py`: successor-admission policies, never proof semantics.
- `cfg.py`: shared native discovery/lowering; target CFG modules: verdict policy.
- Target region modules: bounded composition and explicit conditional premises.
- Target CLI modules: inputs, dispatch and reports; no instruction semantics.
- `native.py`, `services.py`: qualified views of authoritative backend owners.
- `*_compat.py`: historical scoped adapter API, retained for compatibility tests.
  Production drivers must use explicit architecture/policy contracts.
- `verdict.py`: complete accounting and typed public outcomes.
- `verified_pe.py`: byte-verified loader cache; `tests/` contains private controls.

Instruction/SSA semantics belong in `tools/dosunit/`, not duplicated here.
Names select function obligations; names, matching graphs and cache hits never
establish equivalence. Keep unconditional, conditional, failed and refused distinct.
Preserve declared assumptions and register/memory/control observations.

## Focused validation

Run `make lint-iteration` on explicit changed paths and the affected private tests.
Run Python/pytest with `PYTHON_JIT=1` and nice 10. Use at most two concurrent
budgeted proof workers; the repository-wide aggregate limit remains six.
Finish source edits and native builds before source-seal tests.

For module/CLI moves, check fresh-process qualified imports, historical identity,
source seals and installed CLI behavior. Packaging requires the verified Cython
bundle; interpretation is an explicit diagnostic mode, not installed acceptance.
Use `python -m pytest tools/comparator/tests` for private integration. This is
comparator acceptance only; it does not claim decompiler or whole-plan completion.
