# Basta `unused-python-files` — configuration and triage

`scripts/pytest_directory_cache.py` is an explicit pytest plugin entry point:
Make's `PYTEST_ARGS` and both pipeline pytest lanes load it with
`-p scripts.pytest_directory_cache`. Its Basta `--entry` records that dynamic
CLI edge; it is not an unused-file suppression without a production consumer.
The ordinary collection-parity tests cover the plugin's public hook behavior.

Evidence-backed record of the basta 0.3.0 integration fix and the remaining
unused-file findings. Basta is a reachability tool: it builds the import graph
from entry points and reports scanned files nothing reaches. "Only referenced
by tests" (medium, 70%) means every resolved importer is a test file; "certain"
(95%) means no resolved importer at all. Neither is proof of deadness — see the
blind spots below before acting on any finding.

## Verified basta semantics (fixture-proven in `.cache/basta-fixture/`)

- **Entry detection**: `pyproject.toml [project.scripts]`, `__main__.py`,
  `if __name__ == "__main__"`, shebangs, every `__init__.py`, and scripts
  (Makefile/CI/`.sh`) *inside the scanned tree* that name a source file.
  Manifests and scripts in directories that hold no scanned file are not read.
- **Test classification**: files under a `tests/` directory are treated as
  test code only when the directory is reached *inside* a scanned tree. Passing
  `tests/` itself as a scan root loses the classification and reports every
  non-`test_*` helper as "only referenced by tests".
- **`--entry <GLOB>`** marks matching *scanned* files as entry points. Globs
  match basenames (`name.py`, `**/name.py`); multi-segment relative paths like
  `pkg/name.py` do not match. Unscanned files cannot be made entries.
- **`import_module()`/`__import__()` are never followed**, even with literal
  string arguments — a real blind spot for this repo (the lazy CLI proxy in
  `inertia_decompiler/cli.py`, `decompile.py`'s `__import__`).
- Cython is now a mandatory runtime dependency: the Python lifter imports it
  directly, and the earlier no-Cython annotation shim has been removed.
- Fixture controls: a module reachable from an entry was never reported; a
  deliberately orphaned module was reported at 95%.

## Integration fix applied (Makefile `unused-python-files`)

Two defects, both caused by the scan root set `scripts inertia_decompiler
angr_platforms/angr_platforms angr_platforms/tests` lacking project context:

1. `angr_platforms/tests` as a scan root made every test-support module a
   "referenced only by tests" finding. Scanning `angr_platforms` (the parent)
   restores test-dir classification. This suppressed 31 test-internal files.
2. Repo-root entry scripts (`decompile.py`, `dump_debug_info.py`, …) are
   outside the scan, so modules reachable only through them were reported.
   Two proven cases are declared via `--entry` (bounded, per-file):
   - `inertia_decompiler/direct_request_fast_path.py` — imported by
     `decompile.py:194`, the `pyproject.toml [project.scripts]` console entry.
   - `angr_platforms/angr_platforms/X86_16/borland_mangling.py` — imported by
     `dump_debug_info.py:21` (shebang + `__main__` root tool script).

**Rejected alternative**: adding repo-root files (e.g. `decompile.py`) or `.`
to the scan activates the root Makefile/pyproject context — Makefile variable
lists name nearly every maintained file, collapsing the report 86 → 1. That
hides actionable findings, so the root stays out of scope.

Result: 86 → 53 findings (dirty-tree baseline 86; earlier snapshot was 87).
All removals were test-internal files or the two `--entry` declarations; every
remaining finding is unchanged in confidence.

## Current triage

The later [careful per-file audit](basta-unused-files-audit.md) supersedes the initial
candidate classification. It covers all 52 findings, distinguishes compatibility
exports, disabled guards, explicit prototypes, connected proof chains and isolated
implementations, and identifies integration obligations rather than treating
"test-only" as evidence of uselessness. Two additional uncalled private cleanup
implementations were removed; the current report contains 50 candidates.

## Reviewed removals

- `inertia_decompiler/debugger_tui.py`: unused 216-line placeholder UI. No
  caller or test import was found in the checked repository; `debugger.py` and
  the debugger regression use `inertia_decompiler.gdb_tui.GDBTUIApp`. Removed
  the placeholder and its lint/architecture inventory entries.
- `X86_16/cython_annotations.py`: obsolete no-Cython fallback. Cython is now
  required in project dependencies, and the lifter imports it directly. Removed
  the shim and updated regressions to require a loud missing-dependency failure.

The 53-finding count above records the integration checkpoint before these
removals; it is not a current count. Compatibility exports and test-only
semantic contracts remain pending review, rather than being treated as dead.
