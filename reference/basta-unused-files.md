# Basta `unused-python-files` — configuration and triage

The `unused-python-files` Make target scans canonical `inertia`, `tools` and
`tests` source trees with Basta 0.3.0. Run the current target to obtain candidate
counts.

```bash
rtk proxy nice -n 10 make unused-python-files PYTHON=./.venv/bin/python
```

Basta reports static reachability. Test-only references and absent import edges
are review inputs, not proof that a module or its behavior is unnecessary.

## Reachability limits

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
  `inertia/cli/cli.py`, `decompile.py`'s `__import__`).

## Entry points and review

Make explicitly admits `direct_request_fast_path.py`, `borland_mangling.py`,
`pytest_directory_cache.py`, `pytest_live_failures.py` and `pytest_runtime.py`.
These owners have dynamic CLI or pytest consumers outside the scanned trees.
The declarations preserve those edges without hiding other unused-file findings.

Keep repository-root entry scripts outside the scan roots: Basta's Makefile path
reachability can otherwise mark nearly every maintained file as reached and hide
useful diagnostics. Review candidate imports, public exports, tests and runtime
registration before removal. A missing static edge is insufficient by itself.
