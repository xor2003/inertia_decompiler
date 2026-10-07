# Decompiler commands and orchestration

This package owns command handling, function discovery, cache access, fallback
selection and reporting. Semantic recovery belongs to the decompiler layers.

Run `python -m inertia.cli.cli --help` or the repository's `decompile.py` entry
point. `inertia_decompiler` retains historical import and command aliases.

Private tests belong in `tests/cli/`; tests spanning several layers belong in
`tests/integration/`.
