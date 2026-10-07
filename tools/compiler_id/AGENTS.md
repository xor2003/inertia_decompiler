# Compiler identification owner

Read the root semantic/safety rules and [README.md](README.md). Change optional
classification/reporting here; shared signature parsing belongs to its owner.

Focused regression: `nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/compiler_id/tests -q --tb=short`.
Preserve package and legacy CLI/import behavior. Do not use matches as proof.
