# Development infrastructure owner

Read root rules and [README.md](README.md). Preserve selected test nodes,
markers, skips, budgets, ordering and exit codes. Never hide failed checks.

Focused regression: `nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/dev/tests tools/dev/tests/test_agent_test_focus.py tools/dev/tests/test_components.py -q --tb=short`.
Run the component-catalog check after declaration changes. Existing runner
policies stay authoritative until their projections have been migrated.
