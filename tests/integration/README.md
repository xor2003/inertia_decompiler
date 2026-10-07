# Cross-component tests

A test has one physical home and may carry several component labels. Shared
signature/ADA/decompiler checks live here; parser-only tests belong to
`tools/signatures/tests/`. Component declarations preserve all existing labels
and exact gate targets. Shared import/KVM setup is registered by root conftest.

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tests/integration -q --tb=short --durations=5 -n 2
```

Do not use a fixture directory as proof or duplicate tests under each tool.
Large binary/compiler assets remain outside the repository or in ignored roots.
