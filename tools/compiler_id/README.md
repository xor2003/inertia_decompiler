# Compiler identification

Reports optional compiler/library signatures and likely compiler flags. These
are classification evidence; they do not prove function semantics.

```sh
nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.compiler_id PROGRAM.EXE --help
nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/compiler_id/tests -q --tb=short
```

Public command API: `tools.compiler_id.report.main(argv)` and
`tools.compiler_id.cli.main(argv)`. Input is an executable plus optional
signature catalogs/flag profiles. Output is a text report and optional cached
classification data. `--help` lists the current formats and switches.

Signature parsing remains owned by the shared `omf_pat`/signature catalog code.
This tool must not recover argument types, repair generated C, or influence
proof verdicts. It must not depend on CLI/decompiler implementations.

`scripts/report_compiler_matches.py` retains the old command and import identity.
Remove that shim only after external consumers migrate. Tool-specific tests
live here; large compiler/signature datasets remain external or ignored.

Ownership and test labels: [compiler_detector.json](../../reference/components/compiler_detector.json).
