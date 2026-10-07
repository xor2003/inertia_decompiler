# PyVEX lazy IRSB logging

Target: https://github.com/angr/pyvex
Pinned commit: `08ef1010ef83fe3058350fed57b45020d4e57567`.

`fix.patch` changes eager IRSB stringification into lazy logging and adds
two standalone upstream tests. The tiny Gymrat lifter requires no Inertia
imports or DOS architecture. Disabled debug must never stringify the IRSB;
enabled debug must retain the rendered diagnostic.

Apply to the pinned checkout with `git apply /absolute/path/to/fix.patch`.
After installing/building upstream PyVEX and its test dependencies, run:

```sh
PYTHON_JIT=1 nice -n 10 python -m pytest tests/test_gymrat_logging.py -q --tb=short
```

Local evidence: unmodified pinned Python sources produced one failed and
one passed test; patched sources produced two passed tests (1.50 seconds).
The checkout reused the installed PyVEX native library and generated FFI
module. This verifies the Python logging path, not a clean upstream native
build or its full suite. No speedup claim, benchmark, duplicate-issue audit
or upstream submission is included. Complete those before requesting review.
