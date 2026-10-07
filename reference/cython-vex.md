# Required Cython 16-bit VEX lifter

`inertia/frontend/x86_16/lift_86_16.py` is the authoritative implementation for both backends. Cython
compiles this ordinary Python file in pure Python mode; there is no `.pyx`
copy or generated semantic code. Normal startup requires a verified compiled
extension; Python interpretation remains an explicit diagnostic mode.
This changes execution of the lifter, not instruction semantics,
Z3 proof rules, or the PE32 comparator.

Install the build dependencies and compile locally:

```sh
uv pip install --python .venv/bin/python 'Cython>=3.2,<4' setuptools
PYTHON_JIT=1 nice -n 10 .venv/bin/python tools/dev/build_cython_vex.py
```

A C compiler and Python development headers are required. Generated C, objects,
the extension, and its manifest stay under ignored `.cache/cython-vex/`.
The first build takes several minutes; subsequent identical builds reuse
compiler outputs. Rebuild after editing the lifter or changing Python ABI.
`CC=clang` can select Clang when installed; compiler selection and optimization
arguments are recorded in the build identity. The same source and ABI checks
apply to either compiler.
The extension uses `-O2 -g0`: generated C debug symbols are omitted
to reduce compiler work and artifact size; Python tracebacks and annotation
HTML retain the lifter's source diagnostics.

Choose the backend **before starting Python**, including pytest workers:

```sh
INERTIA_VEX_BACKEND=cython PYTHON_JIT=1 nice -n 10 .venv/bin/python decompile.py SORTDEMO.EXE
INERTIA_VEX_BACKEND=python PYTHON_JIT=1 nice -n 10 .venv/bin/python decompile.py SORTDEMO.EXE
```

The default `cython` mode requires a valid compiled artifact and raises an import error for a
missing/stale build. Normal startup never silently falls back. Explicit `auto`
uses a verified build when available and otherwise
interprets Python. `python` never loads the cached extension. The package's
`VEX_BACKEND` records the selected backend; `lift_86_16.__file__` records its
actual source/extension path. Ordinary imports retain their canonical names
and register one lifter. Selection verifies source and extension SHA-256 plus
Python cache tag and SOABI; it never relies solely on timestamps.

Compilation uses `annotation_typing=False`, `infer_types=False`, and
`binding=True`. Owned Python type annotations are not C storage declarations:
integers retain Python precision and wrapping remains explicit in the lifter.
Gymrat instruction/lifter classes and methods stay dynamically bound Python objects. Explicit
`@cython.locals` declarations type the decoder's bounded prefix indices,
actual boolean flags, and locally created bytes/set/list objects. Guest
addresses, register values, and VEX expression arithmetic stay Python objects.
When Cython is absent, a small no-op annotation shim preserves interpretation;
there is no mandatory runtime Cython dependency or C-only source syntax.
See [Cython's pure Python mode documentation](https://docs.cython.org/en/latest/src/tutorial/pure.html).

The instruction/customizer forwarding facade remains an ordinary Python
class. A default sentinel avoids
constructing an `AttributeError` for every helper absent on the instruction.
Instruction helpers still take precedence, `None` remains a valid value,
and changed methods/metadata are read afresh. No bound-method cache is used.
Both wrapped providers remain accessible to frontend memory helpers. The
instance dictionary preserves direction-proof metadata and other dynamic
per-instruction evidence. `@cython.locals(value=object)` keeps the forwarded
value a Python object in compiled mode.

A native Cython class was tested and rejected: its generated `tp_getattro`
calls `PyObject_GenericGetAttr` and constructs an `AttributeError` for each
forwarded lookup before invoking `__getattr__`. The smaller annotation score
inside that method did not establish an overall speedup. Keep this class
ordinary unless a future measured change removes that dispatch cost.

Run differential instruction checks and uncached real-binary SSA benchmarks:

```sh
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m pytest tests/frontend/test_lifter_backend.py tests/frontend/test_x86_16_lifter_cython_dependency.py -n 3 --tb=short --durations=5
INERTIA_VEX_BACKEND=python PYTHON_JIT=1 nice -n 10 .venv/bin/python tools/dev/benchmark_cython_vex.py --out .cache/cython-vex/bench-python
INERTIA_VEX_BACKEND=cython PYTHON_JIT=1 nice -n 10 .venv/bin/python tools/dev/benchmark_cython_vex.py --out .cache/cython-vex/bench-cython
cmp .cache/cython-vex/bench-python/ssa.json .cache/cython-vex/bench-cython/ssa.json
```

The benchmark records wall time, process CPU, peak RSS and lowering counters.
It selects five bounded SORTDEMO functions and performs no VEX disk-cache reads.
Compare identical function selections and SSA artifacts; record host contention
and cache state when interpreting timings. Warm VEX cache hits bypass lifting,
so this acceleration cannot improve that portion of a warm comparator run.

Generate Cython's interaction heatmap without compiling C or changing the
active backend, then correlate it with a current interpreted lowering profile:

```sh
PYTHON_JIT=1 nice -n 10 .venv/bin/python tools/dev/build_cython_vex.py --annotate-only
INERTIA_VEX_BACKEND=python PYTHON_JIT=1 nice -n 10 .venv/bin/python tools/dev/benchmark_cython_vex.py --functions 17 --profile .cache/cython-vex/lowering.prof --out .cache/cython-vex/profile
PYTHON_JIT=1 nice -n 10 .venv/bin/python tools/dev/report_cython_vex.py --annotation "$ANNOTATION_HTML" --profile .cache/cython-vex/lowering.prof --out .cache/cython-vex/interaction-report.md
```

Set `ANNOTATION_HTML` to the path printed by the annotation build.
The build command prints the actual HTML path (its nested source path depends
on the checkout location). Yellow lines use Python's C API; expand them to
inspect generated C. Static annotation heat is not execution time. The report
ranks current interpreted self CPU time alongside interaction scores; profiling
is disabled in production compiled builds, so this is not a compiled speed
measurement. Keep profiled runs separate from uninstrumented timing comparisons.
Use `--force` to regenerate annotations or rebuild compiler outputs explicitly.
