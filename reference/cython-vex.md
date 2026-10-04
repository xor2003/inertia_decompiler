# Required Cython 16-bit VEX lifter

`lift_86_16.py` is the authoritative implementation for both backends. Cython
compiles this ordinary Python file in pure Python mode; there is no `.pyx`
copy or generated semantic code. Normal startup requires a verified compiled
extension; Python interpretation remains an explicit diagnostic mode.
This changes execution of the lifter, not instruction semantics,
Z3 proof rules, or the PE32 comparator.

Install the build dependencies and compile locally:

```sh
uv pip install --python .venv/bin/python 'Cython>=3.2,<4' setuptools
PYTHON_JIT=1 .venv/bin/python scripts/build_cython_vex.py
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
INERTIA_VEX_BACKEND=cython PYTHON_JIT=1 .venv/bin/python decompile.py SORTDEMO.EXE
INERTIA_VEX_BACKEND=python PYTHON_JIT=1 .venv/bin/python decompile.py SORTDEMO.EXE
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
PYTHON_JIT=1 .venv/bin/python -m pytest angr_platforms/tests/test_x86_16_cython_backend.py -n 3 --tb=short --durations=5
INERTIA_VEX_BACKEND=python PYTHON_JIT=1 .venv/bin/python scripts/benchmark_cython_vex.py --out .cache/cython-vex/bench-python
INERTIA_VEX_BACKEND=cython PYTHON_JIT=1 .venv/bin/python scripts/benchmark_cython_vex.py --out .cache/cython-vex/bench-cython
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
PYTHON_JIT=1 .venv/bin/python scripts/build_cython_vex.py --annotate-only
INERTIA_VEX_BACKEND=python PYTHON_JIT=1 .venv/bin/python scripts/benchmark_cython_vex.py --functions 17 --profile .cache/cython-vex/lowering.prof --out .cache/cython-vex/profile
PYTHON_JIT=1 .venv/bin/python scripts/report_cython_vex.py --annotation .cache/cython-vex/annotation/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lift_86_16.html --profile .cache/cython-vex/lowering.prof --out .cache/cython-vex/interaction-report.md
```

The build command prints the actual HTML path (its nested source path depends
on the checkout location). Yellow lines use Python's C API; expand them to
inspect generated C. Static annotation heat is not execution time. The report
ranks current interpreted self CPU time alongside interaction scores; profiling
is disabled in production compiled builds, so this is not a compiled speed
measurement. Keep profiled runs separate from uninstrumented timing comparisons.
Use `--force` to regenerate annotations or rebuild compiler outputs explicitly.

Local acceptance on 2026-09-28: the final build passed 13 backend/report
checks, including differential VEX checks in interpreted, compiled,
Cython-absent, and legacy-import modes. Forwarding tests cover live mutations,
instruction precedence, `None`, dynamic metadata, descriptor fallback, and
propagation of errors other than `AttributeError`.

The annotation/profile report identified 41,709 forwarding calls. Replacing
exception-driven fallback reduced the getter's peak static interaction score
from 58 to 6. This score motivated the experiment; timing and identical SSA
were the acceptance evidence. The compiled artifact shrank from approximately
5.6 MiB to 1.3 MiB after omitting generated C debug symbols.

A serial six-process comparison used three samples of the previous compiled
build and three of the final compiled build. Because other agents were editing
the repository, all processes imported the same immutable snapshot of 2,411
Python sources while retaining original file origins for binary assets. Both
extension hashes and source hashes were verified separately; production backend
freshness checks remain intact. No VEX disk-cache hits occurred. All six SSA
artifacts matched exactly: 17 SORTDEMO functions, 257 blocks, 246 SSA parts,
11,650 assignments, and no lowering refusals. Profiled runs were separate.

| Metric | Previous compiled build | Final compiled build |
| --- | ---: | ---: |
| Lowering CPU samples (seconds) | 9.69, 9.69, 10.01 | 8.97, 7.98, 4.73 |
| Median lowering CPU (seconds) | 9.69 | 7.98 |
| Maximum peak process RSS (MiB) | 281.4 | 279.0 |

The sampled median CPU reduction was 17.7%. Host contention and timing variation
were substantial; this bounded result does not establish a stable full-corpus
or warm-cache comparator speedup. Warm cache hits bypass this lifter entirely.
VEX object creation and third-party wrappers remain major costs.
The local evidence is in `.cache/cython-vex-opt/frozen-summary.json`, the
`frozen-*-*/ssa.json` artifacts, and `interaction-simple.md`; these ignored
artifacts are machine-local. The commands above reproduce the supported
benchmark and interaction report on the current source tree.

Scoped Ruff and strict mypy passed, including the lifter. Broad project gates
are reported separately from these focused checks; a bounded gate that times
out or finds unrelated shared-tree debt is not a full green result.
The final scoped `quality-dev` attempt passed its lint/type/build-smoke and
startup architecture steps, then stopped at `test-ownership-check`: the shared
`test_real16_binary_compare.py` contains skip/xfail in fast-owned tests. The
pipeline and optimization-quality suite were therefore not reached.
