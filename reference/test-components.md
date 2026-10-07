# Test component ownership

Repository tests receive pytest component markers from
[test-components.json](test-components.json), loaded by the root
`tools/dev/pytest_components.py` plugin. This includes explicitly selected comparator
artifact tests. Every parametrized case inherits its module's labels.

| Marker | Component |
| --- | --- |
| `decompiler` | IR, recovery, generated C, decompiler CLI and tail validation |
| `compiler_detector` | Compiler identification and compiler-option detection |
| `signatures` | Library signature catalogs and matching |
| `ssa_z3` | 16/32-bit SSA/Z3 comparison, proof contracts and controls |
| `dosunit` | Unit harness, CLI and capture contracts |
| `ada_script` | Integrated ADA assembly tools |
| `lifter` | Instruction decoding and VEX lifting, including Cython |
| `cpu_flags` | x86 flags and condition semantics |
| `loader` | Executable loading and address-space setup |
| `runtime` | Concrete execution, replay and DOS/PE service models |
| `compiler_toolchain` | Compiler execution, recompilation and fixtures |
| `tooling` | Test infrastructure, scheduling, linters and repository checks |
| `debugger` | Interactive debugger |

Integration tests can belong to multiple components. These are ownership
labels, not dependency closure: importing a lifter fixture does not make every
decompiler test a lifter test. `compiler_detector` concerns compiler flags;
`cpu_flags` concerns processor flags. Labels do not change existing KVM,
resource, skip or execution requirements.

```sh
# Comparator tests, without KVM execution
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest -m 'ssa_z3 and not requires_kvm'

# Decompiler tests / detector and signature tests / ADA tests
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest -m decompiler
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest -m 'compiler_detector or signatures'
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest -m ada_script

# An artifact adapter, selected explicitly as before
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/comparator/tests/test_bc5_driver.py -m ssa_z3

# Cheap ownership/selection regression, also included in default pytest
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/dev/tests/test_components.py
```

Add new test module paths to the appropriate component lists in the JSON
catalog. Keep lists sorted. Add ordinary `@pytest.mark.<component>` marks for
individual cross-component tests when necessary; they supplement module labels.
Unclassified collected repository tests fail before `-m` deselection. The
inventory regression also detects missing modules, deleted modules and malformed
catalogs. Vendor and generated scratch trees are outside this ownership catalog.

Marker selection filters collected tests; it does not avoid module imports.
For the fastest iteration, pass explicit focused test paths as well as markers.
Artifact directories are not added to default collection: their adapter modules
can have colliding names and should retain their existing isolated execution.
