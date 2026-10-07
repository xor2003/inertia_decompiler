# Real-mode x86 frontend

`arch_86_16.py` owns archinfo register storage, overlapping subregisters,
instruction mode and architecture registration. `control_coordinates.py` owns
architectural offsets versus loader-linear control destinations and their
explicit word/dword widths. These are frontend contracts, not decompiler type,
alias, structuring or rewrite recovery.

`load_dos_mz.py` and `load_dos_ne.py` own CLE loader registration, executable
headers, relocations and segment mapping. `ne_resources.py` parses optional NE
resource evidence; it must not infer executable semantics from resource labels.

`interrupt_contract.py` owns typed interrupt-service target evidence and address
projection. `simos_86_16.py` owns DOS SimOS registration, interrupt hooks and the
synthetic interrupt calling convention. Service evidence must retain explicit
unknown/refused cases; it does not authorize decompiler semantic recovery.

`vex_value_contract.py` checks symbolic PyVEX values. `direction_step.py`
derives string direction from the architectural DF bit using the existing
bounded bit-source proof in `inertia.ir.vex_bit_source`. These pure helpers do
not start the legacy lifter/decompiler pipeline when imported directly.

`lifter_backend.py` owns typed backend selection and byte/ABI/confinement checks
for native bundles. Importing this contract does not initialize angr or VEX.
`lift_86_16.py` is the authoritative pure-Python-syntax Cython source; its native
module name is `inertia.frontend.x86_16.lift_86_16`. `lifter_import.py` defers
backend verification until that exact module is requested. Normal startup
requires verified Cython; `INERTIA_VEX_BACKEND=python` selects interpretation
explicitly, and a corrupt native bundle must fail loudly. Other frontend imports
do not select the lifter backend.

Canonical imports:

```python
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16
```

Historical `angr_platforms.X86_16` imports remain exact module aliases.
Instruction helpers still live in the legacy frontend and are imported by their
existing owners; their semantic migration remains separate work.
Importing this package alone does not start the whole legacy pipeline.

Focused controls:

```sh
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m pytest tests/frontend -q --tb=short --durations=5
```

SSA source identity includes both this namespace and the remaining legacy tree.
Moving a contract changes its canonical serialized identity and source hash;
old import aliases preserve lookup, while stale proofs must be regenerated.
