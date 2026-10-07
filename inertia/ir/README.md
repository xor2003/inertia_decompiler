# IR evidence contracts

`vex_bit_source.py` owns `BitSourceProjection8616` and
`project_bit_source_8616`: bounded projection of one selected bit through proven
neutral bitwise operands. It preserves captured reads and refuses unsupported
operators, invalid definitions and exhausted bounds by retaining the original
atom. It does not claim whole-value equivalence.

Consumers include the frontend DF-direction helper. Historical
`angr_platforms.X86_16.ir.vex_bit_source` imports remain exact aliases, including
legacy pickle lookup. The remaining IR modules have not moved yet.

Focused controls:

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tests/ir/test_x86_16_vex_bit_source.py -q --tb=short --durations=5
```
