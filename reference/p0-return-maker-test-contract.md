# ReturnMaker Test Contract Reconciliation

## Reason And Correct Owner

The full-suite audit recorded five tests expecting ReturnMaker to replace the
return register with an earlier load, self-update or constant. On current
production source (`f37229fa1`), the isolated return group reproduced all five:
23 passed, five failed in 9.35 seconds.

The Frontend/angr compatibility owner explicitly separates evidence that a
return exists from the time at which its value is captured. ReturnMaker reads
architectural AX at RET. SSA owns propagation across earlier definitions;
substituting a producer expression here can move reads across BP restoration,
partial-register changes or memory writes. Do not restore that unsafe behavior
to satisfy obsolete tests.

## Test Changes

- Assert exact AX offset, 16-bit width and RET instruction provenance, instead
  of demanding producer substitution into the return expression.
- Retain stack-source and self-update expression checks through the existing
  source-evidence helper, separately from ReturnMaker's output contract.
- Preserve constant values/widths in the producer assignments and the existing
  caller-use, branch-refusal, prototype and counter checks.
- Keep the predecessor statements intact. AIL may copy expression nodes, so
  value/width preservation is checked rather than Python object identity.

No production code, validation or semantic recovery was changed. Existing
`test_x86_16_unobserved_return_maker.py` cases cover three caller-use states
against BP, partial-register and memory mutations, plus call barriers.

## Acceptance And Limitations

DoD: all 28 compatibility tests and 14 related barrier/native-return cases pass
without weakening source-evidence or refusal coverage. Definition of Failure:
moving producer reads to RET, losing AX width/provenance, deleting source
evidence checks, or treating this selected group as full-suite closure.

The final selected run passed **42 tests**, seven dependency warnings, in
**11.36 seconds** (`pytest -n 7`, duration reporting enabled; all reported test
durations below one second). Log: `/tmp/inertia-return-contract-final-check.log`.
File-wide checks remain red:
35 Ruff findings and 210 Pyright errors. The new object-return narrowing uses
explicit third-party AIL casts followed by runtime class assertions; no ignores
or lint exemptions were introduced. Broad gates were not repeated for this
test-only reconciliation. The complete repository audit remains open.
