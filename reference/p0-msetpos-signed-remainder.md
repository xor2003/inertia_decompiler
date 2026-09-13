# mset_pos Signed Remainder Investigation

## Current Reproduction

On 2026-09-11, the exact test
`test_x86_16_cod_samples.py::test_cod_decompilation_cases[f14_mset_pos]`
still fails under `PYTHON_JIT=1 PYTHONHASHSEED=0`, pytest `-n 7`.
Log: `/tmp/inertia-msetpos-current.log`.

Its output has two independent problems, not merely missing `% 80` spelling:

1. The parameter `unsigned short arg_6` is redeclared inside the same function
   as `unsigned char arg_6` at BP+4. Argument/storage ownership needs repair.
2. The remainder expressions use unsigned 32-bit divisor casts even though
   the binary uses signed `CWD; IDIV CX` for both arguments.

The original instruction bytes in `cod/f14/MONOPRIN.COD` read words from BP+4
and BP+6, divide by 80 and 25 respectively, and store DX to DS offsets 2 and 4.
Source is a comparison oracle; these instruction effects must be recoverable
without names or the original C.

## Signedness Root Cause

An observational wrapper around
`lowering.native_integer_constants.lower_native_integer_operation_8616`
delegated unchanged to the original function. Both native construction calls
already received `BinaryOp(op="Mod", bits=32, signed=False)` with the
sign-extended input. Lowering's explicit casts faithfully expose this earlier
wrong signedness; removing those casts would hide the defect.

The installed angr implementation at
`angr/analyses/decompiler/peephole_optimizations/modulo_simplifier.py:64`
constructs the replacement `Mod` with literal `False` while matching
`a - (a / N) * N`. A direct invocation with a signed 32-bit `Div` confirms:

```text
source_div_signed= True result_mod_signed= False
```

Therefore repair the AIL optimization boundary, preserving division signedness
and validating conversions/widths. Do not infer signedness from rendered C,
source names, or sign-looking operand shapes in Rewrite/Lowering.

## Required Follow-up

- Add focused optimizer regressions for signed and unsigned inputs, including
  negative operands and conversion/refusal cases. Validate truncation toward
  zero rather than Python floor-division semantics.
- Integrate through the existing angr compatibility mechanism at the earliest
  owner; do not patch only the installed virtualenv dependency.
- Repair the independent argument identity conflict using Alias/typed storage
  evidence, not declaration text deletion.
- Require strict C compilation and executable negative-input behavior before
  replacing the old formatting-sensitive assertion.
- Rerun the original test, relevant routine tests, types, lint and pipeline.

No production fix or test closure is claimed by this investigation.

## Implementation Checkpoint

The worktree now contains an IR-owned lossless remainder fold and a bootstrap
adapter replacing angr's x86-16 optimization entrypoint. Other architectures
delegate unchanged. Signedness comes from the matched division. The fold
refuses conversion-crossing identities, mismatched widths, zero divisors,
possible signed minus-one overflow, and non-pure dividend expressions.

Before: four regressions failed and two passed (9.34s). After: **22 focused
checks passed in 8.78s**, including compiled C for signed/unsigned negative
inputs. New owner/adapter pass Ruff, MyPy and Pyright; architecture check
passed. Global `quality-fast` still fails at legacy Ruff debt.

**Not accepted as a complete function repair:** fresh mset_pos construction
now receives signed modulo nodes, but the final C references `inertia_eax`
instead of retaining the two argument values, with no visible loads restoring
those values. The conflicting `arg_6` declaration also remains. Do not call
the function fixed or count its original token-only test as semantic success.

A new compile/run test catches this: the old token test passes, while
`test_x86_16_msetpos_behavior.py` fails strict compilation on the conflicting
declaration. Its executable checks also require distinct positive and negative
input values to reach the two outputs. It is registered in the routine
pipeline and ownership mapping, intentionally keeping the gate red until the
remaining defect is repaired; it is not skipped or marked xfail.

Next action is to trace canonical argument storage through native C variable
construction and register-state lowering, then satisfy this executable oracle.
The full pipeline has not been rerun at this checkpoint. Earlier passing
pipeline counts do not apply to this newer, intentionally failing regression.

Logs under `/home/xor/.cache/`: `inertia-remainder-{before,after,mypy,pyright,architecture,quality-fast}.log`,
`inertia-msetpos-after.{c,log}`, and `inertia-msetpos-behavior.log`.

## Environment

The root filesystem became full during investigation (`/`: 0 bytes available;
`/home`: approximately 3.2 GiB available). The diagnostic used
`TMPDIR=/home/xor/.cache` instead of deleting unrelated files. Temporary probe
artifacts are `/home/xor/.cache/inertia-msetpos-signedness-probe.py` and
`/home/xor/.cache/inertia-msetpos-probe.{c,log}`. Future test runs must account
for the space constraint; an ENOSPC failure is not a semantic test result.

## SSA Authority Repair And Remaining Regression

The InitBars regression recorded in this section was subsequently resolved:
see [coordinate producer ownership repair](p0-initbars-coordinate-ownership.md).
The latest routine pipeline passes 3,994 tests and all seven MS C round trips;
global Ruff and the full Step 9 audit remain open.

A fresh observation at the first GP-state lowering pass found contradictory
evidence: registered SSA classified only ESP and EBP as live-ins; the C AST
heuristic classified EAX because argument-derived SSA carriers lacked local
assignments at that intermediate stage. The unconditional union of those sets
replaced both derived values with entry EAX before argument materialization.

`lowering.gp_register_state` now uses proven registered SSA when available;
the legacy AST-only fallback no longer overrides that authoritative result.
The new `test_x86_16_gp_livein_authority.py` demonstrates the original
incorrect replacement and retention after the fix. It is registered with the
routine tests and GP owner.

The shared fix also removes the conflicting declaration through the existing
argument pipeline. No declaration deletion, naming repair or C-text rewrite
was added. Fresh output assigns the two arguments to separate AX-derived
values before signed remainder operations. The source-independent blob
compile/run test and GP tests pass: **20 passed in 11.16s**.
The COD CLI check returned 0 with `validation=passed` and clean whole-tail
validation; scoped MyPy/Pyright passed. Global Ruff remains red, including
legacy findings in the touched GP-state module.

**Broader gate is not green:** the routine run returned **3,991 passed,
2 failed in 196.25s**. The bootstrap inventory expectation was then updated
for the new installed hook and passed its focused rerun (8.64s). InitBars
still fails whole-tail validation with BP-0x70 versus BP-0x72 argument/storage
identity and an uninitialized register-carrier diagnostic. Investigate this
regression before accepting the combined work as a stable checkpoint; do not
restore weaker validation or infer a fresh suite total by subtraction.

All seven MS C round trips passed. Pipeline lane verdicts: two passed, one
failed, none skipped or timed out. The full suite has not been rerun.

Latest logs under `/home/xor/.cache/`: `inertia-gp-authority-{before,after,mypy,pyright,quality-fast,pipeline}.log`,
`inertia-bootstrap-after.log`, `inertia-msetpos-fixed.{c,log}`,
`inertia-msetpos-cli.{c,log}`, and `inertia-msetpos-gp.log`.
