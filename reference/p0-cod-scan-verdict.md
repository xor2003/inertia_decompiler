# COD Batch Verdict Coherence

Step 9 remains open. This is a tooling/reporting repair, not a semantic
repair of `__fimemset`.

## Root Cause

`scripts/decompile_cod_dir.py` replaced a failed child's exit classification
with the success flag from a secondary `FunctionScanResult`. That result
contains diagnostic counts and classifications, not replacement generated C.
For a successful non-fallback scan the renderer selected the failed child's C;
for other scans it discarded that C and emitted diagnostic comments instead.
The batch could therefore return zero without a successful output artifact.

The child artifact, exit classification and tail-validation records now remain
authoritative together. Secondary scans remain visible as diagnostics and do
not promote failures. Partial output is retained, explicitly marked failed.
No decompiler semantics or validation acceptance rules were changed.

## Evidence

- New regression: successful scans with no fallback, `none`, and a named
  fallback must all preserve the failed child's status and partial output.
- Before: all three cases failed, 6.06s.
- After: complete COD batch test module, 34 passed, 6.34s (`pytest -n 7`).
- Real MONOPRIN `__fimemset` regression: still fails, 16.36s, now at the
  required zero-exit assertion instead of incorrectly reaching its old helper
  spelling assertion. Its child validation failure is no longer masked.
- Scoped MyPy passed with `--explicit-package-bases --follow-imports=silent`;
  initial invocation without explicit package bases encountered an existing
  duplicate-module resolution problem. Scoped Pyright passed.
- Ruff `check --fix`: import ordering fixed; 12 legacy complexity/magic-value
  findings remain in the two touched files. No clean global-linter claim.
- Logs: `/home/xor/.cache/cod-scan-{before,after,real,ruff,mypy,pyright}.log`.

## Remaining Work

Investigate `__fimemset` far-pointer/count argument widths, uninitialized local
and postprocess validation rejection at their authoritative semantic owners.
Do not weaken the zero-exit assertion or substitute diagnostic scan success.
Replace the historical intrinsic-name assertion only with equivalent or stronger
behavioral evidence once actual generated C is correct.

The latest retry of the previously failing 21 full-suite nodes was 2 passed,
19 failed in 207.05s. This is not a refreshed full-suite count. The previous
routine gate of 3,994 passed and seven MS C round trips predates this repair.

## Binary-Only Reduction

A subsequent direct COD run with a 60-second timeout exits 4. Its whole-tail
guard identifies uninitialized SS:BP+5 (one byte) and SS:BP+6 (two bytes).
Removing COD metadata entirely still produces incorrect argument storage;
this is not solely a debug-name or source-prototype problem.

The new `test_x86_16_les_stack_argument_behavior.py` reduces the issue to
`PUSH BP; MOV BP,SP; PUSH ES; LES DI,[BP+4]; MOV AX,DI; POP ES; POP BP; RET`.
It strictly compiles generated C and executes asymmetric word inputs. A
`MOV AX,[BP+4]` control passes. The LES case compiles but returns the wrong
value for 0x1234: its generated high-byte expression reuses the low-word
dereference instead of retaining distinct byte-range identity. Result:
**1 passed, 1 failed in 15.16s**, pytest `-n 7`; new test Ruff-clean.

This is a committed-to-worktree failing regression, not a function repair.
It is discovered by the full test suite; routine-owner registration is pending
identification and repair of the exact storage owner. Do not change frontend
byte-safe execution or patch the rendered C to make it pass. Next trace:
LES byte-load identity through Alias and stack-variable subview materialization.

Probe artifacts are under `/home/xor/.cache/fimemset-{current,blob,reduced}.*`;
the focused test log is `fimemset-reduced-test.log`. No broader gate or fresh
full-suite pass count is claimed for this investigation.

## Variable-Binding Boundary Trace

The reduced regression was rerun with generated C included in its failure
message. The LES return is:

```c
return *(inertia_ss * 16 + &arg) | (*(inertia_ss * 16 + &arg) * 0x100);
```

An observational codegen wrapper delegated unchanged to angr while recording
stack virtual variables and their variable-map entries. The final Clinic AIL
still contains distinct one-byte loads through `Reference vvar_20{s2|1b}` and
`Reference vvar_21{s3|1b}`. At C generation both map to the same two-byte
`SimStackVariable` at offset 2, with `variable_offset(...)` equal to `None`.
The second byte's displacement has therefore disappeared in the variable
association, before final C cleanup. The local owner is initially labelled
`ret_addr`; the emitted argument name is not semantic evidence.

Installed angr's `Clinic._link_variables_on_expr` obtains `(var, offset)` from
variable recovery and passes it to `VariableMap.set_variable`.
`CStructuredCodeGenerator._handle_VirtualVariable` returns the associated C
variable directly for a reference/lvalue, without projecting an interior byte.
These observations identify two contracts to verify: recovery must retain the
subrange displacement, and codegen must consume that displacement at the
requested byte width. The exact instruction that first loses the displacement
inside variable recovery has not yet been identified. Do not infer its cause
from the final C or introduce a guessed BP/SP coordinate adjustment.

Trace logs: `/home/xor/.cache/les-ail.log`, `les-map.log`, and `les-current.log`.
The probe lives outside the repository and changes no pipeline behavior.
Next action: inspect the variable-recovery access recorded for the high-byte
reference, then add a focused boundary regression and repair its earliest owner.

### First Loss Confirmed

An unchanged-delegation probe of `SimEngineVRBase._ensure_variable_existence`
now confirms its return values before Clinic linking:

```text
requested stack offset 2 -> variable(base=2, size=2), offset=0
requested stack offset 3 -> variable(base=2, size=2), offset=0
```

The second result must retain an interior-byte displacement. The installed
implementation extracts an annotation offset from a one-byte stack-region load
and records it without reconciling the requested stack address with the
containing variable's base. Clinic subsequently preserves that incorrect zero
as the variable-map association; codegen does not introduce the first loss.
Evidence: `/home/xor/.cache/les-recovery.log`.

Alias is not missing LES's accesses: the stack-word artifact contains exact
machine-BP loads `(4, 2)` and `(6, 2)` at instruction 0x1004. The current
materializer honestly reports `ALIAS_LOAD_AMBIGUOUS` because it selects by
instruction address and requires one candidate. The repair must retain and
consume the expression's exact subrange, not choose the first LES word.
Evidence: `/home/xor/.cache/les-word-artifact.log`.

A temporary, isolated codegen-only experiment reconstructed displacement from
the stack virtual variable. It changed the high address to `&arg + 1`, but
retained the wrong pointer width and redundant segment-base arithmetic.
It was **not landed**: offset repair alone is not semantic completion.
The actual recovery and all downstream typed views must agree before accepting
the existing generated-C behavioral regression. Candidate artifact:
`/home/xor/.cache/les-map-candidate.c`.

## Association Repair Checkpoint

The worktree now contains the Alias-owned `stack_reference_displacement_8616`
and an architecture-scoped variable-registration adapter. It projects only
contained, exact stack virtual-variable ranges; non-contained ranges retain
their previous association. Correction happens before publication, so atom,
statement, instruction indexes and durable access records agree. Other
architectures delegate unchanged. No destructive overwrite of sibling accesses
or guessed frame-coordinate conversion is used.

Fresh native observation confirms the high-byte variable-map displacement is
now **1**, while the low-byte displacement remains zero (`None` in angr's
representation). This repairs the first loss, not the whole function.

- Six focused registration/refusal/bootstrap checks passed in 13.18s.
- New modules and bootstrap pass scoped Ruff; scoped MyPy/Pyright passed.
- Full architecture check passed after adding required ownership headers,
  future annotations and promoted-file registration.
- Before the extra refusal cases, the combined native/association run had
  three passed and one failed: the LES generated-C regression remains red.
  Its corrected variable-map displacement still needs a typed codegen consumer.
- Both regression modules are registered in routine Make/pipeline lists and
  the stack-reference owner. The routine pipeline is intentionally not claimed
  green while this semantic obligation remains open.

Logs: `/home/xor/.cache/les-offset-{focused,after,mypy,pyright,architecture}.log`.
No full-suite refresh or completed semantic function repair is claimed.

### Consumer Experiment And Stronger Oracle

The executable regression now also repeats a word-return check with SS=0x1234.
This prevents accepting a candidate that works only when a redundant DOS
segment-base term happens to be zero. The MOV control passes; the current LES
output still fails its initial asymmetric-word check (1 passed / 1 failed,
6.62s). Thus the new nonzero-SS obligation is not yet reached by the failing
LES implementation and is not claimed as separately verified behavior.

A bounded native-codegen candidate consumed the corrected variable-map offset
using required byte-pointer casts. It produced `&arg` for the low reference and
`(char *)&arg + 1` for the high reference, but retained `inertia_ss * 16` around
both host addresses. The candidate was removed, not installed in bootstrap.
The accepted variable-registration adapter remains in place.

Next owner is typed SS stack-load lowering: consume the exact Alias range and
its stack-value projection instead of leaving a DOS segment base added to a
host C variable address. Do not repeat cosmetic cast/offset-only repairs or
pick the first of LES's two proven load ranges. Generated code must satisfy
both nonzero-SS behavior and whole-tail validation before this function closes.
Logs: `/home/xor/.cache/les-subranges.{c,log}` and `les-nonzero-ss.log`.

## Return Traversal Repair

The existing SS stack-load materializer did not traverse `CReturn.retval`.
Its private child-field list visited assignments and other expressions but
silently skipped loads used directly as return values. Adding that field lets
the existing Alias-backed projection consume the corrected subrange bindings;
no additional codegen hook or C-text rewrite was needed.

The binary-only MOV and LES compile/run regressions now both pass, including
nonzero SS (2 passed, 14.74s). Fresh LES output returns unsigned low/high-byte
projections of its argument, without segment arithmetic. Both structuring and
postprocess snapshots are stable with no reported observable deltas.

Nearby checks: 249 passed, one failed in 22.86s. The failure is full MONOPRIN
`__fimemset`, which still fails its successful-decompilation requirement.
The reduced return repair must not be reported as closure of that function.

Broader verification: routine pytest 4,001 passed in 260.60s; all three pipeline
lanes passed, none failed/skipped/timed out. Full architecture and scoped
MyPy/Pyright passed. `quality-fast` remains red on global Ruff; the touched
legacy `real_mode_linear.py` has 243 Ruff findings. Mypyc import smoke passed
for 39 modules. No new full-suite audit is claimed.

Logs: `/home/xor/.cache/les-retval-{validation,nearby,ruff,mypy,pyright,architecture,quality-fast,pipeline}.log`.

## Native Variable Naming Exception

A fresh `__fimemset` retry exposed an earlier lowering exception:
`AttributeError: property 'name' of 'CVariable' object has no setter`.
Installed angr derives `CVariable.name` from its backing variable or unified
variable. `_ensure_stack_cvar_has_identifier_8616` updated those owners and then
attempted to assign the read-only projection as well. Related naming paths had
the same redundant write, sometimes hidden by broad exception suppression.

Lowering now updates only the backing names. No setter monkeypatch, guessed
storage identity, exception suppression, or rendered-C repair was introduced.
Native-object tests cover unnamed/named variables with and without a unified
owner: before, 2 failed / 2 passed in 12.03s; afterward all four pass.

The fresh combined run has 14 passes and one failure in 18.26s. The sole
failure remains full `__fimemset`. Its lowering exception is gone, but whole-tail
validation still reports uninitialized BP+5 byte and BP+6 word reads. The current
output still has incorrect narrow argument storage. Next investigation must
trace the binary-derived widths and physical offsets through prototype and
stack-subview materialization; this checkpoint does not prove that root cause.

Broader checks: 245 early contract checks passed; routine pytest 4,217 passed
in 256.76s; all three pipeline lanes passed, including seven MS C round trips.
Scoped MyPy/Pyright and full architecture passed. Ruff `check --fix` was run:
the test is clean, while `real_mode_linear.py` retains 243 legacy findings.
Global `quality-fast` remains red on lint debt; 39-module mypyc smoke passed.
No function acceptance or fresh full-suite success is claimed.

Logs: `/home/xor/.cache/stack-name-{before,after,ruff,mypy,pyright,architecture,pipeline,quality-fast}.log`.
