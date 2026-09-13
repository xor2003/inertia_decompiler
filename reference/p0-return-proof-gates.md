# Return Proof Gates (2026-09-12)

Scope: Step 9 correctness and acceptance. This does not close Step 9 or fix
the missing `select_and_apply` return itself.

## Terminal Call Preservation

Reason: Semantics accepted `POP EAX`, `POP EDX`, and an unidentified POP
register as preserving the call result. The first two overwrite result lanes;
an unidentified register is not preservation evidence.

Owner: `semantics/terminal_call_paths.py`, not Rewrite or CLI.

Change: reject full-width result-register overwrites and empty register
identity. Preserve the existing valid frame-restore cases.

DoD: the previous false proofs fail before the fix and refuse afterward;
valid BP/SI/EDI restores still prove. The shared return-chain consumers pass.

Definition of failure: accept any demonstrated result-register clobber or
unknown register as proven, or reject the valid restore controls.

Evidence: 3 failures / 14 passes before; 150 related tests pass afterward in
11.69s under `pytest -n 7`. A real Capstone byte probe separately confirms
`58`, `66 58`, `5a`, and `66 5a` refuse, while `5d`, `5e`, and `66 5f` prove.
The test module is now enrolled in Make's routine inventories and the runner.
Scoped MyPy passes; seven pre-existing Ruff findings remain in the semantic
module. No blanket linter exclusions were added.

## Compile Return Paths

Reason: GCC `-fsyntax-only -Wall -Werror` exits zero for a non-void function
that falls off its end. It therefore did not enforce the advertised compile
acceptance contract. GCC `-c` reports the missing return.

Owner: `inertia_decompiler/recompile_check.py`, compiler acceptance/reporting.
No emitted C is repaired. Compile to the null device without linking, so
external calls need declarations but not host implementations.

DoD: actual GCC rejects missing and partial returns; accepts value returns,
void fallthrough, non-returning loops, and declared external returned calls.
The real broken FPTR artifact must fail with a function/source diagnostic.
Run focused checks and the routine pipeline; report pre-existing blockers.

Definition of failure: syntax-only success remains accepted as compilation,
missing returns pass, linking becomes required, source is rewritten to pass,
or compiler diagnostics are hidden.

Evidence: new missing/partial-return controls fail against the old gate.
After the change, 83 compiler/tooling/return-type tests pass in 12.96s;
adding the subsequently exposed uninitialized-return control gives 84 passes
in 15.39s. That additional control follows the broad run below.
The actual `DFPTR01.batch/select_and_apply.stdout.c` is rejected:
`control reaches end of non-void function [-Werror=return-type]`, with function
name and generated source line. Scoped MyPy passes. The module remains in the
base decompilation-cache source manifest. Its test module is newly enrolled
in the routine inventories. One warmup plus seven valid small-TU samples:
median syntax-only 6.03ms, compile 11.68ms. This is gate overhead, not an
end-to-end performance claim.

## Remaining Root Cause Evidence

The bounded native FPTR CFG at `0x1006f`, with explicit scalar prototypes,
retains the call result and returns it. Its final validation instead rejects
uninitialized stack-local reads. This differs from the CLI fallback, which
had emitted a value-returning header without a return and reported passed.
Do not repair that body by text substitution or merely change its header.

A separate reduced probe proves a prototype-seeding cache dependency defect:
with a proven observed caller result, seed while the callee has a void
prototype, change the callee to a proven unsigned-short result, and seed
again. The caller remains untyped. Clearing only the seeded-function set and
reseeding produces the word return. `analysis_helpers.py` fingerprints caller
block addresses and coarse caller prototype state, but not the consumed
callee prototype. The FPTR logs also show the existing caller skipped after
callee stubs are added. The reduction proves stale seeding, not yet that it
is the sole FPTR cause. Next: a focused regression and dependency-correct
invalidation in the analysis/type owner, retaining unchanged-input reuse.
Do not replace this with unconditional full-project rescans.

The strengthened compiler gate additionally rejects `rot_ui` in the MS C
scalar example: `return (local_5 >> 7) | (a << 1);` reads an uninitialized
byte declared as `[bp+0x3]`. Re-running the exact retained compiler input
proves syntax-only exits zero and compilation exits one. Investigate native
entry-SP versus BP coordinates and argument-byte view materialization in
Alias/Lowering; do not initialize the local to a guessed value, remove the
read, or disable the compiler warning. Its acceptance requires the source
rotation semantics, high-bit inputs, clean tail validation, strict compilation,
and the real compile/decompile/recompile/runtime lane.

## Verification Ledger

- Timestamped POP regression logs run from 02:38:49 to 02:39:46 +02:00
  (57 seconds including edits and checks, not the earlier investigation).
  The first routine run preceded the compile-mode change: 268 early
  contracts pass; 4,366 routine pytest cases pass and three fail in 275.24s.
- Those failures are RunMenu ESC, InitBars stack array, and InitMenu pause
  guard. Each still exposes unassigned stack-local reads; none is suppressed.
- The same run has Ultra QuickC 3/4 passing (`args` fails) and MS C tiny 6/7
  passing (`function_pointers` fails). These are not whole-suite totals.
- Initial compile-gate regression logs run from 02:50:06 to 02:50:56
  (50 seconds including the fix and checks). Global `make mypy` passes
  after explicitly typing the catalog result path in the MS C harness.
  `quality-fast` remains red on lint debt; all 39 mypyc import smoke checks pass.
- Post-change routine pipeline ran 02:52:38-03:00:24 (7m46s, gate wall time):
  268 early contracts pass; 4,382 routine pytest cases pass and the same three
  SORTD cases fail in 284.32s. Ultra QuickC remains 3/4 (`args` fails).
  MS C tiny is now 5/7: FPTR still fails, and compilation newly rejects
  `rot_ui`'s uninitialized return byte. This is newly detected bad generated C,
  not a reason to weaken the gate. The startup architecture check passes.
- Logs live under `/home/xor/.cache/return-compile-gate-*`; earlier POP checks
  use `/home/xor/.cache/terminal-return-pop-*`. Step 9 remains open. Full-suite,
  expanded-pipeline and global quality closure are not established here.
