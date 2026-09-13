# Indirect Calls Must Survive IR Import

Step 9 investigation and repair, 2026-09-12. Step 9 remains open.

## Root Cause

`apply_twice` in the MS C function-pointer fixture failed decompilation. A
fresh normal CLI run first failed the GP stack-restore invariant; a later
fallback also failed prototype-name normalization. The latter was not the
earliest cause and was not patched.

Typed IR omitted both indirect calls. `ir/vex_control_flow.py` admitted
`Ijk_Call` only when VEX's destination was constant. The instructions that
push a return address remained in IR, but the CALL boundary consumed by stack
state and call-effect analysis disappeared. Alias consequently linked the
final SI restore to an AX store to the value argument rather than the original
SI save. Lowering correctly refused those inconsistent restore facts.

The fix belongs at IR import. The terminal adapter now preserves CALL even
when the target is unknown. `ir/vex_import.py` supplies its existing expression
resolver so indirect targets retain their typed temporary provenance. Without
a resolver, the target is explicitly `MemSpace.UNKNOWN`. No callee address,
calling convention, stack effect or return value is invented. Direct CALL and
RET behavior remains covered. No semantic repair was added to naming, Rewrite,
postprocess, Alias or CLI.

## Closed Evidence

- Four new tests failed before the production fix: unknown-target CALL,
  register-indirect CALL, memory-indirect CALL, and a 32-bit operand-size CALL.
  The binary tests exercise both imported IR and its SSA projection.
- Final module: 11 passed in 8.68s under pytest `-n 7`, fixed hash seed and
  `PYTHON_JIT=1`. A corruption control removes CALL from a small binary's IR;
  this recreates a false AX-to-SI stack-restore proof. Keeping the unknown CALL
  refuses that proof. The module was already enrolled in the routine pipeline.
- Fresh `apply_twice` CLI before: exit 4, failed GP restoration and validation.
  After: exit 0, `validation=passed`, clean whole-tail validation. Generated C
  passes `gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only`.
- Output has a typed function-pointer parameter, two calls `value = fn(value)`
  in source order, returns the second result, and preserves the saved SI/DI
  bytes. Comparison used the original C only as an oracle, not recovery input.
- Ruff --fix passes the terminal adapter and its tests. Legacy importer
  complexity/magic-value findings remain visible. Scoped MyPy passes when
  `vex_control_flow.py`, `vex_import.py` and owned dependency `vex_types.py` are
  checked together. The two-file invocation exposed the existing global
  `follow_imports=skip` treatment of that dependency; no type suppression or
  unnecessary runtime conversion was added.
- Full architecture, agent-context and ownership checks pass. quality-fast
  still fails broad lint debt; compiled import smoke passes for 39 modules.

## Timeout Policy Follow-up

MONOPRIN __fimemset's corpus test used a literal 20-second watchdog, bypassing
the existing xdist-aware helper. It now uses `scaled_decompile_timeout(20)`:
the serial budget stays 20 seconds and the default xdist budget is 30 seconds.
The outer watchdog and all success, validation, generated-C and compiled
behavior assertions are unchanged. The corpus and timeout-policy tests passed
14 tests in 33.41s. This is policy consistency, not a decompiler speedup or
proof that the broad-load timeout has been eliminated.

## Broad Acceptance And Source Oracle

The routine pipeline after the IR repair finished with 268 preliminary passes
and 4,639 passes / three failures in 312.53s in its main pytest lane. The
remaining failures are SORTD RunMenu, InitBars and InitMenu. MONOPRIN passed
under that load. QuickC passed 4/4; MS C passed 4/7. This is the curated lane,
not the complete test collection.

All four function-pointer fixture functions already decompiled with clean
validation in that run, but the fixture oracle rejected `ax = apply_twice(...);`
followed by register restores and `return ax`. It required literal return-call
syntax. The tooling-only `scripts/generated_c_return_contract.py` now follows
unchanged local definitions in parsed C. It refuses overwritten values,
arithmetic changes, uncertain joins, intervening calls and indirect writes.
It never changes generated code or claims whole-program equivalence.

Two valid stored-result cases failed before this oracle repair; seven direct
or corrupted controls passed. Afterward the complete harness test module passed
56 tests in 15.01s. The helper and ownership manifest pass Ruff --fix; scoped
MyPy passes including the harness. Make typing/lint lists and explicit test
ownership include the helper. Architecture, agent-context and ownership checks
pass.

A targeted real function-pointer roundtrip then exited zero: four functions,
clean validation, source contract passed, MS C recompilation passed, and rebuilt
execution passed with expected exit code 255. Reported decompilation time was
24.51s. This does not upgrade the earlier whole MS C lane to 5/7 without a
fresh combined run. `pointer_memory` still reports a `fill_bytes` GP restore
materialization failure; `loops_jumps` and the SORTD cases remain open.

DoD for this repair: indirect CALL survives IR and SSA; the corruption control
rejects the false restore proof; source call count/order and returned value
survive; real generated C validates, recompiles and executes successfully.
Failure: dropping CALL, accepting corrupted return provenance, hiding failed
validation, or accepting only a source-contract test without the real roundtrip.
These focused obligations pass. Full collection, expanded gates, remaining
SORTD/MS C failures and global quality acceptance remain open.

The returned-call acceptance checkpoint was observed at 15:15 +02:00. Test
and roundtrip durations above are measured; exclusive engineering time was not
collected. Additional logs: `returned-call-contract-{before,after,ruff}.log`,
`returned-call-final-mypy.log`, `returned-call-contract-gates.log`, and
`returned-call-roundtrip.log` under `/home/xor/.cache/`.

Fresh combined acceptance completed by 15:24 +02:00: 268 preliminary tests
passed in 17.54s, followed by 4,647 passes / the same three SORTD failures in
289.42s. QuickC passed; MS C now passes 5/7, including function_pointers with
both original and rebuilt exit code 255. loops_jumps and pointer_memory remain
failed. Pipeline lane times: pytest 290.095s, QuickC 2.737s, MS C 90.185s.
Cache reuse is present; these timings are not a controlled speedup measurement.
The pipeline exits 2 at Make level. `quality-fast` also exits 2 at global
linters; scoped checks above remain passing. Logs: `returned-call-pipeline.log`
and `returned-call-quality.log`. No complete-suite or Step 9 closure is claimed.

Logs under `/home/xor/.cache/`: `indirect-call-ir-{before,after,final,ruff,
mypy-final}.log`, `indirect-call-{quality,contracts,pipeline}.log`,
`apply-twice-current.{c,log}`, `apply-twice-ir-fixed.{c,log}`, and
`monoprin-timeout-policy.log`. Diagnostic worker exit zero is not acceptance:
its JSON status remained validation_failed during the investigation. Only the
normal CLI run above establishes the reported function acceptance.

Observed diagnostic/acceptance window includes 14:40-14:55 +02:00. It includes
recovery retries and test waits, not exclusive engineering time or an ETA.
