# Captured Register Restores And Semantic Cast Traversal

Step 9 checkpoint, 2026-09-12. Step 9 remains incomplete.

## Proven Causes And Owners

1. `stack_compat.py` treated a block-entry SP Phi as a machine register write
   because it carried the first POP instruction's address. That selected the
   instruction's post-update SP for a predecessor value. Excluding typed Phi
   sources from machine-write candidates restores distinct SI and DI byte
   addresses without changing physical instruction execution or guessing a
   stack-coordinate correction.
2. The legacy CLI AST-node predicate recognized only classes defined inside
   angr's package. It rejected Lowering's `CSemanticCast8616`, hiding reads
   below the cast from dead-local pruning. The CLI now delegates node admission
   to the existing shared C AST owner. No semantic recovery was added to CLI.
3. Lowering's `dead_register_carriers.py` had the same module-prefix-only
   admission bug. A focused test proved it deleted a register assignment with
   a live read under a semantic cast. Its read collector now consumes the same
   shared node predicate. Existing dead, live, effectful and identity refusals
   remain covered.

The shared core traversal gate alone did not prevent independently implemented
consumer callbacks from omitting owned subclasses. Behavior tests therefore
exercise the actual CLI and Lowering consumers, not only the shared walker.
These test modules are already enrolled in the routine pipeline and ownership
manifest; no extra expensive corpus test was added.

## Evidence

- SP-Phi regression: one failing / four passing cases before the fix; the
  complete stack-compatibility module passed 41 tests afterward.
- CLI cast-read regression failed before delegation and passed afterward.
  Related stack, traversal and CLI pruning modules passed 228 tests.
- QuickC `ARGS.EXE`, function `0x10058`: before fixes, CLI exit 4 with failed
  validation and four uninitialized restore-byte reads. After both fixes,
  CLI exit 0, `validation=passed`, clean whole-tail validation, and strict
  `gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only` acceptance. Four saves and
  distinct SI/DI restores survive. This is not a whole-source behavior audit.
- First refreshed routine run: 268 preliminary passes; 4,610 passed / four
  failed in 466.11s. QuickC passed all four selected fixtures, including args;
  MS C passed four of seven complete round trips. Its remaining failures were
  loops_jumps, function_pointers and pointer_memory.
- One routine failure expected stack-read copy propagation through a semantic
  cast. Correct traversal now exposes that captured value to the existing
  memory-backed guard. The test now distinguishes register copies from stack
  and global captures; memory cases include an intervening write and require
  the original captured value to survive. Cast class, source/destination types
  and instruction metadata remain mandatory in every case.
- The Lowering live-read regression failed before the third fix: one failed,
  32 passed in 23.41s. Afterward, five related modules passed 261 tests in
  24.56s with `PYTHON_JIT=1 PYTHONHASHSEED=0`, pytest `-n 7`, and durations.
- Scoped MyPy passes. Ruff `check --fix` reports two existing complexity
  violations in `dead_register_carriers.py`; neither was suppressed. Full
  architecture, context and test-ownership gates pass. `quality-fast` remains
  red on broader lint debt; compiled import smoke passes for 39 modules.

## Final Routine Checkpoint (13:58 +02:00)

The final pipeline is terminal with exit 2. Preliminary contracts passed 268
tests in 28.84s. The routine pytest lane passed 4,612 tests and failed five in
402.47s. No tests or production source were edited during that run.

- SORTD InitBars, RunMenu and SORTDEMO InitMenu remain rejected.
- `mset_pos` now fails strict compilation because a byte-local declaration
  reuses the formal parameter name `arg_6`. The isolated compiled-behavior test
  reproduces this failure. Trace declaration ownership and storage projection;
  do not remove a live value or rename rendered text to hide the conflict.
- `dos_loadProgram` hit its decompilation timeout in the broad lane but passed
  isolated, including its compiled behavior oracle. The isolated two-test
  recheck was one failed / one passed in 45.63s; the passing wrapper took
  23.39s. This does not erase the broad timeout or prove it is fixed.
- QuickC remains 4/4 with passed validation (lane wall time 88.373s).
- MS C remains 4/7 (lane wall time 194.637s): compare16, simple_control,
  storage_classes and scalar_types_io pass compile/decompile/recompile/execute
  with rebuilt exit 255. loops_jumps, function_pointers and pointer_memory fail.

Slowest routine tests: RunMenu 142.93s, InitMenu 137.27s, InitBars 107.45s,
indexed-address inventory 53.82s, and dos_loadProgram 46.44s. These are one-run
timings, not controlled performance improvements. No complete repository
collection, expanded pipeline or Step 9 completion is claimed. Next blocker:
the reproducible `mset_pos` declaration conflict, followed by the remaining
SORTD and MS C semantic failures and the concurrent-load timeout.

## Remaining Investigation

Additional module-prefix-only predicates were found in stack matching,
real-mode lowering, postprocess calls and CLI core. These are investigation
candidates, not proven defects or authorization for a bulk replacement.
The graph generation was 2026-08-27; changed/untracked coverage required exact
source fallback for the material claims above.

Logs are under `/home/xor/.cache/`: `args-restore-{fixed,quality,contracts,
pipeline}.*`, `args-cast-consumers-{before,after,ruff,mypy}.log`,
`args-cast-{quality,contracts,pipeline,corpus-recheck}.log`. Diagnostic probes are temporary
and must not be committed. Earlier exact clock observations were 13:26:53 and
13:32:19 +02:00; the Lowering focused gate checkpoint was 13:42:44 +02:00.
The last exact observation was 13:58:25 +02:00. The observed 13:32:19-13:58:25
window is 26m06s, including broad-gate waits, not exclusive engineering time.
All launched processes are terminal; no commit or push was performed.
