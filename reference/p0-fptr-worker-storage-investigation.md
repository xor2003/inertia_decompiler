# FPTR Worker Storage Investigation

## Scope And Result

Investigation ran 2026-09-12 04:52:33-05:02:36 +02:00: 10m03s elapsed,
including probe execution and investigation, not separately measured CPU time.
This is not a semantic repair
or Step 9 acceptance. All production implementations and tests were left
unchanged during these probes. The preceding seven passing MS C round trips
remain the accepted checkpoint; the direct FPTR attempt remains defective.

Normal CLI command reproduced from a fresh semantic-cache environment:

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 INERTIA_COORDINATE_PROBE_RUN=202609120456 \
  ./decompile.py examples/build_msc6_tiny/function_pointers/FPTR.EXE \
  --proc select_and_apply --no-alternate-source-c
```

The direct candidate restores EDI from the function-pointer local. Strict GCC
rejects pointer-to-integer casts and shifting a function pointer. The final
fallback emits separate saved-register bytes and passes final tail validation.
The rejected payload is
`angr_platforms/.cache/validation_failed_payloads/payload_1789181816_dd4920a97e84.c`.

## What Was Actually Observed

1. A bounded in-process CFG at 0x1006f-0x100a5 does not reproduce the bad restore.
   Without observed return use it emits void; a diagnostic explicit non-void
   prototype retains the returned call and still uses separate saved bytes.
   These are controlled probes, not production evidence for inferred types.
2. The full CLI with in-process timeout settings records 324 distinct lookup
   observations and still rejects an intermediate direct attempt, but does not
   reproduce the same pointer-shift GCC diagnostic. Therefore the in-process
   route is not an equivalent regression for the normal worker failure.
3. A normal forked CLI probe records observations in the worker itself using
   a diagnostic-only JSONL sink. Parent memory counters alone miss these calls.
   The observed worker records 131 distinct lookups; the parent records 293.
   This probe reproduces the exact rejected pointer-shift payload.
4. All observed two-byte variables at entry-SP-4 resolve to machine BP-2,
   including the pointer local. No observed lookup maps it to BP-4. The simple
   proposed coordinate-offset fix is unsupported and was not applied.
5. The worker's native variables differ from those of the bounded/in-process
   probe: some negative stack carriers have two-byte rather than byte storage.
   This is an observation, not proof that process isolation causes the defect.
   Trace native storage construction and subsequent binding/replay together.
6. Registry display names change during annotation/normalization. A projection
   displaying `local_4` at BP-2 is not by itself evidence of a wrong coordinate:
   the variable's recorded entry-SP offset remains -4. Do not infer identity
   from a name suffix or repair this in Rewrite.

The COD comparison oracle places the pointer at BP-2 after a two-byte stack
allocation, then saves DI and SI in distinct slots. It supports the required
behavior only; it must not supply production storage or call semantics.

## Next Investigation And Acceptance

Prioritize the three genuinely failing SORTD routine regressions while keeping
this rejected FPTR candidate visible. Their current final guard identifies
uninitialized saved stack bytes; InitBars also reports an uninitialized register
carrier in intermediate candidates. Do not assume these have the same cause.

For FPTR, capture the saved-register store/load identities at native AIL and
the first Lowering materialization in the normal worker, then identify the
first transformation that binds a saved byte to pointer storage. A regression
must reproduce that transformation without depending on process-specific IDs,
names, source-sidecar types or rendered-C repair.

DoD: binary-derived saved-register storage remains distinct from pointer
storage; required calls and return values survive; the direct candidate passes
strict recompilation and semantic validation, followed by focused and routine
gates. Definition of failure: pointer/integer casts to conceal wrong storage,
deleted restores, unconditional BP deltas, or acceptance based only on the
already-working fallback. No completion claim is made here.

Diagnostic files under `/home/xor/.cache/`:
`probe-fptr-coordinates.py`, `fptr-coordinate-fresh-cli.{c,log}`,
`fptr-coordinate-typed-probe.{c,log}`, `fptr-coordinate-fork-probe.{c,log}`,
`fptr-coordinate-fork-events.jsonl`, and
`fptr-coordinate-publications.{jsonl,c,log}`.
The diagnostic script was iterated between probes; logs and their described
execution modes, not its final form alone, identify each experiment.
