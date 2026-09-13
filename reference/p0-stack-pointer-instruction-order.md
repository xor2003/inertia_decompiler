# Native Stack Propagation Ordering

Timing: first saved-state probe at 00:48:58 +02:00 on 2026-09-12;
broad-gate results collected at 01:06 +02:00. Approximately 17 minutes elapsed,
including analysis, edits, focused tests, and broad gate waits.

## Proven Defect

The binary-only `__fimemset` reduction uses `PUSH DI; PUSH SI; PUSH ES`.
Raw VEX correctly decrements SP before the segment save's address read.
Native SPropagator nevertheless replaced that updated SSA value using
`offset_before(ins_addr, sp)`, producing entry-SP offsets -6/-5 instead of
-8/-7. This made the ES save overwrite the SI save while the ES restore read
different, uninitialized bytes. This predates Lowering and save/restore DCE.

The worker-independent probe observed SSA variable 15 defined at statement 11
and used at statements 12/13 within the same instruction. Its replacement was
-6; the tracker correctly reported the after-instruction offset 65528 (-8).
Evidence: `/home/xor/.cache/fim-stack-propagation-order.log` and
`/home/xor/.cache/fim-native-save-addresses.log`.

## Fix And Controls

`stack_compat.py` now distinguishes pre-instruction values from same-instruction
definitions. A final, dominating register definition can consume the proven
after-instruction offset. Later writes or unknown final offsets refuse the
replacement, leaving the SSA expression intact. Numeric-use and width guards
remain enforced. No assembly/text recovery or Rewrite repair was introduced.

Tests cover updated values, later writes, unknown offsets, and previous
instructions. The existing binary native-SSA test now asserts the exact two
ES-save anchors. An initial test invocation used the wrong AIL constructor
keyword; that run is not before-fix regression evidence. The native probe
above supplies the observed before-fix evidence.

## Verification And Remaining Work

- Scoped Ruff and MyPy pass; 66 focused tests pass in 8.24s.
- Routine gate: 268 early contracts passed; 4,324 pytest tests passed and one
  failed in 251.19s. Both external lanes passed, including MS C round trips.
- `quality-fast` remains red on global Ruff findings; the 39-module mypyc
  import smoke passes. No full-suite or expanded acceptance is claimed.
- `__fimemset` still clobbers ES/EDI in all eight behavioral cases.
- With pruning disabled diagnostically, saves now survive, but generated C has
  duplicate local declarations and narrowed restores. Tail Validation reports
  success for that diagnostic output. This is a remaining validation gap,
  not function acceptance: see `/home/xor/.cache/fim-ordered-no-prune.log`.
- Follow-up ruled out `_promote_direct_stack_cvariable` for this failure and
  traced the new object to Rewrite. See
  [byte-join binding evidence](p0-rewrite-byte-word-bindings.md).

Gate logs: `/home/xor/.cache/fim-sp-order-{final-focused,mypy,quality,pipeline}.log`.
