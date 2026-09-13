# InitBars Composite Root Ownership

## Evidence And Cause

On 2026-09-13, sidecar-free `0x10560` failed with uninitialized stack fields
and missing branch owners at `0x1059f`, `0x105a8`, and `0x105b1`.
The compound guard carried the last JCC's origin, while its container carried
the function-entry address. Comparing those as if they described a single
predicate rejected ownership before call-output stack-object lowering ran.
The entry's linear CFG prefix actually reaches the first predicate at
`0x10598`; the remaining two predicates belong to its short-circuit chain.

## Owner And Fix

Structuring's `condition_ownership.py` selects a candidate first predicate
only for a composite guard with one entry-owned root and an authoritative
origin reachable through typed condition blocks. Branching/cyclic entry,
ambiguous roots, foreign origins and statement-bearing guards refuse.
This selection is not proof of replacement semantics: the existing CFG-chain
materializer must prove the body endpoints and consume the tagged origin.
The single-predicate replacement shortcut is disabled for this path.

Existing Types/Lowering then recovers the addressed stack object and its
fields. No stack initialization is invented, no call arguments are repaired
in Rewrite, and no binary addresses or source names drive production recovery.

## Acceptance

Reason: preserve composite guard ownership across angr's container/origin tags,
so existing typed object evidence can reach the final C.

DoD for this repair:
- ownership and statement-effect refusal cases pass;
- existing condition-materialization and side-effect tests remain green;
- live InitBars preserves the array, required calls and pointer argument;
- semantic and whole-tail validation pass;
- generated output represents the source's monitor/mode condition directly;
- tests are enrolled in routine gates, with broad results reported honestly.

Failure: accept a descendant tag as proof of the entire guard, discard a
predicate or side effect, bypass tail validation, guess locals' values, or
claim whole Step 9 completion from this function's result.

## Verification

The baseline live failure is recorded in `step9-initbars-debug.log` under
`/home/xor/.cache`. After the fix, 79 related tests pass in 38.99s, including
InitBars and RunMenu live regressions. A fresh standalone InitBars command
reports `validation=passed` and clean whole-tail validation. Its output calls
`sub_12ac8(&local_56, inertia_ss)` with a typed stack-object pointer and uses
`field_18 == 1 || field_14 == 2 || !field_14`, matching `SORTDEMO.C`'s guard.
The ownership module and its tests are Ruff-clean; scoped MyPy passes.
Quality-fast remains blocked by shared lint debt, while its 39-module mypyc
import smoke passes. At 15:14 +02:00, the routine pipeline refresh completed:
5,376 pytest cases pass in 221.11s, plus 268 preliminary passes in 9.58s.
QuickC remains 3/4 and MS C tiny 5/7; their remaining failing fixtures are
`args`, `simple_control`, and `loops_jumps`. These are not full-suite results.

Investigation was recorded at 14:58 +02:00; fresh function acceptance was
observed by 15:06 +02:00. This eight-minute interval includes tests and waiting,
not exclusively coding. Initial new unit-test attempts exposed incomplete
third-party fixtures; those are not counted as fail-first semantic evidence.
