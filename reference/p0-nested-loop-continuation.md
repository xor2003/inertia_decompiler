# Nested Loop Continuation And Body Preservation

## Reproduction And Root Causes

The MS C `loops_jumps` fixture originally stopped at `nested_loops` with
`GP stack-restore facts were classified but none materialized`. The legacy
nested-counter callback replaced the entire function body, losing SI/DI saves
and restores and emitting an unsigned limit. Disabling only that callback in
an isolated diagnostic exposed generic output that validated and compiled but
was behaviorally wrong: limit 1 returned 45 instead of 0.

The generic path had three connected condition-ownership defects:

1. The loop header retained the block-start instruction tag; the authoritative
   `ConditionIR` used the terminal JCC tag. Exact-key selection missed the fact.
2. Body ownership included expression provenance. An inner break reused a
   comparison tagged to an outer block, falsely claiming that exit block as
   part of the inner loop. Both edges appeared to continue the loop.
3. After Structuring correctly inverted the raw JGE for fallthrough
   continuation, legacy typed/JCC replay overwrote it with the taken-branch
   comparison. Final output again had `do ... while (j >= limit)`.

This demonstrates why stable before/after Tail Validation is not, by itself,
an independent machine-to-C equivalence proof: the wrong guard was already in
the baseline. Compiled behavioral oracles remain mandatory for these repairs.

## Repairs And Acceptance

| Step | Reason | Definition Of Done | Definition Of Failure | Evidence |
| --- | --- | --- | --- | --- |
| Bind exact block-origin identity | Recover the existing terminal branch identity, not semantics from C spelling | Only a marked block-start JCC with one typed candidate and matching CFG successors binds | Interior/unmarked origin, ambiguity or wrong CFG is accepted | Fail-first positive; four refusal controls pass |
| Separate statement ownership from operand provenance | Reused values cannot claim execution blocks | Loop continuation uses statement-owned blocks | An outer comparison's expression tag makes the exit part of the body | Foreign-operand regression fails before, passes after |
| Preserve owned polarity on replay | Taken-branch meaning differs from loop continuation | Compatibility replay preserves the exact Structuring-owned key and orientation | A later raw comparison overwrites an oriented loop | Two fail-first replay cases; live generic output passes afterward |
| Retire body replacement | Keep all effects, not only arithmetic | Remove callback, wrappers, registration and bootstrap slot; normal CLI preserves GP, signed limit and complete loop behavior | No-op rescue, replacement body, lost state or failed validation | Normal CLI exit 0, validation=passed, clean whole-tail; exhaustive compiled oracle passes |

Structuring owns `loop_condition_identity.py` and loop orientation. The two
legacy consumers only consult its veto predicate; they do not recover or
reorient conditions. Their architecture exceptions and headers explicitly
document this read-only compatibility edge.

The native oracle checks every signed 16-bit limit (-32768 through 32767),
compares returns against an independent C reference, and verifies seeded
32-bit SI/DI lanes. GCC uses `-Wall -Wextra -Werror -O2` and UBSan. Three corrupt
controls alter equality, threshold or GP preservation and must fail. Errors
report the exact limit, actual result and expected result. The original source
is an oracle only; no source, names or rendered-C patterns drive recovery.

Tests are enrolled in Make, routine pipeline, ownership and architecture lists.
The callback retirement updates existing bootstrap/order tests without removing
their obligations. The small-function rollback test now injects the still-live
global-byte callback instead of the retired nested-loop callback.

A separately exposed Tail Validation fixture declared a stack argument without
a type, so the entry-initialization guard correctly refused to assume a width.
The fixture now declares its word type. No production validator was relaxed.

## Checkpoint And Remaining Work

At 17:38 +02:00 on 2026-09-12: 477 focused tests pass in 19.84s; scoped MyPy
passes; architecture/context/ownership gates pass. New focused files pass
Ruff `check --fix`; older touched modules retain visible lint debt. Normal CLI
output was observed at 17:32:56 and passes the exhaustive behavior oracle.

The targeted DOS fixture now gets past nested_loops (return 0, clean
validation), then fails at goto_accumulate with the GP-restore invariant.
The whole fixture is therefore not accepted. Investigate its accumulator
callback/generic path next. Do not weaken the storage invariant.

First recorded generic diagnostic: 17:04; normal CLI accepted at 17:32:56;
focused closure observed by 17:38. These are wall-clock observations, not an
estimate of uninterrupted active work or a whole-goal ETA. Final broad gates
must be recorded after their processes terminate. Step 9 stays open.

Evidence under `/home/xor/.cache/`: `nested-loops-{generic,bound,owned,preserved}-worker.json`,
`nested-loops-{observed,body,owned,preserved}.log`, `nested-loops-final.c/.log`,
`loop-block-identity-{before,after,mypy}.log`, `loop-body-ownership-{before,after}.log`,
`loop-condition-replay-{before,after}.log`, `nested-retirement-focused-final.log`,
`nested-retirement-{gates,mypy,ruff,test-ruff,quality}.log`, and
`nested-loops-roundtrip.log`. Diagnostic callback overrides are temporary
outside-repository probes, not production behavior or acceptance substitutes.

## Next Accumulator Diagnostic

While the source-stable default pipeline ran, a separate process disabled only
the accumulator callback in a temporary cache namespace. The observer confirmed
the callback was bypassed. Its worker reported status=ok and stable validation,
but the compiled generic body returned 18 for input 4 instead of the source
oracle's 14. The generated loop adds 2 unconditionally; the parity-controlled
continue/goto path is missing. Do not retire that callback merely because the
generic result validates or recompiles. Its owning CFG/condition producer and
independent branch-preservation evidence need investigation first.

Reproducer artifacts: `goto-accumulate-generic-worker.json`,
`goto-accumulate-generic.log`, and `goto-accumulate-behavior.c` under
`/home/xor/.cache/`. Strict GCC plus UBSan compilation succeeded; the native
behavior executable exited 1 with `input=4 actual=18 expected=14`. No production
accumulator change or fixture acceptance is claimed.

## Terminal Broad Checkpoint

Observed at 17:48:39 +02:00: preliminary 268 tests pass in 9.95s; curated
pytest finishes with 4,689 passes and the same three SORTD failures in 252.06s.
QuickC passes; MS C remains 6/7 with only loops_jumps failed. Reported lane
wall times are 252.53s, 37.67s and 96.37s. These are not controlled performance
measurements. Make exits 2; quality-fast also exits 2 at global linters, while
compiled-import smoke passes for 39 modules. `git diff --check` passes.

The complete pytest collection and expanded acceptance were not refreshed;
this curated result does not close Step 9. All execution sessions for this
checkpoint are terminal. The next blocking semantic task is the accumulator's
missing parity-controlled continuation, not removal of its callback alone.
