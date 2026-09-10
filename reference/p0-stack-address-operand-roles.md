# Stack Address Operand Roles

## Investigation And Reason

The InitMenu pre-SSA probe records 19 native calls. Arguments at that boundary
still contain loads from native `StackBaseOffset` locations, not the final
materialized objects and values. For example, the final outtext call still
has two word loads there, whereas the final C has one logical pointer argument.
Deleting argument PUSH effects at this boundary is therefore not justified by
the final callsite inventory alone. This is new boundary evidence, not another
return-frame or stack-tracker experiment.

Inspection of the propagation guard exposed a separate correctness defect:
every binary operator inside a memory address inherited the address role.
Consequently `SP * 2`, `SP / 2`, `constant - SP`, and even `SP + SP` qualified
for native stack-relative address replacement. A numeric operand's presence
inside a memory access does not prove it is one stack-relative base.

## Fix And Ownership

`stack_value_use.py` owns native AIL operand-role classification at the
Frontend/angr compatibility boundary. `stack_compat.py` consumes and re-exports
the existing API; native propagation still records refusals through its closed
counters. No Alias recovery, DCE or rendered-C repair was introduced.

Addition and the left operand of subtraction retain a positive base role.
Other binary operations and subtractive right operands remain numeric.
Repeated occurrences of one SSA identity within a single address refuse;
separate loads/stores have independent counts. Segment arithmetic on another
value does not prevent a positive stack offset from remaining an address base.
Existing guard, alternative, call, assignment and width behavior is preserved.

The extraction leaves `stack_compat.py` at 235 lines and the focused owner at
133 lines rather than growing the former beyond 350 lines.

## Acceptance

DoD: demonstrate the counterexamples before the fix; refuse their propagation
while preserving positive affine and segmented address cases, independent
memory accesses, existing numeric-use guards, and compatibility imports; keep
types/docs and routine coverage; run focused and broader gates plus InitMenu
validation without weakening its acceptance assertion.

Definition of failure: infer a stack address solely from a surrounding memory
operation, accept nonlinear or negative base roles, mix counts across separate
memory accesses, drop numeric effects, or claim this guard fix removes InitMenu
bookkeeping or establishes whole-function acceptance.

The new baseline had 18 failures and three passes in 8.11 seconds. After the
fix, the 21 new cases and 36 existing stack-compatibility cases pass: 57 passed,
seven dependency warnings, 8.17 seconds. All are routine-admitted. Scoped Ruff
`check --fix`, MyPy and Pyright pass, with zero Pyright diagnostics.

The focused InitMenu rerun has 57 passes and the unchanged bookkeeping failure,
seven warnings, 46.57 seconds total (38.27 seconds InitMenu). Its behavior
harness after the failing assertion remains unexecuted. The live observer
produces byte-identical C, SHA-256
`4a41e50d2e9dd5a85c438df8fee336b5c679ccfe28483c2677cacb87ca01ae3f`,
with `validation=passed`, clean whole-tail validation and all 18 final callsite
node/inventory shapes still coherent.

Both `make quality-fast` and `make test-pipeline` exited zero. Fast passed
3,342 tests in 142.08 seconds with eight warnings; default passed the same
3,342 tests in 126.90 seconds with seven warnings. All three executable quality
guards passed. QuickC passed in 45.111 seconds and all seven MS C tiny full
roundtrips passed with return code zero in a 61.964-second lane. The default
unit lane remains over budget at 127.352 seconds including overhead. These
routine gates do not establish a full-repository pass.

The slowest fast tests were RunMenu Escape (56.39 seconds), InitBars stack-array
recovery (55.34 seconds), and indexed-address parity inventory (35.98 seconds).
The additional fast warning is the known threaded-fork warning; dependency
warnings remain visible. No controlled performance claim is made. Final
`git diff --check` passed.

Logs: `/tmp/inertia-stack-address-roles-{before,after,acceptance,ruff-final,mypy,pyright,live,gates}.log`.
The read-only pre-SSA observation is `/tmp/inertia-pre-ssa-argument-uses.log`.
Original step start was not captured; focused checks were confirmed by the
observed 2026-09-10 05:11:58 CEST timestamp. Do not infer total active time or a
remaining-plan ETA from these anchors.
Final gate exit and structured lane results were verified at 05:22:24 CEST.
InitMenu's actual stack-effect consumption and the full plan remain open.
