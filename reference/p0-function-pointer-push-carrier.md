# Function Pointer PUSH Carrier Investigation

## Observed Failure

The default MSC6 lane is 6/7. In function_pointers, inc_one, dec_one and
apply_twice have no emitted ESP/EBP dependency. select_and_apply retains its
BP setup and an SP assignment before the correctly materialized call.
The linker reports unresolved `_inertia_esp` and `_inertia_ebp`.

The original source selects a function pointer and passes it with a value to
apply_twice. The source and COD are comparison evidence only, not predicates
for a repair. Numeric source addresses below identify the diagnostic run;
they must not enter production logic.

## Verified Consumer Mismatch (2026-09-09)

Fresh isolated-cache observations, without changing pass decisions, show:

1. The surviving SP assignment belongs to the argument PUSH at rebased 0x1024
   (original 0x10093), not to a call-return-frame instruction.
2. The consumed-PUSH pass receives both exact argument instruction addresses,
   0x1021 and 0x1024. Its first observed census is raw=3, normalized=3,
   classified=2, materialized=2, failures=1. Subsequent passes repeatedly
   retain the one SP carrier with raw=1, normalized=1, classified=0,
   materialized=0, failures=1.
3. `_is_consumed_push_stack_carrier_lhs_8616` returns False for that carrier.
   Its variable is now a SimMemoryVariable, while the authoritative runtime
   register view identifies ESP, width=4, bit_shift=0. The classifier accepts
   native SimRegisterVariable SP, stack locals and dirty expressions, but
   does not consume this runtime-register representation.
4. The surviving SP assignment reads BP. `prove_frame_carrier_uses_8616`
   correctly reports EXTERNAL_USE, so the BP setup also survives. Do not
   weaken this guard or delete the BP setup independently.
5. The fresh diagnostic decompilation exits 0 with validation=passed and
   clean whole-tail validation. Those checks do not prove linkability.

Logs: `/tmp/inertia-fptr-{frame,push,carrier}-probe.log`; final generated C:
`/tmp/inertia-fptr-carrier-probe.c`. Diagnostic wrappers only observe and return
the original decisions. Native graph metadata is stale; exact current source
and runtime observations establish this bounded conclusion.

## Next Repair

Reason: all owned representations of a consumed PUSH must agree; runtime
register publication must not strand its already-materialized stack effects.

Earliest responsible surface: typed call-argument consumption in Lowering,
using authoritative runtime register identity and exact consumed-PUSH evidence.
Prefer a focused helper over growing real_mode_linear.py further. Inspect
whether consumption can run before runtime publication without violating the
existing call-materialization order before choosing another late consumer.

DoD: a regression fails on the present runtime-SP representation and passes
after repair; exact provenance and materialized argument values/classes are
required; genuinely observed numeric SP values and uncertain paths refuse
deletion. Cover uses after the candidate, earlier independent reads, branches,
loops and calls. Fresh select_and_apply must validate, retain both possible
function targets and its call, compile without fictitious register globals,
and run both selector cases. Run scoped linters, quality-fast and the default
MSC6 round-trip pipeline before accepting the repair.

Definition of Failure: blindly accept every runtime SP lvalue, remove a live
numeric SP value, infer deadness from rendered text or names, weaken frame
liveness, fabricate register globals, or call 6/7 a passing lane.

## Implemented Candidate And Evidence

The consumed-PUSH owner now delegates runtime ESP candidates to the focused
`lowering/runtime_push_carrier.py` proof. Exact PUSH provenance and argument
materialization remain prerequisites in the existing caller. The helper uses
authoritative register views, transparent sequence ordering and the complete
following suffix. It refuses later runtime/native SP observations, unknown
dirty expressions, loops, explicit jumps, conditionally nested candidates,
missing arguments and uncertain identity. Earlier reads do not observe the
candidate's later write. Refusals feed the existing liveness counters.

One new runtime-SP regression fails before integration (7.91s). With sequence
wrapper coverage and refusal tests, 32 focused tests pass (8.85s); scoped Ruff
--fix, MyPy and Pyright pass. Routine Make and pipeline lists include the new
test, and architecture ownership includes the new helper.

Fresh isolated select_and_apply now contains only function-pointer selection
and the apply_twice call, without ESP/EBP dependencies. It reports
validation=passed and clean whole-tail validation. The observer records
OBSERVED while later SP-derived expressions remain, then UNOBSERVED after
those expressions disappear. The existing BP-frame liveness guard is unchanged.
GCC -O0 and -O2 compile and execute both selector cases with source-equivalent
callee stubs and no supplied register globals; both exit 0. This bounded
caller check is not a replacement for the complete MS C round-trip lane.

Logs: `/tmp/inertia-runtime-push-{before,after,mypy,pyright}.log`;
`/tmp/inertia-runtime-push-flat.{c,log}`. quality-fast exits 0: 3,125 tests
pass (156.61s), configured checks and all three executable guards pass.
Log: `/tmp/inertia-runtime-push-quality-fast.log`.

The default pipeline now exits 0: 3,125 unit tests pass (120.71s; lane
121.122s), QuickC passes (41.911s), and MSC6 passes 7/7 (70.428s). All seven
original/recompiled exit codes match at 255. function_pointers compiles and
links without the prior runtime-register errors or compiler warnings.
The three lane durations total 233.461s; this is an observed run, not a
controlled optimization comparison. Log:
`/tmp/inertia-runtime-push-test-pipeline.log`. Mutable detailed reports:
`angr_platforms/.cache/test_pipeline/summary.json` and
`examples/build_msc6_tiny/report.json`.

This bounded carrier repair has passed its routine gates. The broader SORTD
plan and whole-repository test audit remain open.
The later [storage snapshot repair](p0-storage-prototype-snapshot.md) resolves
the scalar_types_io pointer-class warnings and keeps MSC6 7/7 green. Those
warnings above describe this earlier carrier-only checkpoint.
