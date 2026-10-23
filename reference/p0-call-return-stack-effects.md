# Numeric SP Across Returning Calls

## Current call-context replay checkpoint (2026-10-19)

The native cohort now passes all 12 controls with current final-AST input checks:
ten framed near/far/stack-argument cases and two programs that compile both real
generated functions. Machine execution and generated C agree, both generated
functions' tail snapshots pass, and upper ESP survives. The numeric-SP pair also
checks four additional machine boundaries and every 16-bit entry word in C.
This is a native integration checkpoint; the six-area goal and broad gates
remain open.

Required behavior is now explicit at the owning boundaries:

- C argument values undergo standard array/function pointer conversion before
  capture. Source-backed argument replay opens authenticated original arguments,
  then binds changed arguments again before validation. Unchanged replay retains
  the root, native call identities and temporary IDs; corrupted contexts refuse.
- Rendering retains the chosen native prototype, declaration provenance and
  target identity when repairing copied metadata or choosing an address label.
  Names do not prove an address or project. Foreign targets are not promoted.
- Discarded results have a required no-value conversion that survives hidden
  cosmetic casts. A void declaration cannot supply a required scalar value,
  including through coherently forged wrapper metadata.
- Runtime segment-carrier materialization inspects casts to find helpers and
  changes only proved segment arguments. It retains all surrounding and unrelated
  casts. Before the fix, an unrelated narrowing expression changed from 9029 to
  74565 in compiled C; the same bug erased the call context's void category.

Evidence is under `.cache/devin-prompts/function-readiness-20261016/`:
`parent-void-context-native-review.json`, `parent-void-context-native.xml` and
`parent-void-context-native-artifacts/`. The unchanged production/native-source
fingerprint is `63b3525b6e7dff4bb0a75ba104436c47342001953a0cf19d46c38d63dc7b8242`
(2188 files). The native run passed 12 tests with two workers in 306.89 seconds;
the Lowering-focused suite passed 321. These are acceptance observations, not a
controlled speedup claim. Exact preimage comparisons retain 43 existing MyPy
diagnostics in the large call/structuring surface and 55 in the segment owner,
with no added diagnostics; neither comparison is a green broad typing gate.

## Earlier source-position and runtime-input checkpoint (2026-10-18)

Source-proved scalar returns now consume an immutable word-sized entry-SP
capture in Types. The saved candidate passes all ten original near/far,
mixed-width and upper-ESP machine-versus-C controls. The final conservative
scope guards have a selected near-case native rerun and 300 focused test passes.

The saved pre-binding two-function control fails: CALL a callee that copies
SP to AX, add one, and RET. With initial ESP=0x12348000, machine AX is 0x7fff;
executing both generated functions yields 0x8001. The callee sees the caller's
entry value instead of its own entry SP=0x7ffe. Both local tail snapshots report
stable. That observation is insufficient for cross-function input acceptance.

`inertia/alias/call_stack_positions.py` owns the new derived positional proof:
caller-before, callee-entry and caller-after offsets relative to caller entry
SP, interpreted modulo 16 bits. The canonical stack transfer observes the
instruction-entry state and physical frame preparation; it does not run a
second stack simulator. Authenticated frame width and callee net transfer
remain owned by `IRCallStackCoordinates8616`. Callee-entry includes the frame
push once; caller-after includes RET-N but excludes a later caller ADD SP.
Unknown incoming positions, missing CFG edges, changed CALL/callee evidence
and conflicting physical preparation refuse. Saved position proofs require
fresh reproduction from current source. Types consumes these positions in the
runtime-input candidate below; Alias itself does not emit C bindings.

The Types owner `entry_stack_pointer_capture.py` now shares one immutable local
between return proofs and call-position requirements. It checks the active IR
publication by identity, freshly reproduces every retained use, validates the
actual initializer and single-write lifetime, and canonically merges new uses.
The strict AST snapshot retains both function scope and all use fields. A
source requirement stored in that capture alone is not an emitted call-input
binding.

The current `lowering/call_stack_inputs.py` candidate emits a binding at the
original C call's expression position. It copies side-effect-free arguments
before changing SP, sets the callee-entry word from the immutable entry capture,
executes the original call once, retains its typed result, and restores the
source-proved caller-after word before yielding that result. Each SP assignment
preserves the current upper ESP bits. Whole-function preflight keeps unsupported
or unproved contexts intact and records a typed refusal; classified publication
failures are hard errors. Evidence counts distinguish refusal from a failed
materialization.

`validation/validation_call_stack_inputs.py` independently checks the current
source, active emitted tree, capture lifetime, variable declarations, argument
and result order, and both word/upper-ESP equations. The equations are proved
with bitvectors rather than accepted from the producer marker. Only verified
contexts have a pure logical view for existing call validators. Missing or
invalid bindings remain semantic failures in tail validation and its cache
descriptor. The actual AST and its binding fields stay in strict snapshots.

Scoped controls pass: 69 source/capture/input tests, 14 coordinate tests,
152 related source/callee/transport tests and 281 tail-validation tests;
scoped typing passes. Deliberate mutations cover
SP equations, upper bits, ordering, result transport, capture, declarations,
project/root scope and signed casts. These results do not replace the real
two-function machine-versus-generated-C control. That stronger control now
passes: both generated functions compile with gcc `-std=c99 -Werror -O2`, return
32767, and retain upper ESP=4660. Local tail snapshots pass as well. The 2,186
production Python/native files have identical before/after fingerprints
(`936daf61e5aeb58a8883956cf3d9d35691be01d931edcd524b9bf245771d4c0c`).
The original scoped review is `parent-call-input-accepted-review.json` under
the receipt directory below. A strengthened run adds four real machine inputs
at word-wrap/sign boundaries, retains the original full-value comparison, and
checks the same generated C over all 65,536 architectural AX16 return words.
It passes in 75.34s on the same production generation; full harness and machine
oracles are saved in `parent-call-input-boundaries-review.json`. The exhaustive
C sweep uses the instruction law; it is not 65,536 machine executions. Earlier
candidates timed out; the original scoped pass took 237.47s. These timings do
not establish a controlled speedup. Near/far/RET-N variants, argument-class
coverage, performance and the current full pipeline remain acceptance work.

Source fingerprints still read current producer code/defaults/captures and
module contents. Nested collection encoding has bounded hash nodes, and module
hashing streams identical content. A coordinate observation shares the fresh
callee-body proof already reproduced by its source check; a later observation
rechecks currency. Tests reject changed module bytes with unchanged size/mtime,
and changed callee bytes after a successful coordinate observation.

Remaining runtime ABI obligations:

- Declare and consume architectural numeric SP inputs separately from C
  stack locals and abstract return control. Do not infer the value from a
  mutable runtime ESP read after a call.
- Bind the callee's required entry-SP value at the actual generated call
  execution point using the source position. Preserve argument evaluation,
  conditional execution, call count, return value, and live upper ESP.
- Model caller-after SP using the independently proved body/RET effect;
  frame width, RET-N purge and later caller cleanup must stay distinct.
- Validate the actual emitted binding and its source requirement. A tag or
  stable opaque-call comparison alone cannot prove the architectural input.
- Run the two actual generated functions against machine execution as well
  as the ten scalar controls. Unknown or unsupported bindings remain explicit
  refusals, never semantic success.

Current receipts live under
`.cache/devin-prompts/function-readiness-20261016/parent-call-input-*`,
`parent-coordinate-observe-*`, `parent-call-position-*` and
`parent-numeric-types-*`. The full six-area goal and broad gates remain open.

## Earlier input-provenance investigation (2026-10-18)

At the earlier baseline, native near/far numeric-SP controls failed compiled-C execution:
machine AX is 32766, while generated C returns 4294967294. This is an open
regression subsequently addressed for these scalar controls. Their success
does not close the cross-function obligation above. The retained input version must not be replaced with mutable
runtime ESP after CALL without proof that its value survives that boundary.

The current source-bound SSA registry proves ESP, EBP and EAX live-ins. A
separate native Clinic observation finds register virtual variable 1 at offset
16, width 16, with no native SSA definition; its remaining use is after CALL.
Variable 2 at offset 20 is likewise upward-exposed. Neither appears in the
native variable manager's input inventory or vvar bindings, even with special
variables included. The native AIL variable-recovery engine explicitly treats
architectural SP as a value without a recovered variable. An existing manager
input lookup therefore cannot authenticate these missing identities.

An earlier proposed native-input route would publish source-bound native input identities in the
owning Alias stage, before Widening and Types consume them. The frontend may
adapt native SSA expressions and definition/use coordinates; Alias must own
the input classification. Bind exact virtual-variable identity, physical
storage, width, definition census, complete graph and current source generation.
Reuse the native allocation publication and graph binding where applicable;
its manager inventory alone does not cover SP. Missing coverage, conflicting
identities, phi definitions or changed source must refuse. Native upward
exposure is an input candidate, not evidence that an implicit call preserved
the register. Bind original value/read provenance and call effects separately.
Absence of an assignment in the final C AST is insufficient evidence.

Lowering must consume that input proof together with independent call effects.
Known zero SP effects can justify an unchanged runtime lane only in the absence
of preceding local writes. Unknown or nonzero effects cannot be relabeled zero.
A proven entry value that outlives mutable architectural state needs an entry
capture. Linked PUSH-CS/near-CALL/far-RET frames require their existing consumed
frame evidence; adjusting their SP arithmetic in cleanup would bypass the
owning frontend contract.

Acceptance remains all ten original numeric-SP cases, checked against machine
execution and compiled generated C, with preserved upper ESP, call count and
tail validation. Add independent refusals for unknown call effects, expired or
forged input identities, missing native definition coverage, phi/conflicting identities
and source mutation. The original callee-body cleanup obligation, including a
plain RET after manual stack adjustment, remains part of stack-effect acceptance.

Source observations and failures are retained in
`.cache/devin-prompts/function-readiness-20261016/parent-numeric-sp-metadata.{jsonl,log}`
and `parent-sp-native-input-registry.json`. These are diagnostic observations,
not a published native input proof or a fixed-function claim.

## Default-Pipeline Checkpoint (2026-09-09)

Follow-up execution repair: `return_near32` and `return_far32` still cleared
upper ESP during nonzero immediate argument cleanup, despite corrected dword
pops. Both now use the existing `update_gpreg(SP, cleanup)` interface. This is
instruction execution in the stack helper boundary, not stack-variable or
call-convention inference. Explicit cleanup bytes and return-frame widths are
unchanged; the large helper file shrinks by twelve lines.

Eight new instruction cases cover near/far returns, zero/six-byte cleanup and
two nonzero upper-ESP values. They assert complete ESP, CS and EIP independently.
The first draft incorrectly compared the backend's `state.addr` to a linearized
CS:EIP address; the final oracle reads architectural CS and EIP separately.
With that correction, the pre-fix run has four failures and fourteen passes
(8.88s), all failures specifically clearing upper ESP during nonzero cleanup.
After repair, the helper, width, 80386 benchmark, numeric call-return and
return-segment tests pass: **237 passed**, seven dependency warnings, 37.15s.
Scoped `ruff check --fix`, MyPy and Pyright pass. Logs:
`/tmp/inertia-return-cleanup-width-{baseline,after,mypy,pyright}.log`.
The newest `quality-fast` exits 0: **3,058 passed**, eight warnings, 160.50s
in its pytest lane, and all three executable guards pass. Log:
`/tmp/inertia-return-width-quality-fast.log`. The default pipeline rerun exits
2: 3,058 unit tests pass (127.37s), QuickC passes, and MSC6 fails with the same
two compile/link diagnostics detailed below. Lane wall times are 127.843s,
50.278s and 77.030s respectively. Log:
`/tmp/inertia-return-width-test-pipeline.log`. Broad verification was observed
running at 16:26:40 CEST and terminal by 16:35:12 CEST (8m32s observation
window, including gate execution and documentation, not active coding time).
No claim that ENTER32 allocation, all mixed-width forms or the MSC6 rebuild
blockers are fixed; no full repository suite or hard pre-commit gate was run
for this follow-up, and no commit/push was made.

`quality-fast` exits 0: 3,050 tests pass in 129.97s, configured static gates
pass, and three executable guards pass. Log:
`/tmp/inertia-return-cleanup-quality-fast.log`.
This is the curated gate, not the full repository test suite.

The subsequent default pipeline exits 2. Its unit lane passes 3,050 tests in
112.67s and QuickC passes; MSC6 tiny fails two of seven constructs. The saved
structured summary is `.cache/frontend/test_pipeline/summary.json`;
per-construct diagnostics are in `examples/build_msc6_tiny/*/report.json`.
Compiler diagnostics are in `decompile_compile_stdout` and linker diagnostics
in `decompile_link_stdout`, not stderr. Do not dump the large nested profiles
when only these fields are needed.

- `scalar_types_io`: MSC6 C2065 at DTYPE01.C:39, undefined `inertia_ebp`.
  The standalone `DTYPE01.batch/byteops_unsigned.stdout.c` declares it as
  `extern unsigned long`; the assembled DOS translation unit does not.
  Its body also assigns the BP value to `a` immediately before overwriting it,
  labels `b` at BP-6 although the optional COD oracle accesses BP-4, and renders
  signed casts around unsigned byte multiply/shift operations. These are
  separate diagnostic leads, not yet proven root causes or repaired behavior.
  `rot_ui` reads an apparently uninitialized high-byte local. Pointer parameter
  warnings in `pick_ptr` remain visible; do not hide them.
- `function_pointers`: compilation succeeds, but LINK reports L2029 for
  `_inertia_esp` and `_inertia_ebp`. `select_and_apply` retains full-register
  frame arithmetic while the assembled translation unit declares both carriers
  as `unsigned short`. Follow producer provenance and declaration transport;
  neither a zero-initialized compatibility global nor late deletion proves the
  function correct.

Declaration-loss path confirmed by source inspection:
`tools/compiler_toolchain/build_msc6_examples.py::_build_from_function_decompiles` calls
`_extract_decompiled_function_definition`, which returns only the matched
signature/body and discards top-level externs. `_build_fallback_source` joins
those bodies and `_prepare_decompiled_source_for_c89` invokes synthetic-global
declaration generation without the original metadata. Preserve original typed
dependencies through this assembly boundary rather than inferring a replacement
width from an identifier. Use structured C parsing for that transport; keep
function bodies unchanged and keep unresolved definitions visible to the linker.

Next bounded work, in order:

1. Reduce the stack-slot/carrier discrepancy to exact binary and native AIL
   provenance. Reason: a declaration-only repair can conceal wrong storage.
   DoD: a focused regression distinguishes saved BP, local bytes and numeric SP,
   with machine-versus-generated-C evidence. Failure: address/name heuristics,
   suppressing numeric SP, or deleting an unclassified store.
2. Trace unsigned byte operations and the high-byte argument view at their
   Semantics/Alias/Types owners. Reason: successful compilation is insufficient.
   DoD: unsigned multiply, divide/remainder, logical shift and rotate cases
   preserve exact values, with source serving only as an optional oracle.
   Failure: signedness repair in rendered C or an uninitialized argument view.
3. Preserve proven carrier declarations through translation-unit assembly and
   rerun both failing constructs, then default pipeline. Reason: the current
   standalone and DOS projections disagree. DoD: strict compilation, DOS
   return/exit-code checks and tail validation pass without lost effects.
   Failure: fabricated runtime state, weakened checks, or calling a fast-only
   result full acceptance.

The requested `/home/xor/pytest_deduplicate/pytest_deduplicate.py` was attempted
with `PYTHON_JIT=1`, `-n 7`, and `test_x86_16_stack_pointer_width.py`.
It exits 1 before collection: `ModuleNotFoundError: No module named 'coverage'`.
Log: `/tmp/inertia-deduplicate-stack-width.log`. No overlap findings exist and
no tests were deleted. Before a useful audit, supply its coverage dependency
in an isolated environment and verify worker-local collection/aggregation;
the inspected entrypoint registers an in-process plugin and stores coverage
in a process-local dictionary. Equal branch coverage alone must not justify
removing distinct width/value/refusal cases.

## Verified Defect

The new `test_x86_16_numeric_sp_call_return.py` executes both an original tiny
binary and its compiled generated C. Starting with SP=0x8000, the binary returns
AX=0x7ffe; generated C initially returned 0x7ffc. The regression is admitted
to the routine pipeline without xfail or a weakened oracle.

The byte fixture is:

```text
55 89 e5 50 e8 09 00 83 c4 02 89 e0 89 ec 5d c3 c3
```

It saves BP, pushes an argument, calls a RET-only callee, cleans the argument,
copies SP into AX and tears down the frame. The saved BP is the only remaining
word at the AX assignment. Generated C instead subtracts six before the call
and adds only two in the returned expression. The CALL return-frame decrement
has survived without its matching return effect. Ordinary execution of the
original instructions is correct; do not change the lifter to compensate.

Focused result: one failed, seven dependency warnings, 10.60s total (2.37s test
call). Failure occurs at the generated-C versus machine-return comparison,
after the original-binary oracle and C compilation/execution succeed.
Evidence: `/tmp/inertia-numeric-call-return-machine.log`.

## RunMenu Evidence

A fresh-cache, in-process observer found the first retained SP assignment at
0x1030e, an ADD SP,2 caller-cleanup instruction, not a CALL. Its folded terms
contain two far-call frame decrements, leaving a net -8 modulo 65536. Exact
binary decoding shows PUSH CS/CALL sequences at 0x102fe/0x102ff and
0x1030a/0x1030b, followed by their argument cleanup.

The late call-frame consumer recognizes three separate simple call decrements
but refuses deletion because other SP uses survive. The folded cleanup-owned
expression is outside that exact-CALL-tag consumer's ownership. Removing its
text or loosening the external-use guard is not a repair.

Evidence: `/tmp/inertia-runmenu-frame-fresh.{c,log}`. An earlier observer run hit
the direct-function cache; it is not evidence about executed lowering stages.

## Repair Order

1. Trace and project returning-call stack effects before native AIL SSA and
   expression folding. Reuse the exact machine-frame owner in
   `semantics/call_return_frame_effects.py`; do not reconstruct effects in
   Rewrite or the CLI. Reason: late cleanup has already merged unrelated
   instruction effects. DoD: the minimal numeric return equals the machine
   result while pre-call numeric copies remain unchanged. Failure: compensating
   at every successor without edge ownership or guessing an unknown interface.
2. Keep machine return-frame effects separate from caller argument cleanup and
   `IRCallStackEffect8616.net_stack_delta`. Reason: the latter already describes
   a different call boundary for storage preservation; adding return-frame bytes
   there blindly can break Alias. DoD: near/far calls, PUSH CS/near-CALL frames,
   callee cleanup and shared successors are covered with typed refusals for
   unresolved cases. Failure: double adjustment, lost upper-register state,
   mistaken cleanup ownership or changes to architectural execution semantics.
3. Verify all projections and executable gates. Reason: existing tail checks
   accepted the incorrect numeric return, so stable pre/post lowering alone is
   insufficient. DoD: the machine-versus-C regression, RunMenu, InitMenu,
   quality-fast and the default test pipeline pass with preserved calls and
   memory effects. Failure: deleting live state to pass no-ESP assertions,
   suppressing the new regression or claiming a full-suite result from this lane.

## Initial Candidate (2026-09-09)

`call_frame_compat.py` now consumes the complete, uniquely matched machine CALL
frame before native AIL SSA, using the existing Semantics-owned VEX effect keys.
It leaves argument pushes, caller cleanup and shared successors untouched.
Eight adapter tests cover exact consumption and atomic refusal. The original
near-call machine-versus-C test now passes; a direct far CALL/RETF variant also
passes. Scoped Ruff and Pyright pass.

The saved three-function executable run passes InitMenu call preservation and
compilation, RunMenu's ESC exit, and InitBars stack-array preservation:
3 passed, 7 dependency warnings, 62.83s. This does not prove all call-frame forms
or whole-binary acceptance. Log: `/tmp/inertia-early-call-frame-executable.log`.

The newly added PUSH CS/near-CALL/RETF variant still fails: original AX=0x7ffe,
compiled generated C AX=0x7ffc. Both programs execute successfully. The separate
PUSH CS frame word survives; generated C also presents its high byte as a call
argument. The test's RET-only harness ignores inferred arguments, so the
argument-shape defect is visible evidence, not an independently validated ABI.
Focused result: 2 passed, 1 failed; `/tmp/inertia-call-frame-widths.log`.

Next repair must establish typed ownership of the separate return-segment push
and its matching far return before SSA. Adjacency alone is not sufficient:
PUSH CS can be an ordinary argument to a near-returning callee. Include that
negative case, unknown callees, pre-call numeric observers, operand widths and
callee cleanup before accepting a new consumer. Do not copy the late
`_callsite_after_push_cs_8616` adjacency heuristic into the early adapter.

Stack-address width and operand width are independent. For a 16-bit stack,
PUSH EAX changes SP by four while retaining upper ESP bits; a 32-bit operand
does not establish ESP-addressed stack storage. Preserve this in typed effects
and tests rather than removing wraparound or upper bits to prettify output.
The current `CallsiteMachineFrameKind8616.return_frame_width` maps only near/far
to two/four bytes; it is not by itself proof of mixed-operand-width frame size.

The initial quality-fast attempt stopped at the ownership manifest before
pytest: compiler-dependent skip support is not permitted in fast ownership
targets. The numeric executable regression remains in the routine pipeline;
the fast ownership rule now selects the eight tool-independent adapter tests.
The rerun reaches pytest: **3,011 passed, 1 failed**, 8 warnings, 104.27s;
the sole failure is the PUSH CS/near-CALL numeric-SP regression. Configured
pre-test checks pass, Make exits 2. Log: `/tmp/inertia-call-frame-quality-fast.log`.
The default pipeline and full suite had not been rerun at that checkpoint.

## Return-Segment And Width Repair (2026-09-09)

Semantics now owns `call_return_segment.py`: the separate PUSH CS must be
adjacent to an exact direct near CALL, with matching fallthrough, a known
callee whose complete native endpoint census consists of compatible far
returns, and uniquely projected VEX push effects. Near returns, mixed returns,
unknown callees/exits, unsupported operand widths and explicit callee cleanup
refuse. The pre-SSA adapter consumes the proven prefix together with the CALL
effects atomically. Missing, duplicate and wrong-role AIL projections retain
the whole group. Source instruction identity and owning call address remain
separate in the typed proof and diagnostics.

The previously failing PUSH CS/near-CALL numeric return now passes. Tests also
execute near, direct-far, ordinary-CS-argument and dword-argument binaries and
their compiled generated C, with both zero and nonzero upper ESP. They check
the numeric return, preserved upper ESP and exactly one generated callee call.
These fixtures do not prove general argument/signature recovery or full ABI
restoration.

The dword-argument fixture found an independent execution defect: `push32` and
`pop32` wrote a zero-extended SP to full ESP. Four single-instruction cases
failed before repair; word operations already passed. Both dword helpers now
update reg16 SP and retain the existing byte-safe segmented memory methods.
That exposed a cancelling defect in `leave32`: full EBP was copied into ESP,
then the old POP cleared the high half. LEAVE now copies BP into SP and pops
full EBP, as specified by the
[Intel 80386 LEAVE operation](https://pdos.csail.mit.edu/6.828/2018/readings/i386/LEAVE.htm).
POPAD's existing hardware-backed upper-lane behavior was not changed.

The hardware-backed instruction module passed after the LEAVE correction, but
the combined run still had seven helper-unit failures. Their fake register
bank modeled SP and ESP as independent stacks. It now aliases SP to ESP's low
half; mixed-width pushes share one stack and keep exact value/address checks.

Latest focused result: **65 passed**, 7 dependency warnings, 17.27s. This covers
the adapter, return-segment proof, numeric compiled-C fixtures, stack-width
execution and helper tests. Scoped Ruff, MyPy and Pyright pass. Logs:
`/tmp/inertia-return-segment-focused.log`,
`/tmp/inertia-stack-pointer-width-before.log`, and
`/tmp/inertia-return-segment-width-verified.log` (the latter preserves the
intermediate seven unit-fixture failures, not a green result).

Broad acceptance remains pending. Follow-up width work must audit ENTER and
other compound stack effects separately; this repair is not proof that every
mixed-width instruction or callee-cleanup boundary is correct.

## Native ABI Regression And Root Cause

The next quality-fast run exposed eight scalar-return smoke failures:
3,034 passed, 8 failed, 133.89s. They reproduce in isolation (50 passed,
8 failed). Their Keystone-generated `ret` encodes as `66 c3`, so the tests
exercise an operand-size-32 near return, not an ordinary word RET.

At the pre-SSA return stage, the native calling convention and prototype were
absent, so ReturnMaker skipped return-register capture and DCE later removed
the producer. A direct fact-collector probe reported `extra_pop=2` for a plain
prefixed RET. Native inference subtracted `arch.bytes` (two) from the four-byte
return pop and misclassified the remaining two bytes as callee argument cleanup.
Restoring the incorrect full-ESP clobber or editing the fixture to avoid the
prefix would only conceal this second defect.

`ReturnFrame8616` now separates operand width, near/far frame bytes and explicit
RET-immediate cleanup. A closed native endpoint census feeds both return-segment
proof and the fact-collector compatibility boundary. Agreeing decoded cleanup
replaces the erroneous width subtraction; unknown or conflicting endpoints keep
the native behavior and publish a failed evidence census, not a positive proof.
The adapter reports all five counters and the consumed return facts.

Results: 89 focused return/smoke tests pass in 24.76s. Eight added near/far,
word/dword and immediate-cleanup contract cases pass with the prefix tests
(17 passed, 8.28s). The existing hardware-backed POPAD behavior remains intact.
Logs: `/tmp/inertia-return-cleanup-smoke.log`,
`/tmp/inertia-return-cleanup-contracts.log`,
`/tmp/inertia-prefixed-return-ail.log`, and
`/tmp/inertia-prefixed-return-facts-detail.log`.
The return/smoke command ran 16:03:10-16:03:35 CEST on 2026-09-09; the contract
command ran 16:04:41-16:04:49. These are command wall-clock intervals from log
timestamps, not estimates of total development time.
