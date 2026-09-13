# Stack Allocation Proof Boundary

## Scope And Evidence

Step 9 investigation, 2026-09-12, approximately 06:39-06:53 +02:00
(about 14 minutes elapsed, including probes and gate waits).
This is a safety checkpoint, not an accepted InitMenu repair.

The normal-worker InitMenu diagnostic used SORTDEMO.EXE at 0x10060, a fresh
temporary function cache, portable-flat C, and no alternate source C. Its
hooks observed transfer inputs and outputs without changing their results.
Both completed probes still failed final stack-local initialization validation.

In the rebased diagnostic IR, the prologue contains:

- 0x1000: PUSH BP;
- 0x1001: BP receives SP;
- 0x1003: AX receives the constant 18;
- 0x1006: CALL, with a complete net_stack_delta=0 effect;
- 0x1009/0x100a: DI/SI saves.

Alias records those saves at entry-SP offsets -4/-6. A subsequent stable
SS:BP-2 byte store at 0x103c has no resolved base and clears both saved-register
origins. These are diagnostic slice coordinates, not asserted original addresses.

The earlier assumption that complete, zero-delta calls ruled calls out was
wrong: such metadata can itself omit stack allocation. The current summary
contains an allocation request, but its producer also accepts helper names and
searches backward for an AX immediate. Neither alone proves the actual callee
transfer or an unclobbered reaching value. The frontend has binary helper
evidence; that evidence must be consumed explicitly before granting a positive
stack-allocation effect.

Artifacts outside the repository:

- `/home/xor/.cache/initmenu-stack-loss.jsonl`: first destructive store and prologue.
- `/home/xor/.cache/initmenu-prologue.log`: completed failing function probe.
- `/home/xor/.cache/stack-allocation-guard-before.log`: four failing controls.
- `/home/xor/.cache/stack-allocation-guard-after.log`: 135 passes in 6.76s.

## Guard Implemented

Semantics now refuses the ordinary argument-cleanup proof when a summary marks
a stack probe or carries an allocation request. It emits UNKNOWN_REFUSE with
STACK_ALLOCATION_UNPROVEN and an incomplete, unknown-delta IR effect. Existing
per-call diagnostics retain the function, block, callsite and failure reason.
This is not a blanket abort: consumers must retain conservative state rather
than rely on a fabricated zero delta.

Reason: ordinary argument cleanup does not describe a callee allocating storage
inside its caller's frame. Zero allocation requests also require proof of the
callee effect; they are not an exemption based on a guessed helper identity.

DoD for this guard: corrupted allocation summaries fail the balanced-call proof,
ordinary balanced calls still pass, outcomes remain fully accounted for, and
tests run through both Make and the Python routine pipeline.

Definition of failure: any allocation request silently obtains a complete
zero-delta proof from argument cleanup, or the guard is used as a substitute for
implementing supported stack allocation.

Five focused controls are enrolled in Make, the routine Python pipeline and
the call-semantics ownership group. Four failed before the change; all pass
within the 135-test related run. Scoped MyPy passes for both production owners.
Ruff check --fix leaves no findings on the touched surface. Global quality-fast
still fails on lint debt; its 39-module mypyc import smoke passes.

Routine verification completed at approximately 06:52 +02:00: 268 early
contract tests pass; the main lane has 4,486 passed and the same three SORTD
failures in 210.51s. All seven MS C tiny compile/decompile/recompile/execute
round trips pass. QuickC remains three of four, with args failing validation.
The main lane also reports the existing multi-threaded fork deprecation warning;
it must not be suppressed. Logs use the `stack-allocation-guard-` prefix under
`/home/xor/.cache/`. Full architecture checks also pass. This is a routine-lane
result, not a complete-suite audit.

## Remaining Repair Order

1. Semantics: fixed block-local allocations now have a typed positive path,
   described below. Keep requests with missing, conflicting or clobbered evidence
   refused. DoD: exact net effects, corrupted controls and real prologue evidence
   survive the full pipeline. Failure: guessed deltas or proof at a later layer.
2. Alias: consume proven nonzero call effects and track BP/SP coordinate
   relationships across CFG joins, clobbers and immutable register captures.
   DoD: saved-byte identities have correct entry coordinates; disjoint BP stores
   preserve them and overlapping/unknown stores refuse. Failure: exempting all
   BP stores, conflating captured and current bases, or preserving stale facts.
   Proven nonzero SP transfer is now consumed. BP tracking has a tested local
   implementation but remains unaccepted because its broader consumers regress.
   Callee BP-preservation evidence must not be assumed for every call.
3. Lowering and validation: verify the resulting saved-register stores and
   restores use matching initialized C objects. DoD: focused InitMenu regression,
   validation=passed, preserved calls/arguments, stricter C recompilation, and
   routine corpus checks pass. Failure: suppressing the initialization check or
   removing live register effects to make C compile.

Step 9 additionally retains its full-suite and global quality acceptance. None
of these remaining obligations is closed by this guard.

## Positive Allocation Proof

Follow-up checkpoint: approximately 06:54-07:21 +02:00, about 27 minutes elapsed
including probes and gates; active engineering time was not separately measured.
The new Semantics owner is
`semantics/call_stack_allocation.py`. It combines frontend binary helper evidence
with a complete AX constant assignment in the caller's IR. Architectural AX
aliases come from the existing register-family inventory. Partial/full AX
clobbers, intervening calls, missing values and incompatible summaries refuse.
The summary's requested size is checked for conflict, never used as the value
proof. No named-probe classification is required when binary evidence exists.

Two pre-Alias integration controls failed before implementation. Alias also
discarded every nonzero call delta; two controls failed before that repair.
Alias now applies a complete, non-escaping delta relative to machine-call entry
SP, excluding the already-executed return-frame push. Unknown entry SP stays
unknown. Tests also check saves made after allocation use adjusted coordinates.

The first live integration probe exposed a coordinate mismatch: slice IR calls
0x21c2 while its summary retains original target 0x11222. The binary helper
evidence was present. The repair consumes the existing
`call_target_identity.x86_16_call_targets_equivalent_8616` mapping instead of
inventing a relocation rule or accepting different targets by helper name.
The corrected test fixture supplies the linked-image bounds that mapping needs.

The fresh live probe subsequently collected
`CallStackAllocationProof8616(callsite_addr=4102, target_addr=70178,
value_instruction_addr=4099, allocation_size=18)`.
This proves runtime collection, not successful final C: the function still
fails its existing uninitialized saved-register stack-local guard.
Logs and typed inputs are in `/home/xor/.cache/initmenu-allocation-source.jsonl`
and `initmenu-allocation-source-after.log`.

The expanded focused run has 179 passes in 7.71s. MyPy passes all four changed
production owners; Pyright passes the new Semantics module. Full architecture
checks pass. New-module Ruff is clean; existing Ruff debt remains in the older
Alias transfer, semantic publication and architecture-check owners. Global
quality-fast remains red. The new source and tests are enrolled in Make,
routine tests, ownership and architecture promotion lists. Raw IR/SSA caching
is unchanged; semantic source changes already enter the downstream cache scope.

The final routine lane has 4,505 passes and the same three SORTD failures in
208.89s. All seven MS C tiny round trips still pass; QuickC remains three of
four. The unmarked-probe positive control is included in this routine result.
No stable complete-suite audit was run. Step 9 remains open.

For the next BP repair, `semantics/call_register_effects.py` is specifically a
synthetic-stub contract; its callee-saved set covers BX/DI/SI, not BP. Do not
claim it proves BP preservation or extend that register set without a matching
ABI/binary proof and tests.

## BP Coordinate Integration: Unaccepted

Checkpoint recorded at 08:03 +02:00 on 2026-09-12. The initial implementation's
exact start was not recorded, so no active-time estimate is asserted.

Alias now carries separate SP/BP entry-relative coordinates, immutable temporary
captures, affine word updates and unanimous CFG joins. Typed address bases keep
legacy bare integer SP coordinates from being reinterpreted as BP evidence.
Full-parent writes invalidate word coordinates. `IRCallStackEffect8616` carries
an explicit `bp_preserved` field, independent of stack delta and preserved
storage. The binary-proven allocating helper supplies this proof; ordinary
calls do not. The raw IR/SSA cache schema is bumped to 4, with round-trip and
old-schema refusal controls.

The 182-test focused checkpoint passed in 7.64s. Broader verification then
contradicted acceptance:

- routine pytest: 4,514 passed, six failed, eight warnings, 233.57s;
- three new stack-annotation smoke failures reach the hard error that GP
  restore facts were classified but none materialized;
- the original three SORTD failures remain;
- MS C tiny: only simple_control passes, six other round trips fail;
- QuickC: three of four, args remains failing;
- quality-fast: Ruff debt remains, 39-module compiled import smoke passes.

The smoke fixtures store AX to a BP-relative local and read it back. The new
Alias evidence exposes those spills to a consumer documented for PUSH/POP
snapshots. Investigate the existing local-variable materialization ownership
and make the distinction explicit in typed evidence. Do not assume all six
MS C failures have this cause before inspecting their individual errors.
DoD: the unchanged annotation tests and all seven round trips pass, every
classified storage fact has a valid consumer, and the SORTD blockers advance.
Failure: bypassing the materialization gate, suppressing BP facts, fabricating
runtime-register snapshots for ordinary locals, or weakening source annotations.

A separate address-resolution gap was fixed after that pipeline run: narrow
frame values and opaque expressions without an exact producer must not become
the current SP/BP base. Six controls failed before the repair. The shared
value-proof predicate now governs both address bases and register updates;
44 related tests pass in 6.53s. Scoped Ruff and seven-owner MyPy pass. A narrower
two-module MyPy invocation reports an Any-return diagnostic that is absent
when the authoritative IR owner is included; no type suppression was added.
The routine pipeline was not rerun after this small repair.

Logs under `/home/xor/.cache/`: `bp-frame-quality-fast.log`,
`bp-frame-test-pipeline.log`, `frame-address-refusal-before.log`,
`frame-address-refusal-after.log`, and `frame-address-refusal-owner-mypy.log`.
Step 9 remains open; no complete-suite or successful InitMenu claim is made.

## Existing Local Return Binding

Follow-up completed at 08:22 +02:00. The first exact diagnostic timestamp is
08:04:56; about 18 minutes elapsed including probes, implementation and gate
waits. Active engineering and unattended wait time were not measured separately.

The annotation fixture's save at 0x100c already becomes an initialized word
local. Its reload at 0x100f has been folded into the return at 0x1015, which
reads that same local. The PUSH/POP snapshot inserter cannot find a standalone
restore owner and must not fabricate a runtime AX value for this ordinary spill.

`semantics/register_definition_return.py` proves a unique same-block register
definition reaches an exact return without overlapping writes, calls, branches,
opaque operations or upstream IR refusals. This is a machine-value flow proof,
not a C binding or calling-convention inference.
`lowering/gp_stack_local_return.py` consumes that proof only for a word AX
return with matching Alias byte coordinates, a unique dominating local writer
at the native save site, no escaped address or intervening calls/control flow,
and consistent bindings for every copy of the return. It records the existing
binding as materialized without changing the C tree. Unsupported cases retain
the normal hard error; this does not prove arbitrary spill-expression values.

The original annotation regression failed before and all three unchanged smoke
tests now pass. Corruption controls reject missing/late/multiple saves, wrong
coordinates, wrong return values/sites, inconsistent return copies and native
register clobbers. The focused/enrollment run has 150 passes in 7.03s. New-owner
Ruff, four-owner MyPy, venv-selected Pyright and full architecture checking pass.
The two source owners and both regression modules are enrolled in Make,
the Python routine lane, ownership selection and architecture promotion.

The completed routine lane has 4,542 passes and the original three SORTD
failures in 217.43s. MS C tiny still has only simple_control passing (1/7);
QuickC remains 3/4. Global quality-fast remains red on legacy Ruff findings;
39 compiled modules pass the import smoke. No complete-suite audit was run.

The previous rel_i16/rel_u16 logs explicitly report the same GP materialization
hard error. Their exact reload consumers are the next investigation; do not
generalize the terminal-return proof to non-terminal uses or discard BP facts.
Logs: `/home/xor/.cache/bp-spill-smoke-before.log`, `bp-spill-smoke-after2.log`,
`local-return-enrollment.log`, `local-return-test-pipeline.log`, and
`local-return-{final-ruff,final-mypy,pyright,architecture-final,quality-fast}.log`.
This closes the annotation regression, not the BP integration or Step 9.

## Native Stack Tracker Disagreement

The subsequent live rel_i16 probe disproves the non-terminal-spill hypothesis
above. Its classified facts are genuine SI/DI POPs. In diagnostic slice
coordinates, Alias records SI's save at 0x100a and restore at 0x1070 with entry
bytes -8/-7; DI is saved at 0x1009 and restored at 0x1071 with bytes -6/-5.
The emitted SI restore instead reads variables at -6/-5. The mismatch must not
be accepted merely because the expression resembles a word recomposition.

The native SPropagator callback exposes the earlier disagreement: its underlying
StackPointerTracker reports SP=-2 at both 0x1006 (before the helper call) and
0x1009 (after it). The proved two-byte allocation requires -4 at 0x1009. It then
reports -6 at the SI POP, matching the incorrect emitted coordinates. These
negative offsets are represented as 32-bit modular integers by angr.

The native tracker only has special allocation handling for other architecture
names in its upstream implementation. Inertia's typed call-allocation effect is
currently consumed by the semantic IR/Alias path, but is not reflected in this
native tracker observation. A downstream C-coordinate adjustment would hide the
divergence rather than fix the producer.

`test_x86_16_stack_tracker_allocation.py` supplies real helper bytes and a native
CFG/tracker. Allocations 2 and 18 fail before repair; zero allocation passes
(2 failed, 1 passed, 5.81s). This is deliberately open regression evidence, not
a passing routine enrollment or completion claim.

Next repair: publish/consume the same binary-backed, unclobbered allocation
proof at the native stack-tracking boundary, before propagation and variable
recovery. DoD: the native controls pass, captured SP values and downstream
locations agree with Alias, rel_i16 validates and recompiles with intact SI/DI,
and all MS C round trips are restored. Failure: duplicate allocation guessing,
helper-name inference, C offset patches, accepting mismatched byte coordinates,
or passing only the Alias checks while the native tracker remains wrong.

Evidence: `/home/xor/.cache/rel-i16-gp.log`, `rel-restore-bindings.log`,
`rel-tracker-bindings.log`, and `native-tracker-allocation-before.log`.
No production code changed during this root-cause checkpoint; the preceding
routine totals remain the latest completed broad results.

## Native Tracker Adapter Implemented

Checkpoint at approximately 08:45 +02:00, following the 08:30:58 root-cause
checkpoint: about 14 minutes elapsed, including implementation, gates and probes.

`stack_tracker_allocation.py` adapts angr's native VEX stack transfer. It uses
the existing VEX block rather than relifting and imports it through the owned
IR importer. The shared Semantics allocation collector can now operate before
C call summaries exist: binary target evidence and an unclobbered complete AX
assignment remain mandatory; supplied summaries retain all consistency checks.
There is no second immediate scanner or helper-name proof.

The adapter runs after angr accounts for the returning call's machine frame
and before it publishes successor state/deltas. It subtracts only a proved
allocation. Recognized allocating calls with unknown operands produce unknown
SP, not a false balanced-call fact. Ordinary calls and other architectures
retain their existing behavior. The installer is idempotent and is called by
the existing stack compatibility startup path.

The initial two failures now pass. Native controls cover allocations 0/2/18,
AL/AH/AX/EAX clobbers and an ordinary call with a nonzero AX value. The related
59-test run passes in 6.32s; scoped Ruff, four-owner MyPy, venv-selected Pyright
and full architecture checks pass. Source and tests are enrolled in Make,
routine Python tests, ownership selection and architecture promotion.

A fresh live rel_i16 probe confirms the repaired native coordinates:
SP is -2 before the allocation, -4 afterward, then -8 at the SI POP and -6
at the DI POP. The diagnostic uses a fresh temporary function-cache namespace
and observes the actual native callback. These values now agree with Alias.
The function still exits with validation failure: GP save/restore projections
cannot be located by the Lowering consumer. Inspect lost projections and their
consumption/elimination evidence next; neither correct native coordinates nor
absence of matching tags alone proves those effects can be discarded.

Completed routine result: 4,550 passes / the same three SORTD failures in
212.12s; MS C remains 1/7 and QuickC 3/4. Global quality-fast remains red on
Ruff debt; 39 compiled-module imports pass. No complete-suite refresh or
successful rel_i16/InitMenu acceptance is claimed.

Evidence under `/home/xor/.cache/`: `tracker-allocation-refusal-tests.log`,
`tracker-allocation-{final-mypy,final-pyright,architecture,quality-fast}.log`,
`tracker-allocation-test-pipeline.log`, and `rel-tracker-after.log`.
