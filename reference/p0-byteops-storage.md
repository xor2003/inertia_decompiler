# Byte Arithmetic Storage And Return Evidence

## Scope And Checkpoint

Step 9 investigation, 2026-09-12, approximately 10:44-10:50 +02:00.
Target: `byteops_unsigned`, original address 0x10046 in the rebuilt MS C
`scalar_types_io/TYPES.EXE`; procedure-slice address 0x1000. Source is an oracle,
not a recovery dependency. Preserve the accepted storage_classes round trip.

The current mandatory compiler lane first fails at:

- scalar_types_io: byteops_unsigned, after add_sc and mix_uc succeed.
- function_pointers: apply_twice, after inc_one and dec_one succeed.
- loops_jumps: nested_loops.
- pointer_memory: fill_bytes.

These are first failing functions, not an exhaustive inventory of defects in
those fixtures. Later functions may remain untested after an early failure.

## Reproduced Evidence

Production command, with PYTHON_JIT=1 and PYTHONHASHSEED=0:

```sh
./decompile.py examples/build_msc6_tiny/scalar_types_io/TYPES.EXE \
  --proc byteops_unsigned --proc-kind NEAR --no-alternate-source-c --timeout 90
```

Exit 4: GP stack-restore facts were classified but none materialized. Enabling
INERTIA_DEBUG_GP_STACK_RESTORE confirms two facts and zero materializations.
Save insertion and runtime-source selection succeed; each restore has
replacement_count=0. Thus this is not proven to be the whole-body deletion
mechanism previously fixed for sum_globals.

An observed private-process hook at `_materialize_fact_8616` compares actual
Alias facts, C variables and `_entry_sp_byte_offset_8616` results:

| Register | Save / Restore (Slice) | Alias Entry-SP Bytes | C Resolver Bytes |
| --- | --- | --- | --- |
| SI | 0x100a / 0x1052 | -10, -9 | -8, -7 |
| DI | 0x1009 / 0x1053 | -8, -7 | -6, -5 |

The C body still contains both save and restore assignments. Its low/high byte
variables resolve two bytes above the Alias-proven coordinates. The exact
producer of this coordinate discrepancy is NOT identified yet. Do not patch
the restore matcher by adding a guessed -2 adjustment or accepting names.

The partial C also declares `char byteops_unsigned(void)` and returns only
the low-byte local. The original source returns an unsigned short and the
original compiler fixture checks 0xC000. Therefore merely satisfying the GP
restore gate cannot establish function correctness. The partial expression
surface also contains `_INSERT` and `CONCAT` forms; strict compilation remains
an independent obligation after the validation failure is repaired.

## Next Actions

1. Trace coordinate creation from native frame tracking through stack-variable
   projection registration. Compare pre/post allocation-helper state and the
   first lowering pass that selects these byte variables.
   Reason: the matcher correctly refuses mismatched storage evidence.
   DoD: a failing regression identifies the producer, whose repaired typed
   projections agree with Alias for both bytes without sample-specific offsets.
   Failure: relax the restore check, infer identity from local names, or hide
   the mismatch behind an invented save/restore body.
2. Verify the binary's terminal AX definition and trace recovered return width
   through Semantics, Types and codegen.
   Reason: the observed partial byte return cannot represent 0xC000.
   DoD: the generated return preserves the binary word result and the MS C
   source oracle passes. Failure: force a source-named signature or substitute
   the known answer without binary evidence.
3. Run focused regressions, strict C compilation and the real scalar_types_io
   compile/decompile/recompile/run lane; continue through later selected
   functions rather than assuming the first repaired function closes the lane.
   DoD: clean tail validation, no lost calls/storage, recompilation and runtime
   checks pass, with storage_classes still green.
   Failure: count partial output, diagnostic bypasses or an early-stopped lane
   as successful decompilation. Refresh quality-fast and test-pipeline before
   claiming acceptance; retain the whole Step 9 completion requirements.

## Evidence Locations

Logs under `/home/xor/.cache/`: `byteops-current.log`, `byteops-current.c`,
`byteops-restore.log`, `byteops-coordinates.log`, `byteops-binding.log`.
The diagnostic hooks executed and the processes exited with the reproduced
validation failure. No production repair or new test pass is claimed here.

Relevant current-source owners: `lowering/gp_stack_restore.py`,
`lowering/gp_stack_restore_identity.py`, and the stack coordinate producer yet
to be isolated. Graph generation 2026-08-27 lacks the two GP modules; exact
source fallback was used. Step 9 remains active.

## Coordinate Producer Checkpoint (2026-09-12 11:15 +02:00)

Native allocation tracking is correct for byteops_unsigned: the observed
allocation helper changes SP from entry-SP-2 to entry-SP-6. Before owned stack
lowering, native byte variables include offsets -6, -8 and -10. Registry tracing
shows the first incorrect registrations are produced by stable SS lowering and
`materialize_stack_cvar_at_offset_from_facts_8616`, not the GP restore matcher.

`entry_sp_offset_for_machine_bp_range_8616` extrapolated a single registry delta
to unrelated ranges before consulting the typed frame relation. A zero-delta
object binding therefore overrode the proven -2 frame relation. Removed that
extrapolation; exact bindings remain usable, while unrelated ranges require
typed frame proof. The regression has 4 failures / 2 passes before this change;
49 related tests pass afterward (16.83s). New module/test surface Ruff passes.
MyPy passes when checking stack_frame_projection together with its coordinate
owner; checking the projection file alone reports an Any return from the imported
owner under that reduced import-checking scope. No ignore was added.

This repairs byteops_unsigned in production: clean validation, strict GCC,
result 0xC000, and unchanged SI/DI parent values. All ten scalar-types selected
functions compile/decompile/recompile/run successfully, rebuilt exit 255.
The standalone builder writes `examples/build_msc6/report.json`; the later
mandatory pipeline also confirms scalar_types_io green in its standard directory.

However, the broader change is NOT accepted yet. Refreshed gates:

- Preliminary checks: 268 passed, 19.77s.
- Main lane: 4,588 passed, 4 failed, 286.63s. Three existing SORTD failures plus
  MONOPRIN __fimemset's uncollected validation. Isolated MONOPRIN reproduction
  also fails (19.39s total), so do not dismiss it as contention alone.
- MS C: compare16, simple_control and scalar_types_io green; storage_classes
  regresses at bump_static. Its sum_globals function still passes.
- QuickC: add and whsum green; hello now fails the GP restore gate, alongside
  the existing args failure (2/4 green).
- Full architecture/ownership pass. quality-fast remains red on Ruff debt;
  compiled-module smoke passes for 39 modules.

The leaf-function regression exposes a missing coordinate-domain contract.
For bump_static, the typed frame artifact reports UNKNOWN with no BP-relative
accesses. The converter receives byte requests (-1,1), (-3,1), (-5,1), with
one-byte registry entries (-2,-2), (-4,-4), (-6,-6), respectively. The removed
global zero-delta extrapolation previously filled these gaps. Working diagnosis:
the caller routes native entry-SP stack views through a machine-BP conversion
interface when there is no proven BP frame. The exact producer/domain selection
must be repaired, not replaced with a universal zero or -2 bias.

Next required step: distinguish entry-SP and machine-BP access provenance at the
typed stack-address/Lowering boundary, preserving native entry-SP views without
inventing a machine-BP relation. Verify the source of those requests before
implementing. DoD: byteops_unsigned remains green, bump_static/storage_classes,
QuickC hello and MONOPRIN regain their previous acceptance, and unknown genuinely
machine-BP ranges still refuse. Failure: restore arbitrary registry extrapolation,
relax saved-register validation, or count the scalar improvement while omitting
the newly failing fixtures. Step 9 stays open; no commit/push performed.

New logs in `/home/xor/.cache/`: `byteops-native-state.log`,
`byteops-registry.log`, `frame-extrapolation-before.log`,
`frame-extrapolation-after.log`, `byteops-frame-fixed.c`,
`byteops-frame-fixed.log`, `check-byteops-frame.c`,
`byteops-frame-roundtrip.log`, `frame-extrapolation-test-pipeline.log`,
`frame-extrapolation-contracts.log`, `frame-monoprin-recheck.log`,
and `bump-frame.log`. All processes completed. Source remained unchanged during
the broad run; the current regression status is authoritative.

## Native Coordinate Follow-up (2026-09-12, 11:34 +02:00)

The native-entry-SP path now preserves explicitly tagged coordinates without
publishing an invented BP relation. Focused evidence after that change:
33 coordinate/stack-variable tests pass; scoped MyPy passes with the consumed
coordinate/naming owners included. Production bump_static passes validation.
At 11:34, QuickC hello also exits 0, validation=passed, clean whole-tail.
This is a direct function check, not a fresh QuickC round-trip lane result.

MONOPRIN remains rejected: the isolated corpus test fails in 19.97s (17.55s
test call), despite clean tail validation. The final text guard rejects
stack_sp_m6_1 and stack_sp_m5_1. These names originate in Lowering's
stack-variable display collision safeguard, not an unsupported instruction.
The logged registry maps BP -6/-5 to entry-SP -8/-7, while the conflicting
C variables carry offsets -6/-5. Their coordinate provenance still needs
reconciliation; do not rename them merely to bypass the guard.

An independent diagnostic compiled the unchanged emitted function body with
the existing strict GCC behavior harness. It passes counts 0..3 in both DF
directions, memory/return checks, and ES/ESI/EDI preservation. This bounded
oracle does not prove storage identity or override the CLI failure.
Compiling the entire emitted section additionally reveals a harness problem:
its SEG_U8/SEG_U16 definitions collide with the emitted runtime prelude under
-Werror. Repair prelude ownership without disabling compiler warnings or
rewriting the generated function under test.

Next: reconcile regenerated native stack views with the exact typed registry,
repair the harness prelude boundary, and rerun MONOPRIN plus full storage and
QuickC lanes before broad gates. Existing broad totals above remain historical;
Step 9 is incomplete. No production code or validation policy changed during
this follow-up investigation. Logs: `monoprin-coordinate-guard.log` and
`hello-native-coordinate.{c,log}` in `/home/xor/.cache/`. All jobs completed.

## Live Projection Repair (2026-09-12, 11:56 +02:00)

The next producer trace resolved the MONOPRIN collision: obsolete positive
byte projections at +5/+6 retained display names local_5/local_6 after their
owners disappeared from both the live body and variable map. Display replay
then renamed unrelated negative locals to unresolved stack placeholders.
The earlier final-registry snapshot was insufficient to identify this cause.

Types/Lowering now reserves projected display names only for current body,
argument, variable-map or declaration owners. Historical coordinate evidence
is retained; no storage relation, C statement, call, or validation policy is
changed. A stale-owner regression failed before repair; controls retain
collision protection for each live surface. The modified owner stays below
350 lines, with typed/documented helpers and clean Ruff/MyPy.

The corpus harness now uses the canonical portable runtime header instead of
competing SEG_U8/SEG_U16 definitions. Its positive oracle covers body-only and
header-bearing output; all six deliberately corrupted controls remain red as
expected. No emitted function text is changed before compilation.

Verification after repair:

- 49 focused tests pass in 25.95s, including successful MONOPRIN CLI exit,
  validation=passed, strict GCC compilation, both DF directions, counts 0..3,
  all-memory comparison, return value and ES/ESI/EDI preservation.
- Full architecture and ownership checks pass. Both relevant test files are
  enrolled in the routine pipeline. Focused Ruff --fix and MyPy pass.
- Routine preliminary contracts: 268 passed, 22.22s. Main lane: 4,597 passed,
  five failed, 327.07s. The full repository collection was not run.
- QuickC: 3/4 pass; hello is restored, args remains failed (lane 49.14s).
- MS C: 4/7 pass (lane 145.177s). storage_classes is restored and
  scalar_types_io remains green; both original and rebuilt executables return
  255. compare16/simple_control also pass. loops_jumps, function_pointers and
  pointer_memory remain failed.
- quality-fast fails on broader Ruff debt. quality-dev additionally reports
  three no-any-return findings in register_definition_return.py (line 47) and
  call_stack_effects.py (lines 77/124). No suppression was added. The 39-module
  compiled import smoke passes.

Remaining main-lane failures are InitBars, RunMenu, InitMenu and two caller
cleanup tests. The caller reproduction is a real value defect, not merely an
arity-format mismatch: two PUSH AX instructions emit
`sub_1020((inertia_eax & 0xffff) >> 8, inertia_eax & 0xffff)`.
Two independent direct reproductions produce byte-identical C. Keep the
argument-value regression; trace physical PUSH widths and reaching values
through the existing call-argument owner instead of repairing rendered calls.
The first caller test's exact zero-argument assertion also needs review only
after that semantic defect is repaired.

Slowest main-lane tests: InitMenu 149.86s, InitBars 114.92s, RunMenu 114.24s.
MONOPRIN takes 39.73s under the broad lane versus 10.24s focused; neither is
a controlled performance comparison. Evidence window 11:34-11:56 includes
investigation, implementation and gate waits, not exclusive CPU time.

Logs: `/home/xor/.cache/fim-live-names-{before,after,ruff,mypy,contracts,quality,
quality-dev,pipeline}.log`, `fim-coordinate-collisions.log`,
`fim-prelude-{before,after}.log`, and `caller-cleanup-{current,repeat}.{c,log}`.
All processes completed. Step 9 remains incomplete; no commit/push performed.

## Caller And Countdown Evidence (2026-09-12, 12:43 +02:00)

The caller-cleanup failure was not a reason to loosen its argument-value
assertion. Lowering's `classify_push_store_width_8616` already refused byte
lvalues as complete PUSH values, but the legacy outgoing-placeholder consumer
in `decompiler_postprocess_calls.py` bypassed that refusal. It now consumes
the same verdict before considering a placeholder. No new recovery was added
to postprocess. The bare-RET callee establishes no formal arity; its recovered
call no longer incorrectly receives AH and AX for two PUSH AX instructions.

Reviewing the generated caller uncovered a second, independent defect:
`DEC CX; JNZ` updated CX but then tested that updated CX against the old-input
boundary of one. A compiled behavioral probe with initial CX=1 performed
65,536 calls instead of one. Frontend now emits a JCC-bound zero/nonzero test
of the result when it cannot prove an independent input value. Proven input
and affine views remain supported. Physical flag execution is unchanged.
Alias accepts the new result view only with an exact branch-time binding and
the existing unique register/storage/CFG proof, converting dispatch comparisons
back to the proven input. No rendered-text or Structuring repair was added.

Regression evidence:

- Initial focused failure: the compiled caller count was wrong; the new
  frontend/Alias view tests also failed before their production changes.
- Existing caller regression now compiles and executes the native body for
  CX=0,1,2,3, checking expected call counts, the preserved ECX high word, final
  zero CX, and unchanged EAX. CX=0 explicitly exercises 16-bit wraparound.
  This behavioral harness does not replace the CLI strict-C acceptance gate.
- Four frontend tests required a coherent contract update: three assumed an
  unbound pre-update register; one mocked a following JCC without providing
  a following instruction. The revised repeated INC/DEC tests compare the
  branch-time result against the original boundary over all 65,536 inputs.
- Six negative Alias cases retain unknown/inexactly bound conditions without
  materialization. Final related four-module run: 115 passed, 19.88s.
- Ruff --fix passes the updated frontend test module. The touched normalizer
  no longer exceeds the complexity threshold; remaining legacy lint findings
  are still reported. Scoped MyPy for Alias, lifter, PUSH classifier and its
  legacy consumer passes; architecture/context/test ownership pass.

Broader evidence, not a whole-goal success claim:

- Routine preliminary contracts: 268 passed, 23.09s. Main lane: 4,606 passed,
  seven failed, 408.64s. This run preceded the four frontend test updates;
  those four subsequently pass focused, not in a refreshed full routine run.
- Remaining corpus failures: SORTD InitBars, RunMenu, and SORTDEMO InitMenu.
- QuickC remains 3/4 (52.726s); args has uninitialized byte-local reads in
  SI/DI restores. MS C remains 4/7 (181.317s): compare16, simple_control,
  storage_classes, scalar_types_io pass; loops_jumps, function_pointers,
  pointer_memory fail. Successful rebuilt fixtures return 255 as expected.
- quality-fast remains red on broader lint debt; compiled import smoke for
  39 modules passes. No full repository collection or expanded pipeline was
  refreshed. Step 9 remains open.

Recorded checkpoint window: 12:27:49-12:43:19 +02:00 (15m30s, includes gate
waits; work began before the first exact clock observation). Main routine
pytest took 408.64s; external lanes took 52.726s and 181.317s. These are wall
times, not exclusive engineering time or controlled performance comparisons.

Logs: `/home/xor/.cache/countdown-{boundary-focused,quality-fast,mypy,contracts,
test-pipeline,frontend-ruff,final-focused}.log`. Earlier diagnostic evidence:
`caller-placeholder-{before,after}.log`, `caller-countdown-before.log`, and
`incdec-post-view-{before,after}.log`. All launched processes have completed.
