# Pointer Fill: Preserve The Function, Not Only The Loop

Step 9 investigation, 2026-09-12, observed 15:25-15:29 +02:00.
This is a diagnosed blocker, not a completed function repair.

## Evidence

The normal fill_bytes CLI for the MS C pointer_memory fixture exits 4. Exact
Alias facts prove SI saved at rebased 0x100a and restored at 0x102f, and DI
saved at 0x1009 and restored at 0x1030. Lowering refuses both: the candidate
statement trees contain no instruction provenance and no matching restore.
These addresses identify diagnostic observations, not implementation rules.

An isolated fresh-cache worker probe inspected the actual failing AST. It
contained only a for loop and a return; every observed node had empty tags.
The assignments initialize/increment the induction variable and write the
indexed destination. The saved-register byte definitions and restores were
absent. The shared traversal did see the loop and its semantic cast children;
this observation does not justify changing traversal or inventing tags.

The producer is the legacy _materialize_byte_pointer_fill_loop_8616 callback
in decompiler_postprocess_stage.py. The Types/Lowering pointer_memory_idioms
dispatcher invokes it from Structuring's validation-prime path. It recognizes
a bounded instruction pattern but replaces cfunc.statements wholesale, without
covering the surrounding function effects. The counted-loop normalizer then
builds a for loop and return. Register restoration correctly refuses the
result when Lowering is replayed before the validation baseline.

A second isolated diagnostic disabled only that byte-fill callback. It
preserved all four saved SI/DI bytes and both restores, but was still
validation_failed: the generic body used a word pointer, emitted a pointer
through a scalar GP mask, and indexed dst by the restored runtime SI value
instead of the induction variable. The final parameter gate reported
expected-class=pointer, actual-class=value for machine BP+4. The worker process
exit zero is only successful transport; its JSON status is failure.

Therefore neither disabling the invariant, copying instruction tags onto the
replacement, nor simply disabling the callback is a complete fix.

## Ordered Repair

1. Recover the generic byte-store base, index and parameter binding from the
   existing binary IR/Alias facts at Types/Lowering, before optional loop
   presentation. Reason: the legacy replacement currently hides incorrect
   generic pointer materialization. DoD: dst[i] writes exactly one byte, count
   remains signed, value narrowing is explicit, and the pointer-class gate
   passes without that callback. Failure: guessed storage, pointer-to-scalar
   masking, incorrect stride/index, or reliance on source names/sidecars.
2. Retire the destructive byte-fill body replacement once the generic path
   passes; retain its important behavior in typed contracts and tests. If a
   presentation transform is still needed, splice only a proven region and
   preserve unrelated statements. Reason: loop recognition does not prove
   whole-function equivalence. DoD: save/restore, calls, memory effects and
   returns survive; unknown or mixed region ownership refuses transformation.
   Failure: whole-body substitution, a late semantic repair, or deletion of
   machine-state effects to make the output resemble the original source.
3. Close the real function and fixture acceptance. Reason: the probe proves
   the dependency, not a repair. DoD: focused corruption controls; normal CLI
   validation=passed with clean whole-tail validation; correct byte stores and
   argument classes; strict generated-C compilation; MS C original/rebuilt
   execution agrees; routine gates include the regressions. Failure: treating
   worker exit zero or a passing narrow shape test as function acceptance.

The original C is an oracle only. Regression cases must include signed count
zero/negative bounds, byte width, unrelated effects, and unknown/mixed evidence.
Keep the GP invariant and function-parameter gate enabled throughout.

## Reproduction Artifacts

Normal command:

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 INERTIA_DEBUG_GP_STACK_RESTORE=1 \
  ./decompile.py examples/build_msc6_tiny/pointer_memory/POINT.EXE \
  --proc fill_bytes --timeout 90 --no-alternate-source-c
```

Logs under /home/xor/.cache: fill-bytes-before.c/.log,
fill-bytes-probe.c/.log, fill-bytes-probe-worker.json,
fill-bytes-no-idiom.c/.log and fill-bytes-no-idiom-worker.json. The temporary
probe overrides a callback only in its own process and uses a fresh decompiler
cache namespace; no production patch was applied. All diagnostic sessions
finished. No broad tests were rerun during these read-only investigations.

Graph generation was stale (2026-08-27); current source and actual worker stack
traces established the producer/consumer chain. This is not an exhaustive
audit of the other pointer-memory idiom callbacks.

## Indexed Base Repair Checkpoint

2026-09-12, implementation/acceptance observed through 15:53 +02:00.
The generic indexed-access failure was reproduced independently of the legacy
callback: its address contained a BX value plus the low word of runtime SI.
The near-pointer fact identified an argument load but discarded the carrier
register. Lowering selected the first syntactically available C variable as
the base, substituted the canonical pointer for BX and retained SI as index.

The decoded-evidence owner now retains the current carrier register name and
an explicit exact-value flag. Register copies retain that state. ADD preserves
pointer-use classification but invalidates exact loaded-value identity;
subsequent copies keep that uncertainty. Missing decoder metadata is not proof.
The existing stack-source version and update evidence remain separate.

The new Types/Lowering owner near_pointer_index_binding.py consumes a unique
instruction-matched, unchanged byte-pointer carrier and canonical argument
storage. It preserves the other addend as the index regardless of operand
order. Missing, changed, mismatched or source-version-shifted evidence refuses
substitution. The indexed provenance fallback no longer substitutes an
arbitrary unrelated register for the pointer base. No body replacement or
late semantic repair was added.

Fail-first evidence: five carrier metadata cases and both indexed operand
orders failed before their respective repairs. Final focused surface: 279
passed in 16.32s, including existing segmented-runtime tests and corruption
controls. The new module/tests pass Ruff --fix; scoped MyPy passes all three
production owners. Existing numeric/complexity lint debt remains in the older
owners. Make typing/lint lists, architecture promotion, ownership and routine
test selection include the new module/tests. Full architecture, context and
ownership gates pass after fixing the header/promotion enrollment omissions.

The isolated callback-disabled real function now retains v11 = i followed by
dst[v11], with all SI/DI saves and restores. It still reports validation_failed:
the final parameter gate sees a pointer/value mismatch, and the saved partial
output still has a word-pointer interface and a pointer inside a runtime GP
mask. Capture the exact interface and coordinate projection at the failing
validation boundary next; a stale prototype publisher is a hypothesis, not a
proven cause. Do not suppress the parameter gate or retire the callback before
this generic path validates and compiles.

Fresh combined run: 268 preliminary passes (20.20s), then 4,663 passed / the
same three SORTD failures (358.12s). QuickC passes; MS C remains 5/7, with
loops_jumps and pointer_memory failing. Lane times: 358.735s, 64.339s and
172.079s respectively. Cache conditions were not controlled for performance
comparison. quality-fast remains red at global linters; compiled-import smoke
passes for 39 modules. The full collection and expanded gate were not refreshed.
Step 9 and fill_bytes remain open.

Logs under /home/xor/.cache: pointer-carrier-{before,after,ruff,mypy}.log,
pointer-index-{before,after,focused,ruff,mypy,quality,pipeline}.log,
pointer-index-gates-final.log, and fill-bytes-bound-worker.json/.c/.log
(the latter output/log filenames are fill-bytes-bound.c and .log).

## Generic Fill Function Acceptance

2026-09-12 follow-up, observed 15:54-16:15 +02:00 before the final broad wait.
The final parameter probe ruled out a coordinate error: entry-SP offsets
2/4/6 correctly projected to machine-BP offsets 4/6/8. At the failing boundary,
both the first C argument and its prototype entry were scalar words.

The exact promotion probe then demonstrated a split representation: the live
codegen interface became char*, but the authoritative prototype snapshot was
still scalar. Near-pointer promotion now publishes through the existing
authoritative-function-prototype API after updating the codegen/function
surfaces. Both operand-order tests failed on the stale snapshot before this
change and pass afterward. The related segmented-runtime surface passed 254
tests in 24.42s.

With that repaired, Structuring and Postprocess validation passed, but the
mandatory compiler check rejected a pointer in the runtime SI integer mask.
The GP write owner now consumes the existing project_pointer_storage_value
helper before integer writes/masks. Narrow writes project a guest offset word;
full-register writes use the existing dword projection. Scalar values and
upper-bit preservation keep their existing behavior. Five pointer-write cases
failed first (AL, AH, SI, EAX, EDI); the GP surface then passed 31 tests in
21.64s. No new rendered-text conversion or runtime helper was introduced.

The destructive byte-fill callback was removed from both production dispatch
paths, its callback contract and postprocess implementation. The old counted
projection normalizer remains compatibility coverage, not a producer that can
replace a function. No other pointer-memory callback was silently disabled.
The retirement/index/GP focused surface passed 24 tests in 25.84s.

Normal CLI acceptance, with no monkeypatch or callback override: exit zero,
validation=passed, clean whole-tail validation, and independent strict GCC
syntax checking passed. The original source remains an oracle only. The C
keeps the induction index, one-byte stores and all saved SI/DI bytes/restores.
It has no required source-call loss (the original fill body has no calls).
Legacy harmless declaration/naming noise remains; that is not hidden as a
semantic improvement.

The emitted C also passes the new compiled behavior oracle with UBSan: counts
-32768, -1, 0, 1, 8, 127, 256 and 32767; values 0, 3, 127, 128, 255, 511 and
65535; every untouched byte including boundary canaries; and preservation of
both SI/DI runtime lanes. Four corrupted controls (fixed index, extra write,
wrong byte value, lost GP state) are rejected. Oracle tests: five passed in
3.95s. Both new test modules are enrolled in the routine pipeline and Make/
ownership lists. This host behavior proof is not a successful whole MS C
fixture roundtrip.

The targeted pointer_memory MS C run confirms fill_bytes exit zero with clean
validation, but sum_words exits 4 at the GP restore invariant. The whole
fixture therefore remains failed before rebuilt execution. Trace its producer
and generic path next rather than weakening the invariant or restoring the
retired byte-fill callback.

Scoped MyPy passes with the actual register-live-in dependency included;
follow_imports=skip alone otherwise exposes its return as Any. New tests pass
Ruff --fix. Older owners retain visible lint debt. Full architecture, context
and ownership checks pass. quality-fast remains red at global linters, while
compiled-import smoke passes for 39 modules. No full-suite or Step 9 completion
is claimed; the final combined run is recorded separately when terminal.

Additional logs under /home/xor/.cache: pointer-publication-{before,after,ruff,
mypy}.log; gp-pointer-{before,after,ruff,mypy}.log;
pointer-retirement-{focused,mypy,quality,pipeline}.log;
pointer-retirement-gates-final.log; pointer-fill-behavior-tests.log;
pointer-memory-roundtrip.log; and fill-bytes-final.c/.log. The isolated
fill-bytes-{parameters,publication,published,gp,pointer-word}-worker.json
artifacts distinguish validation, compilation and transport outcomes.

Final combined checkpoint observed at 16:25 +02:00: 268 preliminary tests
passed in 23.18s; the curated pytest lane finished with 4,673 passes and the
same three SORTD failures in 381.57s. QuickC passes; MS C remains 5/7, with
loops_jumps and pointer_memory failed. Lane wall times were 383.348s, 71.468s
and 141.196s. No full-collection claim or controlled speed comparison follows
from these figures. Slowest tests: RunMenu 143.37s, InitMenu 137.36s, InitBars
103.66s. No execution sessions remain live at this checkpoint.
