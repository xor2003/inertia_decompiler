# Scalar Return Value Capture (2026-09-09)

## Root Cause And Repair

ReturnMaker's compatibility hook found an earlier AX producer, expanded its
temporaries/register dependencies, and moved that expression to RET. That is
not a valid substitution when its inputs change in between. In the minimal
frame reproducer, `AX = BP - 2` preceded BP restoration. The generated return
used restored BP instead of the value already held in AX.

The frontend/angr compatibility boundary now emits a read of the actual scalar
return register at RET. Native SSA owns binding and propagation of its value.
Producer evidence still controls whether an inferred return should exist;
known, ignored and unknown caller-observation decisions remain unchanged.
The same rule applies to constants: a later partial-register write can
invalidate an earlier constant-producing full-register assignment.

- Reason: preserve value lifetimes before SSA rather than repair incorrect C.
- DoD: scalar return construction reads the correct architectural register at
  RET, retaining its width and instruction provenance; BP restoration, partial
  register writes and memory mutations cannot change an earlier captured value;
  existing literal-return semantics and routine pipelines remain valid.
- Definition of failure: move state-dependent producer expressions to RET,
  accept a stale full-register constant after a partial write, invent a return
  without the existing evidence/prototype decision, weaken validation, or
  patch rendered C.

Three BP-restoration cases fail before the repair. The expanded focused module
passes **10 tests**, seven dependency warnings, 8.66s. The existing literal-75
test now checks an AX capture backed by the unchanged AX assignment, rather
than requiring premature constant inlining. The module is admitted to routine
Make/pipeline selection. Existing source-finder APIs remain available to their
other evidence consumers; they are no longer used as scalar return expressions
at this transport boundary. Combined-register return construction is not
covered by this scalar repair and still needs a separate lifetime audit.

## Live Diagnostic And Remaining Work

With the still-process-local numeric-use propagation experiment, the minimal
body now stores the numeric value and returns that same C variable:

```c
inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
v8 = 0xfffe + (inertia_esp & 0xffff);
SEG_U16(inertia_ds, 0x200) = v8;
return v8;
```

The previous return through a host-address-derived frame-memory read is gone
in this diagnostic. This does not prove the complete guest frame ABI: runtime
SP lifetime and frame entry/exit effects still require coherent handling.
The experimental propagation filter is NOT installed. InitMenu and the broad
full-suite/CI goal remain open until executable acceptance proves otherwise.

Scoped Ruff `--fix` and MyPy pass. Pyright passes with the project interpreter
explicitly selected via `--pythonpath .venv/bin/python`. Without it, this
checkout's Pyright resolves an incompatible Register constructor signature;
the same source then reports a spurious missing-argument error. No type ignore
or constructor cast was added to conceal that environment mismatch.

The combined `quality-hard quality-dev quality-fast test-pipeline` invocation
completed with exit 0. Fast and default unit lanes each passed 2,933 tests
(142.15s and 126.77s respectively); three executable quality guards and all
seven MS C tiny compile/decompile/recompile/run cases passed. This is curated
pipeline evidence, not a green full-suite or remote-CI claim.

Whole-executable verification rejected this checkpoint: the exact default
SORTDEMO command accepted **18/20**, versus 19/20 at `c7fe4e0c0`.
It exited 2 after 219.72s (561.47s user, 9.87s system, peak process RSS
403,560 KiB). DrawBar `0x106c8` is newly rejected: the primary attempt reports
stack-local call-argument dependency mismatches during widening copy
propagation; retries report an unexpected return for a proven-empty result
and GCC rejecting a void-valued return. InitMenu remains rejected.
PercolateDown and QuickSort still pass. This patch is therefore NOT ready to
land, despite green curated gates. Investigate the return/stack-value boundary
and add executable regression coverage before claiming acceptance.
Evidence: `/tmp/inertia-sortdemo-return-capture.{c,log}`; run completed around
12:54 local. Do not suppress these failures or treat a clean aggregate tail
summary as acceptance when individual functions were rejected.

## Width-Aware Output Follow-Up (Open)

Most target code uses only 16-bit registers; mixed 16/32-bit code must remain
supported. Reason: upper-register preservation should not clutter generated C
when those bits are proven unobservable. IR register effects/liveness must
provide the proof, and lowering must consume it; the frontend must retain
correct partial-register execution semantics. DoD: proven 16-bit-only uses
lower to word-valued operations, SP arithmetic still wraps at 16 bits, and
mixed-width reads plus call/return boundaries preserve all observable bits.
Tests must cover both simplification and refusal when upper-bit liveness is
unknown. Failure: infer safety merely from absent 32-bit instructions, erase
unknown call effects, drop wraparound, or repair rendered C with patterns.
This is not implemented by the scalar-return repair.

Stack-address size is independent of operand size. For an ordinary real-mode
16-bit stack, a 32-bit PUSH/POP operand changes SP by four, not the stack-address
width. Lowering should represent that as a word-sized SP update, not infer an
ESP merge from 32-bit operand use. Explicit wider-register observations still
require coherent overlapping state. Include this distinction in acceptance
tests; do not change the existing byte-safe frontend execution helpers.

The existing sidecar-free DrawBar executable regression reproduces the new
failure in 18.37s (one failed, seven dependency warnings):
`test_sortd_drawbar_sidecar_free_materializes_stack_buffer_and_conservative_return`.
It reports BP-0x2e instead of BP-0x2c argument dependencies and the empty-result
return contract violation. Reuse this focused loop rather than repeatedly
running all 20 functions. Log: `/tmp/inertia-return-drawbar-focused.log`.

The debug repeat confirms ReturnMaker enters the guessed-prototype,
caller-return-unused branch for DrawBar (`SimTypeShort`, empty incoming return
list). Capturing AX there ultimately exposes a returned void `outtext` call.
Investigate whether the existing producer-evidence decision incorrectly treats
incidental terminal AX state as a value return; caller non-observation alone
is not proof of a void return. Do not restore unsafe expression transport or
delete the call in lowering to silence the failure. The primary stack offset
mismatch also remains an independent acceptance obligation.
Debug evidence: `/tmp/inertia-return-drawbar-debug.log`.

## Call-Barrier Follow-Up

Terminal producer evidence crossed a later call. The source finder and its
predecessor path now refuse across side-effect statements and direct calls,
including assignment-wrapped calls. This does not infer void from caller
non-observation; it refuses the stale producer proof. Prototype-driven scalar
return capture remains in place.

The new intervening-call regression failed before the guard (one failed,
10 passed, 8.42s). Afterward it and the existing sidecar-free DrawBar regression
pass: **12 passed**, seven dependency warnings, 19.97s; DrawBar itself took
11.81s. Ruff `--fix`, scoped MyPy and interpreter-selected Pyright pass.
The executable test retains its stack-buffer, call-argument, recompilation and
tail-validation assertions. Logs: `/tmp/inertia-return-call-barrier-{before,after}.log`.
The preceding 18/20 result is historical evidence from before this guard;
broader gates and the whole executable must be rerun before landing. Additional
call shapes and predecessor/current-block boundaries still need focused audit.

Expanded call-form coverage now checks direct, side-effect-wrapped and
assignment-wrapped intervening calls: 13 unit cases pass in 8.52s. The
assignment fixture writes DX, not AX, to distinguish a stale AX producer from
a new definition of the return register. The first AX-assignment fixture had
the wrong refusal expectation and was corrected, not used to change production
semantics.

The post-guard combined hard/dev/fast/default run completed with exit 0:
2,936 tests per unit lane (126.32s fast, 114.93s default), three executable
quality guards, seven MS C tiny round trips and the pipeline's three selected
final checks. Log: `/tmp/inertia-return-call-barrier-gates.log`.

Final default executable run after the guard: **19/20 accepted**, exit 2,
191.08s wall, 443.03s user, 8.35s system, peak process RSS 356,040 KiB.
DrawBar, PercolateDown and QuickSort pass; InitMenu remains rejected.
Generated C is byte-identical to `c7fe4e0c0`:
`e3f8970e13403ace02bb95f77c2c20cf5bfeac6ea81a723020411c6518fc3936`.
Evidence: `/tmp/inertia-sortdemo-call-barrier.{c,log}`; completion 13:14:08 local.
This verifies the repaired checkpoint, not InitMenu, a green full suite, or
whole-plan completion. Timing is a single verification run, not a speedup claim.

## Next Boundary: Numeric Stack Values

Rechecked after `27ee6a67c`: the minimal binary without the process-local filter
still emits `g_200 = &v0`, `g_201 = &v0 >> 8`, and `return &v0`. With the
diagnostic filter, it emits a word-valued guest offset stored through
`SEG_U16(inertia_ds, 0x200)` and returns the same variable. The diagnostic reports
294 numeric replacements refused and six address uses retained. Neither result
proves the complete frame ABI; the filter remains uninstalled.

The current upstream `SPropagator._analyze` uses stack-tracker offsets to replace
SP/BP virtual-variable uses with `StackBaseOffset` without distinguishing numeric
from address use. Owned `stack_compat.py` currently normalizes replacement
widths only. This frontend adapter is the next repair boundary: preserve numeric
register values rather than introducing host-object address meaning. Alias
continues to own storage identity; do not move recovery into C cleanup.
Before integration, cover mixed address/value uses, load/store guards and data,
call/return operands, absent location evidence and cross-block definitions.
Logs: `/tmp/inertia-frame-production-current.log` and
`/tmp/inertia-frame-context-current.log`.

Candidate implementation now connects `StackValueUse8616` classification to
the owned propagator adapter. Numeric, mixed and absent-location uses retain
their SSA values; address-only uses retain width normalization. Native AIL
visitor composition keeps call operands from inheriting an enclosing address
role. The minimal production probe now emits a word-valued store and return
without the diagnostic monkeypatch (`/tmp/inertia-frame-use-filter-live.log`).
This candidate is uncommitted and not yet accepted against InitMenu or broader
gates. Nineteen focused tests pass (8.96s), including integrated replacement
filtering; the module is already in the routine pipeline. Scoped Ruff, MyPy and
interpreter-selected Pyright pass. Remaining coverage includes guarded loads,
stores, cross-block definitions and opaque/unsupported AIL shapes, followed by
the whole-frame ABI obligation. Do not claim InitMenu fixed from this probe.

Expanded focused coverage: 28 tests pass in 8.25s, including load/store guards,
load alternatives, definition-only occurrences, and graph/block lookup modes.
The sidecar-disabled InitMenu run takes 44.89s and still exits 4. Its reported
compile blocker is now `(char)local_2 = inertia_ebp & 0xffff`, not pointer/integer
arithmetic. It also retains extensive frame-register bookkeeping. Evidence:
`/tmp/inertia-initmenu-stack-use.{c,log}`.

The candidate FAILS the fast quality gate: **2 failed, 2,954 passed**, eight
warnings, 126.77s. InitBars fails GCC on a casted assignment target; RunMenu
fails its assertion that the final body contains no `inertia_esp`, not its ESC
branch assertions. Log: `/tmp/inertia-stack-use-quality-fast.log`.
Do not land this candidate or describe it as accepted. Investigate transitive
SSA use roles: classifying only the immediate assignment treats an intermediate
address computation as a numeric escape even when its eventual use is solely a
memory address. This is a next-step hypothesis requiring a reproducer, not a
license to delete frame state or strip lvalue casts. Frame storage/entry-exit
identity remains a separate acceptance obligation.

Bounded InitBars refusal tracing confirms two different classes, not just
address temporaries. Refused assignments include `t1 = SP` and SP-derived
intermediate values, but refused STORE data also includes both bytes of the
incoming BP saved by PUSH BP. Those saved bytes are genuine numeric values;
replacing them with a stack-object address would be wrong even in ordinary
compiler frames. Transitive address-use classification alone cannot justify
discarding those stores. Follow the saved-BP storage identity into frame
lowering alongside the intermediate-use investigation. The diagnostic changes
no recovery behavior and still exits 4. Evidence:
`/tmp/inertia-initbars-refusals.{c,log}`; script is temporary and untracked.

Mutation tracing located the casted assignment target in
`lower_stable_ss_linear_stack_dereferences_8616`: it consumed a byte-read
projection while replacing an assignment LHS. Its existing stack materializer
already exposes `require_lvalue`; the candidate now passes that contract from
assignment targets. Unsupported partial write projections retain the original
memory store rather than become a casted variable. No rendered-C repair is used.
Two focused role tests cover reads and writes, alongside the existing cast
tests. Combined stack-use/write tests: **32 passed**, seven dependency warnings,
9.55s. Scoped Ruff, MyPy and interpreter-selected Pyright pass.

This does NOT resolve executable acceptance. InitBars now fails uninitialized
stack-array reads instead of the lvalue syntax check. InitMenu's fresh run exits
4 after 32.87s (30.84s user, 0.57s system, peak process RSS 356,804 KiB), reporting
the missing SS:BP-0x12 16-byte object in storage-identity validation. These
reports require storage/frame investigation, not relaxed validation.
Evidence: `/tmp/inertia-initbars-cast-mutation.log`,
`/tmp/inertia-stack-write-live.log`, `/tmp/inertia-stack-use-write-focused.log`,
and `/tmp/inertia-initmenu-stack-write.{c,log}`. Candidate remains uncommitted.

Write-refusal tracing additionally found a requested write at BP-1 matched to
LOAD evidence. The range selector did not filter by access kind. It now accepts
an optional typed kind, and the lowering consumer supplies STORE for assignment
targets and LOAD for reads. Both new tests failed before the filter (8.32s): a
LOAD won over a matching STORE, and load-only evidence satisfied a write query.
After the filter, 42 focused tests pass in 11.06s; Ruff and scoped MyPy/Pyright
pass. The index tests were already in Make and are now explicitly admitted to
the scripted routine pipeline too.

This closes the selector role mismatch, not partial-byte write materialization
or frame ownership. The refused access trace includes BP-2/BP-1 byte writes
inside a two-byte owner, which still require a correct writable projection or
preservation of the original memory operation. Evidence:
`/tmp/inertia-initmenu-write-refusals.log`,
`/tmp/inertia-stack-access-role-{before,after}.log`.

The post-role-filter executable check still fails both InitBars and RunMenu
(45.53s, seven dependency warnings). InitBars' log explicitly records ten
instruction-access materialization failures before the final uninitialized-array
diagnostic. Its partially processed body already contains an initialization
loop, so do not assume the final array diagnostic identifies the first defect.
Complete the earlier byte-write materialization before evaluating downstream
condition/array checks. Evidence: `/tmp/inertia-stack-role-executable-check.log`.
A scalar masked read-modify-write is not automatically a valid replacement for
a byte store: it may introduce an uninitialized read of the other byte. Preserve
the exact byte-write effect and do not read untouched storage solely to update it.

### Exact byte-write candidate

Types/Lowering now projects an Alias-owned word's byte as a writable unsigned
character view. It does not cast an assignment target to an integer or read
the untouched byte. Partial host-pointer writes remain refused. The contract
uses the existing little-endian C storage layout, not cross-endian portability.
Six GCC compile/run cases cover both lanes and initialization by two byte stores
for signed and unsigned words; three out-of-owner ranges and one pointer refusal
complete the ten passing tests (9.08s, seven dependency warnings).

The paired executable regressions now report one passed (InitBars), one failed
(RunMenu), 45.13s. The remaining failure is RunMenu's no-raw-ESP assertion; its
later ESC assertions were not executed. Do not infer their success from this run.
A fresh sidecar-disabled `SORTDEMO.EXE --addr 0x10060` run exits 0 with
`validation=passed` and clean whole-tail validation: wall 41.85s, user 40.49s,
system 0.62s, peak process RSS 332,780 KiB. InitMenu retains the expected drawing,
text, string-copy, formatting and pause-condition operations, but exposes raw
SP/BP updates without an obvious matching frame restore. This is not yet a
closed frame ABI or full function acceptance. Do not delete those effects to
satisfy the no-ESP check without liveness and call-boundary proof.

Evidence: `/tmp/inertia-stack-byte-executable.log`,
`/tmp/inertia-stack-byte-boundaries.log`,
`/tmp/inertia-initmenu-byte-write.{c,log}`.
The fast-gate rerun terminates with **1 failed, 2,977 passed**, seven dependency
warnings, 115.84s for its pytest lane. The only failure is RunMenu's no-raw-ESP
assertion. The preceding configured linter/startup checks completed, but
`make quality-fast` exits 2. Evidence:
`/tmp/inertia-stack-byte-quality-fast.log`. Do not run or claim the default
pipeline green while this prerequisite remains red.

The existing isolated InitMenu regression
`test_sortd_initmenu_sidecar_free_preserves_calls_and_compiles` also passes:
one passed, seven dependency warnings, 41.98s (33.49s test call). It checks clean
tail validation, portable-flat compilation, the expected call counts and
argument classes, stack-array ownership, and pause division. Evidence:
`/tmp/inertia-initmenu-byte-regression.log`. This does not override the open raw
frame-state obligation or establish whole-binary acceptance.

### Runtime call-frame external-use guard

RunMenu's numeric propagation trace includes SP phi inputs, temporary copies,
SP/BP assignments and saved incoming-BP bytes. Immediate operand-role checks
cannot prove these transitive chains address-only. Re-enabling all scalar
StackBaseOffset substitutions would revive the numeric-offset/host-pointer bug.
Evidence: `/tmp/inertia-runmenu-stack-refusals.{c,log}`.

A separate correctness gap was found in the existing call-frame consumer:
virtual SSA carriers required closed uses, but runtime ESP carriers needed only
an adjacent consumed call. Six regressions proved it deleted an SP write despite
external 16/32-bit observations in a call argument, a later assignment, or a
branch. Types/Lowering now refuses consumption when another runtime ESP view
exists outside the candidate statement. This intentionally conservative check
does not infer mutable-register lifetimes or treat another write as a kill.
Before: six failed, nine passed, 8.12s. After: fifteen passed, 8.23s. Scoped
Ruff/MyPy/Pyright pass. The existing Make-admitted module is now also in the
scripted routine lane. Logs: `/tmp/inertia-runtime-frame-use-{before,after}.log`.
This repairs unsafe deletion, not RunMenu's retained frame state. The next proof
must distinguish transitive address-only uses from numeric escapes and cover
restoration and call boundaries before consuming the whole frame group.

After this guard and routine admission, `make quality-fast` reports 2,992 passed,
one failed, seven dependency warnings, 135.57s in pytest. RunMenu's no-raw-ESP
assertion remains the sole failure; InitBars passes. Pre-test configured checks
complete, but Make exits 2. Log: `/tmp/inertia-runtime-frame-quality-fast.log`.
Native SPropagator source also confirms that SP/BP tracker substitutions use the
use-instruction address: future transitive propagation must prove exact SSA
value lifetime, not just find a downstream address operand.

The propagation caller also ignored `REFUSED_WIDENING`: it left an unsafe
16-bit replacement installed for a 32-bit SP/ESP SSA value. The caller now
removes that mapping instead of merely recording failure. Integrated block and
function-mode cases fail before (2 failed, 34 passed, 8.11s) and pass after
(36 passed, 9.13s); scoped Ruff/MyPy/Pyright pass. Evidence:
`/tmp/inertia-stack-width-refusal-{before,after}.log`. The existing routine test
module covers both widths. This is not transitive address-only proof and does
not remove RunMenu's raw ESP bookkeeping.

Evidence in `/tmp`: `inertia-return-register-probe.log`,
`inertia-return-capture-before.log`, `inertia-return-capture-focused.log`,
`inertia-return-capture-context.log`, and `inertia-return-capture-pyright-venv.log`.
Observed timestamps from newly created log files: diagnostic start 12:32:47,
failing-before tests 12:34:59, broad verification start 12:38:57 local.
These exclude the preceding source investigation and are not a full active-work total.
