# Stability-First Execution

User priority, September 20: decompilation stability, then correctness, then
the remaining agreed plan. This changes execution order, not the promised
Ghidra/Reko features or the full Steps 10-12 completion requirements.
Current milestone scope is defined in the [compiler coverage plan](compiler-coverage-plan.md#objective-and-limits):
unpacked 16-bit real-mode C application functions; unpacking and recognized
library bodies are excluded, while library-call semantics remain required.

Latest explicit direction: defer new Ghidra/Reko parity features until stability
work is accepted. Preserve those tasks as deferred, not completed or cancelled.
Finishing the previous Ghidra/Reko parity plan remains a low-priority task after
the current stability/correctness milestone, not a prerequisite for it.
Known incorrect output remains blocking even when decompilation does not crash.
User reaffirmed this order: stability first, correctness next, remaining planned
features last. Keep the existing repair cohort and work one slice at a time.
The revised compiler-coverage plan permits a reusable test-runner slice after
the current small repair checkpoint, without waiting for every corpus failure.

Current carrier-repair routine pytest lane: 6,231 passed, eight failed in
834.96 seconds (`.cache/mcb-carrier-test-pipeline.log`). Seven failures report
timeouts; their causes are not yet established. The eighth is `_dos_envSize`
GP stack-restore materialization, within the active repair cohort. These are
routine-selection results, not a full approximately 11,000-test audit. The
completed pipeline failed overall: two external compiler lanes passed and the
routine pytest lane failed. The preceding 268 contract tests passed. Preserve
these failures; do not label the full suite green or raise timeouts without
diagnosing their causes.

The isolated `_dos_envSize` regression was reproduced before the fix. Alias
proves BX=0 restored by LES at 0x1023 from entry-SP bytes -6/-5; its memory use
was folded, leaving only the ES publication at that instruction. Lowering now
publishes the proven constant GP effect beside one unambiguous pure segment
anchor, preserving the upper register half. Replay recognizes the equivalent
`EBX & 0xffff0000` zero-word write after simplification. Unknown constants,
conflicting effects, wrong registers/masks and ambiguous placement refuse.
Expanded focused result: 124 passed in 43.90 seconds; the live function passes
validation, generated-C compilation and behavior (16.31-second test call).
New-helper Ruff and MyPy pass; tests are enrolled in Make and the routine lane.
Evidence: `.cache/constant-restore-expanded-tests.log`. Broad acceptance remains
open; this does not close the other DOSFUNC failures or the full-suite audit.
`quality-fast` finished with exit 2 on global Ruff debt; its compiled-import
smoke passed 39 modules (`.cache/constant-restore-quality-fast.log`).

The call-carrier replay regression failed before the focused Lowering change
and passed after it (14 tests); it now recognizes the existing unsigned-word
call/copy pair by storage identity and exact callsite instead of rebuilding it.
New-helper Ruff/MyPy pass; legacy `real_mode_linear.py` retains lint debt.
`_dos_mcbInfo` still times out at the unchanged 30-second limit. A diagnostic
90-second run ended with exit 4, not success: final GP restore refusal, an ESI
validation delta and two underspecified `sprintf` calls remain. At those calls,
COD assembly preserves two outer arguments across `strlen` and its two-byte
cleanup before pushing the final argument; recovery reports one argument.
Investigate generic pending-argument preservation across nested calls, not
library-name-specific argument reconstruction. Artifacts:
`.cache/call-bridge-replay-before.log`, `.cache/call-bridge-replay-after.log`,
`.cache/mcbinfo-replay-diagnostic.log`. No function or cohort closure is claimed.

Bounded follow-up: [DOS compiler coverage plan](compiler-coverage-plan.md)
defines the ordered manifest, behavioral oracle, interaction coverage,
budgeted generation/reduction and routine gate, with per-step DoD and failure
criteria. Its revised order delivers a reused four-case runner first, after
the current small repair checkpoint, without opening a parallel workstream.

Future bounded correctness input: the user confirms their
[Csmith fork](https://github.com/xor2003/csmith) supports MS C's 16-bit integer
model. Reuse it after the current repair is accepted, without making generator
integration another prerequisite. Compare compiled original and recompiled
decompiler output under kvikdos; preserve seeds and minimize failures into
deterministic regressions. Random exploration belongs in an optional bounded
lane, not an unbounded default gate.

New bounded diagnostic: [linked selector/offset read](segcopy-stability-probe.md).
Original MS C 6/kvikdos execution passes; decompilation loses a load and is
correctly rejected. Track this after the active stack-restore repair, without
counting it as a passing routine fixture or reopening unrelated parity work.
Use `/home/xor/nndecomp/msex` and `/home/xor/nndecomp` as additional sources for
small buildable examples. Do not turn this into porting entire games.

## Scope Control

- Finish the in-flight call-placement repair and its gates before new work.
- One active defect or gate implementation at a time. No speculative refactors,
  new profiling campaign or parallel feature agents.
- Each repair has a frozen reproducer set and an explicit acceptance checkpoint.
  Stop at that checkpoint; report remaining failures separately rather than
  silently enlarging the repair. Correctness blockers discovered in the changed
  behavior still block acceptance. Do not promise a whole-plan completion date
  from a small passing subset.
- Freeze each acceptance cohort before fixing its failures. Do not replace
  failing fixtures with easier ones or count exclusions as successes.
- Newly discovered unrelated issues go to a backlog with a reproducer and
  severity. Only blockers of the frozen acceptance contract enter that unit.
- Close a repair when its failure reproduces before, its positive/negative
  regressions pass after, and required validation/compilation/behavior gates
  pass. Do not reopen it for unrelated readability or architecture cleanup.
- Run focused checks during development and the existing required broad gates
  at semantic checkpoints. Reuse unchanged-source evidence, keep full logs on
  disk, and report compact failures/counts. Do not repeat rejected experiments.

## Priority And Exit Conditions

| Priority | Work | Reason | Definition of Done | Definition of Failure |
| --- | --- | --- | --- | --- |
| P0 | Finish current call-placement repair | Stop invented calls and conditional-call movement without regressing SORTD | 20/20 SORTD validation, compilation, behavior, focused negative tests and routine pipeline accepted; lint limitations explicit | Any lost/extra call, validation failure, or regression hidden as a successful fallback |
| P0 | Scan every COD file and inventoried function in resumable batches | Find real stability failures beyond SORTD without an unbounded single run | Frozen inventory with one explicit outcome per function; production decompilation status/C coverage/validation/compilation/time reported; ranked reproducible failure list; no silent omissions | An unattempted or failed case counted as passed, lost work on restart, or unresolved object relocations blamed on the decompiler |
| P1 | Repair individual bad functions from that report | The original C and generated assembly provide paired correctness evidence | Before/after C compared against both source and assembly; behavioral checks for relevant returns, writes and branches; deliberately corrupted controls fail | Token matching or syntax-only checks reported as equivalence, or original C copied into the output |
| P2 | Resume the original remaining Tasks 5 and 7.1-7.4 | Deliver agreed readability and Ghidra/Reko parity features | Their original DoD passes within the frozen SORTD scope, preserving the P0/P1 gates | Feature closure based only on an audit, or a stability/correctness regression |
| P2 | Bounded Step 10 measurements | Verify usable runtime after semantic work settles | Existing warmup/repeat protocol and acceptance met; optimize only a measured material bottleneck | Another speculative optimization project, changed semantics, or weaker tests to improve timings |

P0 does not authorize incorrect output: known semantic failures remain blocking.
P1 adds stronger oracles; it does not postpone an already demonstrated wrong
result. Every new case must distinguish successful decompilation, validation,
compilation and behavioral verification, rather than conflating them.

## Whole-Corpus Scan, Individual Repairs

Latest batch: [32-function triage](cod-stability-32-function-triage.md).
Thirteen CLI successes, 19 failures, 400 pending; the next bounded correctness
cohort is the two process-ID wrappers with non-void fallthrough output.
That cohort was subsequently identified as empty source stubs; the
[signature-boundary repair](cod-process-id-signature-repair.md) removes the
late name-based rewrite. Both now validate and compile; the routine pipeline
passed, and newly enrolled focused cases passed separately (see report scope).

The next frozen cohort is the three GP stack-restore refusals. See
[the investigation and refusal-state repair](cod-stack-restore-refusal.md).
Refusal-state protection alone did not accept those functions. Constant-value
proof and exact segmented-load origin projection now get `_dos_envSize` through
validation, compilation and controlled-memory execution. Widening retains
bytewise reads when a typed register-relative offset can wrap at FFFFh. The new
19-test coverage is enrolled in the routine pipeline. Focused checks pass;
the preceding broad run had 6,180 passes and three timeouts, with contract and
MS C tiny-example lanes passing. Read-position and byte-width guards were added
after that run; final broad acceptance remains pending. The other two restore
failures remain open; no whole-cohort or
linked-DOS behavioral equivalence is claimed.

Targeted timeout recheck: InBoxLng passes, while loadprog and SetGear still
time out. Track these as open gate failures; do not dismiss them as contention
without an isolated measurement. Global quality-fast still reports lint debt.

The new `scripts/cod_stability_sweep.py` provides durable per-procedure CLI
attempts, source/code/settings fingerprints, artifact hashes, process-tree
timeouts and bounded workers. Example (run only one writer per output directory):

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python scripts/cod_stability_sweep.py \
  cod .cache/cod-stability-current --limit 8 --workers 2
```

Repeat to attempt the next batch; `--limit 0` attempts all pending procedures.
Completed failures are retained, not retried silently. Changed code or inputs
require a new output directory. Exit 1 means a recorded failure; exit 2 means
pending work without recorded failures. Exit zero only means all CLI attempts
completed successfully, not semantic/compilation acceptance. Structured tail
evidence remains in each stderr artifact and is now copied into each attempt's
typed validation record independently of CLI exit status. Missing, malformed,
wrong-function and multiple reports cannot become passed evidence. Compilation
checks remain pending runner work. No default full-corpus test is added to
the fast development loop.

Initial four-attempt artifact: `.cache/cod-stability-20260920/summary.json`.
Two CLI attempts succeeded (`_bios_clearkeyflags`, `_dos_free`); `_dos_resize`
returned 4 with failed validation, and `_dos_alloc` returned 3 after a 30-second
segmented-memory-reasoning timeout. 428 procedures remain pending. The runner
was subsequently given its missing constant annotation, so this initial
manifest deliberately refuses resume with the changed runner source. Retain it
as historical evidence; use a new directory for the final runner revision.
Nine runner tests passed in 9.58 seconds, including corrupted-artifact refusal
and durable failure/timeout records. Ruff, focused mypy, types/docs and ownership
manifest checks passed. No whole-project green claim is made.

All COD files here are compiler listings for object files, not linked binaries.
Current post-portability checkpoint: `.cache/cod-stability-portability-checkpoint/`
pins the current runner/input/code manifest. Eight attempts completed with six
`cli_ok_unverified`, two failures and 424 pending. Successful CLI attempts:
`_bios_clearkeyflags`, `_dos_free`, `_dos_getfree`, `_dos_loadOverlay`,
`_dos_runProgram`, and `loadprog`. These are normalized fixture outcomes, not
original linked-program equivalence or a whole-corpus pass.

Failure triage for this checkpoint:

- `_dos_resize`: exit 4 after 15.36 seconds. Whole-tail validation is clean;
  the blocking failure is portable-flat GCC compilation: unknown `FILE` and
  undeclared `fprintf`. Do not misclassify this as a semantic tail mismatch.
  Inspect declaration/header ownership and fixture qualification before repair.
  Further source comparison found two correctness discrepancies: listing rows
  343-349 pass `__iob+16` to stdio, but generated C passes the assertion string;
  rows 369-376 return either `rout.x.bx` or zero, but generated C has no return.
  These findings are not repaired by declaring `FILE`. Establish synthetic
  relocation and return-liveness provenance before assigning the semantic owner.
  [Literal identity investigation and partial repair](cod-literal-identity-repair.md)
  removes proximity-based string substitution; full function acceptance remains open.
  [Function extent repair](cod-function-extent-repair.md) restores the omitted
  epilogue through exact input bounds; both source return paths now survive.
- `_dos_alloc`: exit 3 after 36.12 seconds, with a 30-second function-recovery
  deadline. Tail evidence is uncollected. The child reports a terminal timeout;
  the sweep correctly retains its nonzero exit as a failed CLI attempt rather
  than confusing it with the runner's separate process-tree deadline.

Runner evidence follow-up: 12 new cases failed before the structured-report
change; all 21 runner tests passed afterward (6.10 seconds). Direct inspection
of all eight saved stderr artifacts reports seven passed tails and one
uncollected tail (`_dos_alloc`), while the two CLI failures remain failures.
The old artifacts are preserved unchanged. Runner schema 2 and its changed
digest require a new output directory for further attempts. The runner tests
are already enrolled in the routine pipeline. This reporting-only change does
not fix either failing function or prove source-to-generated-C equivalence.

Keep segment-relative addresses, symbol identities and relocation requirements
explicit. Matching OBJ relocation records or verified fixture linking are needed
where listing bytes alone cannot establish executable semantics. A missing OBJ
or unresolved relocation is an input limitation, not a decompiler success or
failure. Even functions without external calls may reference relocatable data.
Object-level extraction/lifting coverage and linked execution equivalence must
be reported separately.

User clarification: scan all COD files, not merely the three-example smoke set
initially proposed. Inventory files case-insensitively and enumerate procedures
before starting decompilation. Attempt eligible functions through the production
path with per-function subprocess deadlines, bounded workers/memory, durable
results and resume support. Reuse existing extraction/runner owners.

Each record needs file/procedure identity, input/source hashes, relocation or
fixture-link status, stage, outcome, validation, compiler errors/warnings,
elapsed time and diagnostic artifact paths. Separate crashes, timeouts, missing
C, validation failures, compilation failures, successful decompilation and
unexecutable/unresolved fixture input. Preserve original source and assembly
alongside generated C for triage; they are test oracles, not replacement output.

The scan is complete when every inventoried function has an explicit outcome,
not when all functions pass. Keep unattempted/pending distinct from failure.
Rank recurring crash/timeout causes and routine-pipeline blockers first, then
silent semantic errors. Fix one root-cause family at a time and rerun affected
cases before another complete scan. Do not add the entire slow scan to every
edit loop; graduate compact regressions into the routine pipeline.

Possible early correctness references, not a scan limit or mandatory first
selection ahead of a worse discovered failure:

1. `cod/f14/MONOPRIN.COD`, `_mset_pos`: signed remainder, stack arguments and
   two DS writes. Cover zero, negative inputs and signed 16-bit boundaries.
2. `cod/f14/NHORZ.COD`, `_ChangeWeather`: both branches, three global writes
   and repeated toggling. Check the exact offsets/widths as well as values.
3. `cod/BIOSFUNC.COD`, `_bios_clearkeyflags`: explicit ES selection and the
   two-byte write at real-mode address `0000:0417`. Check untouched surrounding
   bytes and relevant register/stack effects.

These procedures exist in the current listings and the inspected bodies have
no external calls. Data/segment initialization is explicit test setup, not
inferred program semantics. Their actual smoke/behavior status is not yet
verified. Select correctness repairs by the scan findings, not by convenience.

`cod/default/MAX.COD::_max` illustrates an input qualification requirement:
its listing contains an unresolved `call __chkstk` relocation (`e8 00 00`).
Unlinked bytes must not be treated as the original executable. Keep this
function in the inventory. Relocated fixtures require a linked binary or a documented, verified
fixture-linking contract. Do not NOP helpers or invent their effects to pass.

Use qualified listing bytes and verified boundaries as fixture input; keep source lines,
names and expected values outside semantic recovery. Use independent machine
execution/DOSUnit and compiled-C harnesses where available, not a new emulator.
No sidecar-free correctness claim may depend on COD source expressions, labels
or type hints. Preserve a separate hint-assisted mode if it is tested.

## Linked-Binary Bench

The user supplied `/home/xor/games/Riptide/RIPTIDE.EXE`, `RIPTIDE.map` and
`RIPTIDE.lst`; all three paths were verified present on September 20.
Use this as a separate real linked-binary stability bench. First verify that
the map/listing correspond to the executable; presence alone does not prove a
matching build. Record hashes and address mapping before correctness comparisons.
Run binary-only recovery separately from hint-assisted recovery. Map/listing
evidence may identify functions and support comparisons, not replace recovered
semantics. Start with a bounded batch and retain explicit pending coverage;
this bench must not silently expand a SORTD repair's acceptance scope.

## Small Buildable Examples

Initial read-only inspection of nndecomp found 267 C/C++ files across msex and
the three test-toolchain directories. Candidate order by useful obligations:

1. `msex/f14/src/TEST.C`: mixed signed 16-bit/32-bit comparisons. Preserve the
   original as provenance, but build a parameterized harness: its constant
   assignments otherwise allow folding away the comparisons. Record MS C's
   conversion of 37000 to a 16-bit int; do not assume host-int semantics.
2. `msex/slashem/src/track.c`: bounded circular storage, index wrap, pointer
   returns and a helper call. A reduced build needs explicit fixture definitions
   and retained licensing; the original headers/game state are not standalone.
3. `msex/f14/src/JOYREAD.C`: ordered pointer/value arguments to multiple stdio
   calls. Use controlled files and inspect memory/file effects; missing returns
   and unchecked fopen in the source must not become invented expected results.

Hello-world sources are available but add little beyond existing MSC tiny
coverage. Select examples by missing obligations, not just file size. Reuse
the existing MS C compile/decompile/recompile/run lane and DOSUnit; keep external
source trees unchanged, retain licensing/provenance, and put derived build
artifacts under this workspace. Matching source/binary builds are not verified
yet. These are candidates, not accepted tests or newly completed features.

The first candidate now has a linked MS C 6/kvikdos round-trip regression:
[mixed-width probe and repair evidence](mixwidth-stability-probe.md). Both
functions decompile with passed validation; generated code compiles, links and
executes with the original exit status 255. The fixture CRT wrapper calls only
the exact generated entry function identified by same-build label evidence.
The case is enrolled in the routine tiny lane; all three routine lanes pass
after the portability repair (6,115 main-lane tests). This is a labeled linked-fixture
result, not sidecar-free proof or closure of the whole-corpus stability work.
The additional GCC/UBSan mismatch was repaired in the operand-view owner;
both compiler executions now return 255. See [portability evidence](mixwidth-portability-repair.md).
Compiled exhaustive operand-refinement tests are in the routine pipeline; the
broad checkpoint passed all three lanes and all eight tiny examples. Keep the full linked-host
oracle as a required check when extending this fixture cohort.

## Existing Evidence And Gaps

September 20 inventory check: 60 case-insensitively selected COD files contain
432 procedures according to `corpus_scan.extract_cod_functions`. An independent
count of PROC declarations agrees for every file; no file has an empty result.
This checks inventory counts, not extraction fidelity or successful decompilation.
A recursive filesystem check found no OBJ files under `cod/`; availability
elsewhere is not established.

Do not blindly reuse `corpus_scan.scan_function` as the production acceptance
runner. Its extractor calls `join_cod_entries_with_synthetic_globals`, and its
scan-safe mode has intentional size/loop skips. Its relocation test searches
byte patterns rather than consuming authoritative OBJ fixups. These can support
diagnostics but do not establish a linked-program input contract. Retain fixture
normalization provenance and separate such results from linked-binary validation.

Inspected `test_x86_16_cod_samples.py` already has extraction, lifting and some
live decompilation checks. Its general text-token checks are not behavioral
equivalence. Its direct angr helper is not, by itself, coverage of the complete
production CLI path. Reuse useful fixtures and oracles instead of duplicating
the entire test file.

`test_x86_16_recompilable_subset.py` explicitly allows some live corpus cases
to report `bounded_live_decompile_failed`; its green status does not mean every
listed example successfully decompiled. `test_x86_16_readability_set.py` checks
inventory metadata rather than executing the examples. Keep these checks, but
do not use them as substitutes for the new smoke/behavior verdicts.

The inspected default `scripts/test_pipeline.py` list does not directly include
the full COD-samples module. This is not a claim that no COD-derived fixtures
run elsewhere. Graph coverage was unavailable (`Transport closed`); the bounded
source reads above establish these limitations.

The routine suite exposed a concrete COD stability candidate:
`cod/f14/CARR.COD::_SetGear` exceeded its 30-second recovery deadline. Reproduce
in isolation before attributing it to the current semantic patch or merely
raising its timeout. The suite reported 6,036 passes and one failure; this is
not a green pipeline. The pipeline finished with two lanes passing and one
failing (`.cache/wide-store-test-pipeline.log`); it is not accepted.

Next actions: classify the SetGear failure, then
implement/verify the resumable whole-COD inventory scan using existing owners.
Run its first bounded batch and report actual outcomes. Remaining parity
features stay behind stability and correctness work, without being removed.

SetGear reruns on the unchanged production tree: the isolated regression passed
in 15.63 seconds (24.66 seconds pytest wall time); a second run with SetDLC passed
both tests in 15.13 seconds, with calls taking 4.97 and 6.16 seconds respectively.
Both runs used `PYTHON_JIT=1 PYTHONHASHSEED=0`, pytest `-n 7`, and the existing
timeouts and behavior/validation assertions. Caches were not cleared, so these
are not controlled cold performance comparisons. The timeout is not reproduced
in isolation; contention or cache effects remain hypotheses, not a diagnosed
root cause. Full-pipeline acceptance remains open. Isolated log:
`.cache/setgear-isolated.log`.

First production CLI probe batch: `_mset_pos`, `_ChangeWeather` and
`_bios_clearkeyflags` each exited zero and reported `validation=passed`.
Artifacts are `.cache/cod-{mset-pos,change-weather,clear-key-flags}.{c,log}`.
These are hint-assisted normalized COD fixtures, not original linked binaries.
This is three attempted procedures, not completion of the 432-procedure sweep.

The existing ChangeWeather CLI test now compiles unchanged generated C with
strict GCC diagnostics and UBSan, then checks all 65,536 initial word states
with three consecutive calls each. It checks both global writes and the state
transition against the source and instructions at NHORZ.COD lines 292-336.
Six deliberately corrupted controls prove rejection of narrowed conditions,
wrong constants and lost state updates. The helper is enrolled in Make and the
routine pipeline, alongside the real CLI regression. Focused result: eight
passes in 16.25 seconds; CLI test 5.34 seconds. New-helper Ruff passes; the
existing CLI module retains three unrelated complexity findings. Production
semantics were not changed and the broad pipeline was not rerun for this test
addition. Its previous timeout failure remains open.
