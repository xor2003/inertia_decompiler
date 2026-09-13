# BIOS Private-Frame Proof

## Current Evidence (2026-09-11)

The unchanged BIOS strict-C/behavior regression now passes. Private-write
proof is consumed both by DCE and by the direct-stack MOV replay owner, which
previously recreated the deleted stores. ES live-out and the two-byte BDA store
survive. Routine pytest is now green: 3,898 passed in 206.58s. All seven MS C
round trips pass, with no failed or timed-out pipeline lanes. Global Ruff and
full-suite acceptance remain open.

The subsequent [full audit](p0-full-suite-post-bios-20260911.md) confirms this
BIOS test passes: 11,750 passed, 21 failed elsewhere, 170 skipped. Source was
stable and all 11,941 tests were accounted for. The historical checkpoints
below that say the full suite was not refreshed describe their earlier state.

The sections below retain the investigation history, including superseded
failures. The original evidence was:

The first CLI trace was a cache hit and is not evidence of pass execution.
A fresh binary-byte lift through `build_x86_16_function_ssa` and
`build_x86_16_stack_memory_ssa_alias_artifact` establishes:

- Six logical accesses: saved BP write, two local writes, ES write, saved BP
  read, and return-address read.
- Local ranges are SS:BP-4 and SS:BP-2, each two bytes. Their four execution
  byte writes share BP SSA version 1.
- SP version 1 becomes BP version 1; allocation produces SP version 2 by
  subtracting four from SP version 1. Release copies BP back to SP before POP.
- Stack-memory Alias materializes both logical local writes. Its logical
  census is 6 raw, 2 normalized, 2 classified, 2 materialized, 4 refused.
  The other sites are outside its BP-relative memory-SSA domain: three
  SP-relative saved/control-stack accesses and one ES access. These refusals
  do not mean their frontend execution slices are absent.

The existing DCE walker protects direct stack-move/update evidence before
ordinary local-variable liveness. Do not bypass that safeguard. Coordinate
agreement and Alias materialization alone do not establish private lifetime.

Diagnostic: `/tmp/inertia-bios-ownership-probe.py` and its `.log`.
The fixture is lifted at 0x1000; the CLI oracle body is at 0x10010. Neither
address may become a production special case.

## Next Implementation

1. Prove frame lifetime at IR/Alias using exact SSA definitions and CFG.
   Reason: the missing fact is allocation/release ownership, not C formatting.
   DoD: associate candidate byte ranges with dominating allocation and release
   on every exit, preserving saved BP and return-address ranges; retain typed
   source identities and explicit refusal reasons. Start with the evidenced
   straight-line case without claiming general loop/call support.
   Failure: infer privacy from negative BP offsets alone, confuse source
   snapshots with register definitions, or ignore wrap/mixed-width effects.
2. Close read and escape evidence over that lifetime.
   Reason: an unread C local can still represent observable machine storage.
   DoD: account for overlapping reads, address escapes, calls, unresolved
   accesses and incomplete CFG; unknown evidence retains the write. Consume
   existing exact range-overlap and call-effect contracts.
   Failure: treat Alias refusal as disjointness or require only exact-equal
   offsets to recognize an overlapping read or escape.
3. Consume the proof before Rewrite and keep validation coherent.
   Reason: deletion permission belongs to the storage proof, not DCE spelling.
   DoD: typed per-source decisions reach Lowering and validation with closed
   raw/normalized/classified/materialized/failure counters; the unchanged BIOS
   strict compilation and behavior oracle passes, as do refusal tests and all
   seven MS C round trips. Then refresh the full suite and quality gates.
   Failure: dummy reads, warning suppression, sample-specific recovery,
   deleting the global write/ES effect, or calling focused tests a full pass.

## Block-Local Extent Publication

`ir/stack_extent_evidence.py` now derives matched SP allocation/release spans
from exact word-sized SSA copies and normalized arithmetic. Alias carries
these separately as `released_stack_extents`, including serialization. They
are not private-storage verdicts. Saved-register pushes can form spans too;
no DCE or validation consumer is allowed to equate a span with a dead write.

The real-byte test first failed because a later restored BP has an unknown
value. Restoring BP after release no longer invalidates earlier coordinate
facts; using unknown BP to compute SP still refuses. Other tests cover calls,
native CJMP/JMP, unknown SP, duplicate definitions, ESP/mixed-width writes,
wrap-sized movement, partial release, upstream SSA refusal, and Alias wiring.
The expanded focused set passes 35 tests (seven warnings, 10.19s). Scoped
Ruff/MyPy/Pyright, full architecture checking, and `git diff --check` pass.

This only advances step 1: complete function lifetime, read/escape closure,
and proof-consuming deletion remain open.
An empty extent tuple is not proof that a function has no allocations. The
BIOS strict-C regression still fails; no compiler warning or assertion was
weakened. Full-suite and broad pipeline totals were not refreshed for this
evidence-only change.

Logs: `/tmp/inertia-stack-extent-{before,gate-final,bios,ruff,mypy-final,pyright-final,architecture}.log`.

### Explicit Coordinate Verdicts

The Alias artifact now retains `stack_extent_evidence` as the authoritative
per-block result and derives `released_stack_extents` from it. Serialization
preserves both the explicit refusal and the closed census. Census units are
blocks analyzed, not deleted writes or private bytes.

Unknown coordinates, wrap-sized movements, partial releases and unreleased
allocations have typed refusal reasons. In particular, a block with no
allocations is distinguishable from a refused block even though both expose
an empty extent list. Unreleased allocations prevent a complete-block result;
earlier released subspans are not presented as complete lifetime evidence.

Forty focused tests pass (seven warnings, 9.21s), including the explicit empty
result, failure census and Alias serialization cases. Scoped Ruff, MyPy,
Pyright and the full architecture check pass. This is evidence publication,
not BIOS acceptance or full-suite success.
Logs: `/tmp/inertia-stack-extent-census-{tests,mypy,pyright,architecture}.log`.

### Indexed Operand Refusal

Read/escape preparation found that the new coordinate collector ignored
`IRValue.index`: an indexed SP value could be treated as its constant offset
alone. Three regression cases with unscaled and scaled register indices failed
before the guard. The collector now refuses indexed sources before producing
coordinate evidence. This prevents an unsound premise from reaching later
ownership work; it is not a BIOS deletion fix.

The combined extent/Alias suite passes 43 tests (seven warnings, 8.66s).
Scoped Ruff, MyPy, Pyright and `git diff --check` pass. Read/escape closure is
still open. Logs: `/tmp/inertia-stack-index-{before,after,mypy,pyright}.log`.

### Exact Memory Coordinates

Coordinate evidence now retains the exact SP/BP definition version, source
instruction index and displacement. `address_entry_offset` requires a proven
SS address in the same block, one plain word-sized base, and a definition
preceding the access. Missing versions, different blocks/segments, unknown
provenance, indexed bases and forward references refuse resolution.

The real BIOS byte sequence resolves all raw stack loads/stores. Writes cover
entry-SP bytes -6 through -1, while reads cover -2 through +1. Thus the four
local bytes (-6 through -3) do not overlap saved-BP or return-address reads.
This is tested from lifted bytes, not rendered C or source-name assumptions.
It is an address/read relationship, not yet a private-storage verdict.

The combined extent/Alias suite passes 52 tests (seven warnings, 8.70s).
Scoped Ruff, MyPy, Pyright and `git diff --check` pass. No deletion consumer
was enabled. Escape closure and complete function-exit evidence remain open;
do not infer complete function coverage merely from one SSA block or its
internal predecessor map.

Logs: `/tmp/inertia-stack-address-closure-{tests,mypy,pyright,architecture}.log`.

### Terminal Return Evidence

The existing VEX control-flow importer preserved exact terminal calls but
discarded `Ijk_Ret`. It now emits a `RET` control marker with the last source
instruction address. Return destination values are generally dynamic; no
constant target, return-value convention, or stack-effect replacement is
invented. Preceding typed register/memory effects remain unchanged.

Two new tests failed before this correction. The new tests verify terminal
kind discrimination, preserved constant call targets, and real-byte return
propagation through IR and SSA. They are admitted to Make, ownership selection,
and the routine pipeline. The focused set passes 58 tests (seven warnings,
9.26s); scoped Ruff, MyPy and Pyright pass.

Broad verification: routine pytest reports 3,875 passed, one known BIOS strict-C
failure, eight warnings, 193.83s. All seven MS C round trips pass, with no
timed-out lanes. `quality-fast` remains red on global Ruff debt. These are not
refreshed full-suite totals. No private-store deletion consumer is enabled;
the remaining ownership proof must consume the explicit return marker rather
than infer a return from an empty successor list.

Logs: `/tmp/inertia-ir-return-{before,after,mypy,pyright,pipeline,quality}.log`.

### Derived-Address Escape Component

Alias now publishes `frame_address_escape` from the focused
`stack_address_escape.py` owner. Function-level publication requires one
entry-to-return block, exact extent evidence and no joins. The analysis tracks
SSA copies, stored values and outgoing general/segment register values. It
does not treat a load's address as its loaded data. Exact SS byte store/load
states distinguish restored BP from an outgoing frame pointer.

The unrestored-BP counterexample failed before removing BP's blanket output
exclusion. A separate partial-register counterexample failed before preserving
wider live pointer information. Full word/dword overwrites are accepted;
partial overwrites refuse. The first word-only guard was too restrictive for
the real body's dword direction-state register, so it was replaced with width-
aware overwrite checks rather than a special case for that register.

The real BIOS body reports no derived-address data escape. This does not prove
absence of arbitrary memory aliases: per-write unread/lifetime decisions and
their consumers are still required. No DCE protection was bypassed and no
private-store deletion is enabled yet.

The combined extent/escape/Alias set passes 63 tests (seven warnings, 8.98s).
Scoped Ruff, MyPy and Pyright pass; the full architecture check and
`git diff --check` pass. New coverage is admitted to Make, ownership selection
and the routine pipeline. No fresh full-suite or broad pipeline count is
claimed for this evidence-only change.

Logs: `/tmp/inertia-stack-escape-{bp-before,bp-after,partial-before,complete,mypy-complete,pyright-complete,architecture}.log`.

### Per-Source Write Proof Publication

Alias now publishes immutable private-write decisions grouped by machine
instruction. Every raw byte store must have the matching canonical Alias range
and memory version, lie inside a released allocation, and be disjoint from all
resolved reads. Unknown reads, escaped frames, missing Alias bytes and partial
allocation coverage retain the whole source write. The saved BP and ES global
stores in the BIOS fixture are not approved.

The publication regression checks the actual Alias builder and serialization:
four source groups, two proven local writes and two explicit refusals. Census
materialization counts published proofs, not deleted C assignments. Standalone
classifier success alone is not sufficient evidence of pipeline integration.

Verification: 51 extent/escape/private-write tests passed in 8.90s, with seven
dependency warnings. Scoped Ruff (`--fix`), MyPy and Pyright passed. The new
module and regressions are registered in Make, architecture ownership and the
routine test pipeline. Logs: `/tmp/inertia-private-proof-{gate,mypy,pyright}.log`.

Still open: consume the exact current-SSA proof at Lowering/DCE, preserving
unknown memory effects and impure expressions; then rerun the unchanged BIOS
strict-C behavior oracle, tail validation and broad gates. This evidence-only
checkpoint does not establish a BIOS fix or a green full suite.

### Current-SSA Consumer Investigation

Lowering now exposes a proof consumer that requires source-SSA object identity,
the current function address and the root statement's exact instruction tag.
Tests reject copied/stale SSA, the wrong function, refused source stores and
nested-only provenance. The DCE memory guard consumes this proof only for an
exact stack assignment with an already-classified pure local RHS; ambiguous
source evidence remains protected.

The first integration used an artifact-specific discardability predicate that
refuses plain constants. A fresh-cache, in-worker probe demonstrated this;
the guard now uses the existing local-value purity classifier. A subsequent
debug run confirms `delete_non_temp_discardable` for both BIOS local writes.
Nevertheless, both writes appear in final generated C. The next investigation
must locate downstream recreation or restoration, not weaken another DCE
guard. Probe logs: `/tmp/inertia-private-probe{3,4,5}.log`.

The unchanged BIOS regression still fails strict compilation; the combined
consumer/BIOS gate is 19 passed, one failed (15.14s). Lowering MyPy/Pyright and
architecture checks pass. Ruff reports 12 complexity/Boolean-condition findings
in the existing DCE walker; this touched surface is not lint-clean. No full
pipeline acceptance or function-fix claim is made.

### Replay Root Cause And Focused Acceptance

The final recreation was traced to
`_replay_direct_stack_semantics_after_regen_8616` invoking direct-stack MOV
Lowering. The materializer rebuilt both stores from retained machine facts
after DCE had removed them. Neither stale rendered text nor a validator
rollback was the cause. See `/tmp/inertia-private-probe6.log` for creation
stacks from the actual fresh-cache analysis worker.

The direct-stack materializer now consumes the same current-SSA Alias verdict
before rebuilding storage projections. It preserves the recovered fact inventory
and raw count and reports `private_write_elided_count` separately. It does not
drop the source instruction's register/flag effects or authorize removal of
side-effecting C expressions. Unknown or stale proof still requires normal
materialization. No CLI semantic exception was added.

The unchanged BIOS regression now passes strict GCC, three seeded whole-memory
and segment behavior comparisons, `validation=passed`, and clean whole-tail
validation. Combined consumer/BIOS checks: 20 passed, seven dependency warnings,
15.53s. Logs: `/tmp/inertia-private-replay-after.log`. This supersedes the
focused failure above.

Routine acceptance is green: 3,898 pytest tests in 206.58s and all seven MS C
compile/decompile/recompile/execute comparisons pass. Pipeline summary: three
selected lanes, three passed, zero failed/skipped/timed-out. Log:
`/tmp/inertia-private-replay-pipeline.log`. `quality-fast` remains red at global
Ruff; 255 findings also remain across the two large touched owners in the
scoped Ruff run. MyPy and Pyright pass for the touched owners; full architecture
and diff checks also pass. Full-suite totals have
not been refreshed; this is not completion of the repository-wide goal.
