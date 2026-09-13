# Frame Coordinate Coherence

Checkpoint: 2026-09-10, routine and executable gates completed by 20:00 CEST.
Individual test timings are recorded below; active implementation time was
not separately measured.

## Defect And Owner

The BIOS lifetime investigation exposed another unsafe prerequisite: frame
analysis published BP = entry-SP - 2 after the first access even when later
accesses used rebased BP. Memory SSA's contradiction guard already refused a
shared storage coordinate, but the frame-coordinate artifact remained PROVEN.
Lowering could therefore consume contradictory projections of the same fact.

The fix is at Analysis's IR frame-evidence producer. It consumes the existing
IR-owned captured-BP contradiction census before publishing the relation.
It does not recover semantics in Lowering or Rewrite, or grant dead-store
permission. SSA blocks used by the census are reused for scalar setup tracing.
Block-local version numbers are not compared across different blocks.

## Acceptance

Reason: a stale coordinate cannot be a premise for address lowering or private
stack lifetime proof.

DoD: machine-code ADD-BP and MOV-BP rebase cases return typed CONFLICT with no
published delta and closed failure accounting; unchanged frames retain their
proven relation; existing frame, affine, address and pipeline regressions pass.

Definition of failure: treating absence of a contradiction as a lifetime or
cross-block equality proof, discarding stores, suppressing validation changes,
or repairing rendered C instead of the frame-evidence owner.

## Results

- Before: both rebase regressions fail because the artifact reports PROVEN.
  The unchanged-frame control passes.
- After: 157 frame, affine, coordinate and wiring tests pass in 10.02s.
- The touched analysis module and new tests pass Ruff; analysis passes MyPy
  and Pyright. Separated scalar tracing, reaching setup and evidence publication
  to resolve the pre-existing complexity finding without weakening its limit.
- The existing routine regression module also owns changes to the frame
  analysis producer in the ownership manifest.
- `make -k quality-fast test-pipeline ... PARALLEL_JOBS=7`: fast 3,653 passed
  and one BIOS strict-C failure in 174.84s; default 3,653 passed and that same
  failure in 143.49s. All three quality executable guards and both default
  executable lanes pass, including MS C tiny compile/decompile/recompile/run.
- Startup architecture and context checks pass. Global lint remains red;
  aggregate Make exits 2. No full-suite or performance improvement is claimed.

Logs: `/tmp/inertia-frame-coordinate-before.log`,
`/tmp/inertia-frame-coordinate-final.log`,
`/tmp/inertia-frame-coordinate-gates.log`.

BIOS remains compile-invalid due to two protected stack carriers. Next work
still needs actual allocation, read and escape closure. This repair prevents
one unsound premise; it does not complete that proof or P0.

## BIOS Execution Acceptance Follow-Up

Verified 2026-09-10 by 22:30 CEST. The existing strict-C test now compiles and
executes unchanged generated C instead of stopping at syntax checking. It
retains C11, Wall, Wextra and Werror; there is only one compiler invocation.
Three nonzero initial memory patterns and ES values check the two-byte zero
write at linear 0417h, ES=0, unchanged CS/DS/SS and no other global-memory
changes. The oracle deliberately does not claim a raw machine-stack snapshot
or complete register/flags equivalence: generated locals use native C storage.

One correct implementation passes. Seven strictly compiled mutations are
rejected: lost ES, lost store, byte-only store, shifted address, wrong value,
unrelated DS modification, and an additional global-memory write. The existing
module is already selected by routine Make/pipeline tests. Scoped Ruff passes.

Before this test change, the real regression failed on both unused locals.
Afterward: eight oracle controls pass, the real regression still fails for the
same reason (2.13s). No production change or full-suite refresh is claimed.

Next implementation obligation remains at IR/Alias storage ownership: prove
allocation and release around each candidate, account for overlapping reads
and indirect/address escapes, and consume that proof before deletion. DoD:
the real function passes unchanged-C execution and validation, with negative
read/escape/unknown-coordinate cases retaining their stores. Failure: marking
locals volatile or adding dummy reads merely to silence GCC, disabling unused
warnings, treating absent Alias facts as proof, or deleting stores in Rewrite.

## Call Escape Range Preservation

The next proof audit found `IRCallStackEffect8616.preserves` comparing escaped
ranges by exact tuple equality. A preserved word and an escaped byte within it
could therefore both be accepted. Existing memory-SSA overlap closure caught
this only when the byte also occurred as a caller access; the escaped byte
alone did not create a memory cell. Stack-object widening consumes the same
preservation method, so the correction belongs at that shared IR contract.

`ir/stack_range_overlap.py` now supplies conservative byte-range comparison.
Same-coordinate ranges use circular 16-bit distance. Different stack bases,
unknown spaces/status/width and differing captured base provenance cannot
prove disjointness. Known distinct segments and disjoint adjacent ranges stay
accepted. No alias identity, lifetime, or DCE permission is manufactured.

Reason: private-stack proof cannot rely on a call effect that overlooks a
partial escape. DoD for this slice: overlapping escapes refuse preservation
even without a matching caller access; memory SSA retains the refusal; exact
disjoint controls remain accepted. Failure: requiring exact escape equality,
flattening distinct segments, guessing BP/SP equality, or deleting effects.

Before: four new overlap cases fail and two disjoint controls pass (8.34s).
After: 53 focused memory-SSA/call-effect/Alias tests pass (9.78s), including
unknown-coordinate and FFFFh wrap cases. Scoped Ruff, MyPy and Pyright pass.
The byte-SSA regression module is now in both routine selections; the helper
is in Make's linter lists and the existing IR ownership mapping. Broad routine
lanes each report 3,761 passed and one BIOS failure (204.98s / 173.40s). All
executable quality guards and MS C tiny round trips pass; global lint remains
red. BIOS private lifetime and strict compilation remain open. The subsequent
full audit reports 11,618 passed, 26 failed and 170 skipped; see the dedicated
full-suite baseline report rather than extrapolating these focused results.
