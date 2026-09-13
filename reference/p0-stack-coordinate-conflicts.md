# Stack Coordinate Conflict Refusal

## Reason And Acceptance

BIOS lifetime investigation confirmed that the existing affine tracer now
resolves SP updates to entry-SP deltas -2, -6, -2, 0 and +2. Its six remaining
SP-relative Alias refusals are not missing arithmetic semantics: memory SSA
currently versions BP-relative ranges only. Their normalization and lifetime
proof remain open; no private-store deletion is justified yet.

A prerequisite safety check exposed a separate defect. Memory-SSA geometry
keys omitted the captured BP definition. Actual instruction sequences with
`MOV BP,1000h; MOV [BP-2],1234h; MOV BP,2000h; MOV AX,[BP-2]` incorrectly
published one storage history. ADD-based BP rebasing reproduced the same bug.
Different offsets cannot establish disjointness across unknown BP rebases.

DoD: refuse contradictory coordinates before building memory cells, prevent
logical Alias identity from bypassing that refusal, retain original accesses
and provenance, close evidence accounting, and keep same-definition temporary
snapshots accepted. Definition of failure: merging contradictory storage,
deleting effects, fabricating normalized frame coordinates, or treating absence
of an observed conflict as a lifetime or cross-block-equivalence proof.

## Implementation And Scope

IR owns `StackCoordinateAgreement8616` and its contradiction census. When one
block's stack operands observe different BP versions, function-wide BP geometry
is refused rather than compared without normalization. No cells or overlap
facts are published for those coordinates. Original IR instructions remain;
each unprojected access receives a refusal. Alias's versioned and logical
projections consume the same IR owner, with typed logical refusal reasons.

Versions are block-local and are deliberately not compared across blocks.
Missing legacy provenance is not claimed to prove conflict or equality.
This is a conservative contradiction guard, not complete frame normalization,
escape analysis, general storage liveness, or a BIOS strict-C fix.

## Evidence

Before: two machine-byte regressions failed, one unchanged-BP case passed
(8.13s). After: 143 focused memory-SSA/Alias/provenance/wiring tests pass
(9.98s), including older snapshots retained across later BP overwrites and
changed displacements. The new regressions are in Make's fast targets,
the routine pipeline and the ownership manifest.

Scoped MyPy and Pyright pass. Ruff fixed import ordering; existing complexity
findings remain in the large memory-SSA and Alias builders. No suppression
or threshold change was added. Investigation began around 18:36 CEST on
2026-09-10; focused verification was complete before 18:47 CEST. Routine gates
were then running with production held stable. Logs:
`/tmp/inertia-stack-conflict-before.log`, `/tmp/inertia-stack-conflict-focused.log`,
`/tmp/inertia-stack-conflict-ruff.log`, `/tmp/inertia-stack-conflict-mypy.log`,
`/tmp/inertia-stack-conflict-pyright.log`, `/tmp/inertia-stack-conflict-gates.log`.

Routine gates completed before 18:55 CEST. Fast pytest: 3,629 passed and the
known BIOS strict-C failure in 171.57s. Default pytest: the same counts in
142.80s. All three executable quality guards pass; the default executable
lanes, including MS C round trips, pass. Both Make goals correctly remain red
because BIOS strict compilation and global Ruff debt are unresolved. No new
routine failure appeared; the full suite was not rerun after this guard.

## Ownership Gate Cleanup

The changed ownership manifest still failed Ruff's complexity rule (25 > 10).
Validation was split into source paths, target paths, rule policy and per-node
checks within its existing owner. Public contracts and diagnostic text/order
remain unchanged; one source-index cache spans all rules in an invocation.
No new module or suppression was needed, and the oversized file shrank.

Reason: recurring changed-file lint debt impeded every regression admission.
DoD: Ruff, MyPy, Pyright and the real manifest CLI pass while preserving all
validation obligations and source-cache reuse. Definition of failure: lost
diagnostics, different error order, skipped node/skip-policy checks, repeated
source parsing per target, or relaxed validation rules. Two new tests protect
multi-error order and cache reuse without skipping a later node's skip policy;
they are admitted to routine checks and changed-file ownership.

Before: 59 manifest tests pass, Ruff rejects the complex validator. After:
124 manifest, source-index and pipeline tests pass in 2.96s; scoped Ruff,
MyPy, Pyright and `test_ownership_manifest.py --check` pass. This tooling-only
follow-up did not rerun the executable gates or full suite and does not close
their recorded failures. Evidence: `/tmp/inertia-manifest-before.log`,
`/tmp/inertia-manifest-final.log`, `/tmp/inertia-manifest-mypy.log`,
`/tmp/inertia-manifest-pyright.log`.
