# Stack Use-Closure Experiment (Not Retained)

## Question

Can transitive address-only use proof remove RunMenu's retained SP bookkeeping
without reviving numeric stack-offset to host-pointer substitution?

## Experiment

A temporary frontend prototype followed SSA copies, block-local temporaries,
constant offsets and complete phi merges. Numeric escapes, unresolved sinks,
duplicate definitions and incomplete phis refused. Integration additionally
required matching native tracker offsets at the definition and use instruction.

The isolated prototype reached 56 passing tests. Its integrated positive case
failed before wiring and passed afterward. These experimental tests were removed
with the prototype; they are not part of the current repository test count.

The paired executable regression reported one passed (InitMenu) and one failed
(RunMenu), seven dependency warnings, 59.64s. RunMenu still failed the existing
no-raw-ESP assertion. After removing the prototype, a direct RunMenu run produced
byte-identical C, with SHA-256:

`29e148cbb324b2c469391f798f8f9a9da7297e0305287c540d7000694047aad9`

Both direct outputs reported clean whole-tail validation. This is no evidence
of a RunMenu quality improvement or complete frame-state correctness. The
prototype and its temporary module/test/admission changes were removed; earlier
numeric-use, width-refusal, byte-write and call-frame safety fixes remain intact.
The restored stack-compatibility module has 36 passing tests (9.12s), and Ruff
passes. No fresh broad-gate result is claimed for this experiment.

## Observation Failure And Correction

Parent-process counters were empty while the CLI used isolated execution. They
did not prove that the native tracker or analysis was absent. A corrected probe
with both `INERTIA_OTEL_PROFILE_IN_PROCESS=1` and
`INERTIA_DIRECT_ADDR_FORCE_THREAD=1` observed 348 analyses with a tracker and 40
without one. It explicitly installed the existing compatibility hook before
wrapping it. The earlier tracker-unavailable interpretation is rejected.

Do not use `/tmp/inertia-runmenu-tracker.c` or its first in-process variant as
acceptance evidence: those diagnostic runs did not establish hook execution.

## Next Investigation

Reason: local use-role proof alone has not eliminated the retained frame state.
Locate the first surviving SP assignment in the actual worker, then trace its
exact SSA definition, consumers, call-frame consumption and restoration facts.
Do not rebuild the same closure prototype without a demonstrated refusal it
can resolve. Do not treat all SP writes as dead or relax the no-ESP assertion.

DoD: identify the earliest missing or unconsumed typed fact on RunMenu, add a
regression reproducing that defect, preserve numeric escapes and mixed-width
state, and pass the RunMenu executable regression without weakening validation.

Definition of failure: unchanged generated C, deletion without closed liveness
and call-boundary evidence, lost restoration or calls, or green synthetic tests
without executable improvement.

## Evidence

Observed artifact interval: first unit-result completion at 14:38:54 through
the corrected probe's completion at 14:53:11 on 2026-09-09, local time (14m17s).
This excludes earlier construction and is not an active-work duration.

- `/tmp/inertia-stack-flow-executable.log`
- `/tmp/inertia-runmenu-flow.{c,log}`
- `/tmp/inertia-runmenu-tracker-thread.{c,log}`
- `/tmp/inertia-stack-flow-restored.log`

These temporary diagnostic paths are not committed artifacts.
