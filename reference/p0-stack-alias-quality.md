# Stack Alias Quality Checkpoint

Verified 2026-09-10 at 19:46 CEST. Test elapsed times below are measured;
total active implementation time was not separately recorded.

## Scope And Reason

The BIOS strict-C blocker requires stack lifetime/read/escape proof. Current
logical stack identity and scalar entry-frame contracts do not grant deletion
permission. No such permission was added in this follow-up.

The Alias artifact builder had complexity 15, above the shared limit of 10.
Moved its per-phi identity classification into the existing per-access Alias
projection owner, and separated ordered upstream-refusal indexing/consumption.
The builder is now 324 lines rather than 343. It retains diagnostic ordering,
phi input versions, orphan refusals, evidence counts and upstream-failure policy.
No new layer or production module was introduced.

DoD: existing access/phi/coordinate and wiring regressions pass, missing-version
phi inputs refuse, and touched production files pass Ruff, MyPy and Pyright.
Definition of failure: changing Alias identity, losing refusals/counts,
reinterpreting storage coordinates, or weakening the complexity threshold.

## Evidence

- Baseline: 24 Alias/coordinate tests passed in 8.36s; builder Ruff failed.
- Final: 136 Alias/coordinate/wiring tests passed in 9.37s. Added unversioned
  target and both unversioned incoming-phi cases to the existing regression.
- Both production modules and the touched regression module pass Ruff; the
  production modules pass MyPy and Pyright. Nine existing unnamed-count
  assertions now use descriptive expected values, with unchanged expectations.
- `make -k quality-dev ... PARALLEL_JOBS=7`: 3,649 passed, one known BIOS
  strict-C failure, 163.25s. Startup architecture, context, ownership and all
  three executable quality guards passed. Global Ruff remains red.

## Shared Typing Configuration Repair

The development gate also reproduced `no-any-return` in
`lowering/stack_address_coordinates.py`. Global `follow_imports = "skip"`
erased the already-typed `ir.native_stack_anchor` return contract when its
consumer was checked in isolation or in the smaller development file list.

Added that small owned contract to the existing global `follow_imports =
"normal"` overrides. No consumer casts, ignores or weakened checks were added.
This fixes both direct tool use and Make, not just one invocation's flags.

DoD: the previously failing direct single-file command and `make mypy-dev`
pass using shared configuration, with a regression guarding contract visibility.
Definition of failure: silencing Any, dropping the consumer from the checked
scope, or making direct checks disagree with Make.

Both MyPy commands now pass. The configuration guard and native stack-anchor
tests pass: 25 tests in 8.60s. Ruff passes for the guard. These checks postdate
the routine gate above; the entire gate has not been rerun after this config edit.

Logs: `/tmp/inertia-alias-builder-before.log`,
`/tmp/inertia-alias-builder-checked.log`, `/tmp/inertia-alias-quality-dev.log`,
`/tmp/inertia-anchor-mypy-dev-after.log`, `/tmp/inertia-anchor-typing-tests.log`.

P0, BIOS strict compilation, global lint debt and the full-plan goal remain
open. No refreshed full-suite count or performance improvement is claimed.
