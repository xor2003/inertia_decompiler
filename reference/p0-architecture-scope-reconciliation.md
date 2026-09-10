# Architecture And Quality Scope Reconciliation

## Current Status

The full architecture audit is now clean. All **371 tests** in
`test_decompiler_architecture_check.py` pass, including current-tree compliance
and negative enforcement cases, in **40.44 seconds** with seven dependency
warnings. The slowest test is the complete current-tree audit at **15.43s**.
Log: `/tmp/inertia-architecture-complete-tests.log`.

The follow-up closed all 19 outstanding findings by adding the seven canonical
ownership headers and registering twelve modules already present in Make's
typed/Ruff scopes. No exemptions, thresholds or enforcement logic changed.
All twelve modules now pass Ruff (`check --fix`), MyPy and Pyright. Their
**eight Ruff findings are resolved**: meaningful constants name the operand,
prefix and proof limits; the call-shape guard separates unchanged evidence;
and a private typed query owns the bit projector's shared proof budget.
The checker itself retains 70 Ruff findings.
Architecture compliance is not global linter or full-suite completion.

The scoped clarity DoD is met: **96 focused tests pass** in **9.31s**, with
seven dependency warnings, and scoped Ruff/types pass. Two depth-boundary
regressions passed against the original implementation before refactoring;
exhaustion must discard partial projections. The original shared budget,
right-first short-circuit order and captured-read restriction remain intact.
Definition of Failure: weakening bounds, changing short-circuit evaluation,
weakening refusal evidence, or suppressing the rules.
Log: `/tmp/inertia-scoped-clarity-after.log`.

The post-refactor `make -k quality-fast test-pipeline` run finished:

- Fast lane: **3,504 passed**, eight warnings, **179.75s**.
- Default lane: **3,504 passed**, seven warnings, **144.73s**. These lanes
  overlap; their counts must not be added as unique coverage.
- All three executable quality guards and all seven MS C tiny full round trips
  passed (`recompile=ok decompile_run=ok`).
- Startup architecture, agent context, ownership and 39 compiled-module import
  checks passed. Understand-Anything automatic updates remain disabled.
- Combined exit status: **2**, because repository-wide Ruff still fails.
  This is not a green global quality gate or a complete-suite audit.

The slowest fast-lane regression was InitMenu at **82.02s**, followed by
InitBars at **74.71s** and RunMenu at **73.31s**. Complete log:
`/tmp/inertia-clarity-gates.log`.

## Evidence And Changes

The full architecture audit, unlike the startup-only check, found 29 violations.
Ten were corrected without changing checker rules or decompiler semantics:

- Added canonical ownership/forbidden-work headers to the recent reload-consumer,
  induction-comparison and pretest-initializer helpers.
- Admitted those three helpers to the architecture checker's promoted typed
  inventory, matching their existing Make typing/Ruff scopes.
- Added the already-promoted call-argument preservation owner to Make's typed
  and Ruff scopes.
- Added two existing fast-lane stored-call-result tests to `QA_PYTEST_TARGETS`.

DoD for this correction: the ten findings disappear, the owning helper tests and
scoped types/linters pass, and no rule is weakened. Definition of Failure:
adding debt exemptions instead of coverage, relaxing header requirements, or
claiming startup checks prove complete architecture compliance.

## Verification And Remaining Work

- Full checker: **29 -> 19 findings**, still failing.
- Focused helper/stored-call tests: **39 passed**, seven warnings, **12.08s**,
  using `pytest -n 7 --durations=10`.
- Four scoped decompiler helpers: Ruff, MyPy and Pyright pass.
- Architecture script: MyPy/Pyright pass; **70 Ruff findings** remain.
- No full-suite or broad gate rerun after these metadata/header edits.

The intermediate remaining findings were seven ownership headers (terminal-return Semantics,
call-argument publication/machine-stack-name Lowering, and four displacement/
stack-provenance IR modules), plus twelve missing promoted-inventory entries.
The latter include those seven owners and `ail_displacement_compat.py`,
`call_cleanup_compat.py`, `codegen_parentheses.py`, `direction_step.py`,
`stack_value_use.py`. Check every owner's actual typing/Ruff state before
promotion; do not silently exempt it.

## Discovery And Tiny-Helper Fixtures

The two separate fixture failures are now corrected without production changes.
The discovery fixture supplies `project.loader.main_object.binary = None`;
the original prohibition on convention seeding remains checked. The tiny-helper
fixture constructs a native CFunction for the real stack-declaration snapshot
and returns call-containing block addresses from `get_call_sites()`, matching
angr's contract rather than returning an interior instruction address.

DoD: both original failures and the adjacent discovery isolation tests pass;
the tiny-helper policy assertion still runs and custom structuring stays off.
Definition of Failure: bypassing the snapshot type check, mocking away callsite
processing to hide an invalid fixture, or changing production discovery policy.

The first native-fixture run passed four tests in 11.99 seconds. The small
discovery file passes Ruff; its three intentional fake-project boundaries now
use explicit native-project typing casts, not ignores. The large CLI test file
retains 174 Ruff findings and 600 Pyright errors. Final focused run: **four
passed**, seven warnings, **8.97 seconds**, using `pytest -n 7` with durations.
The small discovery file passes Pyright with zero errors/warnings. Logs:
`/tmp/inertia-discovery-fixtures-final.log` and
`/tmp/inertia-discovery-fixtures-pyright-small.log`. No broad/full-suite result
is implied.

Logs: `/tmp/inertia-architecture-current.log`,
`/tmp/inertia-architecture-followup.log`,
`/tmp/inertia-architecture-wiring-tests.log`,
`/tmp/inertia-discovery-contract-current.log`.
