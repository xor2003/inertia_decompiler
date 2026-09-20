# Step 9: Bounded SORTD Acceptance

## Authority And Scope

On September 19, 2026, the user approved limiting Step 9 to the existing
20 non-library SORTD functions. This contract supersedes historical checkpoints
that made Step 9 depend on unrelated COD functions, completion of Tasks 3/8,
or elimination of all pre-existing repository-wide test and lint debt.
Those obligations remain open in [the separate backlog](post-step9-backlog.md).
This is a scope change, not permission to weaken semantic validation.

Freeze the declared MZ image of `SORTD.EXE`, whose recorded SHA256 is
`09e3ce9746b96ebc2fdefd73f34cdf63c1be6acf6c2736c8fc89db595f2ce798`.
Verify this identity during the final audit. Trailing sidecar/debug material is
not recovery input. Use the existing address inventory without adding unrelated
functions or requiring source names:

`10010 10060 101f0 102e0 10498 10560 10678 106c8 10768 107b8`
`10808 108d0 10970 109e8 10a88 10b50 10c18 10ce0 10e70 10f38`

## Ordered Acceptance

### 1. Whole-Binary Semantic Acceptance

Reason: isolated successes do not prove that all selected functions survive
discovery, scheduling, analysis and export together.

DoD: the sidecar-free whole-binary gate covers exactly the frozen inventory;
all 20 functions emit nonempty C and pass tail validation; discovery and
attempt counters close; no assembly fallback, timeout, traceback or violations.
Record the input, source state, command, timing, report and generated artifacts.

Failure: a missing function, unknown/uncollected/failed validation, hidden
fallback, changed semantic effect, or reduced selection/threshold.

### 2. Compilation And Existing Behavior

Reason: validation alone does not prove that exported C compiles or that the
existing behavioral oracles still accept it.

DoD: the current generated functions and combined translation unit pass the
project's strict C compilation gates without replacing bodies; existing SORTD
sort-core and RunMenu execution gates pass, including their corruption controls.
The default pipeline, including actual MS C tiny round trips, is rerun after
the final production change. Record any failure and attribute it before closure.

User-approved compiler policy (September 19, 2026): compiler errors block
acceptance; warnings require examination rather than automatically blocking it.
Record each warning category and its disposition: fix, justified narrow
suppression, or documented debt. The four previously reported `variable set but
not used` warnings are permitted readability debt. Keep the unsuppressed raw
report; do not disable warnings wholesale or remove live code to silence them.
A warning exposing a correctness defect still blocks under the semantic and
behavioral contracts. This policy concerns generated-C compiler diagnostics,
not a waiver of lint/type checks or newly introduced regressions.
The latest saved `step9-sortd-compilation.json` reports zero errors and zero
warnings, so no suppression or warning deferral is needed for that artifact.

Failure: compiler errors, unexamined warnings, unjustified suppression, lost
calls/argument classes/memory effects,
changed branches or returns, an in-scope behavioral failure, or a new regression
introduced by our changes anywhere in the project.

### 3. Address-Matched Comparison

Reason: the deliverable is a reviewable whole-file comparison, not visual
similarity to a peer's output.

DoD: refresh the 20-function index and semantic review against the final saved
Inertia artifact. Label missing Ghidra functions and historical peer versions.
Document call/argument classes, memory effects, control flow, types and remaining
non-cosmetic debt. Numeric names and honestly documented verbosity are acceptable.

Failure: stale anchors, mismatched binaries, cosmetic-only review, or using peer
C/source/debug information as semantic recovery evidence.

### 4. Final Gate Ledger And Closure

Reason: a bounded milestone must distinguish its acceptance from whole-project
health without hiding either.

DoD: on unchanged final production source, run the required quality and test
gates once and preserve exact outcomes and scope: `make quality-hard`,
`make test-pipeline`, the three SORTD gates below, and focused tests for the
changed owners. Use `PYTHON_JIT=1` and the project venv. Relevant checks must pass.
Pre-existing unrelated full-suite/global-lint failures may remain only with
explicit evidence and backlog entries; no new regression is waived. Update the
plan, artifact identities and gate ledger, then mark Step 9 complete and stop.

Failure: presenting a curated run as the full suite, calling a red gate green,
silently skipping a required run, using stale acceptance after source changes,
or expanding Step 9 into new unrelated repair families.

The SORTD gates are `scripts/check_sortd_sidecar_free.py`,
`scripts/check_generated_translation_unit.py`, and
`scripts/check_sortd_generated_sort_core.py`, using the same freshly generated
function artifacts. Whole-collection and unrelated expanded-lane audits remain
in the separate quality backlog; do not claim they passed or silently select a
smaller collection under their names.

## Explicit Non-Goals

- TIDShowRange, LIFE, other unrelated COD/binary repairs, and 80387 recovery.
- Finishing general interprocedural/SSA/alias/type migrations in Tasks 3 and 8.
- Eliminating all pre-existing global lint, typing and pytest debt.
- Further optimization unless needed to complete these acceptance runs reliably.
- Proof of linked whole-program DOS equivalence for every possible input path.

The current comparison and gate evidence must state these limitations explicitly.
