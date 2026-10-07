# P0 GitHub CI Closure

## Current Checkpoint (2026-09-09)

Run `34321600834` on `be7f019da` is now verified completed with failure:
**42 failed, 5,063 passed, 10 warnings in 537.23s**. Pyright's first two
batches pass; the third reports **24 errors**, not a whole-production total.
Missing `kvikdos` remains visible in the failed DOS recompilation checks.
InitMenu also fails portable GCC on pointer/integer `&` operands; do not
attribute every failure to missing tools. No CI check is disabled or relaxed.
Log: `/tmp/inertia-ci-34321600834-failed.log`.

The local address-snapshot checkpoint passes hard/fast/default gates with
2,865 routine unit tests, three executable guards, QuickC, and all seven
MS C tiny round trips. The subsequent full local audit reports 10,794 passed,
37 failed and 170 skipped in 792.10s; its two new expectation failures are
corrected in focused tests, not yet a new full-suite result.
Neither those local lanes nor the lower first-failing Pyright batch count
establish CI closure or whole-project typing acceptance.

### Earlier Same-Day Checkpoint

Completed run `34287484156` on `8f5bdd05a` reports **42 failed, 4,846 passed,
10 warnings in 536.13s** for its selected tests. Remote Pyright reported 32
errors. After the current validation-contract repair, local CI-mode Pyright
reports **31 errors** in return compatibility, structuring, function evidence
inventory and helper ABI. Missing `kvikdos` still appears in the failed run;
the approved private DOS-toolchain provisioning question remains unresolved.

Make's global and development MyPy scopes now pass; `quality-fast` and
`quality-dev` and `quality-hard` also pass. This does not establish whole-repository typing,
full-suite success or remote CI closure. See
[the validation-contract checkpoint](p0-validation-type-contracts.md).
Fresh logs: `/tmp/inertia-ci-34287484156-failed.log` and
`/tmp/inertia-validation-contract-global-pyright.log`.

## Previous Checkpoint (2026-09-08)

Checkpoint `89531dc57` was pushed to master. Run `34281763397` is now completed
with failure: Pyright and Pytest failed; Ruff, Vulture, and Lizard passed.
Pytest reports **42 failed, 4,764 passed, 11 warnings in 490.87s** for its
selected set, not the whole repository. Pyright reports zero errors in its
first batch and **40 errors in its second batch**, also reproduced locally
with `CI=1 make pyright PYTHON=./.venv/bin/python PYRIGHT_WATCH=0`.

Of 42 failure sections, **34 mention `kvikdos not found`**. Eight others are:
the DOS LoadProgram wrapper, MSC6 signed-long comparison at 65614, three
InitMenu tests, two PercolateDown tests, and caller-cleanup loop preservation.
Missing kvikdos does not prove those 34 tests otherwise pass. For example,
sidecar-free InitBars passes its tail stages remotely but fails the mandatory
MS C syntax check because kvikdos is absent. The workflow installs Python
dependencies only; an approved private DOS-toolchain provisioning source has
been requested. Do not publish proprietary compiler files or skip validation.

Return compatibility contributes 23 of the locally reproduced Pyright errors.
Installed AIL marker classes alias their static types to native Rust classes,
but this installation lacks their `.pyi` files. Merely replacing `Expr`/`Stmt`
module aliases did not improve diagnostics and was reverted. Next use precise
typed boundaries after actual native variant checks; do not cast to unchecked
Any or weaken diagnostics. Other failures include instruction-value unions,
structuring collection inference, and optional/unknown validation summaries.

Local MyPy at that checkpoint: **14 diagnostics**; the default pipeline passed 2,550
tests plus QuickC and MS C tiny lanes. Logs:
`/tmp/inertia-ci-34281763397-failed.log`, `/tmp/inertia-pyright-ci-repro.log`.

## Previous Checkpoint (2026-09-07)

Fresh local Vulture execution found five diagnostics, not the historical remote
two. One exposed an unreachable exact-BP identity guard in the legacy call
argument consumer. Its wrong indentation allowed a different BP offset or an
SP-based variable to lose its unified identity. The guard now refuses both;
existing coordinate evidence remains authoritative, with no new recovery rule.

- Reason: a required identity check must execute before clearing an alias.
- DoD for this repair: exact-match behavior retained; mismatched BP and SP
  identities preserved; surrounding argument regressions and scoped tools pass.
- Definition of failure: clearing identity without an exact BP coordinate,
  inventing new storage evidence, or treating focused tests as corpus acceptance.
- Evidence: before, two failures/two passes; after, 178 passed in 23.13s.
  Ruff `check --fix`, scoped MyPy, and scoped Pyright passed. Tests exercise
  the nested guard directly plus the existing call-argument materializer suite;
  they do not establish live SORTD equivalence. Logs:
  `/tmp/inertia-stack-guard-before.log`, `/tmp/inertia-stack-guard-after.log`.

The unreachable trailing returns in `cli_access_trait_rewrite.py` and
`cli_induction_rewrite.py` are now removed. Their seven existing artifact and
condition-wrapper regressions pass before (17.30s) and after (18.73s); scoped
Ruff, MyPy, and Pyright pass. This is dead-code removal only, with no change to
condition recovery or artifact-backed naming. Useful docstrings were retained
and added to the touched helpers.

- Reason: eliminate confirmed dead statements without moving recovery into CLI.
- DoD: reachable behavior and refusal cases unchanged; focused tests and scoped
  lint/type checks pass; refresh the actual global Vulture findings.
- Definition of failure: changing condition meaning, dropping a live refusal,
  hiding diagnostics, or claiming the complete gate passed.

The refreshed global Vulture command still fails, reporting exactly the two
interface parameters below. Both belong to Protocol declarations; the
OpenTelemetry timeout keyword is also consumed at the provider call boundary.
No artificial parameter reads, API-breaking renames, Vulture exclusions, or
confidence filters were added. Logs: `/tmp/inertia-cli-cleanup-before.log`,
`/tmp/inertia-cli-cleanup-after.log`, `/tmp/inertia-vulture-refresh.log`.
Global Vulture and remote CI closure remain open.

Remote refresh during the latest follow-up failed with a GitHub API connection
timeout. The run below remains the last verified remote result, not a freshly
confirmed latest run. The current workflow installs Python dependencies but
does not provision kvikdos or the licensed DOS compiler prerequisites.

The completed local combined `quality-dev test-pipeline` run exited zero:
2,236 tests passed in the development gate, 2,236 in the default unit lane,
and all seven MS C tiny compile/run/decompile/recompile/run cases passed.
These overlapping local selections are neither a full-suite census nor remote
acceptance. Pending working-tree fixes are not yet verified on GitHub.
Log: `/tmp/inertia-aggregate-final-gates.log`.

Latest inspected completed CI: `34141065397` on `511b0d3cb`, with **4425
tests passed and 42 failed in 457.85s**. Ruff/Lizard passed; Pyright/Vulture
failed. Pyright's second batch reports 49 errors; Vulture reports two unused
interface parameters. The workflow runs a focused selection, not the full suite.

Thirty-five failure sections mention missing `kvikdos`; this does not prove
they have no additional defects. Seven other failures require separate semantic
or test-contract investigation. See "Verified Remote Baseline" below.
Pending local fixes have not established remote acceptance. CI closure remains
mandatory before claiming P0 complete; performance Step 10 stays deferred.
The historical counts below are checkpoints, not a current full-project census.

Latest local follow-up: the recorded-return replay crash repair passes 181
focused tests, scoped Ruff/MyPy/Pyright, and the architecture check. The fresh
global `quality-fast` run still fails on 125 MyPy diagnostic lines. This does
not change the remote result above; the current shared tree is not CI-accepted.

## Initial Evidence (2026-09-07)

At initial inspection, the eight latest workflow runs were failed. Two were inspected:
Pyright fails, and subsequent Vulture, Lizard, and pytest steps are skipped.
The then-latest run, 34131575884 on e7b84fe8b, reported 49 Pyright errors in the
first Make batch. This is not a full typing census or a pytest failure count.

Run: https://github.com/xor2003/inertia/cli/actions/runs/34131575884

The project requires Python >=3.14 and CI installs 3.14.7, but the shared
Pyright configuration still targeted 3.11. The local correction targets 3.14.
Independent workflow checks now run after successful dependency installation
even if another check fails. Cancellation still stops them; failed checks
still fail the job. No continue-on-error or diagnostic suppression is added.
The edited workflow passes actionlint 1.7.7.

## Remaining Task

Local instruction-contract repair: provenance now consumes the existing
`DecodedInstructionFactSurface8616` instead of maintaining an incompatible
duplicate hierarchy. Protocol methods explicitly declare abstract bodies.
Scoped Pyright improves from eight errors to zero; Ruff and scoped MyPy pass.
The 16 register-reaching-source regressions pass before (8.19s) and after
(8.40s). No instruction semantics or typing suppressions were changed.
The current local first Make Pyright batch reports 37 errors after this repair;
it still stops before later batches. This is not directly interchangeable with
the remote count because installed dependency surfaces differ.
`quality-dev` passes on the shared working tree, including 2,119 tests in
100.42s and the executable guards. This gate includes pending unrelated
changes and is not a clean-commit or remote full-suite acceptance result.

- Reason: skipped tests provide no regression evidence, and local narrow
  gates do not establish remote acceptance.
- Order: align tool configuration; collect every CI check result; repair
  actual typing, lint, and test failures in their owning layers; rerun CI.
- DoD: all required checks pass on the pushed commit, including executed
  pytest. Record the run URL and actual test totals. Preserve the separate
  full-suite and DOS round-trip acceptance requirements in the main plan.
- Definition of failure: skipped checks reported as passing, relaxed typing
  rules, hidden diagnostics, removed behavioral coverage, or a local-only
  result substituted for remote CI success.

Status: open. The configuration correction does not resolve existing typing
debt. Run 34133441640 on 704dc5688 confirms the changed execution conditions:
Ruff and Lizard passed, Pyright and Vulture failed, and pytest subsequently
ran: **4,384 passed, 44 failed in 477.50s**, with 10 warnings. This focused CI
selection is not the full suite. Pyright reported 28 errors in its first batch.
Vulture reported unused `propagator` in stack_compat.py and `timeout_millis`
in telemetry.py. Run 34133444219 is a separate
Dependabot job, not the focused test workflow.

The next local typing repair preserves the segmented-byte access methods and
declares their existing active-instruction field and PyVEX decorated result
types. The decorator returns VexValue even when the wrapped implementation
returns RdTmp. `access.py` now passes Pyright, MyPy, and Ruff, with no new
suppression; 34 access/emulator/stack-helper tests pass in 9.00s. The current
first Make Pyright batch has 30 errors. Remaining batches are still uncounted.
The default test pipeline passes all three lanes on this shared tree, with
2,119 unit tests in 105.02s and successful external compiler round trips
(`/tmp/inertia-ci-access-pipeline.log`). This does not close named InitMenu or
the source-stable full audit.

Pending follow-up: the direct-call stack-effect helper now declares its actual
Capstone `CsInsn` input rather than `object`. Its caller feeds decoded Capstone
instructions; no instruction processing changes. `analysis_helpers.py` passes
Ruff, scoped MyPy, and Pyright. Eleven interrupt/AST regressions pass before
(8.44s) and after (10.61s). Broad gates have not been repeated for this
annotation-only follow-up.

## Interpreter Resolution And Next Failure Groups

Pyright's verbose log proved that invoking `.venv/bin/python -m pyright`
without `--pythonpath` still inspected system Python 3.12 packages on this
host. Earlier local first-batch counts therefore mixed real source errors and
environment mismatches; do not use them as a clean typing progress census.
Make now selects its `PYTHON` explicitly for every Pyright invocation,
including the separately timed DCE batch. The regression dry-runs all three
Pyright targets: one failure before, three passes after (1.29s).
For direct use, pass `--pythonpath ./.venv/bin/python` as well.

Callsite None checks and the abstract tag-map method are now explicit;
108 callsite/register-source tests pass before (8.66s) and after (9.74s).
Scoped MyPy and Ruff pass; Pyright passes for callsite_summary.py when it uses
the actual project environment. The corrected first Make batch has 17 errors.

Prioritize the newly visible CI failures as follows, without deleting checks:
1. Clean-checkout setup: two partition-controller tests assume `.cache/pytest`
   exists; COMP32 tests need their generated binary; DOS recompilation needs
   kvikdos. Reproduce without local artifacts and establish explicit fixture
   creation/toolchain prerequisites, not success-by-skip.
2. Test contract drift: the frame-push inventory-cache test calls a changed
   helper signature without `request_cache`. Verify its intended cache behavior
   against the current owner before repairing the test.
3. Real decompiler failures: inspect exact tail-validation and call-effect
   diagnostics, separate timeouts from semantic failures, and retain the
   sidecar-free acceptance contract. Environment fixes alone cannot close them.

Detailed remote log: `/tmp/inertia-ci-704dc-failed.log`.

Follow-up `quality-dev` passes on the current shared tree: 2,119 tests in
101.37s, architecture/ownership checks, and generated-C guards. The three
Makefile output/interpreter tests were also run separately and pass. These
local results form a partial checkpoint; remote CI and full-suite closure remain
open.

Clean-cache follow-up: both controller cases reproduce the remote
FileNotFoundError with REPO_ROOT redirected to an empty temporary directory.
The runner now creates its cache parent; all 21 partition-runner tests pass
in 1.93s, including cleanup of per-run temporary files. Ruff, scoped MyPy,
and Pyright pass. The stale frame-push cache test now passes `callsite_addr`
and uses keyword arguments, retaining the result and single-collection
assertions: one failed/four passed before, five passed after in 7.72s.
These three CI failure cases are fixed under focused checks; remote acceptance
is not yet rerun. The Vulture findings are protocol parameter declarations,
not established dead runtime code.

COMP32 fixture follow-up: preserved the existing 4,187-byte executable, matching
C source and COD/MAP files under `tests/fixtures/msc6/compare32`.
The address-specific tests now use this versioned input instead of the ignored
build directory. Four SHA-256 checks protect its identity; the original four
decompiler assertions are unchanged. Before: four passed in 11.83s. After:
eight passed in 5.40s (warm caches; not a performance comparison). Ruff passes.
This removes the clean-checkout missing-input dependency, not the separate
requirement to run the MS C compiler round-trip pipeline. Exact historical
binary rebuild reproducibility is not claimed. Broad/remote gates have not
yet been repeated for this fixture-only change.

Typing follow-up: explicit architecture-binding result types remove
four more diagnostics. The installed angr implementations return concrete
SimTypeFunction/SimTypePointer objects, although the public with_arch return
annotation is SimType. The casts preserve those existing classes, not new
semantic recovery; two redundant pointer capability checks are removed.
Eight annotation regressions pass before (17.25s); 63 smoke/prototype tests
pass after (27.61s). Ruff and scoped MyPy pass. The corrected first Pyright
batch at that point reported 13 errors.

The AIL OUT compatibility consumer now declares exact block, dirty-statement,
helper-expression, and constant-payload fields instead of reading them through
`object` or assigning through `Any`. Runtime class guards and conversion
semantics are unchanged. The existing I/O regression now covers 8/16/32-bit
OUT instructions: seven tests pass before (8.04s) and after (9.26s).
Scoped Ruff, MyPy, and Pyright pass for compat.py. The first broader Pyright
batch has 11 errors; later batches remain uncounted.

Combined `quality-dev` passes with 2,119 tests in 147.61s, compiled-import and
architecture/ownership checks, and generated-C guards. This checkpoint is
local/shared-tree evidence, not full-suite or remote CI closure.

## CI PATH Interpreter Correction

Run 34135704289 on d60aeadc1 finished with **4,392 passed, 41 failed in
532.20s**. Missing COMP32 files and partition cache directories are no longer
the reported failure modes; the four COMP32 decompilation assertions still
fail remotely and need separate diagnosis. Vulture remains open.

Its 382 Pyright diagnostics were inflated by a regression in the interpreter
selection change: CI uses `PYTHON=python`, and Pyright interpreted the bare
argument as a repository-relative file instead of looking it up on PATH.
Local verbose reproduction confirmed `/home/xor/vextest/python` and missing
dependency search paths. Make now asks the selected interpreter for
`sys.executable` before passing `--pythonpath`. The regression covers both
explicit paths and PATH commands: one failed/three passed before, four passed
after (2.55s). A live `make pyright-files PYTHON=python` check with the venv on
PATH passes for callsite_summary.py. No missing-import suppression is used.

The AST child-field typing follow-up passes nine focused tests,
Ruff, scoped MyPy and Pyright pass, including new conditional-pair and switch
replacement/idempotence coverage. `quality-dev` also passes: 2,119 tests in
161.81s, compiled-import/architecture/ownership checks, and generated-C guards.
This is a local typing checkpoint, not remote CI or full-suite closure.

### External Toolchain Prerequisite

Inspection of the four COMP32 failure bodies identifies the immediate cause:
the mandatory MS C 5.1 syntax acceptance check reports `kvikdos not found`.
These are no longer missing binary inputs, and the log does not justify
labeling these four failures as new semantic-recovery defects.
`recompile_check.py` consumes `INERTIA_KVIKDOS_PATH` and `INERTIA_MSC51_ROOT`;
without overrides it uses workstation-specific `/home/xor/...` paths. The
hosted workflow installs neither tool. Repository secret and release listings
are empty as checked on 2026-09-07.

User input requested: an authorized private compiler artifact or an existing
self-hosted runner with the required toolchain. Do not publish proprietary
compiler files, register a runner on this workstation without authorization,
disable MS C acceptance, or turn missing prerequisites into passing skips.
Other typing and decompiler failures remain actionable while this prerequisite
is being resolved. This is not a blocker for the entire plan.

### First Pyright Batch Closed Locally

Pending changes expose existing return types and Lowering-proven carrier
classes, type the stack-name candidate list, and use the known integer key
after callsite equality succeeds. They add no recovery in postprocess.
Both compatibility modules pass scoped Ruff, MyPy, and Pyright. Forty selected
return/carrier tests pass before; both complete callsite test modules pass
179 tests in 10.00s. Eight annotation regressions pass in 14.94s.

The last first-batch error was the missing optional Unicorn import. Test/dev
extras now include unicorn==2.1.4, matching installed angr's own declared
Unicorn extra. It was installed with uv, and 65 smoke/I/O tests pass in 22.51s.
The first Make Pyright batch is green. The next, previously unmeasured batch
reports **58 errors**; later batches remain uncounted. This is not full typing
closure. The subsequent `quality-dev` checkpoint below covers these changes.

### Frontend Protocol Declarations

The next batch includes docstring-only Protocol methods that Pyright treats as
implicit `None` returns. The block factory, Capstone register lookup, decoder,
and loader-memory declarations now use explicit abstract ellipsis bodies.
Runtime implementations and frontend semantics are unchanged. Scoped Ruff
(`check --fix`), MyPy, and Pyright pass for the three touched modules.
The focused decoder/inventory selection passes 8 tests in 8.66s; this run
overlapped the edits and is not a clean before-change baseline.
A clean post-edit rerun passes 8 tests in 10.59s. `PYTHON_JIT=1
PYTHONHASHSEED=0 make quality-dev PYTHON=./.venv/bin/python` exits zero,
including 2119 tests in 105.58s, the 39-module compiled-import smoke,
architecture/ownership checks, and quality guards. The slowest test is the
RunMenu ESC-preservation regression at 45.41s. This verifies the development
gate, not the full suite or the unfinished InitMenu semantic repair.

Remote run `34137913096` on `012c0a71a` completed with **4395 passed,
41 failed, 10 warnings in 452.15s**. Ruff and Lizard passed; Vulture failed;
Pyright stopped at 9 errors in its first failing batch. These results precede
the pending first-batch and frontend declaration fixes. Neither local typing
progress nor a shorter remote runtime closes the CI or semantic acceptance gate.

### Caller-Cleanup Failure Reproduced

On `6590e6759` plus the pending shared-tree changes, the focused
`test_caller_cleanup_loop_preserves_affine_stack_pointer` fails locally:
1 failed, 7 warnings in 10.95s (`PYTHON_JIT=1 PYTHONHASHSEED=0`, pytest
`-n 7 --dist loadgroup --durations=5 --tb=short --no-header -q`).
All three stack-pointer assertions pass. The final assertion requires the
literal `sub_1020();`, but output contains
`sub_1020((inertia_eax & 0xffff) >> 8, inertia_eax & 0xffff);`.
Thus this assertion failure does not establish call loss; the call survives.
It also does not prove the emitted argument values/classes are correct.

There is independent semantic evidence against closure: whole-tail validation
rejects an uninitialized `reg+0x24:size2` read, and output retains raw FLAGS
conditions. The current architecture maps offset 0x24 to FLAGS/EFLAGS.
Postprocess discards its rejected result and emits the earlier representation.
Next: inspect flag definitions/liveness and the recovered call-storage contract
at their semantic owners, then repair the signature-sensitive assertion with
durable target/effect evidence. Do not merely relax the assertion and claim
semantic acceptance. No regression assertion was changed in this investigation.

### Optimized INC/DEC Execution Repair

The caller-cleanup probe exposed an earlier frontend defect: the optimized
INC/DEC path wrote the arithmetic register result but never called the shared
Eflags owner. A raw lift of `add sp,4; dec cx; jnz` therefore contained the
ADD flag write but no DEC flag write, so the branch executed against stale
flags. This is instruction execution, not a Rewrite recovery problem.

The simple lifter now invokes the existing INC/DEC Eflags helper before the
register update, preserving its defined-bit/liveness and carry contracts.
Eight execution regressions cover INC and DEC, zero/nonzero results with
contradictory incoming ZF, and 16/32-bit architecture address widths. All eight
fail before; all pass after. The provenance test also checks that the flag
helper receives the original operand. The focused combined selection reports
14 passed and the original caller-cleanup assertion still failed in 13.20s.
That function remains open: its FLAGS live-in validation and call argument
contract are not closed by this execution repair.

The regression module is enrolled in the regular pipeline and Make selections.
Scoped Ruff/MyPy/Pyright pass for the lifter; Ruff/MyPy pass for the pipeline
owner. The first development gate found one emulator stub without the newly
required DEC flag method (2118 passed, 1 failed); it now records the call and
asserts the original operand while retaining its disabled-affine-state checks.
The final focused frontend selection passes 30 tests in 19.70s.
The default pipeline passes all three lanes, including 2130 tests in 99.21s
and seven MS C tiny-example compile/decompile/recompile/run checks. The final
development gate also exits zero: 2130 tests in 95.65s plus compiled-import,
architecture, ownership, and generated-C quality guards. These gates ran on
the shared tree, including the separately pending InitMenu changes; they are
not a clean-commit full-suite result. The full suite is not yet green.

### Immediate Bit-Group Dispatch Contract

Pyright identified a genuine call-contract mismatch in `Instr16.code_0fba`:
the error callback occupied the required opcode-string parameter. Valid
selectors still dispatched, but invalid selectors raised a generic error
containing a function representation instead of invoking the intended error
handler. The 32-bit sibling already passed the opcode and callback correctly.
The 16-bit handler now supplies `"0x0fba"` explicitly.

Parameterized tests exercise all eight selectors for both operand widths.
Before: four invalid 16-bit cases fail, 16 tests pass (8.72s). After: all 20
tests pass (9.25s), including exact error arguments and valid-handler identity.
The module is enrolled in regular pipeline and Make selections. Existing VEX
boundary adapters now precede LOOP/IDIV dynamic-member access, and an obsolete
class-level typing suppression was removed. Scoped Ruff, MyPy, and Pyright
pass for `instr16.py`; no instruction arithmetic was changed by those adapters.
`quality-dev` exits zero with 2150 tests passed in 103.08s, compiled-import,
architecture/ownership, and generated-C quality guards. This shared-tree gate
does not close the full suite; the default external pipeline was last run for
the preceding INC/DEC repair, not repeated for this dispatch-only change.

Remote run `34139402208` on `6590e6759` confirmed first-batch Pyright closure
(zero errors), then stopped at 55 errors in the second batch. Pytest remained
4395 passed, 41 failed in 466.47s. It predates the INC/DEC execution repair;
neither this count nor the local scoped fixes establishes current full closure.

### Read-Only Callsite Summary Contract

The validation classifier only reads `helper_calls`, but its Protocol declared
a writable attribute incompatible with the frozen production summary. It now
declares a read-only property. No validation acceptance/refusal logic changed.
The five classifier/structuring-consumer tests now use the real
`X86_16TailValidationSummary` instead of mutable summary stubs. They pass before
(9.12s) and after (14.76s); all five are enrolled in regular pipeline/Make gates.
Scoped Ruff, MyPy, and Pyright pass for the validation owner. The four summary
compatibility diagnostics disappear from the structuring consumer, which still
has six separate callback/collection-inference errors. This is not global
typing closure. `quality-dev` exits zero with 2155 tests in 120.63s and the
compiled-import, architecture/ownership, and generated-C quality guards. The
default external pipeline was not repeated for this typing-only change.
This checkpoint remains local pending the next verified commit batch.

### Verified Remote Baseline: 2026-09-07

Run https://github.com/xor2003/inertia/cli/actions/runs/34141065397
on `511b0d3cb` completed with failure. Pytest: **4425 passed, 42 failed**
in 457.85s. Pyright: first batch zero errors, second batch 49 errors.
Vulture reports unused interface parameters `propagator` and `timeout_millis`.
The failed workflow steps are Pyright, Vulture, and Pytest.

Of the 42 pytest failure sections, 35 contain `kvikdos not found`. This is
an environment blocker, not evidence that those tests have no other defects.
The remaining seven concern the DOS LoadProgram wrapper, InitMenu, two
PercolateDown regressions, InitBars, INC/DEC typed-JCC context, and caller
cleanup loop stack-pointer preservation. Diagnose them independently.

CI closure requires provisioning the DOS execution/compiler prerequisites
without publishing proprietary compiler files, correcting remaining code and
typing defects, and a successful remote run of all required checks. Do not
skip these tests or weaken validation to obtain a green badge. Local focused
and shared-tree quality gates are not substitutes for that remote result.

### Indexed Refusal Typing Checkpoint

The latest local `quality-fast` run fails on 129 MyPy diagnostic lines. Four
come from reusing one loop variable for IR refusals and Alias refusals in
`lowering/indexed_address_parity_inventory.py`. Distinct typed loop variables
remove that accidental type conflict without changing diagnostic classification.
Scoped Ruff `check --fix`, MyPy, and Pyright pass. All six focused inventory
tests pass (8.40s), including both typed-refusal families. The global gate has
not been rerun after this change; do not subtract four and report a verified
new global total. This checkpoint is local and does not close remote CI.
