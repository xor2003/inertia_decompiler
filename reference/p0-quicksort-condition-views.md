# QuickSort Condition Views

## Scope And Contract

The 2026-09-13 original-failure refresh reports two QuickSort regressions,
named and sidecar-free, with matching condition-view discrepancies. Fix the
authoritative typed owner; do not erase semantic casts from fingerprints or
accept mismatches by function address.

DoD: both live cases pass whole-tail validation, strict C recompilation and
their call/control-flow assertions, with focused valid and refusal controls.
Failure: dropping a signedness/width conversion without proof, mutating the
live AST in validation, accepting changed storage, or weakening the guard.

## Composite Guard Checkpoint

### Mandatory Coverage Gate

Final branch validation now consumes published Structuring condition
obligations and rechecks their owners on the current AST. It does not trust
the old `complete` flag or a later reduced fact inventory. The authoritative
Structuring classifier accounts for single conditions and composite provenance;
validation neither reconstructs predicates nor changes generated C. Before
Structuring publishes obligations, intermediate snapshots retain their existing
predicate-only validation scope. This gate covers missing known condition
owners, not every possible unresolved CFG branch or incorrect predicate.

New missing-owner controls failed before the fix (2 failed, 3 passed, 6.13s).
The extended branch-validation controls pass (25), covering stale complete and
incomplete snapshots, restored ownership, composite provenance and a reduced
fact inventory. Live sidecar-free QuickSort now exits nonzero and explicitly
reports missing owners at JCCs `0x10d67`, `0x10d79`, `0x10d8e`, `0x10da0`, with
their block addresses. This replaces a false passing validation verdict, not
the missing typed materialization itself.

The source-stable routine pipeline completed with no stage timeouts:

- Preliminary contracts: 268 passed, 16.33s.
- Curated pytest: 5,159 passed, 7 failed, 273.42s.
- QuickC: `hello`, `add`, `whsum` pass; `args` fails (stage 57.074s).
- MS C tiny: `compare16`, `storage_classes`, `function_pointers`,
  `pointer_memory`, `scalar_types_io` complete their round trips;
  `simple_control` and `loops_jumps` fail (stage 178.017s).

The curated failures are the nested-tag JCC unit test and live PercolateUp,
InitBars, RunMenu, LoadProgram, InBoxLng and SetGear cases. Subsequent repair
preserves the existing direct `1 && predicate` / `0 || predicate` single-owner
case without admitting wrapped compound or statement-bearing predicates.
The complete JCC/typed-consumer and coverage regression set then passes:
161 tests, 7.39s. The six live failures and external failures remain unclosed;
the broad pipeline was not rerun after this neutral-root refinement.

New helper/test Ruff and focused MyPy pass; full architecture passes after
registering the helper in promoted gates. Global MyPy reports 25 diagnostics
across `omf_pat.py`, `scripts/report_compiler_matches.py` and
`scripts/verify_borrow_real_mode.py`. `quality-fast` remains red on lint;
its 39-module mypyc import smoke passes. The touched legacy branch validator
still has five Ruff complexity/Boolean-expression findings. No Step 9 or
whole-suite completion is claimed.

Evidence under `/home/xor/.cache/`: `step9-condition-coverage-{before,after,live,
pipeline,quality,mypy,focused-mypy,architecture,ruff}.log` and
`step9-neutral-root-after.log`. New tests are enrolled in routine/changed-file
gates; the new owner is enrolled in typed/Ruff gates.

### Prior Localization

An isolated, uncached 2026-09-13 trace after both single-fact consumer vetoes
shows two logical conjunctions surviving typed, JCC, chain, loop and cleanup
materialization. The pivot comparisons and negated break polarity now survive.
The latest named and sidecar-free live run still reports two behavioral
failures, alongside 48 passing focused tests (50.64s); neither function is fixed.

The oracle now reports the case index, harness line and failed invariant.
Current generated C fails case 8, `{0, 3, -2}`, at sorted-order verification.
Its comparisons reconstruct the pivot word from unsigned bytes without the
signed-word interpretation. In a diagnostic-only experiment, adding a signed
word conversion at those two comparisons makes all ten cases pass. This is
localization evidence, not a production text repair or full semantic proof.
Fix typed constituent-condition materialization, not rendered C or declarations
by sample-specific matching. The incomplete condition evidence closure must
also become visible to mandatory validation rather than accepting surviving
conditions alone.

A source-oracle mutation making the pivot unsigned is now rejected. Mutation
tests require case/line/invariant diagnostics; no existing acceptance was
weakened. The six oracle controls and compound-condition controls pass together:
28 passed in 10.16s. Focused Ruff and the architecture check pass. Broad gates
are not refreshed and no original failing case is newly counted closed.

Artifacts under `/home/xor/.cache/`: `step9-quicksort-double-veto.c`,
`step9-quicksort-double-veto.log`, `step9-wrapped-jcc-after.log`,
`step9-quicksort-diagnostics.log`, and `step9-double-veto-architecture.log`.

## Nested Identity Projection

Validation's `project_identity_semantic_casts_8616` stopped at a non-identity
outer semantic cast. Consequently a required conversion around subtraction
prevented traversal to an inner variable cast already proven identical to
the current declaration. Binary-operation traversal alone was insufficient.

The comparison-only projection now visits the outer cast's operand, using
the existing declaration/width/signedness proof for inner identities. It
copies the outer node only when an inner projection changes, preserving the
required conversion, metadata and original AST. No generated C is rewritten.

Before: the new two-case regression produced one pass and one failure in
6.75s. After: 27 related tests passed in 15.78s. Controls retain the inner
conversion when the current declaration has different signedness, preserve
the outer byte conversion and verify the original fingerprint is unchanged.
The test module is already in the routine pipeline. Ruff and project MyPy
pass after the change. Three adjacent Ruff findings were repaired without
changing their conditions or test expectations.

Live results: both QuickSort cases still fail, in 67.06s. Final diagnostics
now report one control-flow mismatch, the indexed-memory comparison, rather
than the earlier indexed-memory and subtraction mismatches. Earlier-stage
diagnostics can still mention subtraction; this is not function acceptance.

Remaining investigation: expected memory-address indexes include an explicit
signed-word to unsigned-word semantic conversion; the final storage view
does not. Establish the actual declaration, offset-width and typed index
evidence before changing either lowering or validation. A signed comparison
of loaded bytes does not itself prove the index conversion redundant.

Evidence: `/home/xor/.cache/step9-nested-identity-before.log`,
`step9-nested-identity-after.log`, `step9-nested-identity-live.log`, and
`step9-nested-identity-mypy.log` in the same directory. Broad pipeline and
full-suite acceptance have not been refreshed for this change. No original
failure count reduction is claimed.

## Load-Site Index Value Preservation

A focused runtime-helper regression confirms another defect in Types/Lowering:
the load-site join proved the stack identity but then rebuilt a bare stack
variable, discarding an explicit unsigned view from the matched address.
The join now returns the exact matched index together with its site evidence;
the consumer uses that expression without changing its conversion. The raw
instruction-address fallback still uses its separate stack-source path.

Before: the signed-stack/unsigned-address-view regression fails because the
materialized array index is a bare signed CVariable. After: 14 coordinate and
runtime-helper tests pass in 6.66s, retaining missing-coordinate and segment
conflict refusals. The 180-test segmented-load module passes. Both live
QuickSort cases still fail with the same final indexed comparison mismatch
(combined run 78.29s). This proves the helper defect, not the remaining live
root cause. Investigate the raw load-site fallback and other index producers.

Project MyPy passes. Ruff fixed one import order issue and reports 191
remaining findings across touched legacy files; no lint-clean claim. The
coordinate regression module is now explicitly enrolled in the routine
pipeline. Logs are `step9-index-view-{before,after,live,mypy,ruff}.log` under
`/home/xor/.cache/`. No QuickSort or Step 9 completion is claimed.

Broad gate follow-up: routine pipeline's preliminary contracts pass (268),
then curated pytest reports 5,109 passed / one failed in 272.29s. QuickC
passes in 35.814s and all configured MS C tiny full round trips pass in
93.745s. The sole curated failure requires exactly `outtext(aszMenu[i])`;
isolated output instead contains `outtext(aszMenu[(unsigned short)i])` with
an `unsigned short i` declaration. Validation already passes. The assertion
now reuses that test's existing declaration-dependent equivalent index list,
retaining the exact call, array and index requirements. No generated-C change.

After quality-fast finished, a sequential focused rerun passes all 15 InitMenu,
coordinate and runtime-helper cases in 11.02s. Quality-fast remains red on lint
debt; its 39-module mypyc import smoke passes. A first focused run overlapped
that quality gate and is superseded by the sequential rerun. No fresh complete
pipeline success is claimed after the assertion adjustment. Evidence:
`step9-index-view-pipeline.log`, `step9-initmenu-index.c`,
`step9-index-view-quality.log`, `step9-index-view-initmenu-final.log`.

## Raw Load-Site Index Contract

The raw fallback also ignored `index_stack_width`, accepting same-offset
storage of a different width and borrowing signedness from the C declaration.
Six direct fallback controls initially produced five failures / one pass in
6.40s. The existing indexed-load subview owner now consumes exact word-source
evidence, checks physical storage and emitted integer width, and applies an
unsigned semantic word view for signed storage. Unknown types and non-word
sources refuse; wider address-domain recovery is not inferred here.

Four additional refusal controls cover absent, bottom, pointer and byte types.
The older positive raw-load fixture now explicitly supplies its required word
type; the separate unknown-type control requires refusal. All 194 subview and
segmented-load tests pass in 16.04s. Focused module/test Ruff passes; project
MyPy passed after the production change. Both QuickSort cases still fail with
the same final indexed-comparison mismatch (combined earlier run: 196 passed,
three failed in 74.51s, including the subsequently corrected untyped fixture).

The subview test module is now explicitly enrolled in the routine pipeline.
Broad gates are not refreshed after this raw-index change. Next capture the
actual live producer path for the failing QuickSort comparison before another
repair; the two proven load-site bugs did not close its remaining mismatch.
Evidence: `step9-raw-index-{before,after,final,mypy,ruff}.log` in the cache
directory. No original-failure reduction or Step 9 acceptance is claimed.

## Live Producer And Declaration Lifecycle

Two uncached, in-process diagnostic runs identify the actual lifecycle:
indexed load sites initially produce unsigned CVariable indexes. Later
`apply_condition_argument_types_8616` changes those shared variables to
signed arguments. The earlier address value interpretation was not retained.
The observational probe lives outside the repository and never rewrites C.

Types/Lowering now preserves a matching direct integer array index's previous
view before refining the shared declaration. Offset and scalar/physical width
must match; existing explicit conversions remain untouched. Repeated replay
does not add another wrapper. This preserves existing indexed-access semantics
at the mutation boundary, rather than guessing new semantics in Rewrite.

With that repair, both emitted QuickSort comparisons contain unsigned index
casts, but validation initially still reported bare indexes. A second focused
regression proved that `_global_indexed_ds_deref_fingerprint_8616` and its
scaled-expression helper stripped semantic casts. Those value-fingerprint
paths now strip only cosmetic casts; converted and bare signed indexes must
remain distinguishable. No global cast-stripping relaxation was introduced.

Latest live run: both QuickSort cases pass return-code, clean-output and
whole-tail validation assertions, then fail later output-shape assertions.
The sidecar-free test demands an early-return layout; the named test demands
an exact pivot assignment. The run reports 32 passed / two failed in 49.14s.
Do not count either as fixed until those differences are checked against
source behavior and strict recompilation. No output assertion was removed.

Latest focused controls: 34 passed in 6.80s, including wrong offset/width and
non-mutating fingerprint checks. Project MyPy passes; Ruff reports 68 findings
in the touched legacy modules/tests. The condition-argument test module is now
explicitly enrolled in the routine pipeline. Broad gates require refresh.

Evidence under `/home/xor/.cache/`: `step9-quicksort-producer.log`,
`step9-quicksort-refinement.log`, `step9-argument-index-before.log`,
`step9-index-fingerprint-{before,after,mypy}.log`,
`step9-index-lifecycle-{controls,ruff}.log`. Next inspect the emitted pivot and
control-flow behavior, then run the broader gates without overlapping edits.

## Behavioral Failure Despite Passing Validation

The subsequent source comparison disproves the interpretation that only
formatting remains. Generated QuickSort has lost both array-versus-pivot scan
comparisons. Its remaining scan break guards are reversed (`iDown > iUp`),
so a nontrivial partition repeatedly swaps without advancing. The unchanged
output passes strict gcc syntax and reports `validation=passed`, but fails
compiled execution. This is a semantic defect and a validation coverage gap.

The new `x86_16_quicksort_behavior.py` harness compiles unchanged generated C
with `-std=c11 -Wall -Wextra -Werror -O2`. It checks ten three-element inputs,
including all permutations, signed bytes and duplicates. It requires sorted
values, preserved item identities, correct paired swap/draw arguments and
preserved SI/DI runtime state. A bounded swap budget exposes repeated partition
work without waiting for a long timeout. This is bounded regression coverage,
not exhaustive equivalence, and does not replace existing validation/assertions.

DoD: both generated variants pass this runtime contract, strict compilation,
whole-tail validation and their existing semantic assertions; source scan
comparisons survive. Failure: accepting sortedness without item preservation,
lost/reversed guards, unbounded partition work, wrong pointers or draw arguments,
or treating compiler rejection as a successful runtime mutation test.

The source-derived reference passes all inputs. Four mutations (lost scan
comparison, changed pivot, wrong draw arguments and wrong pivot swap) compile
but fail at runtime. All five oracle tests pass in 1.08s. The live named and
sidecar-free tests now invoke the oracle before their existing shape checks:
both fail at runtime; 65 related/ownership checks pass in 9.29s. The helper,
mutation tests and ownership are enrolled in Make and the routine pipeline.
Focused Ruff passes. No original failure is closed.

Evidence: `step9-quicksort-current.c`, `step9-quicksort-current.log`,
`step9-quicksort-oracle-{final,live}.log`, and
`step9-quicksort-behavior-gate.log` under `/home/xor/.cache/`.
Next priority: identify the pass deleting/inverting the scan conditions and
why whole-tail validation accepts that loss. Do not relax the existing output
assertions as cosmetic until the behavior is actually repaired.

## Provenance Preservation Checkpoint

2026-09-13: current work supersedes the earlier behavioral blocker above.

- IR now rewires overlapping prefixes through a proven canonical suffix-owner
  chain. This removes a false predecessor and its spurious SSA phis without
  relaxing phi or successor evidence.
- Structuring now materializes both compound pretest guards from their complete
  typed conditions and CFG, retaining executed bodies and refusing effectful or
  ambiguous exits. It records precision evidence and closed ownership counts.
- Validation compares raw current fingerprints with the same compacted token
  format used when recording precision evidence.
- Sidecar-free QuickSort passes semantic validation, strict gcc and the ten-case
  signed sorting/call-effect oracle. Its old shape assertions remain unresolved.
- Named QuickSort's final AST lost seven condition owners because the legacy CLI
  simplifier rebuilt binary operations without tags. Preserving those existing
  tags is metadata retention, not semantic recovery. The focused regression
  fails before the fix and passes afterward; routine Make/pipeline and changed
  ownership inventories now include it.

Named QuickSort still fails two predicate precision checks. The observed
Structuring fingerprint includes signed word casts on the two scan bounds;
the final fingerprint lacks those casts after declaration-identity cleanup.
The complete compound predicate provenance survives now. The next obligation
is typed per-constituent comparison evidence, including negative signedness and
changed-operator controls. Do not trust provenance alone or weaken validation.

Verification artifacts under `/home/xor/.cache/`:

- `step9-cli-provenance-before.log`: 1 failed / 2 passed, 6.82s; missing tags.
- `step9-cli-provenance-after.log`: 3 passed / 1 live failure, 56.65s; the named
  failure changes from seven missing owners to two predicate mismatches.
- `step9-quicksort-tags-fixed.{c,log}`: isolated-cache in-process reproduction,
  exit 4; complete guard provenance and the remaining precision mismatch.
- `step9-cli-provenance-ruff.log`: 99 CLI legacy findings; no lint closure.

These are focused results, not a refreshed full suite or Step 9 completion.

### Integer Views And Focused Acceptance

The initial attempt to project only currently redundant casts at both endpoints
was rejected: declarations refine after recording, so the two observations can
produce different fingerprints even with unchanged value interpretation.

Validation now retains its original exact evidence and additionally records an
immutable integer-view token. A cast of a variable to the same integer width
records destination width/signedness and storage identity; a bare variable uses
the authoritative emitted declaration type from Lowering. Thus an explicit
signed word view can match a later signed word declaration without ignoring
signedness. Other casts retain exact fingerprints. Operators and the full
logical-expression structure remain in the token. No generated C is modified
by this validation comparison.

Eight controls cover unchanged/refined declarations, identity/non-identity
casts, and changed comparison operators. The original identity case failed
before repair. Both QuickSort live cases now pass validation, strict gcc and
compiled behavior. The oracle adds empty/singleton range checks, including no
calls, no item mutations and preserved GP registers. Shape assertions no longer
require one guard polarity or scan-break layout; required calls, argument
classes, recursive bounds and pivot initialization are still checked.

Artifacts under `/home/xor/.cache/`:

- `step9-precision-identity-before.log`: 1 failed / 16 passed, 9.74s.
- `step9-precision-identity-live.log`: unsuccessful projection-only experiment,
  17 passed / one live failure, 61.42s; do not repeat it.
- `step9-integer-view-live.log`: 26 passed / one obsolete pivot-index assertion,
  34.57s. Named generated C passed compiled behavior before that assertion.
- `step9-quicksort-final-focused.log`: 37 passed / one obsolete pivot-copy
  assertion, 33.35s. Both generated bodies passed compiled behavior.
- `step9-quicksort-acceptance.log`: 38 passed, 9.00s; warm cached live output.
- `step9-quicksort-focused-mypy.log` and `step9-quicksort-architecture.log`: pass.

Broad gates and remaining original failures still prevent Step 9 completion.

### Broad Refresh

`step9-quicksort-pipeline.log` records 268 preliminary passes, followed by
5,201 curated passes / 10 failures in 262.73s. The three unit failures are now
corrected: integer-view fingerprinting is lazy when no such precision evidence
exists (preserving bound-call callback behavior), and the Structuring ordering
fixture supplies its required function address. The related 74-test rerun passes
in 9.42s (`step9-pipeline-followup-tests.log`). Do not report the whole curated
lane as green: its seven live failures remain unclosed:

- PercolateUp caller cleanup;
- binary-only InitBars stack array;
- binary-only RunMenu Escape;
- InitMenu pause guard;
- InBoxLng compiled behavior;
- COD LoadProgram segment stores;
- SetGear CLI guard recovery.

MS C tiny remains 5/7 (`simple_control` and `loops_jumps` fail); QuickC also
fails. Lane times were 263.303s curated, 46.511s QuickC, and 145.524s MS C tiny.
`quality-fast` remains red. The new composite guard's redundant cast reported
by promoted MyPy was removed; `step9-pipeline-followup-mypy.log` records the
full MyPy inventory's 25 errors: 22 in `omf_pat.py`, one in
`scripts/verify_borrow_real_mode.py`, and two in
`scripts/report_compiler_matches.py`. No suppressions were introduced.

Next investigate InitMenu's precision mismatch: the diagnostic's normalized
current predicate equals the displayed precision candidate, so compare the raw
token path against the project-specific fingerprint normalizer. Do not remove
the compact-token fix or accept provenance without predicate equality.

### InitMenu Storage-View Precision

The isolated-cache producer trace in `step9-initmenu-precision.log` confirmed
the precise mismatch. Current AST fingerprints use
`And(global:0x132,const:65535)` and `Shr(global:0x132,const:16)`; recorded
precision uses `ds_global:0x132` and `ds_global:0x134`. The existing final branch
normalizer already proves these storage views equivalent. Precision matching
now also tokenizes that normalized current predicate before comparing it with
recorded evidence, preserving the exact and typed-integer matching paths.
There is no new global recovery and no provenance-only acceptance.

Eight controls exercise the correct pair and corrupted mask, shift and base
address at fingerprint limits 16 and 512. Both positive cases failed before
repair (`step9-global-view-before.log`: 2 failed / 27 passed in 12.18s). After
repair the live InitMenu pause-guard regression and related validation tests
pass (`step9-global-view-live.log`: 57 passed in 40.11s; live body 29.55s).

The last external failures have different diagnostics: SIMPLE `switch_fold`
loses the `const:10` return, while LOOPS `nested_loops` loses required condition
owners and later exposes unresolved stack carriers. Do not assume fixing this
storage-view comparison closes either external lane.

The refreshed `step9-initmenu-pipeline.log` confirms 268 preliminary passes and
5,213 curated passes / six failures in 306.96s. The remaining failures are
PercolateUp, InitBars, RunMenu, InBoxLng, LoadProgram and SetGear. QuickC remains
3/4 (`args` fails); MS C tiny remains 5/7 (`simple_control`, `loops_jumps` fail).
Measured lane times: curated 307.509s, QuickC 54.635s, MS C tiny 193.819s.
`step9-initmenu-quality-fast.log` remains red on Ruff; promoted MyPy and the
39-module mypyc import smoke pass. This is a routine-gate refresh, not the
complete pytest collection or Step 9 completion.
