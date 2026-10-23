# Scoped returning-stack effects

## Purpose and current boundary

Alias may prove a returning SP displacement under an authenticated invocation
context even when no context-free displacement is available. This is a separate
proof surface, not permission to relax universal coverage or substitute a
convenient execution environment. The scoped Alias owner and dual-context
Semantics adapter and IR/SSA carrier transport have passed focused independent
review. Caller Alias and Types consumption remain separate acceptance
obligations.

Current independently reproduced evidence is the declared-environment fixture
in `.cache/devin-prompts/local-call-stack-proof-20261020/parent-review.json`:
15 reproduced probe steps, joint obligation counts 2/2/2/2/0, scoped coverage
accepted, context-free coverage refused, existing SP consumer refusing. The
fixture declares SS/SP, return bytes and an environment. It does not establish
those inputs for a different binary or a missing startup/service context.

## Focused review checkpoint

The scoped Alias owner now has independently replayed positive and negative
native controls: 13 tests passed in the first adversarial review, including
foreign-project rejection, universal-coverage refusal and fabricated transfer
rejection. The source-drift control in that review used a second project;
it does not establish in-place revocation of the original retained scope.
A followup added actual mutation of the original project memory, separately
for caller and callee bytes, while retaining the original scope and result.
Independent replay passed all 15 controls and lint; both mutations revoked
accessors and fresh production. Receipts:
`.cache/devin-prompts/scoped-stack-freshness-20261020/parent-review.json`.
Continuation-only views and declared-entry-link seed routes remain untested.

The supporting constant-state merge retains contradicted bits as unknown
throughout a seed batch, and accepts compatible wider views by comparing only
known overlap. Four failing controls were reproduced before repair; 212
stack/constant regressions and another 101 disjoint supporting regressions passed
on the repaired source. These focused results do not establish caller integration
or whole-function equivalence. The scoped test is admitted to the decompiler
routine catalog and call-stack ownership selector. Three stale catalog-test
expectations were corrected without relaxing exact selection checks. The
catalog gate is now green: the zero-count repeat failure was traced to definite-write
classification discarding REP metadata. The typed prefix now survives and
repeated comparisons no longer kill prior flags without count evidence. Native
lookahead is also bounded by max_inst; a suffix outside the lift cannot justify
flag deletion. The resolved xfail was removed, not bypassed. Both Python and
Cython runs passed all 140 selected flag/CFG/native/binary controls; catalog
checks passed all 71 tests. Full pipeline acceptance remains open. Receipts:
`.cache/devin-prompts/repeat-flag-preservation-20261020/parent-review.json`.

## Required proof contract

A consumed effect must satisfy all of the following at the time of projection:

1. Its retained publication was accepted with typed, closed evidence counters.
2. Coverage is current for the offered scope.
3. The scope belongs to the exact callee body, source project and physical CALL
   chain whose entry state is used. A numeric head address alone is insufficient.
4. The authenticated entry state, live effective blocks and returning transfers
   still reproduce the retained proof. Source, view, scope, or caller-input drift
   revokes the result.
5. Every live returning path has a proven compatible displacement; unresolved
   effects or unproved paths remain refusals. Unknown does not mean zero.

Condition 2 does NOT imply condition 3: the universal branch of
`IRBoundaryCoverageResult8616.complete_for` deliberately ignores an offered
scope. A new scoped consumer must authenticate its entry-state binding even
when supplied with otherwise complete universal coverage.

The normal context-free accessor must not return a conditional displacement.
Only an accessor that consumes and revalidates the offered invocation context
may project that displacement. Retained observed values are diagnostics, not
authority. Replacing a result's counters or transfer tuple must not mint proof.

## Alias state and control flow

Numeric register constants and entry-SP-relative coordinates are different
facts. AX=0 does not mean AX equals entry SP. Seed only the numeric facts
transported by the authenticated chain, preserving lane widths and unknown bits.
Use the canonical constant-flow transfer and existing stack-coordinate owner;
do not create a second ad hoc evaluator.

At a CFG join, keep only facts common to all reached predecessors. Distinguish
an unvisited edge from an analyzed unknown state. Modeled partial writes may
retain only bits justified by their transfer; unmodeled, wide or overlapping
writes must kill affected evidence. Calls and selector/memory effects retain
their existing proof requirements.

Use live effective blocks from the authenticated scoped view. Do not delete
pending markers, mutate the shared raw artifact, or publish a scoped projection
into the context-free IR registry. An infeasible path may be excluded only by
current scope evidence; a path that merely lacks proof may not be called
nonreturning.

## Independent acceptance controls

| Control | Required outcome |
| --- | --- |
| Native returning body with proven incoming AX=0 | Correct scoped displacement, closed counters |
| Same returning arithmetic with a different authenticated AX value | Different correct displacement; no hardcoded +2 |
| Missing incoming numeric value | Typed refusal; no zero default |
| Unknown overlapping register write before SUB | Lost constant unless the canonical lane transfer proves it |
| Conflicting predecessor constants or backedge state | Must-state refusal when the returning displacement is no longer proven |
| Absent, foreign, replaced or stale scope | No displacement |
| Universal coverage paired with an unrelated scope | Refusal despite universal coverage being complete |
| Same head address from another source project | No borrowed entry-state authority |
| Changed caller input or callee bytes after publication | Retained result no longer projects |
| Forged retained count/transfer tuple | No accepted projection |
| Scoped-dead block with pending markers | Raw artifact and markers preserved; only authenticated live view is consumed |
| Context-free getter on a scoped-only success | Refusal |

## Downstream integration obligations

The existing `CalleeStackCallResult8616` consumes a universal Alias body proof
and authenticates physical CALL identity. Do not place a scope-dependent scalar
inside this old contract while leaving its consumers unaware of the scope.
A scoped CALL result must carry the caller-to-callee chain and revalidate the
appropriate consuming caller context as well as the callee proof.

The same restriction applies to first-class IR call-stack fields, SSA/native
copies, serialization, caller stack-position solving, argument-stack-top
materialization, diagnostics and lifecycle readiness. Binding an effect to call
bytes alone does not make an assumption about caller entry state universal.
If a serialized surface cannot retain and reauthenticate the scope, restoration
must return a typed non-result, not a complete scalar fact.

Whole-function acceptance still requires tail validation, surviving call and
argument semantics, applicable generated-C compilation/execution, and the
integration gates in `decompiler-evidence-improvements.md`. A positive Alias
fixture or a worker handoff is not that acceptance.

## Integration constraint after the Alias review

A callee invocation chain retains its parent caller domain and physical CALL
row. This is available caller evidence, but possession of the chain does not
by itself authorize a different caller consumer. A scoped Semantics adapter
must authenticate the offered caller domain against that retained parent as
well as authenticate the callee domain against the body proof. Matching numeric
callsite addresses is insufficient. Retain the independently decoded CALL
coordinates and source identity, and revalidate both domains on projection.

Keep the universal `CalleeStackCallResult8616` and
`IRCallStackCoordinates8616.net_sp_delta` context-free. A scoped sibling must
publish only through scope-taking accessors; copied or serialized carriers
that cannot retain that authority must refuse. The next implementation step
is a scope-aware coordinate carrier and coherent IR/SSA transport, followed
by caller-Alias consumption. Do not pass a scoped scalar
through an existing universal field as an intermediate implementation.

## Semantics adapter checkpoint

`inertia/semantics/scoped_callee_stack_effects.py` retains both caller and
callee domains, requires shared authenticated provenance for both offered
scopes, and rechecks the physical CALL plus the Alias body proof on access.
Context-free completion remains false. Native controls cover distinct numeric
seeds, absent/foreign/swapped scopes, wrong physical coordinates, retained
source mutation, fabricated fields and pending coverage. Independent combined
replay with Alias and universal call-coordinate regressions passed 77 tests;
iteration lint passed. All 15 existing Alias tests preserved their assertions
when their native setup moved to `tests/support/scoped_stack_fixture.py`.

The new test and helper are connected to call-stack ownership selection and
the routine component catalog. This is a verified adapter, not integrated
caller-SP recovery or a TYPES.EXE improvement. Receipt:
`.cache/devin-prompts/scoped-stack-semantics-20261020/parent-review.json`.

## IR/SSA carrier checkpoint

The scoped sibling now travels through `IRCallStackEffect8616`, native detach
and SSA effect-site collection without populating universal SP fields. Parent
review reproduced and fixed missing accessor checks: coordinate/effect
agreement and coordinate-source census replay are required on every access.
Parent review also added the omitted field to native schema comparison; native
copies retain identical scoped authority, while removed/replaced carriers
refuse binding. The original universal copy regression passes again.

After those repairs, 137 native transport/source-binding/coordinate controls
passed on Cython, and 71 catalog controls passed. New producers and tests are
admitted to ownership/routine lists; all four scoped implementation sources are
included in the live decompilation-cache source fingerprint. Serialization
checks cover diagnostic export and authority-free defaults, not a general
roundtrip loader. The next step is caller Alias consumption under explicit
scopes, preserving the registered raw artifact and requiring the actual
consumer CALL to match the retained source. Receipt:
`.cache/devin-prompts/scoped-stack-transport-20261020/parent-review.json`.

## Caller solver authority review

Parent review reproduced foreign-artifact acceptance in the first scoped
caller solver: a context proved for one native project with AX=4 was applied
to another project's AX=0 artifact, producing SP deltas -4 and -2. The common
solver entry point must authenticate its supplied artifact and every overlaid
CALL, not only the CALL requested by a position accessor. This implementation
is not accepted until that negative control refuses and valid independently
bound multiple CALLs still work. Evidence and bounded repair task:
`.cache/devin-prompts/scoped-caller-stack-20261020/parent-foreign-overlay-probe.log`
and `.cache/devin-prompts/scoped-caller-auth-20261020/TASK.md`.

The new caller test module is admitted to the routine catalog and ownership
selection; 81 catalog/selection tests and iteration lint passed. This proves
test admission, not semantic acceptance.

Downstream integration must preserve scoped authority through the call plan,
`CallStackInputBinding8616`, and `EntryStackPointerUse8616`, then independently
re-prove it in Validation. The entry capture currently admits plain universal
positions only; adding scope to the call marker alone is insufficient. Every
retained capture use must be revalidated, and conditional success must retain
its invocation-domain restriction rather than become universal validation.
Detailed source review and required positive/negative controls:
`.cache/devin-prompts/scoped-caller-auth-20261020/PARENT_CAPTURE_INTEGRATION.md`.

The initial sequential diagnostic omitted required producer context: the
fixture removes its installed invocation source before returning. With that
same authenticated source installed through the existing API, the public
prefix-preservation collector supplies evidence and the second declared-entry
domain proves complete. No production change was required for that step.
Evidence: `.cache/devin-prompts/scoped-caller-auth-20261020/`
`parent-sequential-source.log`. The earlier bare/source-free refusals are
retained as diagnostic history, not evidence that sequential execution is
unsupported. Full sequential carrier-to-solver and executable acceptance
are checked separately.

## Caller authority repair checkpoint

The foreign-artifact repair now has an independent native 12-test pass with
unchanged source hashes and a clean iteration lint. The worker's expanded
68-test run also passed. Each bound call authenticates the exact caller
artifact and physical CALL before the common solver consumes its delta;
distinct calls retain distinct callee-domain proofs under shared caller
entry provenance. The multi-call positive uses disjoint branches with equal
deltas, and does not close sequential domain transport.

Receipt: `.cache/devin-prompts/scoped-caller-auth-20261020/parent-review.json`.
The next bounded implementation task carries this authority through Lowering,
entry capture, argument replay and independent Validation, with generated-C
execution and absent/foreign/stale-context controls. Task and baseline:
`.cache/devin-prompts/scoped-stack-lowering-20261020/`. Full pipeline and
whole-function acceptance remain outstanding.

## Sequential distinct-effect control

The corrected native control now carries authenticated public prefix
preservation through the second entry domain, builds each call's own scoped
carrier and consumes both through the shared Alias solver. The first CALL
has net delta0; the second has net delta-4. Block exits are 0, -4, and -2
after the caller RET. Independent run exited0; receipt:
`.cache/devin-prompts/scoped-caller-auth-20261020/parent-sequential-review.json`.
This closes the earlier missing-context diagnostic and demonstrates distinct
per-call effects without a production resolver change. Permanent routine
regression admission is still pending. The selector fixture is not a
whole-function executable equivalence result; Lowering/Validation transport
and a returning native-to-generated-C acceptance fixture remain required.
