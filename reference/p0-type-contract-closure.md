# Type Contract Closure

## Split-Return CFG Coordinates (2026-09-08)

Reason: ordering and equality recovery validated optional branch addresses
through an aggregate `all(...)` check, then converted the still-optional fields
with `int(...)`. The runtime refusal existed, but the proof did not survive
the type boundary. Nineteen MyPy diagnostics described this one repeated gap.

Types/Lowering now projects each condition to a checked integer triple
(block, taken, fallthrough) once. Both decision-graph paths consume those typed
coordinates. No cast, suppression, guessed target, or new semantic recovery
was introduced. The production module shrank from 344 to 340 lines.

- DoD: preserve accepted ordering/equality CFGs and transparent paths; refuse
  every missing graph coordinate; scoped type/lint checks pass; the relevant
  global diagnostics disappear.
- Definition of Failure: accepting missing targets, replacing them with zero,
  suppressing type errors, changing branch direction, or weakening CFG proof.

Verification: 17 split-return tests passed in 10.06s with seven dependency
warnings. Nine cases independently remove each coordinate of the three-node
ordering graph. Existing real-lifter strict/equality tests also pass. Scoped
Ruff `check --fix`, MyPy, Pyright, and `git diff --check` pass.

The refreshed `quality-fast` gate remains red with **73 MyPy diagnostic lines**,
down from 92. Log: `/tmp/inertia-split-edges-quality.log`. The default executable
pipeline was not rerun for this behavior-preserving typing refactor; its last
passing evidence is in `p0-condition-capture-refusals.md`. Full-suite failures,
InitMenu acceptance, and the rest of the plan remain open.

## Frontend Boundary Alternatives (2026-09-08)

Reason: mapped-image bounds were accessed through `cast(object, project)`,
and a return-type consumer assigned two distinct function representations to
one narrowly inferred variable. Loader/main-object protocols now state the
consumed fields; the consumer keeps the canonical function and exact binary
boundary separate before selecting a typed union. Runtime behavior is unchanged.

- DoD: inclusive loader limits remain correct, outside/empty ranges refuse,
  compatibility projects without bounds retain boundary-builder fallback,
  canonical and exact-range return evidence still work, and scoped tools pass.
- Definition of Failure: guessed bounds, discarded fallback, widened Any to
  silence errors, or altered return-storage semantics.

Nine boundary tests pass in 9.98s and sixteen unused-return tests pass in 9.01s.
Each run reports seven dependency warnings. Scoped Ruff, MyPy and Pyright pass;
Pyright also exposed a docstring-only Protocol method, fixed with its abstract
ellipsis body. `git diff --check` passes. Refreshed `quality-fast` remains red
with **70 MyPy diagnostic lines**, down from 73. Log:
`/tmp/inertia-boundary-contract-quality.log`. No full-suite or executable
pipeline rerun is claimed for these behavior-preserving contract changes.

## Cache Return Contracts (2026-09-08)

Removed two redundant result casts from the JSON cache adapter and direct-global
cache key adapter. Their authoritative callees already expose exact return
types. Keys, invalidation, schema validation and malformed-record refusal are
unchanged. DoD: existing round-trip/refusal/source-scope tests and scoped types
pass. Definition of Failure: weakening validation or changing cache identity.

All 46 selected cache tests pass in 12.85s with seven dependency warnings;
scoped Ruff, MyPy, Pyright and `git diff --check` pass. These two diagnostics
are closed locally. The global gate was not rerun for cast removal; 70 remains
the last measured global count, not a claim about the current total.

## Logical Alias Version Invariant (2026-09-08)

The logical stack access `versions` property now checks each optional raw SSA
version before publishing an integer tuple. Missing identity raises a clear
ValueError instead of incidental `int(None)` TypeError; valid order is unchanged.
DoD: a damaged copy of a real lifted Alias record refuses missing identity,
valid byte versions remain ordered, related tests and scoped tools pass.
Definition of Failure: inventing zero, omitting a slice, or accepting missing
identity as a proven SSA version. This is an accessor contract repair, not a
claim that upstream production emitted such malformed records.

20 Alias/Widening tests pass in 9.20s with seven dependency warnings; scoped
Ruff, MyPy, Pyright and whitespace checks pass. One further local MyPy diagnostic
is closed. No new global count, executable result, or InitMenu improvement is
claimed by this scoped check.

## Proof-Owner Cast Batch (2026-09-08)

Removed five redundant casts in Alias query forwarding, stack-object containment,
terminal instruction decoding, and published status-flag artifact decoding.
The stack-variable classifier now accurately accepts object and narrows it using
its existing isinstance guard. Capstone operands retain an explicit dynamic
tuple type at the third-party boundary. No storage or instruction semantics
were changed. Scoped Ruff/MyPy/Pyright pass; whitespace checks pass.

The first related run reports **73 passed, 1 failed** in 17.86s; an isolated
rerun confirms the failure in
`test_cfg_context_consumes_incdec_flags_materialized_as_typed_jcc`.
It expects no FLAGS Put for DEC AX / JGE, but one remains. The assertion is
unchanged and must not be relaxed without checking branch/overflow semantics.
The follow-up Alias/terminal subset passes 42 tests in 10.36s. Each pytest run
reports seven dependency warnings. These results are not a green focused batch.

Refreshed `quality-fast` remains red with **62 MyPy diagnostic lines**, including
the preceding cache/version fixes. Log: `/tmp/inertia-proof-cast-quality.log`.
Next: inspect INC/DEC typed-condition consumption and packed-FLAGS publication
against the failing regression before claiming this batch's test closure.

## INC/DEC Test Contract Reconciled (2026-09-08)

The flag-suppression assertion above predates commit 484e108c701ff4664e9e8bcabd02e7e8e1a4e42c,
which repaired optimized INC/DEC executing with stale flags. Its expected
empty FLAGS publication contradicted its own liveness expectation that SF and
OF remain live. Production behavior is preserved: the test now requires live
publication while retaining exact dead-bit-mask and materialization checks.

Twenty-eight new execution cases cover INC/DEC with both carry inputs at zero,
wrap, and signed-overflow boundaries. They assert AX, SF, OF, preserved carry,
and the actual JGE destination, not just whether a FLAGS Put exists. All 56
context/provenance tests pass in 15.53s with seven dependency warnings.
An isolated process temporarily replaced DEC flag publication with a no-op;
the new overflow regression correctly failed. No such mutation is in the tree.

Reason: preserve the established execution repair rather than reintroduce stale
flags to satisfy an old optimization expectation. DoD: live-bit contract and
boundary execution tests pass; omitted publication is detected; regression
modules are admitted to the default pipeline. Definition of Failure: suppressing
SF/OF without proof, ignoring overflow or carry, or replacing execution tests
with mere rendered-output assertions. The status-flag context module is now
explicitly included alongside the already-admitted INC/DEC execution module.
Ruff and whitespace checks pass. The complete default pipeline was not rerun
for this test-only reconciliation; prior passing counts remain historical.

## Carry/Borrow Placement Contracts (2026-09-08)

The existing provenance refusal now narrows all four coordinates individually,
so optional producer addresses never enter the integer-only placement fact.
Idempotence detection inspects CBinaryOp predicates, the nodes actually emitted
by this owner, before reading evidence tags. Neither recovery nor CFG ownership
rules were moved into Rewrite.

DoD: scoped tools pass and replay recognizes the existing predicate without
changing it. Definition of Failure: defaulting a missing producer address,
accepting an arbitrary tagged object as a materialized predicate, or replacing
the same carry calculation twice. All twelve placement tests pass in 10.92s
with seven dependency warnings, including the added replay assertion. Scoped
Ruff/MyPy/Pyright and whitespace checks pass.

Latest `quality-fast` remains red with **59 MyPy diagnostic lines**, down from
62; log `/tmp/inertia-carry-placement-quality.log`. No updated full-suite or
executable-pipeline result is claimed by this focused check.

## Condition Transfer Read Contracts (2026-09-08)

Lowering's condition-cache reader now accepts a read-only mapping of typed
condition/failure sequences. Both ambient frontend lists and exact-relift lists
fit this consumer contract without invariant-dictionary casts or dropping
failure types. Optional decoded targets and the Capstone wrapper tuple are
explicitly typed at their existing dynamic boundaries; runtime behavior is
unchanged. DoD: both cache sources, missing evidence, and capture refusal tests
pass with scoped tools. Definition of Failure: discarding failures to satisfy
types, weakening ownership checks, or mutating a read-only projection.

55 transfer/capture/relift tests pass in 14.73s with seven dependency warnings.
Scoped Ruff, MyPy, Pyright and whitespace checks pass. Two more MyPy diagnostics
are closed locally; the last measured global count remains 59 pending refresh.

## Retired Unsafe Condition Prototype (2026-09-08)

Removed the quarantined, unused `postprocess/condition_patterns.py` prototype.
It replaced `(x - y) < 0` with `x < y` without proving arithmetic width or
overflow behavior. For signed 16-bit x=-32768, y=1, the wrapped subtraction is
32767: the first condition is false and the second true. This is semantic
recovery and cannot be admitted as cleanup.

Graph tracing found no callers of the entry helper; exact source/config search
found only its own functions and admission inventories, which explicitly called
it TEST_ONLY_PROTOTYPE. The graph generation is stale; this conclusion is scoped
to the checked owned source, not unknown external/dynamic callers. Makefile,
architecture inventory, admission records, expectations and the module-status
reference were updated together. No production decompilation benefit is claimed.

Reason: remove an unsafe dead implementation rather than type-polish or promote
it. DoD: no owned production caller lost, inventories agree, layer/inventory
tests and scoped linters pass. Definition of Failure: admitting the rewrite
without typed overflow proof, removing a live semantic owner, or leaving stale
required paths in gates. All 24 layer/inventory tests pass in 34.17s with seven
dependency warnings. Ruff, Pyright and whitespace checks pass.

`quality-fast` remains red with **56 MyPy diagnostic lines**, down from 59,
including the preceding two condition-transfer fixes. Log:
`/tmp/inertia-retired-pattern-quality.log`. Full suite and executable pipeline
were not rerun for removal of this unused prototype.

## Control-Stack Tag Adapter (2026-09-08)

Reason: the escape materializer checked a dynamic `get` method before copying
an optional tag container, leaving an unproven type contract. It now consumes
the existing `copy_structured_tags_8616` boundary adapter and uses the owned
dictionary. No escape classification or machine-level deletion proof changed.

DoD: preserve Python dictionaries, immutable mappings, and native angr Tags;
retain prior evidence, consume the exact RET, and make replay idempotent;
real entry-POP/RET decompilation and scoped types/lint checks must pass.
Definition of Failure: losing native tags, appending a duplicate RET, exposing
the discarded address as a C result, or weakening the escape proof.

A rejected Mapping-only check failed both real decompilation cases. Runtime
inspection showed `angr.rustylib.ailment.Tags` is not a Python Mapping, although
it supports dictionary operations. Restoring the original body passed all four
then-existing tests; using the established adapter passes all five final tests
in 10.15s, with seven dependency warnings and no individual duration over one
second. New cases cover dict, MappingProxyType, and native Tags explicitly.
Ruff `check --fix`, scoped MyPy, Pyright, and whitespace checks pass.
Refreshed `quality-fast` remains red with **55 MyPy diagnostic lines**, down
from 56; compiled import smoke passes for 39 modules. Log:
`/tmp/inertia-control-stack-adapter-quality.log`.

The refreshed default pipeline passes all three lanes, with zero failed,
skipped, or timed-out lanes. Unit lane: **2,505 passed, eight warnings, 172.32s**;
its advisory 30-second budget remains exceeded. Slowest tests: sidecar-free
InitBars 65.15s, RunMenu ESC preservation 60.83s, indexed-address inventory
39.39s. All four selected QuickC fixtures validate, and all seven MS C tiny
compile/run/decompile/recompile/exit-code round trips pass. Log:
`/tmp/inertia-control-stack-pipeline.log`; structured evidence:
`.cache/frontend/test_pipeline/summary.json`. This is the curated default
pipeline, not a refreshed full-suite census, and does not close InitMenu or P0.

## Stack SSA Storage Contracts (2026-09-08)

Reason: aggregate tuple checks refused failed Alias results at runtime but did
not narrow each result for overlap containment or phi fact publication. The
overlap path now accumulates only individually checked storage facts; the phi
path derives its typed collection only after the existing all-input refusal
check. No classification, containment, or equality rule changed.

DoD: retain valid partial/contained overlaps and exact phi identity; refuse
provisional evidence at each of the three overlap and phi positions with closed
failure accounting; scoped types and related Alias/Lowering tests pass.
Definition of Failure: filtering failed evidence into an accepted partial fact,
inventing storage identity, or weakening a hard error for a falsely stable
unresolvable address. The latter remains a hard error, not a soft refusal.

All 31 focused Alias, lowering, and safety tests pass in 12.36s with seven
dependency warnings; individual durations are below one second. Ruff
`check --fix`, scoped MyPy, Pyright, and whitespace checks pass. Refreshed
`quality-fast` remains red with **45 MyPy diagnostics**, down from 55:
`/tmp/inertia-alias-storage-quality.log`. Focused test log:
`/tmp/inertia-alias-storage-contract-final.log`. The preceding default pipeline
is the last executable evidence; no new full-suite or InitMenu result is claimed
for this behavior-preserving type-contract change.

## Call Output And Compatibility Contracts (2026-09-08)

Reason: call-output publication reused `summary` for an optional callsite
record and the function's metadata dictionary, producing two incompatible
assignment diagnostics. The dictionary now has its own `function_summary`
name. Existing tests additionally verify metadata identity, source immutability,
and all five published evidence counters. Runtime semantics are unchanged.

The callsite compatibility export list also omitted `CallsiteReturnUseKind8616`
while exporting its related caller-use records. Restoring that enum export
closes four consumer diagnostics without creating another enum owner. Its new
regression fails before the export and passes after, checking identity with
`caller_return_use_contracts.CallsiteReturnUseKind8616`.

DoD: retain exact call-output definitions, logical-memory rebasing, refusal
behavior, source metadata, and one authoritative enum; focused tests and scoped
tools pass. Definition of Failure: dropping metadata or failed facts, mutating
the input artifact, replacing the enum, or changing call/return effects.

29 call-output and return-condition tests pass in 10.47s with seven dependency
warnings, with individual durations below one second. Ruff `check --fix`,
scoped MyPy, and Pyright pass. Direct Pyright must include
`--pythonpath .venv/bin/python`, as Make already does: omitting it selected
system Python 3.12 dependencies and falsely reported missing PrototypeSource.
The corrected venv run also rechecks the preceding stack SSA and control-stack
modules successfully. No import workaround or suppression was added.

Global `quality-fast` remains red with **39 MyPy diagnostics**, down from 45.
Logs: `/tmp/inertia-call-output-quality.log` and
`/tmp/inertia-call-output-contract-final.log`. No new executable acceptance or
full-suite result is claimed by these contract-only changes.

## Logical Store Address Guard (2026-09-08)

Reason: the IR logical-word write tracer used boolean `&=` after checking
`isinstance(address, IRAddress)`. That evaluates the address matcher even when
the type check fails. A malformed STORE carrying IRValue in the address slot
raised AttributeError instead of its owned LOGICAL_ACCESS_CONFLICT refusal.
Short-circuit conjunction now keeps the matcher behind the address proof.

DoD: invalid low/high STORE addresses yield typed refusals with closed five
counters; valid zero/increment write proofs and the SORTD indexed loop consumer
remain green; scoped tools and the default pipeline pass. Definition of Failure:
an incidental exception, silently dropping the candidate, accepting a non-address
as storage, or weakening logical-memory matching. This is an IR guard repair,
not evidence that the normal lifter emits malformed operands.

Before: two new cases raised AttributeError, five existing cases passed.
After: nine focused write/range/topology tests pass in 18.18s with eight warnings.
Slowest: SORTD InitBars overlap-prefix regression, 7.50s. Ruff `check --fix`,
scoped MyPy, venv-selected Pyright, and whitespace checks pass. Logs:
`/tmp/inertia-logical-address-before.log` and `/tmp/inertia-logical-address-after.log`.
Refreshed `quality-fast` remains red with **38 MyPy diagnostics**, down from 39;
log `/tmp/inertia-logical-address-quality.log`. Default pipeline passes all
three lanes: **2,507 unit tests passed in 169.58s**, seven warnings, four QuickC
fixtures validated, all seven MS C tiny round trips passed, no failed/skipped/
timed-out lanes. The unit lane still exceeds its advisory budget. Slowest tests:
InitBars 58.52s, RunMenu ESC preservation 57.56s, indexed-address inventory 33.40s.
Evidence: `/tmp/inertia-logical-address-pipeline.log` and
`.cache/frontend/test_pipeline/summary.json`. InitMenu acceptance and the
full-suite failure census remain open; this curated result does not replace them.

## Condition View Operand Guard (2026-09-08)

Reason: validation's same-width semantic-cast projection read `.size` from
optional/untyped ConditionIR operands without first proving a typed value.
It now accepts IRValue or IRBinaryValue before consuming width. Missing or
unknown operands return no equivalence projection instead of AttributeError;
the branch validator keeps its existing mismatch/refusal handling. No AST or
branch semantics are rewritten.

DoD: missing/unknown operands on both sides refuse, nonpositive/mismatched
widths refuse, exact scalar/binary widths still project, existing signed-view
acceptance and predicate-mismatch validation remain green, scoped tools and
default pipeline pass. Definition of Failure: guessed widths, an incidental
exception, accepting an unproven cast, or suppressing a validation mismatch.

The corrected regression fixture produced four pre-fix AttributeErrors and
eight passing cases. After the guard, all 40 focused semantic-view/branch/loop
validation tests pass in 12.07s with seven dependency warnings; all individual
durations are below one second. Scoped Ruff `check --fix`, MyPy, venv-selected
Pyright, and whitespace checks pass. Logs:
`/tmp/inertia-condition-view-before.log`, `/tmp/inertia-condition-view-after.log`.
Global `quality-fast` remains red with **37 MyPy diagnostics**, down from 38;
log `/tmp/inertia-condition-view-quality.log`. The default pipeline passes all
three lanes, with no failed/skipped/timed-out lanes. Its unit lane took 151.563s
including process overhead and remains over its advisory budget; all four
QuickC fixtures validate and all seven MS C round trips pass. Slowest tests:
RunMenu ESC preservation 61.65s, InitBars 50.57s, indexed inventory 35.68s.
Evidence: `/tmp/inertia-condition-view-pipeline.log` and the pipeline summary.
This defensive validation change does not establish that normal production
ConditionIR contains malformed operands; InitMenu/full-suite/CI remain open.

## Control Register Execution Contract (2026-09-08)

Reason: concrete CR reads returned int, the existing lifting override returned
VexValue, and the decoded-instruction protocol still required int. The base
read contract, override, protocol and consumer now explicitly return
`int | VexValue`, preserving both existing execution modes. Concrete storage
fields remain integers; no instruction or register availability changed.

Pyright also exposed the decorated VexValue cast result at the write boundary.
Writes now call the underlying IRSB cast directly and require a raw IRExpr
before constructing Put. This preserves the wrapper's existing 32-bit cast
operation and rejects malformed input explicitly instead of building invalid IR.

DoD: integer/raw/wrapped writes to CR0/CR2/CR3 produce 32-bit Put at the exact
register offset, lifted reads remain VexValue, concrete reads remain integers,
invalid inputs refuse, the 80386 corpus and scoped tools pass. Definition of
Failure: changed cast width or register lane, lost CLTS/control-register effects,
invented CR availability, or type suppression. Segmented byte-wrap helpers were
not changed.

Before the write-boundary adjustment: 1,074 selected frontend cases passed with
one skip. Final: **1,084 passed, one skipped**, seven warnings, 77.79s. The skip
is the existing opt-in exhaustive deduplicated 80386 corpus. Slowest test:
hardware-case loader/deduplication, 1.60s. Scoped Ruff `check --fix`, MyPy,
venv-selected Pyright, and whitespace checks pass. `quality-fast` remains red
with **35 MyPy diagnostics**, down from 37. Logs:
`/tmp/inertia-cr-contract-final.log`, `/tmp/inertia-cr-contract-quality.log`.
Default pipeline: **2,507 unit tests passed in 119.35s**, eight warnings; all
three lanes pass, with zero failed/skipped/timed-out lanes. Four QuickC fixtures
validate and all seven MS C tiny round trips pass. Slowest tests: InitBars
52.14s, RunMenu ESC preservation 49.76s, indexed inventory 25.79s. Log:
`/tmp/inertia-cr-contract-pipeline.log`; structured pipeline summary retains
per-lane evidence. No full-suite/CI closure or new SORTD function acceptance
is claimed here.

## Binary Loop Update Operands (2026-09-08)

Reason: ConditionRegisterUpdateIR permits binary RHS values, but its Structuring
consumer called an IRValue-only converter that read `.space`. All seven new
binary/nested operand tests reproduced AttributeError before the repair.

The existing six-operator composition moved from the legacy typed-condition
module into the focused Structuring owner `condition_binary_value.py`. The
scalar/binary lowering API and compatibility condition builder now consume
that one helper through the already-admitted condition_lowering boundary.
No new postprocess import exception was added. Unsupported operators or absent
C-expression operands refuse; no instruction decoding or storage recovery was
introduced. The oversized compatibility and loop modules shrink.

Loop-update RHS/operator checks now precede initializer and register-identity
mutation. A refusal regression verifies the original initializer identity,
value, and empty loop body remain intact. Related Pyright contracts now state
assignment-tag access, capture a narrowed register identity before its callback,
and check the optional pretest guard directly.

DoD: preserve all six existing operator mappings, nested structure, scalar
behavior and legacy conditions; refuse unsupported RHS without AST mutation;
focused tests, architecture admission and scoped tools pass; default pipeline
remains green. Definition of Failure: inventing an operator/operand, widening
an address, partial loop mutation on refusal, or moving semantics into Rewrite.

43 focused tests pass in 8.69s with seven dependency warnings. Scoped Ruff
`check --fix`, MyPy and venv-selected Pyright pass, including the architecture
inventory script. Full architecture checks pass. The initial pipeline attempt
was correctly stopped by the unadmitted direct compatibility import; it was
restarted after correcting the boundary, ownership header and typed inventory.
Logs: `/tmp/inertia-binary-lowering-before.log`,
`/tmp/inertia-binary-lowering-final.log`,
`/tmp/inertia-binary-lowering-architecture-final.log`.

Quality refresh first hit a MyPy internal error; after scoped processes had
finished, the sequential retry completed normally with **34 MyPy diagnostics**,
down from 35. The internal error's cause is unproven. Log:
`/tmp/inertia-binary-lowering-quality-retry.log`. Default pipeline passes all
three lanes: **2,507 unit tests in 142.40s**, seven warnings, four QuickC
validations, all seven MS C tiny round trips, zero failed/skipped/timed-out
lanes. Slowest: RunMenu ESC preservation 52.75s, InitBars 42.86s, indexed
inventory 30.16s. Log: `/tmp/inertia-binary-lowering-pipeline-final.log`.
No new SORTD function acceptance or full-suite closure is claimed.

## Unobserved Result View Contract (2026-09-08)

Reason: a combined physical/runtime register-view guard established validity,
but a later conditional expression still dereferenced an optional runtime view
in MyPy's model. Explicit width branches preserve the existing physical-view
precedence and refusal guard. The angr statement-copy boundary now declares
`list[object]`, retaining all statements before per-element checks instead of
Pyright's inferred Never list. Runtime transformations are unchanged.

DoD: proven void masked projections retain the call; unknown views retain the
original assignment; existing liveness, residual-value and interrupt-result
tests pass with scoped tools. Definition of Failure: deleting an unknown result,
losing the call/residual value, guessing a width, or suppressing type errors.

14 focused tests pass in 9.45s with seven dependency warnings. The added unknown
view case forces both authoritative classifiers to refuse and checks the exact
assignment remains. Scoped Ruff `check --fix`, MyPy, venv-selected Pyright, and
whitespace checks pass. Global `quality-fast` remains red with **33 MyPy
diagnostics**, down from 34; log `/tmp/inertia-unobserved-view-quality.log`.
Test log: `/tmp/inertia-unobserved-view-tests.log`. No new default/full-suite
run or SORTD acceptance is claimed for this behavior-preserving typing change.

## IR Owner Return Types (2026-09-08)

Removed redundant result casts around the authoritative VEX byte-width helper
and status-flag CFG effect summarizer. Their owners already return int and
StatusFlagEffect8616 respectively. The factory/function lookup Protocol methods
now explicitly mark abstract bodies, resolving Pyright's inferred missing
return without changing any implementation.

Reason: consume owner types directly rather than restating them in casts.
DoD: VEX import, successor, hot-path and status-flag projection tests and scoped
tools pass. Definition of Failure: changed widths, effects, cache identity,
recursion handling, or weakened diagnostics. All 45 focused tests pass in
10.24s with seven dependency warnings; scoped Ruff `check --fix`, MyPy,
venv-selected Pyright and whitespace checks pass. Log:
`/tmp/inertia-ir-cast-tests.log`. No executable/full-suite rerun is claimed for
these runtime-neutral edits; the remaining acceptance blockers are unchanged.
Global `quality-fast` remains red with **31 MyPy diagnostics**, down from 33;
log `/tmp/inertia-ir-cast-quality.log`.

## Call-Condition Index And Bridge Boundary (2026-09-08)

Reason: the condition-index loop reused a variable later assigned an optional
lookup result. Naming the recorded condition separately preserves both types
without changing lookup or refusal behavior. Scoped Pyright also exposed an
unchecked destination storage class in bridge removal; the helper now returns
without mutation unless the destination is a SimStackVariable. Its docstring
now describes the actual register-to-stack assignment direction.

DoD: existing return-condition behavior remains green, matching stack bridges
can be removed, non-stack destinations retain both assignments, and scoped
tools pass. Definition of Failure: guessed storage, deleting a bridge for an
unknown destination, or altering optional-condition lookup semantics.
The original 23 condition tests passed before the boundary guard; all 25 final
condition/boundary tests pass in 9.27s with seven dependency warnings. Scoped
Ruff `check --fix`, MyPy, venv-selected Pyright, and whitespace checks pass.
Global quality refresh after the indexing rename remains red with **30 MyPy
diagnostics**, down from 31; the later stack-class guard also passes scoped types.
Logs: `/tmp/inertia-call-condition-index-quality.log` and
`/tmp/inertia-call-condition-bridge-tests.log`. No fresh default/full-suite or
SORTD acceptance result is claimed by this contract-boundary check.

## Tail Fingerprint Return Contracts (2026-09-08)

Removed four redundant `cast(str, ...)` calls from tail fingerprint consumers.
Their producers already return explicitly typed strings; annotations remain
intact. Added a docstring to the touched nested iterator-guard fingerprint
helper. No validation rule, observable, refusal, or generated C is changed.

Reason: the global typing gate must accept the authoritative producer types.
DoD: scoped Ruff, MyPy, Pyright and affected validation tests pass without
weakening comparisons. Met: 408 tests passed in 14.22s, seven dependency
warnings, all five slowest tests under one second. Definition of failure:
remove annotations, suppress diagnostics, or weaken a validation verdict.

Global `quality-fast` remains red, now **25 MyPy diagnostics**, down from 29.
Logs: `/tmp/inertia-tail-fingerprint-types-tests.log` and
`/tmp/inertia-tail-fingerprint-types-quality.log`. The preceding restored
default pipeline passed 2,530 tests and both DOS lanes; no new full-suite or
remote CI result is claimed by this typing-only change.

## CLI Checked Values And Collection Names (2026-09-08)

The interrupt-call boundary now uses the `callee_target` value it checked
instead of reading a potentially dynamic attribute twice. Function-name
precedence and wrapper argument classes are unchanged. A regression failed
before (one failed, five passed) and passes after; all 29 related tests pass
in 9.70s. The new test module is admitted to Make, the default lane, and the
source-to-test ownership manifest. Admission checks pass 109 tests in 2.80s.

A separate local-name collision in legacy helper rendering assigned a tuple
to a name already inferred as a list. Naming that tuple `source_replacements`
preserves its type and iteration order without conversion. Four rendering
tests pass in 19.67s. Both touched functions retain annotations and now have
docstrings; no semantic recovery was added to the CLI.

Reason: checked dynamic values and distinct collection contracts must survive
the compatibility boundary. DoD: retain name precedence, refuse non-string
targets, read dynamic targets once, preserve rendering, and pass scoped
tools/regressions. Met. Definition of failure: unchecked second lookup,
guessed wrapper arguments, collection coercion, or new text-based recovery.
Ruff `check --fix`, scoped MyPy, and venv Pyright pass. Global `quality-fast`
remains red with **23 MyPy diagnostics**, down from 25.

Logs: `/tmp/inertia-interrupt-boundary-before.log`,
`/tmp/inertia-interrupt-boundary-after.log`,
`/tmp/inertia-interrupt-boundary-admission.log`,
`/tmp/inertia-helper-render-types-tests.log`, and
`/tmp/inertia-cli-boundary-types-quality.log`.

The default pipeline also passes: 2,536 unit tests in 126.53s, QuickC, and all
MS C tiny round trips; three lanes passed, none failed/skipped/timed out.
Lane wall times: 126.923s, 38.350s, and 57.517s. Evidence:
`/tmp/inertia-interrupt-boundary-pipeline.log`. These checks do not close the
numeric-frame defect or full-suite/CI acceptance.

## Explicit Stack Projection Compatibility Export (2026-09-08)

The existing `real_mode_linear` re-export of `project_stack_value_range_8616`
is now explicit. JCC retains its admitted import path and calls the same
canonical Lowering function. A direct import from its owner was rejected by
the architecture guard and reverted; no new compatibility exception was added.

Reason: the existing API must be visible to strict type checking without
expanding postprocess dependencies. DoD: unchanged function identity, JCC
regressions, architecture gate, and scoped tools pass. Met: 98 JCC tests pass
in 9.16s; Ruff `check --fix`, MyPy, venv Pyright, and startup architecture pass.
Definition of failure: duplicate recovery, unchecked casts, or weakening the
protected-import gate. Global `quality-fast` still fails with **22 MyPy
diagnostics**, down from 23. This import declaration changes no function body;
the preceding 2,536-test/default DOS pipeline is not a new run for this change.
Logs: `/tmp/inertia-jcc-export-tests.log`,
`/tmp/inertia-jcc-export-architecture.log`, `/tmp/inertia-jcc-export-quality.log`.
