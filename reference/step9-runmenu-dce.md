# RunMenu DCE And Validation Evidence

Scope: the bounded Step 9 SORTD inventory. This repairs generic owners; no
function address, compiler name, source text or generated-C pattern is recovery
input. RunMenu addresses below identify diagnostics only.

## Root Causes

1. Contextual validation refused register-backed materialized predicates even
   when Structuring had already recorded their exact immutable precision proof.
   It instead replayed instructions in address order across mutually exclusive
   branches. Deleting unused `v29` changed that replay's apparent input from a
   global high word to the keyboard stack byte. Neither was the actual dispatch
   value, which is the uppercase call's captured return.
2. DCE's adjacent-duplicate check used storage equality as value equality.
   Distinct SSA values backed by AX compared equal; consecutive decrements were
   treated as duplicate assignments. The live `ir_36` definition disappeared
   while its condition still read it. Whole-tail validation rejected the pass
   and restored the function. This was a real protection, not a gate to bypass.
3. The validation copy-alias resolver could use the first register assignment
   after its map had already classified that register as multiply defined.
   Traversal order is not a reaching-definition proof.

## Changes And Ownership

- Validation now consumes exact per-JCC precision evidence before falling back
  to replay. The current predicate must match the sole recorded after-token;
  missing, conflicting or stale evidence refuses. It does not substitute a
  stored expression for changed code or waive condition deltas.
- DCE distinguishes register-value objects and type views from physical storage
  equality. Duplicate assignments must also be independent of their destination;
  repeated updates and overlapping stack reads cannot be discarded as duplicates.
  The existing purity and liveness checks still apply.
- Validation no longer selects the first physical/name register writer when
  unique value resolution fails. Exact uniquely defined versions remain usable.
- Fingerprint version is 40. Types/docs and normal pipeline enrollment are kept.

## Tests And Live Evidence

- Ambiguous register aliases: four new failures before, focused cases pass after.
- Owned precision predicates: two new failures before; stale constants/operators,
  wrong JCC, missing and conflicting records are negative controls. The tests
  clear the expression cache at mutation boundaries, as live validation does.
- Consecutive decrements: both SSA-version and in-place update cases failed
  before; both pass after. Additional checks cover live version copies, distinct
  RHS versions and overlapping stack ranges. Existing genuine duplicates still
  prune correctly.
- Final source-stable focused surface: 229 passed in 16.94s. Scoped
  Ruff/MyPy/type/doc checks, project-wide MyPy, architecture and ownership pass.
- Live RunMenu exits 0 with `validation=passed` and clean whole-tail validation.
  Its C diff removes only `v12`/`v29` declarations and assignments; the live
  decrement chain, calls, writes and branches survive. Evidence:
  `.cache/step9-runmenu-value-identity.{c,log}`.

Final whole-binary acceptance began September 19, 22:44:13 +02:00.
The 1,051-file production-manifest digest, rechecked after that run, is
`0e6d25693be5c59bbf8d65eedf920e6405b4723ce9162fb2b9aa3ab17840368c`.
The observed investigation window includes 22:17-22:41 (24 minutes); earlier
setup and later final gates are outside that interval.

## Rejected Experiment

An in-process probe confirmed that cloned calls retain instruction/target tags
and the address-keyed inventory while losing node-ID summary entries. However,
globally expanding captured calls into fingerprints still disagreed with
immutable precision records created in the register domain and made live
RunMenu fail. That integration, its helper and its temporary tests were removed.
Do not repeat partial captured-call expansion: every owned projection would
need a coherent contract. It is unnecessary for this bounded repair because
the existing precision proof already covers the materialized condition.

## Closure

Final whole-binary acceptance passes all 20 functions with closed counters and
zero violations. Explicit generated-C compilation passes with zero errors and
zero warnings; the 19-function generated behavior harness passes. The saved
comparison and address links were refreshed. Global quality-fast/quality-hard
remain red on existing Ruff debt; neither is claimed green. The final default
pipeline passed 5,861 routine tests in 352.04s and both external lanes (four
QuickC fixtures and seven MS C tiny round trips). Bounded Step 9 is complete.
See [the closure ledger](step9-closure.md) for the acceptance audit and limitations.
