# Original binary-behavior plan: acceptance checklist

This is an execution checklist for the original M0–M7 requirements in
[the plan](binary-behavior-equivalence-plan.md), not a replacement or reduced
scope. Updated 2026-10-06. Implementation receipts are not milestone acceptance.
Unchecked means acceptance is not established, including when code already exists.
Later D0–D5 experiments are not additional completion requirements.

## User scope correction — 2026-10-06

The user clarified that this task improves the real16/PE32 Z3 comparators, not
the decompiler as a whole. This paragraph supersedes historical requirements
below that made unrelated decompiler failures blockers for M5/M7 acceptance.
Keep those failures visible, but evaluate this task with comparator-specific
proof, corruption/refusal, cache/dependency, public-contract, fixed-corpus and
resource controls, plus changed-owner lint/types and directly affected shared
lifter/IR regressions. No whole-function generated-C or DOS recompilation gate
is required unless it verifies an actual affected comparator requirement.
Static comparison is independent of KVM; native execution checks remain distinct.
Repository-wide release/PR gates are separate from this task's completion.

## Fixed evidence and accounting

Keep the existing selection and hashes in
`.cache/comparator-implementation/three-track-corpus/manifest.json`.
It contains real16 SORTDEMO, MSC8 PE32 and BC5 PE32 tracks and executable
command arrays. Its `historical_only` reports are not fresh acceptance.
Retain changed-binary samples and all refusals; do not replace difficult samples
with successful ones. Tiny assembled controls supplement this selection.
ELF compatibility remains supported but is not the target of new flat32 work.

Every requirement below needs a receipt with source/binary hashes, command,
budgets, environment, verdict/reason, elapsed time and evidence location.
For each of the plan's seven behavior rows (calls, loops, memory, control,
dependencies, outcomes, evidence), both real16 and PE32 require four control
classes: original/original, equivalent changed code, corruption, incomplete.
That is 56 matrix cells to account for, not 56 equally costly tasks or a
percentage of implementation effort. One test can cover multiple cells only
when its actual assertions and binary inputs establish each obligation.

The existing exact-node map is
`.cache/comparator-implementation/m7-acceptance-matrix.md`; its outcome
supplement is `m7-outcome-matrix/RECONCILIATION.md`. It records56supported
bounded control cells, not56unconditional program proofs. Current M5 repair
attachments, public bridge and comparator checkpoint supersede affected older
receipts; the final corpus/cache evidence remains a separate M7 obligation.

## Original milestone obligations

| ID | Acceptance obligation | Receipt required |
| --- | --- | --- |
| M0.1 — ACCEPTED | Preserve source/binary baselines and audit proof promotion | Current 1,236-file snapshot, binary/build hashes and reviewed promotion audits; m0-current-baseline/ACCEPTANCE.md |
| M0.2 — ACCEPTED | Reproduce all frozen selections on both architectures | All 55 representative rows plus eight tiny controls accounted in current capability-matrix.json; original selections unchanged |
| M1.1 — ACCEPTED | Reject missing/stale/narrower evidence and conditional promotion | Current public-domain and rejection controls;296+884early gate,104boundary,9projection/provenance;8/8frozen fixture outcomes retained |
| M1.2 — ACCEPTED | Bind caches to content, contracts and transitive dependencies | Mutation/invalidation controls;15BC5cold/warm rows and329/356lowered parts identical, unchanged input/source hashes; m1-public-domain-parent/ACCEPTANCE.md |
| M2.1 — ACCEPTED | Prove real16 direct call chains | Near/far/operand-size, CS:IP, SS:SP, argument/cleanup/alias controls; current323-test selection; m2-region-target-parent/ACCEPTANCE.md |
| M2.2 — ACCEPTED | Prove PE32 direct call chains through both drivers | Full EIP/ESP, memory/frame/outcome controls and actual PE32 public drivers; current early gate296+993 |
| M2.3 — ACCEPTED | Reject changed callee/argument/return/cleanup and invalidate callers | Changed-binary/dependency controls and unresolved-call refusals; unchanged323-test selection |
| M3.1 — ACCEPTED | Close matched-loop induction on both tracks | Zero/one/many, nested/early-exit/checked-callee loops; m3-flat32-call-loop/ACCEPTANCE.md |
| M3.2 — ACCEPTED | Preserve full live state and infinite behavior | Full-state and corruption controls, closed transition induction without unrolling; current early gate296+993 |
| M4.1 — ACCEPTED | Prove changed-shape loops on both tracks | Actual-MZ and both actual-PE public driver register/stack/affine/rotation proofs; m4-exit-controls/ACCEPTANCE.md and relations-receipt-index.json |
| M4.2 — ACCEPTED | Prove progress and full memory relations | Integrated12 mutation/exhaustion controls,20 rotation/condition/progress/refusal controls and full-state public proofs; unsupported relations remain unknown |
| M5.1 — ACCEPTED | Prove recursive SCCs without circular assumptions | Base/progress and admission mutations, source-bound conditional component summaries, current public bridge; m5-current-acceptance-attachment/ACCEPTANCE.md; no arbitrary-entry promotion |
| M5.2 — ACCEPTED | Close admitted indirect targets | Actual-MZ and both PE32 complete-target/changed-callback controls in505refresh; unknown targets refuse; attachment exact-node mapping |
| M5.3 — ACCEPTED | Relate environment, faults and nonreturning outcomes | DOS/BIOS/device and PE32 service/exception controls;198premise-chain/156diagnostic/50version and current terminal bridge; assumptions propagated |
| M6.1 — ACCEPTED | Demonstrate independent function replay on both architectures | Fresh228-test native/reset/program selection; current early gate; m6-acceptance-parent/ACCEPTANCE.md |
| M6.2 — ACCEPTED | Establish reset/snapshot isolation and deterministic vectors | Fresh snapshot/reset checks and reviewed21-test capture/public selection; source identity qualifications in current-receipt.json |
| M6.3 — ACCEPTED | Demonstrate initialized whole-program replay | Initialized MZ file/output/device and import-free PE32 output/declared-exit scenarios; deterministic boundary/fuzz vectors; explicit supported limits retained |
| M7.1 — ACCEPTED | Keep public interfaces and documentation coherent | Current30public bridges and scoped reuse of unchanged schema assertions; corrected both driver descriptions and MSC8 README, actual CLI helps/scoped lint; comparator-help-review-fix/PARENT_REVIEW.md |
| M7.2 — ACCEPTED | Measure fixed-manifest cold/warm performance and semantics | comparator-profile-final-validation/PARENT_REVIEW.md:14recorded runs,55obligations per phase, exact parity,3046stable identities; named phases/RSS/budgets,16dependency controls and cache-disabled receipt; no controlled speedup claim |
| M7.3 — ACCEPTED | Pass comparator acceptance checks without hiding prior failures | comparator-profile-final-validation/COMPLETION_AUDIT.md reconciles current comparator gates/public bridges/source deltas; final diagnostic MyPy/Ruff/11tests and2parent controls pass; unrelated decompiler failures remain separate |

M0–M4 and M6 are accepted 2026-10-03; M5 is accepted 2026-10-06
within its declared conditional component/environment contracts. M7 is accepted
2026-10-06; all original comparator milestones are complete within their contracts.
Refused/conditional observations remain unproved. The plan
records reviewed implementations separately; this table does not erase them.
Attach exact evidence before checking off a row. Missing, conditional, stale or
unexecuted evidence stays open. A concrete reconstruction mismatch is reported
as such; the comparator must not be altered to make unequal binaries pass.

## Current execution

Follow the comparator-specific commands and evidence ledger in the
[current plan](binary-behavior-equivalence-plan.md). M5/M7 are not automatically
accepted by removing unrelated gate dependencies: verify their actual proof,
corruption/refusal, public-contract, corpus, cache and resource requirements.
Refresh only evidence whose relevant source/binary/contract dependencies changed.

All older queue entries, broad-gate results and historical command lists are
preserved in [the archived checklist](binary-behavior-acceptance-history-20261006.md).
They are historical records, not additional current completion requirements.
