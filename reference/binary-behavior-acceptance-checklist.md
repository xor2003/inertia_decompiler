# Original binary-behavior plan: acceptance checklist

This is an execution checklist for the original M0–M7 requirements in
[the plan](binary-behavior-equivalence-plan.md), not a replacement or reduced
scope. Updated 2026-10-03. Implementation receipts are not milestone acceptance.
Unchecked means acceptance is not established, including when code already exists.
Later D0–D5 experiments are not additional completion requirements.

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
| M5.1 | Prove recursive SCCs without circular assumptions | Base/progress mutations, joint source-bound summaries and public integration |
| M5.2 | Close admitted indirect targets | Complete target relation and changed callback controls; unknown targets refuse |
| M5.3 | Relate environment, faults and nonreturning outcomes | DOS/BIOS/device and PE32 service/exception controls; assumptions propagated |
| M6.1 — ACCEPTED | Demonstrate independent function replay on both architectures | Fresh228-test native/reset/program selection; current early gate; m6-acceptance-parent/ACCEPTANCE.md |
| M6.2 — ACCEPTED | Establish reset/snapshot isolation and deterministic vectors | Fresh snapshot/reset checks and reviewed21-test capture/public selection; source identity qualifications in current-receipt.json |
| M6.3 — ACCEPTED | Demonstrate initialized whole-program replay | Initialized MZ file/output/device and import-free PE32 output/declared-exit scenarios; deterministic boundary/fuzz vectors; explicit supported limits retained |
| M7.1 | Keep public interfaces and documentation coherent | z3func/dosunit and both flat32 adapters, schemas/help/spec/workflow checks |
| M7.2 | Measure fixed-manifest cold/warm performance and semantics | Load/lift/normalize/solve, RSS, counts/reasons, cache/dependency parity and bounded budgets |
| M7.3 | Pass required final gates without hiding prior failures | Scoped/regular/hard gates, flat32 tests, pipeline and applicable expanded audit |

M0–M4 and M6 are accepted 2026-10-03; M5 and M7 remain open.
Refused/conditional observations remain unproved. The plan
records reviewed implementations separately; this table does not erase them.
Attach exact evidence before checking off a row. Missing, conditional, stale or
unexecuted evidence stays open. A concrete reconstruction mismatch is reported
as such; the comparator must not be altered to make unequal binaries pass.

## Current bounded work queue

Selected-lowering checkpoint (2026-10-03): real16 `--select` now schedules
catalogued binary-call closure independently on both sides, preserving aliases,
ambiguous mappings, unknown-control fallback and existing budgets. Parent final
cohort:65passed; BC5/MSC8 adapters:19/17passed. Counted-work and refusal controls
are enrolled in the normal and early gates; scoped-linter enrollment is tested.
The representative diagnostic lowers4oracle/6candidate catalog functions rather
than20each, but crashes during candidate callee discovery (exit139). One plain
serial retry completes within the unchanged120-second watchdog and reports all3
requested functions UNKNOWN: InsertionSort paired_region_admission_refused;
SwapBars/Sleep macro_unsupported_boundary. Catalog-lowering work falls75%; no
wall-time speedup or proof acceptance is claimed, and the native diagnostic
crash remains unresolved. See `real16-selection-budget/PARENT_REVIEW.md` under
the comparator cache for retained logs. No original milestone closes.

Latest checkpoint (2026-10-03): final early gate296+821passed with2workers.
Adjacent CALL validation reuse halves actual native relifts and measures about
2x on the controlled transfer microbenchmark; fresh byte/domain/registry/state
mutations still refuse. Live failure reporting preserves final summaries/status.
Broad quality-dev completed10122passed/15failed/19skipped in1583.39s; it remains
red. The three comparator failures pass serially under unchanged proof limits;
the other12 failures remain unresolved here. Do not restart the broad suite
until focused fixes or a controlled scheduling change justify it.

M0 candidate blocker progressed: unchanged full SORTDEMO.C now builds cleanly
with installed MSC6 through system DOSBox. All20procedures and3frozen selections
have exact optional catalogs. Combined comparison hit120s external watchdog
before reporting; preserve all3as unreported. Tiny supplement has7of8expected
outcomes after two CLI corrections, with one strict-budget positive UNKNOWN.
M6 capture now has6native service selectors and8independently checked raw pairs;
native PSP/allocator/scratch writes still require typed modeling. These receipts
do not complete an original milestone. See the plan's latest ledger and
`.cache/comparator-implementation/ACTIVE_HANDOFF.md` before using historical
queue entries below.

The initial queued checks finished: native KVM reset failed on actual video
residue, the timeout fixture repair passed its controls, and the eleven-module
comparator gate passed182tests. These results do not establish broad acceptance.

Use `make comparator-check-fast PYTHON=./.venv/bin/python PYTEST_WORKERS=6`
under the nice/JIT environment below as the early integration gate when all
six slots are available. It reuses existing source-provenance, real16 native
target/call/NOP controls, both flat32 adapters, actual PE32 relational controls,
and deterministic query/composition-budget controls. This selection catches
the recent proof-admission defects without running unrelated decompiler cases.
Initial eleven-module gate:182passed128.91s with3workers. Updated gate including
collection-cache controls:189passed89.05s with2workers. Different cache/load
conditions prevent treating that as a controlled end-to-end speedup.
The gate now also covers the incomplete-pipe EOF race and the BP/boundary/
segment-summary fixture cohort. Expanded gate:242passed/4warnings109.61s with
2workers, JIT enabled and nice10. Source-free NOP fixtures were replaced with
native project-bound evidence after independent review; production proof gates
were not relaxed. Parent fixture/NOP cohort:81passed/5warnings150.77s with
5workers; later typed fixture correction plus scheduler cohort:57passed21.56s
serial. Different cohorts/load conditions are not an end-to-end speedup claim.
Retain the normal broad gates for the semantic checkpoint and final acceptance.

The fast pipeline now requires comparator admission automatically, after the
shared decompiler contracts. Explicit dependency edges serialize the pools even
under `make -j`; admission stops at its first failure. Four Make execution
controls exercise successful and rejected admission with one/six Make jobs.
The contract pool is capped at two workers (serial requests remain serial):
the unchanged296controls measured15.05s with two versus28.68s with six under
shared host load. The comparator pool still honors the requested worker count.
Receipts: `.cache/comparator-implementation/early-gate-order/`. This optimizes
failure feedback; the additional admission pass is not a whole-suite speedup.

Latest early gate after interrupt-frame and vector-policy enrollment:
296contracts passed in12.88s with2workers, then291comparator controls passed
in58.47s with5workers. One serial slot was reserved for the staged Devin
descriptor-provenance task. Vector model integration has307passing controls;
the final19vector controls cover positive, mutation and refusal boundaries.
Initialized original/original MZ replay now reaches1759instructions and refuses
AX4400/BX4 (device information). At the retained native1719 cutpoint, every
captured integer register and all654784 declared RAM bytes agree exactly.
This is one retained execution cutpoint, not all-input or complete-program
equivalence. Fresh direct KVM execution subsequently succeeded: repeated native
capture again agrees on all declared bytes/registers;12native reset/snapshot/
abort/resize controls pass20.00s. Device-limited attempts remain recorded skips.
Receipts: `.cache/comparator-implementation/real16-vectors/REVIEW.md`.

Device-information follow-up admits declared AX4400 responses, with unknown
handles/selectors still refused. Five native startup responses are retained;
the first completed query matches every captured integer register and all
654784declared RAM bytes. Actual original/original reaches1847instructions;
adding captured initial BIOS-data bytes reaches1860 and INT10/AH0F refusal.
Final early gate296contracts15.02s then303comparators70.22s; integration71pass,
enrollment134pass and scoped lint/types pass. This does not close whole-program
termination or full native reset. The first descriptor-ledger stage failed the
parent's repeated-reset control after overflow; that repair is recorded below.
Receipts: real16-device-info/REVIEW.md and native-fd-provenance/parent-review/.

Latest reviewed integration: native descriptor acquisition/release ledger now
drains overflow residue without allocating anchor descriptors. Parent8compiled
controls pass; actual128-dup guest regression fails saved production and passes
the repair. Final14native controls include repeated status6 refusal after4100
dups and fresh-worker recovery; a separate no-KVM compiled ownership control
passes. Stdio redirection, external files/positions and full paused snapshots
remain unclosed. M1.1 audit produced8reviewed/enrolled PE32 seal controls; its
real16 conditional/candidate-only questions still need public controls.
Final early gate296contracts+311comparators and scoped lint/types pass. This
does not turn the earlier broad25failures into passes. All jobs are terminal.
See native-fd-provenance/parent-review/INTEGRATION.md and
m1-evidence-audit/seal/PARENT_REVIEW.md.

M2 follow-up now has native and public PE32 controls for nested calls whose
pointer disjointness depends on caller state. One root-bound retry preserves
that state, reuses lifted blocks and charges the same budgets; generic root
failures are not retried. Final new/domain/budget cohort49passes, integration
cohort251passes, both adapter suites19/17passes. New controls are routinely
enrolled, including the fast comparator gate. Frozen BC5 self/changed remain
15refused each: this is a specific admission improvement, not final M2 or
representative-corpus acceptance. See contextual-flat32/REVIEW.md.

1. Diagnose the terminal broad result in
   `collection-cost-review/quality-dev-remaining.log`:25failed/9510passed in
   1953.63s with4workers. Saved failure-diff.json has12retained/5cleared/
   13newly observed relative to the previous17failure run. New groups include
   scheduler tests, old source-free NOP fixtures and live decompiler cases.
   Scheduler EOF/readiness and eight NOP fixture failures now have focused
   repairs; the broad result has not been rerun and must not be relabeled green.
   InitBars has both expensive pre-function discovery and a recorded hard
   materialization failure; the later debug run timed out. Do not treat a larger
   timeout as a semantic repair. The full type-ratchet now passes.
   Make did not execute decomp-opt-regression-suite after the pipeline failure.
2. Review Devin's staged `entry-domain-call-binding` delta. Require source-bound
   call/padding/domain evidence and unchanged corruption/refusal controls.
   Require a shared aggregate budget across nested imports: the parent found
   that recursive collection currently creates a fresh64-resolution budget.
   Deterministic counted branching controls must precede another long replay.
   Stop this assignment at a reviewed patch or a precise unresolved obligation;
   do not silently expand its file ownership or substitute normalized targets.
3. Timeout readiness is integrated: saved-baseline red, delayed-start control,
   broken-cleanup rejection and final27-test cohort pass. Keep this evidence;
   no production timeout increase was needed.
4. Native reset review is complete for environment/video RAM and mapped handles:
   independent5controls pass, production6native/37fast controls pass. Tests use
   the enrolled worker-native module and one isolated wrapper compile per cohort.
   Overflow residue is now repaired by the reviewed acquisition/release ledger,
   with actual native parity and persistent-failure controls. The rejected
   snapshot/anchor approaches remain unpromoted. External state and full paused
   snapshots remain M6 obligations; see the newer native-fd-provenance parent
   integration receipt before resuming this slice.
5. Reconcile the existing controls and corpus receipts against M0–M7 and the
   56 matrix cells. Prioritize a missing original obligation over optional
   optimization. A test filename alone does not establish a cell.
6. The two M1.1 public-accounting experiments now have seven reviewed real-MZ
   controls: layout assumptions remain conditional; corruption fails; ambiguous
   candidate mappings and missing counterpart identities refuse. Parent mutation
   checks reject deliberate assumption/accounting bypasses. Mapping correspondence
   is not execution reachability, and the literal missing-region/missing-row
   branches remain untested by this new cohort. Do not promote this coverage
   result to complete M1 acceptance. Receipt: m1-real16-boundaries/PARENT_REVIEW.md.

The provenance-cost follow-up removes two discarded full-source checks per
real16 comparison, retaining both lowering seals and both sides' post-solver
and post-retry freshness gates. Same-input ABBA comparison measurements on a
leaf and an acyclic region improve from median7.85s to5.48s (~30%); this is not
a full-corpus speed claim. No hash cache or budget relaxation was introduced.
The existing early gate now includes source-mutation, real16 reuse/freshness and
public-accounting controls, plus a counted source-check budget. Its enrollment
regression fails on the pre-change Makefile. See provenance-cost/REVIEW.md.
Final integration:296contracts passed, then339comparator controls passed with
five workers in187.05s; the independent enrollment cohort155passed. Both PE32
adapter suites19/17passed; scoped lint/types and startup/ownership gates pass.
All owned jobs are terminal. The broad25failure result remains unresolved;
this early gate is not a replacement for original M7 acceptance.

Cache/callee/timeout checkpoint: VEX v7 rejects changed loaded bytes, semantic
sources and decode domains; both PE32 adapters retain warm parity. Identical
nonleaf bytes no longer discharge transitive callee obligations. The native
alarm records expiration before raising, so ctypes wrapping or swallowing
cannot escape as an unrelated error or success. No budgets were increased.
New controls and scoped-linter selection are enrolled in Make and the pipeline.
Fresh cache identity costs0.67–1.16s once per lowering invocation on the sampled
host; the prior30% small-fixture provenance gain remains a separate result.

Final frozen-source serial gate:296contracts pass34.96s,351comparator controls
pass368.00s (combined~6m43s). BC5/MSC8 suites19/17pass; Make/fixture34pass;
scoped Ruff, MyPy with typed owner closure, Pyright, type-ratchet and structural
checks pass. Earlier parallel runs remain recorded: a parent source edit
correctly invalidated evidence; the stable two-worker run hit a250ms proof
budget refusal under host load around78. The new deterministic native-alarm
controls fail3cases on saved production and pass after the fix. This closes
the observed exception-handling defect, not all load-sensitive refusals.

Broad linters-dev still failed at real16_program_vectors.py:35 and reported
59Basta findings; it was not a scoped gate despite FILES being supplied. The
original broad25failed/9510passed result and original M0–M7 obligations remain
open. Receipts: m1-cache-identity/REVIEW.md (including final-sha256.txt and
admission-serial.log), m1-callee-cache/PARENT_REVIEW.md and
m1-alarm-boundary/REVIEW.md. All owned jobs are terminal at this checkpoint.

Latest M6.3 checkpoint: declared INT10/AH0F query integrated
after parent review of Devin's policy module. Live-vector, owned-handler,
interrupt-frame alias and complete-receipt controls remain fail-closed; no
other BIOS service is admitted. Frozen SORTDEMO reaches1892instructions
(previous1860), records one complete video query, then refuses AH1B/AX1B02.
Both sides remain incomplete. /dev/kvm is unavailable in this sandbox, and
Kvikdos itself lacks AH1B support; no fresh native agreement is claimed.
Integration160pass, Make/ownership93pass, final serial early gate296contracts
19.78s +449comparators292.85s; scoped lint/types and structural checks pass.
Two parent mutation controls reject removed vector/receipt guards. Receipt:
real16-video-query/REVIEW.md. Libdosbox recorder intake is a separate bounded
audit; it must not be mistaken for deterministic backend acceptance.

All Python commands use `PYTHON_JIT=1`, `nice -n 10`, workspace TMPDIR and the
project interpreter. Aggregate pytest limit: six. Parent validation and both
Devin workstreams are terminal at this checkpoint; no slot remains reserved.
The full changed-surface type-ratchet now passes after per-file snapshot reuse.
Required final commands retain the repository
contracts: `make quality-dev`, `make quality-fast`, `make quality-hard`,
`make test-pipeline`, and `make test-pipeline-expanded` for the broad slow audit,
all with `PYTHON=./.venv/bin/python` and explicitly selected worker counts.
Standalone adapter gates are `artifacts/bc5-z3cmp32/test_z3cmp32.py` and
`artifacts/msc8-z3cmp32/test_z3cmp32.py`, supplemented by their changed-owner tests.

Timing-sensitive refusal changes are reported separately from semantic changes.
Do not raise budgets merely to force repeatability, conceal unknowns, or count
a faster microbenchmark as end-to-end corpus improvement. Completion requires
the original plan's exits, not merely exhausting this work queue.


2026-10-03 functionality-state checkpoint: parent reviewed and integrated Devin's
explicit INT10/AH1B/BX0 policy with live BDA reads, bounded destination/IVT/frame/
code/source guards and complete68-byte receipts. All public projections and
routine gates enrolled. Expanded integration280pass57.33s; enrollment134pass;
scoped Ruff/MyPy/Pyright clean; two independent guard/receipt sabotages rejected.
Frozen SORTDEMO now1906instructions(previous1892), then honest undeclared ROM
read0xC2A66, not termination or native agreement. Parent independently matches
the64-byte table to native capture; separate1MiB capture includes unchanged ROM.
Six-worker early gate296contracts then1failure/22pass; exact failing transitive
callee control passes serially under unchanged budgets. Two-worker retry14191
finished0:296contracts+682comparators pass with unchanged budgets and source
hashes. ROM contract Devin51498 owns staging only. Original M0-M7 and broad25
failure result remain open. Receipt: real16-video-state/PARENT_REVIEW.md.


2026-10-03 ROM/native-entry checkpoint: parent integrated reviewed read-only
ROM declarations and exact read coverage while preserving writable RAM boundaries.
209focused/134enrollment pass;3parent forgery reds repaired,2mutations detected;
scoped lint/types clean. Early gate296contracts+814comparators passes2workers.
Synthetic SORTDEMO reaches1964 then AXEF00 refusal. Independent native-entry
capture now verifies26256loaded bytes/34relocs; production initializer matches
917504declared bytes and16register fields exactly, with no service policy claim.
Quality-dev first stopped on omitted SegOffset typing owner; inventory fixed,
retry58991 live with comparator2/later6workers (97pool controls). Native service
capture Devin79549 and true full-program candidate build Devin36342 are staging
only. M0/M1 audit identified missing tiny manifest/real16 candidate and stale
matrix; parent rejected narrower "M0 exit met" promotion. No original M0-M7
acceptance. Receipts real16-rom-contract/PARENT_REVIEW.md, real16-native-entry/
parent-projection-review.json, m0-m1-exit-audit/PARENT_REVIEW.md.
