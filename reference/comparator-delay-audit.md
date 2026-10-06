# Comparator plan delay audit — 2026-10-05

## Current acceptance status — 2026-10-06 (supersedes latest-checkpoint wording)

The 20.30s/33.56s LoadProgram pair ran under the internal
`native_compare.py` runner (imports cache/generation/atom owners, overrides
the cache directory before `cli_core.main`): not public `decompile.py`
timing/entrypoint acceptance and no demonstrated speedup. Unchanged
generated C passes GCC execution on all 8 error-code vectors via the
correct five-word binary ABI; the reviewed LoadProgramAbi SOURCE/BINARY
helper + 18 controls are integrated. Focused public run: 18 passed /
2 failed in 91.73 s, both unchanged 20s/10s timeouts (was 1 failed 64.51s).
Public diagnosed CLI exits 3 with 3 s child stack dumps (typehoon, segment
lowering, repeated atom/dataclass traversal, pointer-output publication),
not exact time shares. SWAPS 100s diagnostic: 225 installs
inventory_refused 24.09s inclusive; 42 imports/30 completed, 2 matching
context duplicates; 272 premise/260 completed None; snapshots omit mutable
bytes/patches/registry/resolver — unsound cache keys, no cache or proof
accepted. Delegated work streams in this snapshot: LoadProgram runtime,
SWAPS authority lifecycle, InitBars remaining obligations, and this
acceptance-docs review — each owns its checks; terminal status is not
inferred from saved files. M5/M7 remain open; public LoadProgram
timing/entrypoint gates unresolved. Evidence under
`.cache/comparator-implementation/`: perf-retained-native-review/,
loadprogram-acceptance-parent/, swaps-request-counts/.

## Latest checkpoint — 2026-10-06, after receipt publication repair

Bounded SWAPS request measurement now exists (`swaps-request-counts/`): at
the 100s external diagnostic cutoff, 42 IR imports started/30 returned,
272 premise requests started/260 returned None, 225 deferred installs all
returned inventory_refused. Completed installs total 24.09s inclusive. Only
2 IR import requests repeat both argument identities and recorded
resolution context; 173 install requests repeat those snapshots. These
snapshots do not bind mutable bytes, patches, registry or resolver state,
so they are not cache keys. Input objects were pinned to prevent identity
recycling. Inclusive times overlap; the interrupted diagnostic is not a
proof verdict or benchmark. One earlier setup attempt was stopped after
detecting incomplete hook binding and is preserved separately. No new cache
is accepted from these counts.

Final parent measurement under internal `native_compare.py` (which
pre-imports cache/generation/atom owners and overrides the cache directory;
not the public `decompile.py` entrypoint): production-source LoadProgram
completed exit 0 with validation=passed and the declared-call assumption
consumed, 20.30s total wall, 273248KiB RSS. Private dispatch completed
33.56s/273288KiB with identical C and same status/assumption. Separate
fresh caches, sequential ordinary fork runs, unchanged 20s analysis budget;
four relevant source hashes unchanged. One pair under variable host load is
not reliable comparative performance evidence; it demonstrates no speedup,
so the candidate remains private. Latest internal-runner completion
supersedes the earlier timeout for this invocation only; it is not public
entrypoint acceptance. Final source-shape/round-trip and M5/M7 gates remain
open. Both workers are terminal; parent performed the measurements after
stopping the setup-heavy worker. Evidence:
perf-retained-native-review/{REPORT.md,results.json,*-native.log}.

The previously staged native CALL replay and declaration integration are now
production changes. A further actual-stage-order regression reproduced lost
consumption receipts when function-summary publication replaced segment-state
summaries. Republish now reauthenticates already-consumed receipts, including
function identity and revocation controls. The focused cohort passed67tests
in21.07s; scoped lint/MyPy and startup architecture pass. This supersedes older
instructions below to integrate those same slices again.

The post-fix fresh-cache native run still exits3/timeout at the unchanged20s
analysis budget:39.30s total wall,272144KiB peak RSS. Total wall includes work
outside that analysis deadline; the difference is not itself proof of a solver
budget overrun. Missing receipts from this timeout do not diagnose a new
consumption failure. Evidence:receipt-stage-order/{production-green,native}.log.

The retained-IR profile contains44,324atom calls and3,888dataclass expansions
for one graph. Private exact-built-in dispatch reduces median traversal from
153ms to91ms; private pure-Python Cython reduces351ms to214ms in a separate
measurement. These runs are not directly comparable and neither establishes
native completion or end-to-end gain. No optimization has been promoted.
Evidence:retained-ir-speed/{baseline.prof,dispatch-compare.log} and
retained-ir-cython/parent-compare.log.

Devin's saved-evidence audit completed and was parent-reviewed, including
corrections to timing aggregation and timeout interpretation. The native
measurement task was stopped during setup (terminal143, no patch); the parent
took over the existing runner for a sequential fresh-cache baseline/candidate
pair. This avoids another open-ended handoff. Do not restart previous rejected
cache designs or broaden proof budgets. M5/M7 remain open.

Parent live host snapshot at01:33 on2026-10-06:8available CPUs, load averages
31.64/25.22/21.47, multiple active cc1plus processes and a codebase-memory
indexer. This is timing contention evidence, not a measured attribution of
the native timeout. No unrelated process was stopped or reprioritized. Keep
native comparisons sequential and record load with their timing results.

## Current recheck — 2026-10-06

### Production instrumentation after declaration integration

Two bounded diagnostic runs on the promoted sources verified the hooks inside
the analysis worker. The first observed 16 declaration-consumption checks,
1,621 ms inclusive, of which native CALL rebinding took 1,587 ms. Current-image
hashing totaled 0.86 ms; projection authentication totaled 0.96 ms. Optimizing
these hashes would not materially address the timeout.

The second instrumented validation-generation fields. It completed 30
fingerprints of `_inertia_segment_state_artifact`, totaling 6,778 ms inclusive
(maximum 517 ms). `unified_local_vars` totaled418ms; all observed atom sorting
totaled608ms. These times overlap and must not be summed. The native command
still terminated with timeout at its unchanged20s analysis budget. Instrumented
timings are diagnostic, not a cold/warm speedup claim.

Next performance question: which nested segment-state fields account for those
30 traversals, and which repeated work can be removed while preserving exact
mutation/provenance detection? Do not revive the rejected cyclic-cache proposal
or cache mutable evidence by identity alone. Both earlier proposals failed the
native completion requirement; the new evidence identifies the expensive root
field rather than proving a cache design sound.

A subsequent nested-field diagnostic completed four `source_artifact`
traversals totaling2,742ms. State-map fields totaled approximately234ms;
receipts totaled0.78ms. The extra per-field instrumentation adds overhead, so
these figures are not directly comparable to the preceding run. They localize
the repeated work to retained IR traversal. `segment-field-summary.json` and
the corresponding raw events preserve the completed-prefix counts; a timeout
does not establish that all traversals finished.

Evidence under `.cache/comparator-implementation/m7-declaration-integration/`:
`consumption-profile.jsonl`, `field-profile-summary.json`, corresponding CLI
logs and stack samples. The production CLI guard now preserves timeout/error/
unknown/prior-validation-failure causes rather than relabeling them as a missing
declaration receipt. Its real-method controls pass in the59-test follow-up.

KVM is available in the current execution environment: opening `/dev/kvm`,
`KVM_GET_API_VERSION` (12), and `KVM_CREATE_VM` all succeeded. The earlier
sandbox observation below is historical, not a current blocker. Static SSA/Z3
comparison does not require KVM regardless of this result.

The delay is a combination of expensive serial proof work and integration
turnaround, not demonstrated solver nondeterminism:

- SWAPS: the saved collector took 334.11 seconds; sampling found 10–12 nested
  IR builds. Measure identical request keys before implementing request-local
  reuse; nesting alone does not prove duplicate computation.
- LoadProgram: the full attempt still hits its 20-second budget while focused
  controls pass. The latest dedicated `projection-events.log` now records
  successful consumption and a receipt, unlike the earlier failed probe.
  Stop diagnosing absent console output as absent execution. Localize the
  remaining post-consumption time on the exact candidate before retrying.
- Integration: a reviewed native CALL replay-context repair remains staged.
  The existing production red test is 1 failed / 3 passed in 11.25 seconds.
  Finish this bounded repair and enroll the declaration controls before another
  broad acceptance run; starting more overlapping investigations delays delivery.
- Gate cost: the saved comparator checkpoint was 11.06 + 204.16 seconds.
  This does not explain a day of elapsed development by itself. Repeated native
  attempts, rejected proposals, and cross-consumer repair are separate costs.
- Host contention: a live snapshot showed an indexer using over two CPU cores,
  two unrelated replay jobs near one core each, and a long-running Python job
  in `/home/xor/games/airborn`. These are competing workloads, not proof of this
  task's bottleneck; none was terminated or reprioritized. Record host load for
  timing comparisons and retain the two-worker wall-budgeted proof cap.

### Immediate execution order

1. Integrate the reviewed replay-context slice; batch its existing focused
   controls and scoped lint/types on frozen sources.
2. Finish declaration transport enrollment and integration. Run one diagnosed
   native acceptance attempt; record the earliest remaining failed contract.
3. Instrument exact request counts in the bounded SWAPS collector; only add
   reuse when duplicate complete work is observed, with stale-input controls.
4. Run the required broad gate once for that integrated source set. Use up to
   six workers for independent tests, not for wall-budgeted proof chains.

This recheck adds current environment and saved-evidence reconciliation, not
a fresh performance benchmark or a claimed speedup. M5/M7 remain open; the
other six milestones are accepted, not an estimate that only 25% effort remains.

## Follow-up evidence review — 2026-10-06

The saved native traces narrow the next action further. LoadProgram repeatedly
reaches a closed registry and proven target, but reports `same_artifact=False`
in `m7-declaration-trace/native.log`. Its later projection probe ends with
pointer/value parameter mismatches and a missing/stale declaration-consumption
receipt. This is a semantic integration blocker, not evidence that Z3 needs
a longer timeout. Authenticate the raw-to-semantic projection before retrying
the whole native acceptance case; do not remove artifact identity checks.

The existing OTel summary in
`m7-declaration-integration/loadprogram-span-summary.json` records 45 root
fingerprint spans totaling 196.638 ms and 44 descriptor spans totaling 3.299 ms.
These narrow spans do not explain the earlier inclusive 15.54-second timing.
Neither rejected atom-cache proposal demonstrated native completion within the
unchanged 20-second budget. Further Cython/atom-cache work is not justified by
these measurements alone.

The projection log also shows successive rejected postprocess salvage attempts
at 00:11:00, 00:11:03 and 00:11:05 after the original validation rejection at
00:10:55. This is a candidate for a typed prerequisite gate: measure whether an
attempt can affect the failed contract before starting expensive validation.
Do not skip salvage based on diagnostic strings; prove that an ineligible
attempt cannot repair the invariant, and retain repair-capable controls.

### Shortest next iteration

1. Reproduce the artifact/projection mismatch in the existing native consumer
   fixture; repair authenticated projection handling and batch its positive,
   stale-source and revocation controls in one interpreter.
2. Run one fresh-cache native LoadProgram attempt with verified diagnostic
   hooks. The previous projection trace contains no declaration hook output;
   absence is not proof of cache reuse or of an unexecuted consumer.
3. For SWAPS, count exact duplicate requests within one bounded collector
   attempt before introducing caching. Preserve the existing request budget
   and measure end-to-end time, RSS and verdict after any proposed reuse.
4. Run the broad comparator gate once after integration on frozen sources.
   Six workers remain useful for independent tests; wall-budgeted proof tests
   retain their two-worker cap. Keep agent tasks to a reproducer plus a patch,
   with the existing 15–20 minute checkpoint.

This follow-up inspected saved evidence, not a fresh whole-suite benchmark.
The current command sandbox exposes neither host processes nor `/dev/kvm`, so
it cannot establish whether an earlier host worker is still running. Previous
host KVM API12 evidence remains distinct; static comparison does not need KVM.
M5/M7 remain open. No production speedup is claimed by this documentation change.

Artifact directories above are relative to `.cache/comparator-implementation/`.

## Measured bottleneck

The running SWAPS collector regression was sampled externally with `py-spy`
at 20 Hz for 15 seconds: 299 samples, zero sampler errors. At a subsequent
process check it had consumed 4m29s CPU in 4m42s elapsed, with about 342 MiB
resident memory. This is active CPU work, not waiting for KVM. Sampling adds
overhead; this run is not an uninstrumented performance baseline.

All samples were inside `publish_pointer_parameter_caller_targets_8616`,
through recursive entry-domain caller/callee proof construction. Each sample
contained 10–12 nested `build_x86_16_ir_function_artifact` calls. This shows
deep work nesting; sampling alone does not establish repeated identical inputs
or an infinite cycle.

Inclusive sample shares (overlap; do not add):

| Operation | Samples |
| --- | ---: |
| Invocation inventory construction | 24.4% |
| IR surface import | 29.8% |
| Entry-jump source digest construction | 14.4% |

A preliminary single stack also caught scalar-definition index construction.
The larger sample does not justify prioritizing that over recursive evidence
construction. This is one expensive collector phase, not a profile of every
16/32-bit comparator mode.

Raw evidence: `.cache/comparator-implementation/delay-profile/`
(`swaps-stacks.txt`, `sampler.log`, `summary.json`, `hotspots.json`).

## Optimization order

1. Count invocation-intake attempts, IR imports and proof requests by exact
   authority/input identity within this collector request. The retained-source
   accessor calls deferred `install(project)` whenever the source remains
   absent. Determine whether refused intake is rebuilt on these accesses;
   the current stack sample shows this path is expensive but does not prove
   duplicate keys. Reuse only under identical image, declarations, inventory
   roots, resolver and proof scope. Do not make a transient deadline refusal
   a permanent cached result or prevent retry after prerequisites change.
2. Collapse repeated completed caller/callee work within one request. Existing
   callee sessions already retain complete closures; measure misses before
   adding another cache. Keep cyclic/in-flight evidence unproven, preserve
   scope distinctions, and bound retained state by existing request limits.
3. Reuse canonical source serialization/digests only for an unchanged owned
   source snapshot. Preserve mutation/staleness controls; object identity
   alone is not enough for mutable IR. Likewise, build scalar-definition
   indexes once per stable analysis batch if counters justify it.
4. Batch short regressions to amortize interpreter/native import cost. Use
   the bounded reproducer for diagnosis and the actual SWAPS collector for
   acceptance. Keep broad gates at coherent integration checkpoints.

For each optimization, compare the same frozen-source collector before/after,
including verdicts, proof obligations, wall time, peak RSS and cache state.
Add stale-input and changed-prerequisite controls where reuse is introduced.
Do not increase proof budgets, drop evidence validation or claim success from
microbenchmarks. More workers cannot shorten this serial dependency chain;
keep the existing two-worker cap for wall-budgeted proofs.

## Why delivery has taken longer than test runtime

The plan records a 334.73-second retained SWAPS failure, whereas the latest
recorded comparator gate took 11.06 seconds for prechecks plus 204.16 seconds
for tests. Repeating the expensive acceptance case at each prerequisite is
costly. The plan also records a 54-minute external-call delegation without
completed candidate tests. Semantic gaps, review corrections and integration
delay contribute alongside runtime. Keep delegation checkpoints and integrate
reviewed slices before expanding their scope.

M0–M4 and M6 are accepted in the current ledger; M5 and M7 remain open.
Six accepted milestones out of eight is not a remaining-effort percentage.
No runtime speedup or new milestone acceptance is claimed by this audit.
