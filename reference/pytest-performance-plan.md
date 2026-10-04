# Pytest Performance Investigation and Plan

## Goal

Keep the same correctness and development gates while making the normal pytest
feedback loop fast, deterministic, and measurable. No test may be deleted,
weakened, skipped, or made order-dependent to meet a time budget.

## Baseline (2026-08-08)

Environment: `./.venv/bin/python`, pytest 9.0.3, pytest-xdist 3.8.0.

| Measurement | Result |
|---|---:|
| Full test-tree collection | 2,759 tests in 15.36 s |
| Focused pipeline lane, `-n 7 --dist loadgroup` | 1,806 passed in 60.26 s |
| Focused lane budget | 30 s |
| Architecture-contract test | 26.27 s |
| Ownership-manifest test | 14.41 s |
| Remaining focused tests and pytest overhead | about 19.58 s |

The two repository-wide static tests consume 40.68 seconds, about 67.5% of the
focused lane wall time.

## Current measured state (2026-08-16)

The broad xdist collection issue is closed on this checkout. The full suite
completed with `6628 passed, 170 skipped, 79 warnings` in `1312.14s` using
`-n 7 --dist loadgroup`; peak RSS was `1,442,748 KiB`. The focused unit lane
completed with `1448 passed in 38.92s`, and the external MS C tiny-example
contracts remain green.

Architecture and ownership scans are mandatory hard-gate prerequisites and are
no longer duplicated inside focused pytest execution. Their whole-repository
assertions use the registered `repository_contract` marker; `pytest`,
`pytest-files`, and `pytest-profile` deselect that marker after the explicit
hard gates run, while `pytest-all` remains unfiltered. A two-worker marker-only
run passed both checks in 27.99 seconds (architecture 15.54 seconds, ownership
2.34 seconds). The corresponding focused profile collected 419 scanner tests,
passed 417, recorded exactly those two marked tests as `not-run`, and completed
in 7.13 seconds. Pytest now reports the ten slowest tests globally through
`pyproject.toml`; the focused pipeline keeps its more detailed 25-test report.

The decompilation cache now writes records atomically and uses path-independent
binary content identity (`schema=9`). The key also includes the recovered CFG
shape, original/active/recovery addresses, compiler target, complete explicit
COD and synthetic annotation inputs, typed caller-return/helper evidence, and
the serialized sidecar metadata digest. Unsupported evidence disables reuse.
Direct-address CLI runs still need an end-to-end cold/warm equivalence
measurement before being counted as optimized. The measured full-suite
bottleneck remains the sidecar-free
SortDemo subprocess tests, which can take about 205-255 seconds under the
scale-4 contention audit. The ten-slowest report is dominated by
InitMenu/RunMenu/QuickSort and one MS C runtime contract, rather than
collection or worker startup.

The initial serial profile run produced `.cache/pytest/focused-profile.json`:
2,843 collected, 2,841 passed, and two MS C comparison assertion failures in
365.15 seconds. The profile records setup/call/teardown durations and stable
node metadata. Its slowest valid nodes were InitBars at 89.46 seconds, the
architecture scan at 16.91 seconds, recompilable-subset syntax checking at
11.21 seconds, and several SortDemo subprocess tests at 8-11 seconds.

The first locked-cache SortDemo cluster run passed 11 tests in 268.64 seconds
with 368,472 KiB peak RSS. A warm repeat reached 25.61 seconds but exposed a
cache identity bug: typed-switch mode reused a normal RunMenu artifact. The
cache now fingerprints `INERTIA_*` runtime switches and bypasses cached
payloads when typed-switch diagnostics are explicitly requested. The typed
switch regression then passed cold in 93.11 seconds. The direct-address result
boundary now preserves and replays the same opt-in diagnostics instead of
silently rebuilding them; the exact RunMenu regression passed in 95.81 seconds
cold and 6.82 seconds warm, a 14.0x reduction with all assertions retained.
Cache and lock-focused tests pass; the two original MS C failures also pass
after restoring the cached-path `merged_statuses` diagnostic.

The external `/home/xor/pytest_deduplicate` tool completed its 42-test bounded
slice but crashed afterward in its supersession comparison with an internal
`AssertionError`. No deletion decision is based on that output; the tool must
be patched or wrapped defensively before it can be used as a project gate.

Profile schema 10 now consumes the shared one-pass source index and records
per-node purpose, reviewed and inferred owner layers, manifest ownership
contracts, direct and local-helper-backed assertions, explicit expectation
APIs, required evidence, input/option/cache/module hints, and direct subprocess
calls. It also preserves direct and helper-transitive subprocess, input, and
option costs; structured decompiler-call and pytest-parameter facts recover
binary symbols and function addresses, with collection-time `CallSpec2` values
narrowing each concrete parameterized node. Executed profiles also sample
worker RSS at pytest phase boundaries. Profile-only `RUSAGE_CHILDREN`
snapshots attribute aggregate descendant user/system CPU to each complete test
protocol without wrapping subprocess APIs. Artifacts contain explicit top-50
wall-time and child-CPU rankings; aggregate child CPU may exceed wall time when
descendants run concurrently.
Manifest-backed reviews remain distinct from conservative static
classification, so inferred ownership is never presented as human-reviewed.

The profile launcher now propagates its plugin into xdist workers, merges unique
executed node records, records worker exit/crash events, and removes run-scoped
fragments after the controller writes the final artifact. The default Makefile
profile target now uses the project worker count and `loadgroup`; a two-worker
smoke produced 9/9 passed records with both worker exits captured.

Profile schema 10 also fingerprints relevant source, test, and configuration
files before and after execution. The artifact reports both snapshots and an
explicit `source_state.stable` verdict, so a long run overlapped by another
agent's source edit is invalidated rather than treated as a comparable timing.
The source-state unit and two-worker profile smoke pass (4 tests in 3.69
seconds); source hashing is confined to profiling and does not affect normal
pytest lanes.

The first seven-worker Makefile profile collected all 2,850 focused nodes and
finished in 599.46 seconds: 2,849 passed and one serial-clean-worker cache test
failed. The artifact retained the failed node and worker exit status. The root
cause was semantic cache identity including ephemeral child-result paths and
architecture parent-PID tokens. Those transport variables are now excluded;
the failed regression plus cache identity tests pass. Parent-owned direct-work
locks are explicitly bypassed by recursive clean-worker children, preventing a
self-deadlock once transport tokens no longer split the key. A real sidecar-free
RunMenu regression passed cold in 95.86 seconds and warm in 7.70 seconds. The slowest
nodes were RunMenu at 252.24 seconds, InitMenu at 238.83 seconds, and InitBars at
213.70 seconds. Worker elapsed times ranged from about 305 to 594 seconds, so
the critical path is now clearly decompilation grouping/cache wait rather than
collection or worker startup.

A subsequent seven-worker run after the cache correctness fix passed all 2,851
executed tests in 575.01 seconds, but it was still effectively cold: RunMenu
cost 240.91 seconds, InitMenu 228.68 seconds, and InitBars 204.54 seconds.
Worker elapsed times ranged from 287.11 to 573.04 seconds. Investigation found
that `INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE`, which is read only by pytest helper
wrappers, was inherited by `decompile.py` and incorrectly included in semantic
cache identity. Focused scale `1.5` and full/profile scale `4` therefore built
separate artifacts. The variable is now excluded as non-semantic test control.
A sidecar-free `Sleep` end-to-end check produced and validated the artifact in
13.11 seconds under scale `1.5`; the same command under scale `4` reused it with
`direct function cache hit validation=passed` in 3.15 seconds and emitted the
same C. Unit regressions also preserve separation for genuine semantic runtime
modes.

The function-result cache now uses schema 9 and partitions artifacts by the
compiler target carried by the typed `FunctionWorkItem` contract. This closes
an unsafe identity gap where portable-flat generated C and GCC acceptance
could otherwise satisfy an `msc-dos` lookup. The dynamic angr project access is
centralized in one documented work-item property; no new scattered `getattr`
access was introduced. Cache-key/work-item and persistent-cache
acceptance/timeout regressions pass. Recovery graph shape, explicit annotation
inputs, typed caller-return evidence, binary-proven compiler-helper targets,
and complete sidecar metadata are now serialized by one CLI-owned cache-context
contract. Malformed project evidence or unsupported CFG nodes refuse cache
reuse. The focused cache/work-item/serial-worker surface passes 59 tests;
cold/warm generated
C, diagnostics, validation, compiler, and concurrent-producer equivalence
remain open before final warm timings can count toward the target. As an initial
schema-9 end-to-end check, sidecar-free `Sleep` completed cold in 12.36 seconds
at 279,996 KiB and warm in 3.08 seconds at 277,904 KiB after CFG edge-kind
metadata was added to the key. Both runs returned zero,
produced byte-identical C with SHA-256
`c25a0fdbc560bd7d9248309523f2e4cf4ae8a8496605b8b452ee2d31f161b440`,
reported `validation=passed` and whole-tail clean, and had no GCC syntax error;
the warm run explicitly reported a direct function cache hit.

A three-worker cold profile of the dominant RunMenu, InitMenu, and InitBars
contracts passed in 122.79 seconds; the identical warm profile passed in 30.76
seconds. It exposed a remaining InitBars-specific control-flow cost: the CLI
repeated a sidecar primary decompilation known to fail postprocess validation
before consulting an already accepted clean-worker cache. The generic
sidecar-canonicalized fallback boundary now performs a cache-only preflight.
Source, semantic environment, evidence, option, or result-schema changes still
miss and force the primary path. After one source-invalidated 92.51-second cold
rebuild, the InitBars test passed warm in 3.95 seconds instead of 26.42 seconds;
a direct CLI check completed in 4.01 seconds, emitted the same accepted C hash,
reported the clean-worker cache hit and whole-tail pass, and did not enter the
primary decompilation stage. A post-fix two-worker cluster then passed cold in
122.48 seconds and warm in 17.03 seconds; the source-stable profile artifacts
record 121.46 and 15.98 seconds respectively. The warm RunMenu, InitMenu, and
InitBars calls were 8.95, 4.42, and 3.98 seconds. Three outer heavy workers
briefly exceeded the 2 GiB aggregate process target because each can spawn a
nested decompiler, while two outer workers stayed near 1.5 GiB. Heavy profiles
should therefore use two outer workers until child concurrency is accounted
for; ordinary unit lanes can retain seven workers.

A source-stable full-suite cold profile passed `6666` tests with `170` skipped
in 1257.29 seconds. Its first warm repeat reached 676.55 seconds but was invalid
as an acceptance result: two CMP32 nodes lost ordered stage-status diagnostics,
Beep lost the direct failure-family diagnostic, and one COD timeout test failed
under contention. The cache now preserves the complete tail snapshot, restores
the authoritative `structuring` then `postprocess` stage order after sorted JSON
transport, and carries the typed direct failure-family snapshot through function
and clean-worker cache protocols. The exact three-node regression passed in
35.68 seconds cold and 7.24 seconds warm. The COD contention timeout and three
source-stable full repetitions remain open.

The current source-stable schema-11 collection-only inventory (pytest
`testpaths`, without an explicit repository-root path) completes in about 22
seconds with 6,851 collected nodes and no collection errors. The enforced
inventory audit reports 3,817 conservative static classifications, 2,928
reviewed ownership-manifest classifications, and 106 explicitly reviewed
dynamic-module classifications. Every collected node has an owner layer,
purpose, and required evidence record. Local helper traversal recovers 631
helper-backed assertion contracts; transitive call-cost facts and concrete
parameter addresses now identify repeated decompiler work without conflating
different functions. Explicit exception/assertion APIs and checked subprocesses
distinguish valid indirect contracts from inert tests.
Two pass-only preliminary loop tests and two duplicate COD parameter rows were
retired with machine-checked substantive replacement nodes. `make
pytest-inventory` now
fails on missing fields, duplicate node IDs, unresolved review, missing owner
layers, missing evidence, or count mismatch. Profile-only cache I/O events now
record per-key namespace/digest identities, structured key context, hits,
misses, invalid entries, stores, failed stores, and structured validation
statuses without parsing stderr. A
source-stable persistent-cache smoke recorded one exact function key, one hit,
two misses, one atomic store, no invalid/failed operation, and validation
`stable`. Full execution costs, per-tool decompiler/compiler phase timing, and
the three-run full baseline remain open. A separate source-stable subprocess
smoke measured 3.17 seconds wall and 3.70 aggregate child CPU and populated
both machine-readable rankings. The current dominant SortDemo cluster passed
cold in 184.20 seconds and warm in 16.85 seconds with two workers. Every warm
function key had one validated hit and no store; per-node child CPU closely
matched wall time (9.34, 5.85, and 3.40 seconds), so the remaining warm cost is
active child work rather than lock waiting.

Full-suite schema-10 attempts at seven and four outer workers were stopped at
about 34 percent rather than risk OOM. The seven-worker process set reached
about 2,474,976 KiB RSS; the complete four-worker process tree later reached
about 3,503,216 KiB while nested decompiler and MS C runtime-gate children were
active. Four outer workers are therefore not a safe heavy-lane default merely
because they use fewer CPUs; full profiling must use two outer workers until
nested concurrency is bounded. The four-worker attempt also exposed one
order-dependent recovery-cache test: its first-call-miss assertion used the
shared repository cache even though production identity is intentionally
content-addressed and path-independent. The test now owns an isolated cache
root and passes on repeated invocations without weakening cross-path production
reuse. A subsequent two-worker attempt reached about 2,473,472 KiB while nested
decompiler children overlapped and was also stopped. It retained two observed
failures plus one Ctrl-C-interrupted record: an original-address identity bug
and an InitMenu cold rebuild that timed out under contention after 480 seconds.
Original-address tracking now validates the owning function object even for
objects that cannot be weak-referenced, preventing a reused Python object id
from inheriting stale exact-slice metadata. Focused collision, source-label,
cache-isolation, Ruff, strict-mypy, and architecture checks pass. The isolated
current-source InitMenu test passed cold in 97.24 seconds (94.55-second call,
about 740 MiB observed process-tree RSS) and warm in 6.39 seconds (3.83-second
call). The 480-second xdist timeout is therefore contention, not intrinsic
serial cost. A serial full baseline remains required; two outer workers are not
accepted for the heavy lane until nested concurrency is bounded.

The first complete current-tree serial schema-10 profile is source-stable and
green: 6,673 passed, 170 skipped, and no failures across 6,843 collected nodes.
It took 3,266.34 seconds, so it is correctness evidence rather than a
performance acceptance run. The profile recorded 472 cache hits, 407 misses,
188 stores, one refused invalid entry, and no failed stores. Its dominant tests
were active child-CPU work: sidecar-free RunMenu variants took about 97-102
seconds, InitMenu variants about 82-89 seconds, and the largest MS C runtime
examples about 76-82 seconds. Serial nested phases remained below the 2 GiB
budget but reached about 1.8 GiB, leaving too little margin for an additional
outer worker.

Profile schema 11 now attaches the structured cache-key context to each exact
profiler-only operation without changing cache identity or stored payloads.
This proved why a focused InitMenu key (`fcfe...`) became `d42a...` in the full
run: adding only `INERTIA_OTEL_EXPORT_OTLP=1` reproduces both the full recovery
and function-key digests. A two-node telemetry-then-InitMenu reproducer also
carried that leaked value and forced an otherwise unnecessary 83.71-second
rebuild. Telemetry tests now restore the flag they enable, all
`INERTIA_OTEL_*` observability controls are excluded from semantic decompilation
cache identity, and typed-switch replacement requests prepare their structuring
artifacts explicitly instead of mutating process-global diagnostic state. The
post-fix current-source InitMenu build passed cold in 89.97 seconds; the exact
telemetry-then-InitMenu reproducer then passed both nodes in 6.26 seconds, with
the InitMenu call at 3.68 seconds, one function-cache hit, eleven recovery-cache
hits, no miss/store, and no OTLP field in either key context.

Four COCKPIT COD nodes in the serial profile each waited 30.11-30.12 seconds
and skipped, consuming about 120 seconds without proving generated-C behavior.
The measured causes were independent: killed producers left permanent
exclusive-create cache locks, and explicit `--timeout 10` was shape-expanded
to a 188-second direct-address deadline, beyond the tests' 30-second process
budget. Cache locks now record PID plus process-start identity and reclaim an
unchanged dead-owner inode; fork timeout work owns a disposable process group
and reaps nested descendants. Crash, legacy-lock, nested-descendant, Ruff, and
strict-mypy regressions pass. Explicit timeouts now receive only three to eight
seconds of bounded IPC/finalization overhead and ignore shape expansion. The
dedicated `_TIDShowRange` and `_DrawRadarAlt` nodes pass without skips in about
15 seconds each. Their exact duplicate parameter rows were retired with
machine-readable replacements: the DrawRadarAlt row asserted a strict subset,
while the TIDShowRange row bypassed all nominal output tokens on timeout and
could not satisfy them on success. This removes a projected 30 seconds without
retiring the stronger TIDShowRange composite. That composite still completes
decompilation and passes its trait-publication contract in 49.94 seconds. An
attempt to replace it with a strict CLI assertion failed at both 60- and
90-second budgets: postprocess validation rejects the changed output because
of repeated uninitialized-register-carrier findings, rolls back, and the CLI
eventually times out. The timeout-tolerant dedicated test therefore proves only
structured timeout behavior on that path. Strict generated-C completion and
the validation failure are open semantic debt, not removable test cost.

The strict TIDShowRange investigation exposed a real stack-lowering crash:
two sibling pointer-dereference paths could read an unassigned resolved offset
when alias evidence had no integer base. Both now refuse that unsupported
rewrite and retain the original expression, with a focused regression. Direct
CLI recovery also uses the main-thread process alarm instead of abandoning a
timed-out daemon worker. Runtime segment access now builds its assignment-source
index lazily and only after direct DS/ES/SS evidence fails; focused tests prove
zero index builds for direct segment access and one shared build for copied
segment access. These fixes remove avoidable work and failure modes, but they do
not make the unresolved postprocess validation result acceptable.
The cache, timeout-policy, fork-lifecycle, and retained COD surface passes 43
tests with two workers in 34.85 seconds. The fast external pipeline passes
1,455 pytest checks in 40.11 seconds and its selected MS C
compile-decompile-recompile lane reports one pass, no failure, no skip, and no
timeout.

A source-stable schema-11 profile of five RunMenu contracts initially took
317.50 seconds with two workers. Semantic cache-key normalization reduced the
cluster to 238.89 seconds by sharing sidecar-free variants and by excluding
`INERTIA_DISABLE_TIMING` from generated-C identity. Three distinct producers
remain legitimate: sidecar-free, sidecar-backed default, and typed-switch
diagnostic mode. The first normalized run still showed two simultaneous stores
for the same sidecar-free function key because the parent direct-work lock was
partitioned by `ignore_local_sidecar_hints` even though no sidecar existed.
Recovery/producer lock identity now applies the same evidence rule as the
function cache: that policy is normalized only when no local sidecar exists,
and remains semantic when a sidecar is present. The exact two-worker
sidecar-free pair then passed in 107.75 seconds (106.68 profiler elapsed) with
one store and one validated hit on the same function key, eliminating one full
RunMenu producer's CPU and memory cost. Focused key and producer-lock coverage
passes 15 tests, and the changed cache surface passes the parallel Ruff, mypy,
and type-ratchet gate.

The remaining dominant SortDemo families were then classified by exact cache
identity rather than test names. Two sidecar-free InitMenu contracts now share
one recovery-shape/function key: the cold producer took 83.73 seconds and the
second contract was a validated 3.74-second hit (90.57 seconds profiler elapsed,
source stable). QuickSort requires two legitimate producers because
sidecar-backed and sidecar-free evidence differ; their cold calls took 86.03
and 79.53 seconds, while the acceptance scorecard reused the sidecar-backed key
in 4.18 seconds (90.85 seconds profiler elapsed with two workers, source
stable). These are not deletion candidates and need CPU optimization rather
than weaker test consolidation.

The two InitBars contracts are also intentionally distinct: the sidecar-free
binary-evidence producer took 73.69 seconds and stored one accepted function
artifact, while the sidecar-backed recovery/fallback contract took 102.33
seconds under different metadata identity. They passed concurrently in 104.03
seconds (102.99 profiler elapsed, source stable). The sidecar-backed cold path
does not publish its failed primary candidates; its accepted clean-worker
artifact remains the warm-reuse owner, so merging these tests would conflate
different evidence and failure modes.

The MS C runtime gate previously decompiled every independent function in an
example serially. Its seven xdist-grouped examples now keep pytest-level
serialization but run at most two tiny function subprocesses concurrently,
preserving deterministic function order and per-function process isolation.
The worker control is removed from child environments so it cannot split
semantic cache identity. A controlled cold `scalar_types_io` run fell from
75.17 to 51.44 seconds (31.6%); the source-stable seven-example acceptance run
passed all rows in 173.89 seconds. Their summed calls were 172.23 seconds,
compared with 293.87 seconds in the last complete serial profile, a 121.64-second
reduction on that grouped critical path. Bounded-concurrency, ordering,
configuration, transport-isolation, runtime rebuild, and execution checks pass;
the promoted gate script also passes Ruff and mypy.

A subsequent all-files `-n 7 --dist loadgroup` attempt was deliberately stopped
after 78.13 seconds and 1,051 passing nodes because the controller plus seven
pytest workers alone occupied about 3.16 GiB aggregate RSS; active decompiler
children increased the process tree further. Individual workers retained about
390-665 MiB after collecting the complete decompiler test graph. The
source-stable partial profile is
`.cache/pytest/full-profile-v12-n7-run1.json`. This candidate fails the 2 GiB
scheduling DoD even though seven CPUs are available: every xdist worker imports
the full angr-heavy module graph before test distribution.

The first import-aware runner proved exact light-lane execution, but a single
long-lived heavy process still retained enough state that one nested decompiler
pushed aggregate RSS to 2,191 MiB after 1,014.33 seconds and 59% of its lane.
The controller killed the complete descendant tree; 180 light nodes had passed,
the source fingerprint was stable, and no partial heavy report was accepted.
The replacement pre-partitions files before import into sixteen short-lived heavy
batches, runs one heavy batch at a time by default, and executes reviewed light
batches in the remaining N-1 slots. A real 14-node smoke selected and passed all
14 nodes exactly once at 144,296 KiB peak RSS. Focused partition, detached-child
termination, Makefile, and ownership contracts pass; the authoritative
inventory is now 6,872 nodes. An isolated 60-node MS C/status probe passed at
1,097,408 KiB, proving the later 2,066 MiB batch abort was accumulated import
state rather than an intrinsically oversized test. Active-node attribution then
identified the MONOPRIN six-function COD anchor as a separate 2,246,636 KiB
spike with four COD workers. Two workers passed alone in 52.12 seconds at
1,373,636 KiB but still exceeded 2 GiB with the containing batch's imported
state. Its concurrency-independent assertion now uses one worker and passes in
103.94 seconds at 677,864 KiB. Concurrent heavy owners remain an explicit
experiment only after nested-process memory coordination is proven.

The first source-stable complete import-aware run observed all 6,861 nodes
exactly once in 1,637.33 seconds at 1,409 MiB peak RSS: 6,694 passed, 165
skipped, and two failed. The compiler-matrix failure was a transient Wine MSC8
page fault whose 90-second timeout escaped the build result; external-tool
timeouts now become typed nonzero process results and the real matrix plus unit
regression pass. The instruction-equivalence failure exposed mutable frontend
register-layout debt: repeated `Arch86_16` construction could collapse helper
and FPU offsets after archinfo built its maps. Register declarations are now
immutable; repeat-instantiation, exact instruction, and 496-node ordered-shard
regressions pass. Full-run summaries now retain failed node IDs and ordered
worker paths. A new complete run is still required before claiming green.
The deterministic COD timeout contract also uses the shortest proven 1-second
analysis budget: it retains exit code 3, recovery-stage classification, and
retry guidance while reducing the measured test call from about 24.34 seconds
to 5.43 seconds with a 20-second escape ceiling.

The three `_overlay_load` COD contracts each spent a 20-second analysis budget
and followed the same timeout path, taking 24.59-24.64 seconds apiece and 75.51
seconds serially. The detailed sample regression already contained the full
successful-path guard/order contract of one duplicate and strictly stronger
status/output checks than the parameterized row; its timeout branch now also
requires the function header asserted by that row. The exact subset test and
parameter row are retired with machine-readable replacements. The retained
contract passes in 24.59 seconds, a measured 50.92-second serial reduction. It
still permits a structured timeout, so mandatory generated-C completion remains
semantic debt rather than a reason to retire further coverage. Pass-level timing
first exposed an incompatible wrapper that dropped the typed
`boundary_fingerprint` keyword; the wrapper now forwards the complete contract
and has a strict regression. External sampling then attributed about 46% of
the sampled pre-structuring work to angr rewriting lifter-generated X86-16 ITE
values into synthetic CFG diamonds. The X86-16 structuring option owner now
disables that transform only for proven straight-line functions. Branching
functions retain angr's normal ITE conversion; the broader disable was reverted
after focused semantic regressions showed that CFG exits alone do not prove the
conversion redundant. The remaining work is real Clinic and postprocess CPU,
not validation waiting, and must be profiled before these tests are merged.

The ownership-manifest scanner now uses one immutable, SHA-256-invalidated AST
index per test source. Indexed and uncached results are equality-tested, and
file, class, and method skip/xfail scope is preserved. Its isolated `--check`
runtime fell from 5.87 seconds to 2.37 seconds (about 60%) with unchanged exit
status; 58 focused scanner/index tests and strict mypy pass.

The architecture scanner already had path/stat parse caching when re-audited.
Its pytest target and skip/xfail checks now consume the shared one-pass source
index; narrowed-field rules skip assignment/getattr scans until a guard creates
an active narrowing; dynamic-boundary ownership uses one definition-span index;
and annotation debt traverses only statement bodies. Definition lookup is also
indexed per parsed module. Mutation tests and the current-tree contract remain
green. The latest isolated run took 12.94 seconds at 636,628 KiB; the preceding
three runs took 13.11-13.49 seconds (median 13.20 seconds). This improves on
17.93 seconds and 806,820 KiB but is
still above the 5-10 second DoD. Remaining work is shared fact extraction for
the broad import, owned-contract, and promoted-typed scans.

The historical mandatory `make pytest` target supplied 230 unique targets (201
files and 29 explicit node IDs). A measured `-n 7 --dist loadgroup` run reached
worker startup but collected/executed no tests and exited with pytest status 5
after 23.43 seconds. A small xdist test works, so broad parallel collection has
a separate stability/diagnostics problem. It must be understood before changing
the default scheduler.

The latest complete import-aware run observed all 6,873 inventoried nodes
exactly once: 6,698 passed, 166 skipped, and nine failed in 2,208.89 seconds.
Peak aggregate RSS was 1,658,220 KiB, so two heavy workers stayed inside the
2 GiB budget, but file-level heavy partitioning left the large SortDemo module
on one serial critical path. The nine failures were correctness prerequisites,
not performance exclusions. Focused reruns now close all nine: startup/Make
environment isolation, TID timeout accounting, the straight-line Clinic policy,
SetGear condition-register liveness, InBoxLng wide predicate recovery, and the
three DrawTime contracts all pass. InBoxLng now carries immutable typed
register-value snapshots from IR producers into Alias; 12 raw condition facts
normalize into four 32-bit comparisons, all 12 facts materialize, and whole-tail
validation passes. The next scheduling experiment must split overweight heavy
files by atomic pytest node groups while preserving exact inventory, xdist-group
ownership, source stability, and the same 2 GiB limit.

That experiment is now complete. The source-stable import-aware run collected
and executed all 6,879 nodes exactly once, with no missing, unexpected, or
duplicate nodes. It finished in 1,817.73 seconds, a 391.16-second (17.7%)
improvement over the preceding 2,208.89-second run, and peaked at 1,551,584 KiB.
The runner split only the measured-overweight SortDemo and MS C regression
files into two atomic node shards; all other files retained single-worker
ownership. The run reported 6,705 passed, 166 skipped, and eight failures.
Those failures reduced to three implementation defects now closed by focused
tests: condition refresh did not return its typed changed-state contract, the
timing guard leaked a monkeypatched tail-summary collector into later LIFE
tests, and the new IR binding module lacked exact architecture ownership and
promotion registration. The complete affected surface passes 74 tests in
20.98 seconds, the original eight nodes pass, and architecture, Ruff, mypy,
and the changed-file type ratchet are green. A post-fix complete run remains
required before correctness acceptance.

The run recorded 3,064.25 seconds of test-call work. With two memory-safe heavy
workers, the lower bound is about 1,532 seconds before process/import overhead;
scheduler tuning alone therefore cannot meet 300 seconds. SortDemo contributes
1,439.48 seconds, including six 80-117-second RunMenu, InitMenu, InitBars, and
QuickSort nodes. The next work must measure and reduce cold producer work,
prove warm artifact reuse across equivalent contracts, and then profile CPU
hotspots for mypyc. Lowering the shard threshold or adding low-memory tail
workers is secondary because it cannot remove the dominant work.

The post-fix cold repetition is now accepted: all 6,879 inventoried nodes ran
exactly once, with 6,713 passed, 166 skipped, no failures, stable source, and
1,602,140 KiB peak RSS. It completed in 1,662.65 seconds. The immediate
source-identical warm repetition preserved the same outcomes and exact node
coverage at 1,660,060 KiB peak RSS, but still took 895.46 seconds. Cache reuse
therefore removed 767.20 seconds (46.1%) of wall time without reaching the
300-second target. The warm run retained 1,379.20 seconds of aggregate call
work: SortDemo contributed 250.81 seconds, the CLI module 215.82, MS C runtime
regressions 156.06, COD regressions 129.98, COD samples 98.48, real-compiler
debug generation 90.20, and the MONOPRIN string anchor 62.09. Scheduling alone
cannot remove this work.

A structured two-worker profile of the eight slowest warm contracts passed in
142.72 seconds and separated their causes. MONOPRIN consumed 67.52 seconds of
child CPU while rebuilding all six COD procedures even though the test asserts
only `__fimemset`; one function artifact hit and five unrelated misses were
recorded. The segmented `_TIDShowRange` access-trait contract consumed 59.26
seconds in-process with no cache boundary. The `cmp32` runtime row used 64.03
seconds of child CPU in 33.69 seconds wall through bounded two-way function
parallelism. Four CLI/COD contracts each spent about 20-25 seconds on a real
function-cache miss. The real-compiler matrix took only 0.49 seconds in this
focused warm run, so its 90.20-second full-run result is contention/cache-state
evidence and must be repeated before code changes are assigned to it.

Deterministic `cProfile` is rejected for the 59-second `_TIDShowRange` contract:
instrumentation pushed it through its 90-second structuring timeout and changed
the outcome. A five-hertz `py-spy` sample preserved the pass in 52.52 seconds
with 269 error-free samples. It attributes about 39.2 seconds to the owned
decompilation implementation, 27.0 seconds to structuring, and 14.6 seconds to
repeated callsite summarization. About 10.6 seconds of that callsite work is
repeated neighbor-target collection and block decoding. The next owning-code
optimization is a typed, request-owned callsite machine-fact inventory reused
by Structuring, Lowering, and Validation; mypyc selection follows only after
that duplicate analysis is removed and the remaining self-time is remeasured.

The first two duplicate-work fixes are now implemented. The MONOPRIN anchor
uses the existing exact `--proc-name __fimemset` selection, retains the script's
real COD/CLI/output-file path, and strengthens the string-intrinsic assertion
to the selected procedure section. It passes in 10.00 seconds serially and
14.38 seconds in the seven-worker focused lane, versus 62.09 seconds in the
accepted warm full run and 67.62 seconds in the focused profile. No test node or
assertion was removed. Separately, postprocess call matching now consumes the
authoritative typed summary inventory it already publishes instead of creating
competing summaries. A new typed `CallsiteTargetInventory8616` collects the
immutable CFG-derived neighbor targets once for multi-callsite summary builds;
the module is enrolled in Ruff, mypy, the type ratchet, and architecture
promotion checks. Unit coverage proves one target collection and one shared
inventory for multiple callsites. The exact `_TIDShowRange` semantic contract
passes three unchanged repetitions at 44.96, 45.57, and 45.17 seconds (45.17
median, 45.57 maximum), down from the preceding isolated 48.44-50.78-second
range. This established the remaining Validation callers as the next measured
owner without caching mutable prototype facts.

Validation now consumes the authoritative typed callsite summary inventory
published by the earlier recovery stage. Fingerprint matching, contextual
summary pairing, expected-call counts, and missing-call finalization share that
owned projection; direct unit contexts retain the previous recovery fallback.
Regression tests fail if an owned inventory is ignored. The exact segmented
procedure contract passes in 42.09 seconds overall (37.75 seconds in its test
body), and a five-hertz follow-up profile passes in 40.86 seconds with 203
error-free samples. Callsite summarization and neighbor-target collection no
longer appear among the leading owned frames. Telemetry attributes the remaining
37.62 seconds to 28.18 seconds of angr/decompiler work, including 9.40 seconds
of Structuring validation priming, 8.91 seconds of angr structuring, and 6.16
seconds of codegen regeneration.

The first reviewed integration-test consolidation also preserves all assertions
while removing repeated execution. Eight broad or superseded SortDemo nodes
launched twelve decompilations already covered by stricter per-function
contracts. Their scorecard, raw-carrier, validation, crash, and call-shape
assertions now execute in those stronger survivors. All ten affected surviving
contracts pass together and the complete reduced module passes 36 tests. The
accepted warm history assigns 57.60 aggregate seconds to the removed nodes. A
cold source-invalidated two-worker module run took 458.28 seconds and is not a
warm performance baseline. Seven concurrent decompiler subprocesses caused a
15-second analysis timeout and inflated individual durations, so heavy semantic
tests remain bounded to the measured memory-safe lane even though tooling and
light tests use seven workers.

The next Structuring profile found two Lowering idempotence and complexity
defects without removing any required replay. Named DS-global materialization
replaced its own generated `CVariable` on every pass, so generated variables
now retain a typed `SegmentedLoadIdentity8616` marker and the owner refuses an
already-materialized identity. Its unit contract now requires a second replay
to return `False` and preserve object identity. The structured `_INSERT`
cleanup also performed one whole-AST occurrence scan per candidate assignment;
it now builds one exact storage-identity occurrence index and preserves both
distinct-node and shared-node read refusals. The real `_TIDShowRange` contract
still passes, with its test-call time reduced from 36.35 seconds before these
fixes to 34.92 seconds after them (1.43 seconds, 3.9%). Full `cProfile` remains
observer-distorting: it reached the unchanged 90-second decompilation budget at
97.06 seconds, but its partial ranking confirmed the quadratic `_INSERT` scan.
No timeout was raised. Remaining measured costs are repeated but mutation-
driven runtime-segment, indexed-global, direct-stack, callsite-argument, and
condition materializers; each needs its own idempotence/evidence-inventory proof
before replay scheduling can change.

Immutable binary discovery is now separated from those mutable replays. A
typed `FunctionEvidenceInventory8616` in the summaries layer owns four enum-
classified projections: instruction summaries, near-pointer arguments, indexed
global load sites, and indexed global stores. Entries are project-request
local, use the stable binary address for addressable functions, and invalidate
when the function size or decoded-block surface changes; opaque third-party
objects retain an owner-checked identity fallback. This closes a nondeterministic
layout corruption in which short-lived `FunctionRangeView8616` objects reused a
Python object ID and inherited another function's indexed-global facts. No C
AST, alias, prototype, or validation object is cached. The forced-ID-collision,
recreated-range, invalidation, and opaque-owner regressions pass. Six independent
cold-fingerprint HeapSort runs also preserve typed `g_0B4C` arguments,
`validation=passed`, required calls, and portable-flat recompilation; the old
implementation had reproduced the raw `SEG_PTR` failure by runs two and six.
The Makefile typed/Ruff sets and architecture promotion registry all enforce
the new module. In the exact procedure profile, indexed load/store
recovery fell from 1.83 seconds to 0.034 seconds, near-pointer collection from
1.09 seconds to 0.012 seconds, and instruction-summary collection from 0.687
seconds to 0.017 seconds. The unchanged semantic contract passes in 33.08
seconds, 3.27 seconds (9.0%) below the 36.35-second pre-cycle baseline. Cache
reuse and decoded-block invalidation are both covered by focused tests.

A current five-hertz profile after that inventory passed the same semantic
contract in 32.78 seconds with 189 samples and no sampling errors. It exposed
one remaining duplicate owner: direct-global call-return store collection spent
about 3.2 seconds rebuilding callsite summaries already published by
Structuring. Lowering now consumes the authoritative typed callsite inventory
for exact addresses and invokes recovery only for missing callsites. The unit
contract fails if complete owned evidence triggers recovery, while direct unit
contexts still exercise the missing-summary fallback. Three unchanged real
contract repetitions pass at 30.70, 30.59, and 30.88 seconds (30.70 median,
30.88 maximum), down 2.38 seconds (7.2%) from the 33.08-second pre-fix result.
The mandatory pipeline remains green: all three stages pass, including four
Ultra QuickC validations and all seven MS C compile-decompile-recompile-run
constructs.

The accepted warm profile also inflated two timeout-tolerant CLI contracts:
`_rotate_pt` and `_TIDShowRange` spent 42.31 and 46.57 seconds after the
full-suite scale changed their explicit 10-second analysis budgets to 40
seconds. Controlled direct runs at both budgets returned the same typed timeout
status `3` and no generated C. Those two contracts now opt out of contention
scaling, retain every existing success-path assertion, and preserve their
10-second deadline under xdist. Three two-worker scale-4 repetitions pass; the
node calls are stable at 15.10-15.46 seconds. Against the accepted warm run this
projects a 58.33-second aggregate reduction and about 31 seconds from their
parallel critical path without changing the observed result class. A separate
shared C-AST iterator micro-optimization was rejected and reverted: despite 38
focused tests passing, its three-run 31.21-second median was worse than the
30.70-second pre-change median.

The seven MS C compile-decompile-recompile-run pytest contracts previously
invoked the same independent runtime-gate setup once per parameter row. They
retain all seven node IDs and per-example assertions, but now share one
module-scoped setup whose exact gate commands run in isolated output directories.
The inner pool is limited to two workers: enforcing process-tree runs rejected
four workers at 2,098,176 KiB and three workers at 2,117,116 KiB against the
2,097,152 KiB limit. Two workers passed all seven exact nodes at 1,646,912 KiB
with a stable source tree. Three unchanged repetitions completed in 57.11,
58.09, and 58.30 seconds (58.09-second median, 58.30-second maximum), compared
with 172.23 seconds of accepted aggregate call work before consolidation. This
removes about 114.14 seconds while preserving each runtime and exit-code
contract; raising the inner pool requires a new aggregate-RSS proof. The
post-consolidation mandatory pipeline passes all three stages with no timeout:
the focused unit lane takes 40.297 seconds and remains over its 30-second soft
budget, Ultra QuickC validates all four selected fixtures in 46.869 seconds,
and all seven MS C constructs complete in 71.555 seconds.

Reviewing the remaining COD integration contracts exposed a false green in
`loadprog`: call validation compared variadic helpers only against declarations,
and a name-based helper override collapsed five binary-proven 16-bit stack words
into an unproven four-argument near-pointer prototype. A typed Recovery-metadata
ABI catalog now owns declaration, variadic, and logical-width projections;
Validation still requires variadic calls to match binary-proven arity. The
unsupported `loadprog` grouping was removed instead of parsing COD `FAR` text or
repairing the rendered call. Its exact regression now requires tail validation,
recompilation, all five physical parameters, and use of the fifth word. The real
function and both wrappers pass together in 11.52 seconds, followed by green
`quality-dev` and mandatory pipeline gates. Far-pointer grouping remains a future
Types/Lowering improvement only when binary IR, use, or caller evidence proves it.

Cross-lane clean-worker reuse no longer partitions an accepted artifact by an
exact timeout value. Serial-worker cache schema 2 removes timeout from semantic
identity, records the producing analysis budget, and admits only monotonic reuse:
a stronger-budget validated result may satisfy a weaker request, while a weaker
artifact cannot satisfy or overwrite a stronger request. The cache owner uses a
per-key lock when replacing an insufficient entry. Key, monotonic-admission, and
concurrent-downgrade regressions pass. The real sidecar-backed InitBars contract
passed cold at scale 4 in 79.34 seconds with one observable serial-worker store,
then passed with all existing validation, recompilation, source-oracle, and
call-shape assertions at scale 1.5 in 4.02 seconds. Both source-stable profiles
used the same serial-worker key; the warm run recorded one hit and no store. This
closes the prior 74-second apparent warm miss caused solely by the full and
focused lanes requesting different timeout budgets.

The next warm in-process hotspot is repeated exact frontend block decoding. A
sample of the two-word conditional contract put 149 of 244 samples in the
x86-16 lifter below a JCC linear predecessor scan. An initial attempt to skip
that scan was rejected: the exact unsigned CMP32 regression then lost stable
postprocess validation because the scan's wider instruction stream is also
consumed by condition replay. The accepted implementation keeps the scan and
all of its instructions, but caches exact `(address, instruction limit,
optimization level)` Capstone results on the immutable request-owned project.
The profile then exposed five identical expensive refusals for address `0x200`:
each reported no loaded bytes. A typed negative record now retains the exception
class and message without retaining a traceback, so deterministic refusal stays
observable while identical requests do not rerun the lifter. Mutable C AST,
semantic state, aliases, prototypes, and validation results are not cached. Unit
and JCC integration regressions require distinct requests to stay distinct,
successful repeated scans to decode once, and repeated refusals to raise the
same typed failure after one underlying request. End-to-end timing and CMP32
acceptance must be remeasured before this optimization is closed. Runtime
instrumentation then showed the larger root cause: a blob function and its main
object began at `0x1000`, but the scan selected `loader.min_addr=0x0`, decoded
269 unrelated external/image requests, and stopped at `0x200` before reaching
the function. The scan now prefers the loaded main-object minimum over a lower
loader-global minimum while retaining function/cache candidates and the
established main-object-wide stream. This distinction matters: an attempted
function-entry-only scan made the tiny contracts fast but failed the exact
unsigned CMP32 postprocess-validation contract, so it was rejected. A regression
uses a lower loader-global minimum and requires decoding to begin at the main
object/function boundary. The final unchanged contracts pass together in 3.17
seconds versus the 21.92-second baseline. Both CMP32 scalar-type parameters pass
with their ordered stable stage diagnostics. A final 2.56-second `py-spy` run
recorded 71 samples and no JCC linear-scan, JCC translation, or x86-16 lifter
frame.

The corresponding focused two-worker profile then passed 2,890 tests in
148.080 artifact seconds on a stable source tree, down from 163.766 seconds in
the preceding accepted warm profile. The conditional/JCC node left the top-25
ranking, confirming that the exact frontend cache removed measured work rather
than moving it to another test. Its source-invalidated producer took 429.337
seconds; cold and warm figures remain separate because they answer different
questions.

The next `py-spy --subprocesses` sample found that a direct function-result cache
hit still spent roughly four seconds rebuilding caller return-use evidence. The
CLI scanned every pre-entry catalog range with detailed Capstone before looking
up the already accepted function artifact. A shallow Capstone prefilter followed
by detailed decoding only for call-bearing ranges was implemented, tested, and
rejected: almost every catalog range contained a call, and the exact RunMenu
node regressed from 8.20 to 9.24 seconds. That experiment and its temporary
module were removed; it is evidence against adding a second decode path.

The accepted fix reuses the existing typed display-catalog artifact. Direct and
neighbor target paths now hydrate exact `CallerReturnUseEvidence8616` before a
live scan and publish newly collected evidence back through the existing
content-addressed recovery key. Per-key locking, schema validation, atomic
storage, and deterministic merging preserve independent target evidence under
concurrent workers. The CLI owns cache hydration/publication only; X86-16
Recovery remains the authoritative owner of the semantic evidence. Focused
contracts cover exact reuse, live publication, and independent-target merging.
The exact signed RunMenu node took 44.78 seconds on its producer and then 2.83,
2.84, and 2.88 seconds on three ordinary warm runs. A final subprocess sample
contained no caller-return-use collection frame.

The source-stable focused profile sequence passed all 2,893 executed tests with
both workers exiting zero: 399.313 seconds for the producer, 132.594 seconds for
the first warm transition, and 124.240 seconds at steady state. All three used
source identity `58b5fb4bf592c811a746cb4fdf36fbf91e8181c8933e916c95ccb50619ba0b49`.
Function-decompile misses fell from four in the transitional run to one in the
steady run; that remaining `InitBars` path intentionally does not store the
function artifact. The stable top node is now the recompilable-subset contract
at 11.86 seconds. Sampling attributes about 8.42 seconds to its six required
bounded live corpus decompilations, so deleting a second GCC pass would not
address the dominant cost. `quality-dev` passes Ruff, development typing,
mypyc import smoke for 38 modules, architecture/context/ownership checks, 1,462
fast tests, and compiled-vs-pure quality guards. The mandatory three-stage
pipeline also passes, including all four Ultra QuickC fixtures and all seven MS
C compile-decompile-recompile-run constructs.

The next complete import-aware run exposed both a correctness defect and a
resource-scheduling defect. The real `_dos_loadProgram` contract proved five
physical stack words but four logical C arguments with widths `(2, 2, 2, 4)`.
Lowering had recovered that projection, but a later summary rebuild discarded
it and Validation preferred a stale five-word prototype. The typed logical
shape now survives only when the complete physical callsite identity is equal,
the authoritative inventory receives the reconciled summary, and Validation
consumes that proven projection before a stale prototype. Focused inventory,
materialization, validation, and real CLI regressions pass, including tail
validation and portable recompilation. The same full attempt also showed two
MSC6 shards exceeding the 2 GiB limit. The runner now learns paths from a
memory-exceeded wave and schedules those paths as exclusive heavy jobs without
hard-coding corpus names.

The first complete run after those fixes observed all 6,895 inventoried nodes
exactly once at 2,012,612 KiB peak RSS in 1,807.75 seconds. It reported 6,728
passed, 166 skipped, and one outdated tail-validation test double; the test
double now accepts the typed summary-inventory argument and passes. Learned
MSC6 exclusivity removed the OOM failure, but the large SortDemo file still ran
as one cold critical path while current timings were being learned.

The immediate source-stable repetition used those timings to split SortDemo
and CLI by atomic pytest nodes. It observed all 6,895 nodes exactly once in
645.31 seconds at 1,845,644 KiB peak RSS: 6,728 passed, 166 skipped, and the
instruction-equivalence node failed intermittently. That node passes alone at
6.04 seconds, so no semantic assertion has been weakened or retried away. The
run proved warm SortDemo calls of roughly 3-9 seconds, with its intentional
two-run file-summary contract at 20.54 seconds; the MS C shared setup fell from
125.57 to 60.92 seconds. Two-worker heavy waves still serialize sixteen jobs,
and their non-MSC peaks range from 594,188 to 1,376,308 KiB. The next bounded
experiment uses four short-lived heavy slots under the unchanged hard 2 GiB
monitor; four is accepted as the default only if the complete run remains
green, exact, source-stable, and below the limit.

Full-run diagnostics are now durable rather than terminal-only. Worker reports
retain a bounded traceback for each failed node, and the controller publishes
those details in summary schema 2. This is required because the temporary
worker directories and their captured output are removed after aggregation;
the prior intermittent instruction failure otherwise had no root-cause
evidence. The report schema remains backward-compatible with older worker
records. Ruff with fixes, mypy, the changed-file type ratchet, and all 17
partition-runner contracts pass.

The first four-heavy-worker experiment observed all 6,897 nodes exactly once
in 663.91 seconds at 2,036,096 KiB peak RSS. It was source-stable and stayed
below the 2,097,152 KiB limit, but it is not accepted: only about 60 MiB of
memory margin remained, it was slower than the preceding 645.31-second run,
and two nodes failed. One failure was the Makefile default assertion that had
not yet been updated. The other exposed a real order-dependent Validation bug:
temporary rebuilt C-AST nodes were identified by process-global integer object
IDs, so Python ID reuse could make an unrelated later node look temporary and
retain stale fingerprint data. The temporary-node registry is now scoped to
one fingerprint operation with `ContextVar` and retains exact object identity;
the 64-test fingerprint surface passes. Four heavy workers remain an experiment
until a green repeated run establishes both speed and a defensible memory
margin.

Summary schema 3 records every node's terminal outcome and rejects pass-to-skip,
pass-to-fail, and skip-to-fail transitions. Aggregate counts are insufficient:
the four-worker run let the real MSC8 debug-info corpus skip after a contended
compiler build even though the total skip count did not change. The registered
`resource_serial` marker now classifies external-tool contracts that become
unreliable under heavy contention. Marked paths and paths learned from a memory
abort share the generic exclusive-wave scheduler; the policy is inventory
driven and contains no corpus filename allowlist. The runner and real compiler
surface passes 20 focused tests, the compiler matrix passes in 1.12 seconds in
that check, and Ruff, mypy, and the changed-definition type ratchet are green.

Current execution status: baseline/inventory, xdist diagnosis, scanner caching,
content-addressed artifact reuse, exact-node partitioning, durable failure and
skip evidence, and outcome/resource guards are implemented. Exact complete runs
now execute all 6,946 collected nodes within the 2 GiB budget. The measured
scheduler and source-bound MS C runtime-gate artifact cache reduced the final
three source-stable warm runs to 337.58, 345.70, and 341.42 seconds without
caching pytest verdicts. Each run passed 6,805 tests, skipped 141 unavailable or
explicitly opt-in contracts, and had zero failures. The measured two-heavy-
worker default is accepted and the final hard quality gate is green. This plan
is complete.

The follow-up four-heavy-worker schema-3 run crossed the hard limit in its
first SortDemo wave: 2,098,596 KiB against 2,097,152 KiB after 251.85 seconds.
The controller terminated the complete process tree, retained the 180 finished
light nodes, reported 6,719 missing nodes, and did not misreport a partial run
as success. Four heavy workers are therefore rejected. A multi-worker aggregate
abort also no longer marks every participant as intrinsically exclusive; only
a one-heavy-worker abort proves path-level memory isolation. Marker-owned
resource isolation and memory-learned isolation are persisted separately, so
removing a resource marker does not leave stale scheduling policy. The default
returns to the measured two-heavy-worker limit while the other N-1 budget slots
remain available to reviewed light work.

The next two-heavy-worker cold run rebuilt the lost timing baseline and passed
all 6,900 nodes exactly once: 6,733 passed, 166 skipped, no failures, stable
source, and 2,006,988 KiB peak RSS. It took 1,340.96 seconds because the prior
aborted summary had overwritten successful durations and left the 499.12-second
SortDemo file under-sharded. Summary schema 4 now retains a complete scheduling
duration map across partial attempts and advances the accepted per-node outcome
baseline only after a successful exact run. Failed attempts keep their own
diagnostics without erasing the last usable schedule or outcome truth.

The immediate warm repetition used those timings, split SortDemo and CLI into
two atomic shards each, and passed all 6,901 nodes exactly once in 679.40
seconds: 6,734 passed, 166 skipped, no reported failures, stable source, and
1,847,736 KiB peak RSS. The initial schema-4 audit found one selected node with
no terminal outcome: the failure-traceback unit test kept the live partition
plugin's report dictionaries monkeypatched through its own call report. The
test now restores those dictionaries before returning, and the controller
requires one terminal outcome for every expected node. A real plugin invocation
records that node as passed; focused runner tests and the Ruff/mypy/type ratchet
remain green.

The warm aggregate call costs are now 175.22 seconds for SortDemo regressions,
172.30 for CLI, 115.77 for the MS C runtime regressions, 87.36 for COD
regressions, and 61.53 for COD samples. The MS C exclusive wave takes 115.92
seconds, including a 65.00-second seven-example setup. Its scalar-types runtime
gate passes alone in 18.43 seconds at 202,228 KiB. Replacing its ten isolated
two-way decompilations with the existing one-process batch was measured and
rejected at 45.40 seconds; no batch-path change or artifact was retained. The
next optimization must reduce measured isolated CLI startup/analysis work or
provide an equivalent typed artifact boundary, not merely reuse an existing
slower batch API.

The terminal-outcome and resource-history work is now accepted end to end. A
source-stable exact run observed all 6,916 inventoried nodes once, with 6,750
passed, 166 skipped, no failure, no missing or duplicate outcome, and
1,732,064 KiB peak aggregate RSS. It completed in 598.08 seconds, down from the
preceding exact 753.98-second run by 155.90 seconds (20.7%). The scheduler
reuses only exact accepted path-and-shard memory contracts, keeps a 128 MiB
controller reserve plus ten-percent worker headroom, and refuses to infer shard
identity from display names. The two exclusive external-tool waves remain
separate: their measured worker peaks are 195,500 and 1,652,192 KiB, so merging
them would consume the safety margin on the single available observation.
The next full attempt was rejected after 975.55 seconds: the helper-carrier
shortcut caused two semantic failures, only 3,403 of 6,916 outcomes completed,
and one wave reached 2,149,860 KiB against the 2 GiB cap. Both failed nodes pass
after removing the shortcut. The scheduler now retains typed exact-contract
peaks from failed or aborted runs as conservative lower bounds only; they can
split a future wave but cannot authorize higher concurrency. This preserves the
last successful schedule while preventing the observed 418-to-617 MiB and
396-to-602 MiB worker growth from repeating the same unsafe packing.
The schema-7 repetition then executed all 6,919 nodes exactly once with 6,751
passed, 166 skipped, two failures, stable source, and a memory-safe 1,799,784
KiB peak, but took 1,223.72 seconds. Both failures pass in focused reruns. The
InitBars failure exposed a terminal-policy defect after DCE timeout: validated,
recompilable C containing a declared and assigned `vvar_653` was rejected as an
unresolved reference. Final CLI quality now rejects only virtual temporaries
without declarations; declared generic temporaries remain visible in the
readability scorecard instead of suppressing the function. The instruction
equivalence test now reports its exact input when an intermittent mismatch
recurs. This cold run does not replace the accepted 598.08-second warm baseline.

The next exact schema-7 run accounted for all 6,921 nodes once with 6,753
passed, 166 skipped, two failures, stable source, and 2,023,088 KiB peak RSS
under the 2 GiB limit; elapsed time was 1,238.31 seconds. `InitMenu` timed out
only in a wave that launched nine pytest workers despite `--workers 7` and then
correctly failed tail validation. Light and heavy lanes now execute as separate
waves, so every wave honors the global CPU cap as well as the RSS envelope.
The other failure showed that the legacy cross-architecture instruction test
compared 16-bit `ret` against a four-byte 32-bit stack pop and usually passed
vacuously because unconstrained return targets produced no successors. It now
seeds a concrete return stack, normalizes the reference stack width, and checks
control flow deterministically. Unsupported 32-bit `retf` comparison was
removed from that duplicate list; dedicated 16-bit `retf` control-transfer and
stack-adjustment tests remain green. Removing diagnostic IR rendering reduced
the focused instruction test from 6.46 to about 4.0 seconds.

The corrected global worker cap then produced an accepted exact warm run. All
6,921 inventoried nodes executed once, with 6,755 passed, 166 skipped, no
failure, no missing or duplicate outcome, stable source, and 1,696,264 KiB peak
aggregate RSS. It completed in 554.97 seconds, improving the prior accepted
598.08-second result by 43.11 seconds. The scheduler now records elapsed time
for each resource wave as typed summary data rather than requiring terminal-log
inference.

The first source-invalidated run with that instrumentation also passed all
6,921 nodes exactly once, with the same 6,755/166 outcome split, stable source,
and 2,022,948 KiB peak RSS. It took 1,186.75 seconds and therefore does not
replace the accepted warm baseline. Its measured critical path is explicit:
the two SortDemo shards plus one LIFE worker occupied 490.40 seconds, and the
exclusive seven-example MS C regression module occupied 263.04 seconds. The MS
C worker alone peaked at 1,946,496 KiB, so overlapping it with another heavy
worker or raising its inner concurrency is rejected under the 2 GiB contract.
The SortDemo module contributed 969.14 seconds of aggregate node work; two
memory-safe shards are already within about one percent of the 484.57-second
two-worker lower bound. Scheduler tuning cannot remove those two costs.

Two follow-up shortcuts were measured and rejected. A structured C-AST
type-classification cache was slower in a ten-million-call microbenchmark
(1.25 seconds versus 0.73 seconds), while removing two redundant checks yielded
only a 37.74-second three-run warm median against one 38.30-second local
baseline. The complete change was reverted because the apparent 1.5 percent
gain was below the acceptance bar. Replacing isolated SortDemo contracts with
the existing whole-binary N-1-worker CLI path was also invalid: it took 247.43
seconds, timed out three of twenty selected functions, emitted assembly/detail
fallback, failed aggregate tail validation, and exited 2. Per-function
acceptance contracts remain authoritative until a batch path preserves every
function, diagnostic, validation result, compiler result, and exit code.

The typed C-AST module was then compiled in the isolated mypyc package and
compared against the same in-process semantic contract. Three compiled warm
runs took 37.76, 37.79, and 38.31 seconds (37.79-second median), versus a
37.74-second pure-Python median, while retaining slightly more RSS. All
assertions passed, but the candidate provides no speedup; it is not enrolled in
the compiled default and its experimental native artifacts were removed.

Compiling the current RunMenu hot surface with mypyc is not an accepted speed
optimization. The same isolated contract had a 16.41-second pure-Python median
and a 16.81-second compiled median while the compiled run retained about 8 MiB
more RSS. The experiment therefore stays disabled. Mypyc remains a later step
only for a newly measured CPU owner whose compiled and pure outputs,
diagnostics, validation facts, and outcomes are equal and whose three-run median
improves.

The current semantic profile also narrows the remaining in-process work. A
ten-hertz source-preserving sample of the segmented-procedure contract spent
most owned time in Structuring validation priming, angr Clinic simplification,
Lowering replay, postprocess, and CLI regeneration. Exact decoded-block reuse
is now shared by terminal-register return evidence, with a regression proving
one frontend decode per unique block across repeated collection, but it had no
defensible wall-time gain. A proposed helper-carrier idempotence shortcut cut
the unchanged sample call from 50.67 seconds to 34.60 and 32.51 seconds, but the
full suite correctly rejected it: the final projection changed proven physical
`ds` accesses to runtime `inertia_ds`, and materialization counters no longer
partitioned every candidate. The shortcut and its test were removed. The next
candidate must eliminate a proven repeated immutable analysis or add an exact
artifact boundary; changing Clinic policy remains rejected because both tested
fast policies lost validation stability or generated C.

Direct DS/ES load and store discovery now joins the request-owned immutable
function-evidence inventory. The exact binary address, width, segment, and
instruction facts are reused only while the function size and decoded-block
surface remain identical; mutable C AST, alias, prototype, and validation state
still replay normally. A focused contract requires one load and one store
collection for a stable surface and recollection after a block-size change.
All 176 function-inventory and segmented-global regressions pass. On the exact
segmented-procedure contract, the two warm test bodies improved from 32.44 and
32.33 seconds before the change to 30.71 and 31.93 seconds after it (32.39 to
31.32-second median, 3.3%). Corresponding wall medians improved from 38.53 to
37.47 seconds under the intentionally noisy seven-worker single-node harness.
The follow-up ten-hertz profile records zero direct-load or direct-store
recovery samples, confirming that later mutable replays consume the inventory
instead of decoding the function again.

Cold SortDemo profiling then exposed a separate quadratic Lowering query:
direct stack-update recovery scanned the complete structured tree once per
candidate assignment merely to prove that the assignment had a rendered
statement or loop owner. The owner now builds one exact object-identity index
per mutable check; the later replacement phase creates its own index lazily,
after earlier mutations, so newly inserted nodes cannot be hidden by stale
state. A regression with twenty candidate assignments requires exactly two
tree traversals instead of forty-one. All 238 direct-stack and runtime-lowering
regressions pass. Source-invalidated sidecar-free `InitBars` completed in 62.36
seconds versus 66.84 seconds in the accepted cold baseline, while the distinct
sidecar-backed contract completed in 79.76 seconds versus 88.47 seconds. Both
retain `validation=passed`, their call/stack/global assertions, and generated-C
acceptance.

The mypyc development gate also now keys its isolated native cache by the exact
compiled module cohort as well as the schema. This prevents an experimental
`--module` build from leaving default extensions linked against a helper that
is absent after the experiment is removed. The cohort-change regression
preserves a same-cohort cache and deletes an incompatible one; a clean bounded
seven-job rebuild and compiled import smoke pass for all 38 default modules.

The next source-stable exact baselines include all 6,924 inventoried nodes. The
cold run passed 6,758 and skipped 166 with no failures, missing nodes,
duplicates, or outcome regressions; it completed in 1,093.83 seconds at
2,021,060 KiB peak RSS, a 7.8% improvement over the preceding 1,186.75-second
cold run. Its immediate warm repetition preserved the same outcomes and source
state in 540.62 seconds at 1,697,408 KiB. The warm critical waves were 90.7
seconds for SortDemo, 93.7 seconds for CLI, and 113.0 seconds for the exclusive
MS C regression module, with the remaining measured work spread across five
37.5-to-61.0-second waves.

The MS C module repeated focused function decompilations after its seven full
compile/decompile/recompile/run gates had already produced and validated the
same per-function C and diagnostics. Focused shape assertions now consume those
gate-owned `.dec.txt` and `.dec.err.txt` artifacts; the gate still requires
clean tail validation, successful MS C compilation, the expected runtime
sentinel, and exit code 255 for every example. All 24 nodes pass under both a
serial run (59.59 seconds) and `pytest -n 7 --dist loadgroup` (60.77 seconds),
instead of the prior 113.0-second warm full-suite wave. The complete module is
now one registered `resource_serial` xdist group: an initial changed-file run
proved that grouping only the final parameterized nodes duplicated the module
fixture across workers and multiplied decompiler processes, so that weaker
marker placement is rejected.

The exact full-suite acceptance after that consolidation observed all 6,924
inventoried nodes once: 6,758 passed, 166 skipped, no failures, missing nodes,
duplicates, or outcome regressions, with stable source and 1,718,460 KiB peak
RSS. It completed in 473.40 seconds. The exclusive MS C wave fell from 113.0
to 64.9 seconds; the complete compile/decompile/recompile/run gate remains the
artifact owner, so no runtime, compiler, validation, or exit-code assertion was
removed.

Measured jobs now use dynamic admission instead of waiting at static wave
barriers. Every worker retains its exact accepted RSS contract, ten-percent
headroom, the 128 MiB controller reserve, the seven-worker CPU cap, and the live
2 GiB process-tree monitor. A regression proves that a later small job backfills
past a reservation-blocked large job without losing reports or outcomes. The
next source-stable exact run observed all 6,925 nodes once, with 6,759 passed,
166 skipped, zero failures, and 1,720,124 KiB peak RSS. It completed in 435.59
seconds: the dynamically admitted measured lane took 358.75 seconds and the MS
C exclusive lane 64.08 seconds. This is the current accepted baseline and is
still 135.59 seconds above the target.

The protected segmented `_TIDShowRange` contract was re-profiled rather than
weakened. Repository telemetry attributes about 9.45 seconds to angr
Structuring, 7.63 seconds to owned validation priming, 3.40 seconds to
postprocess, 2.62 seconds to codegen regeneration, and 1.38 seconds to CLI
preparation in a 30.09-second decompilation. A Lowering result defect conflated
successful materialization with a fresh AST mutation and recreated an AX return
identity on every replay. The typed result now has a separate `changed_count`,
reuses the exact identity, and the legacy bridge compares only its invocation's
counter delta. Unit and repeated real semantic contracts pass, but the three-run
TID median is unchanged (31.46 versus 31.32 seconds), so this is correctness
work and is not counted as a performance improvement.

Resource history also exposed eight stale coarse workers that each owned 51-55
unrelated files, performed only 16-29 seconds of test work, and retained as much
as 874 MiB through accumulated imports. The scheduler now refuses to reuse an
unsharded contract wider than 32 paths and enforces the same bound when creating
new jobs. New contracts first run under the conservative two-worker limit; only
an exact successful RSS observation permits later dynamic admission. Focused
scheduler, typing, architecture, ownership, and changed-file gates pass. The
first exact remeasurement and its immediate warm repetition remain open; this
experiment is not accepted until both preserve every node/outcome and improve
the 435.59-second baseline under 2 GiB.

The next durable schema-7 exact run observed all 6,926 inventoried nodes once:
6,760 passed, 166 skipped, no failures, missing nodes, duplicates, or outcome
regressions, with stable source and 1,759,676 KiB peak RSS. The complete runner
took 529.62 seconds. Its measured dynamic wave occupied 343.48 seconds and the
exclusive MS C wave 68.50 seconds; the remaining light and conservative heavy
waves consumed about 112 seconds. This is a green correctness baseline, but it
does not replace the accepted 435.59-second performance baseline. The next
optimization must shorten measured decompilation work or safely admit more of
the already sharded work; reporting only pytest's inner elapsed time is not
sufficient for the sub-300-second DoD.

The `_overlay_functionAddress` regression also exposed one obsolete duplicate
integration contract. Exact binary evidence now carries the copied far-pointer
segment source through Types/Lowering, Widening replays the exact stack-word
owner after final Structuring regeneration, and terminal AX materialization
refuses to narrow an explicit DX:AX return. The retained COD integration test
requires clean whole-tail validation, both segmented loads, the 32-bit return
composition, C-only stdout, and successful portable recompilation. Two focused
unit contracts cover copied-source invalidation and wide-return preservation;
the former source-spelling-dependent duplicate subprocess test was removed.
All 14 focused contracts pass under `pytest -n 7`, with the real COD acceptance
remaining the only material cost at about 4.7 seconds. This consolidation is
not counted as a suite speedup until the next exact full run preserves every
outcome.

The wide-return correction then exposed a complementary explicit-prototype
contract: adjacent `BP+4`/`BP+6` words copied into `AX`/`DX` must remain the one
declared 32-bit stack argument, while unrelated `DX:AX` sources must retain an
explicit high/low composition. The frontend adapter now accepts canonical AIL
`BasePointerOffset` addresses, consumes the existing Widening census, and
materializes one four-byte AIL stack owner only for its classified offset.
Structuring consumes that typed owner; otherwise it emits the explicit shift/or
value needed by segmented-global returns. The focused prototype and COD tests
both pass, and `make quality-dev PYTHON=./.venv/bin/python` is green with 1,469
fast-pipeline tests, Ruff, 33-file mypy, 38-module mypyc import smoke,
architecture/context/ownership checks, and the CMP16, LOOPS, and FPTR MS C
quality comparisons. The exact source-stable full-suite remeasurement remains
required before this increment can replace either performance baseline.

The next schema-7 exact run inventoried 6,937 nodes but stopped after the
measured wave: 6,236 passed, 100 skipped, four failed, and 597 exclusive nodes
were not started. It took 343.59 seconds, including a 331.47-second measured
wave, and reached 2,263,720 KiB aggregate process-tree RSS, above the 2 GiB
contract. Two failures were stale assertions (C-only stdout diagnostics and an
unbound terminal `SimTypeShort`). The other two exposed a real semantic error:
three different words loaded into `ES` were collapsed into the same
`SEG_U16(inertia_es, 2)` destination even though whole-tail validation passed.
This failed run is diagnostic evidence only and does not replace either green
baseline.

Types/Lowering now carries the exact typed `IRAddress` source for a segment
register loaded from memory within the basic block and materializes nested
segmented helpers such as `SEG_U16(SEG_U16(inertia_ds, 28682), 2)`. Unknown
segment writes erase the evidence. Tail validation now includes that source in
the required-memory-effect identity, so collapsed destinations fail validation
instead of silently passing. Nineteen focused contracts cover source recovery,
unknown-source refusal, collapsed-source rejection, distinct-source acceptance,
and both real `_LookDown`/`_LookUp` COD functions. Ruff, focused mypy, those
focused tests, and the 38-module mypyc import smoke pass. The resource scheduler
must still keep the complete exact suite below 2 GiB before the three sub-300
acceptance runs can begin.

Resource-history acceptance is now bound to the exact pytest source snapshot.
Schema 8 retains failed-run RSS observations only as conservative lower bounds;
only a successful same-source peak may authorize measured concurrency. Focused
source-change, legacy-history, scheduler, Ruff, and mypy contracts pass. The
first schema-8 exact run observed all 6,942 inventoried nodes once in 1,129.10
seconds: 6,775 passed, 166 skipped, and one stale BIOS COD assertion failed
after two adjacent byte stores were correctly coalesced into one word store.
Peak aggregate process-tree RSS was 2,045,636 KiB, below the 2 GiB cap, and the
source fingerprint remained stable. The stale assertion now requires the
equivalent word store and passes, but the failed run remains diagnostic evidence
and is not a green baseline.

That run also exposed two scheduler authority defects. Failed lower-bound
observations were still admitted through the conservative-peak accessor, and
unknown workers were split into precomputed pair waves whose barriers wasted
capacity. Measured admission now requires an accepted `peak_for` value, while
all unknown non-exclusive workers enter one deterministic two-worker backfill
queue. Exclusive workers remain serialized and the global process-tree cap is
unchanged. The focused scheduler and BIOS surface passes 37 tests under
`pytest -n 7`; exact full-suite remeasurement is still required.

The final skip audit replaced aggregate skip counts with schema-9 structured
reasons and re-ran every formerly skipped node. Twenty-four stale fixture paths
were repaired and now execute as ordinary tests. The remaining 141 skips are
all accounted for: 94 unavailable compiler COD fixtures; 23 unavailable sample
COM/EXE/LST fixtures; eight unavailable LIFE object/executable signature
fixtures; five external F-15 fixtures; five absent trace-script contracts;
three absent sample-manifest contracts; two optional compiler-output fixtures;
and one explicitly exhaustive 80286 opt-in. There are no timeout skips. A
Microsoft C 8 build failure had also been hidden behind `pytest.skip`; changing
it to an assertion exposed the compiler's deterministic `C1001` on long Wine
paths. The corpus builder now runs that path-sensitive compiler in an
automatically cleaned short staging directory and copies only the requested
artifacts back. A deliberately long-path regression passes repeatedly.

The resulting source-stable calibration executed every one of the 6,946 nodes:
6,805 passed, 141 skipped, zero failed, in 508.65 seconds at 1,700,308 KiB peak
RSS. Its three unchanged warm acceptance repetitions completed in 337.58,
345.70, and 341.42 seconds with the same outcomes and source hash. Their peak
RSS measurements were 1,699,980, 1,679,020, and 1,678,412 KiB. All three are
below the accepted 400-second full-suite limit and the 2 GiB process-tree
budget; the performance repetition DoD is complete.

The closing `make quality-hard PYTHON=./.venv/bin/python PARALLEL_JOBS=7
LINT_JOBS=7` gate passed Ruff in fix mode, promoted strict mypy, the 38-module
mypyc build/import smoke, the complexity budget, architecture/context/ownership
checks, 1,469 fast-pipeline tests, the required external MS C runtime gate, and
the CMP16, LOOPS, and FPTR pure-Python/default quality comparisons.

## Profile evidence

### Architecture contract

`scripts/check_decompiler_architecture.py` under `cProfile`:

- 64.09 s profiler time;
- 117,619,314 calls;
- `_parse_python`: 7,857 calls, 9.41 s cumulative;
- `ast.walk`: 4,818,825 calls, 23.27 s cumulative;
- repeated narrow-field scans: more than 20 s cumulative;
- `_check_terminal_call_result_structuring_ownership` is accidentally invoked
  twice by `check_decompiler_architecture`.

The checker runs many independent rules over the same files, reparsing and
rewalking the same syntax trees. Disk I/O is not the main cost; repeated AST
construction and traversal are.

### Ownership manifest

`scripts/test_ownership_manifest.py --check` under `cProfile`:

- 11.09 s profiler time;
- 325 `ast.parse` calls;
- only 49 node-specific targets require node existence checks;
- `_target_skip_xfail_lines` reparses files for 276 targets;
- AST parsing alone costs 5.97 s, with repeated walks adding several seconds.

The manifest should parse each distinct test file once and derive both its node
index and skip/xfail index from that tree.

## Acceptance criteria

1. Identical violations, ordering, exit status, and pytest selection before and
   after each optimization.
2. Mutation tests prove cached scans notice changed file contents within a new
   invocation and never reuse stale results.
3. Focused pipeline remains 1,806 passing tests or increases when new tests are
   added; no new skip/xfail is permitted in the fast lane.
4. Warm-cache and cold-cache timings are reported separately.
5. Three consecutive runs are measured; use the median and retain the maximum.
6. Initial target: focused pipeline median below 30 s. Stretch target: below
   20 s on this machine.
7. Full mandatory pytest must collect and run tests reliably under xdist before
   its timing is accepted.

## Implementation plan

### P0: Make timing and failures explainable

**Reason:** Optimization decisions need reproducible phase, worker, failure,
and memory evidence. Aggregate pytest wall time cannot identify whether a run
is slow because of collection, useful work, duplicated work, contention, or a
crashed worker.

- Add a `pytest-profile` target that records collection time, setup/call/teardown
  durations, worker crashes, and the 25 slowest tests without changing the
  normal pass/fail rules.
- Preserve per-worker stderr and enable pytest faulthandler for the broad xdist
  collection failure. Record worker exit codes and memory pressure.
- Re-run the same 230-target command serially and with `-n 1`, `-n 2`, `-n 4`,
  and `-n 7`. Find the smallest failing worker count or target subset by
  deterministic bisection.
- Compare `load`, `loadgroup`, and `worksteal` only after collection is stable.
  Select from measured median wall time and peak aggregate RSS, not intuition.

**DoD:** The broad command has either a deterministic minimized
failure reproducer or three stable repetitions; the profiler writes a compact
machine-readable artifact under the existing cache directory with selection,
phase durations, worker events, exit codes, and memory evidence; normal pytest
selection and pass/fail rules are unchanged.

**Definition of failure:** A worker failure, missing node, status-5 run, or
selection mismatch cannot be attributed; profile collection changes test
behavior; or an optimization is proposed from aggregate wall time without
repeatable phase and worker evidence.

### P1: Cache ownership-manifest AST work inside one invocation

**Reason:** The ownership checker reparses the same small set of test modules
for many manifest targets. A request-owned AST index removes duplicate work
without changing any ownership rule or persisting stale repository state.

- Build one immutable index per distinct test path: parsed AST, pytest node IDs,
  and skip/xfail line numbers by node.
- Reuse that index for all ownership rules and repeated targets.
- Keep cache lifetime limited to one validation invocation, or key it by path
  plus content fingerprint. Do not use a path-only process-global cache.
- Add equivalence tests comparing indexed and uncached validation on valid and
  deliberately broken temporary manifests.

**DoD:** Indexed and uncached validation produce exactly equal
violations, ordering, and exit status on valid and deliberately broken inputs;
mutation tests prove changed content is observed; the isolated current-tree
check is measured at roughly 1-3 seconds without new skips or exclusions.

**Definition of failure:** The index is path-only or process-global, changed
files reuse stale syntax, node or skip/xfail scope differs, violation ordering
changes, or runtime falls only because an ownership rule stopped executing.

### P1: Give the architecture checker one scan context

**Reason:** Architecture rules repeatedly walk the same production ASTs. One
request-owned scan context can share facts while keeping each rule and its
diagnostics independently testable.

- Introduce a request-owned scan context containing file text, parsed AST, module
  docstring, and reusable per-file indexes.
- Route every architecture rule through that context so each file is read and
  parsed once per invocation.
- Replace repeated full `ast.walk` calls with indexes built during one visitor:
  definitions, calls, imports, assignments, attributes, constants, and relevant
  source locations.
- Fuse rules that inspect the same node kind while keeping rule ownership and
  violation messages separate.
- Verify apparent duplicate rule invocations across full and startup entry
  points; remove one only when both calls occur in the same execution path.
- First preserve an uncached reference path in tests and assert exact tuple
  equality for all violations on synthetic fixtures and the current tree.

**DoD:** Every rule consumes one request-owned scan context;
full and startup entry-point overlap is documented and same-path duplicates are
removed; cached and reference paths emit
exactly equal violation tuples, ordering, and exit status on fixtures and the
current tree; mutation tests reject stale facts; the isolated check is measured
at roughly 5-10 seconds or has a newly evidenced target.

**Definition of failure:** Any rule is omitted, diagnostics or ordering drift,
file changes are missed, memory exceeds the development budget, or speed comes
from broad exemptions, reduced scan scope, or disabled architecture checks.

### P2: Remove repository-wide scans from the xdist critical path

**Reason:** Whole-repository assertions are mandatory once-per-checkout gates,
not per-worker unit work. Scheduling them once alongside ordinary tests keeps
the proof while removing duplicate collection and execution from the critical
path.

- Keep architecture and manifest validation mandatory, but run each exactly once
  as explicit quality-gate jobs alongside the parallel unit-test lane.
- Do not make every xdist worker import and collect repository scanners merely to
  execute one global assertion.
- Keep small unit tests for scanner behavior in pytest. The whole-repository
  assertions remain hard gates in `quality-fast` and `quality-hard`.
- Have the orchestrator wait for every concurrent gate and combine all failures;
  never cancel or hide one failure because another job failed first.

This changes scheduling, not coverage. It shortens the critical path because the
global scans and ordinary tests can run concurrently.

**DoD:** Architecture and ownership repository contracts remain
mandatory in `quality-fast` and `quality-hard`, execute exactly once per gate,
and may run concurrently with the focused lane; scanner unit tests remain in
pytest; the orchestrator waits for and reports every gate result.

**Definition of failure:** A direct focused command can silently replace the
hard gate, a repository assertion is skipped, an xdist worker repeats the scan,
one concurrent failure hides another, or pass counts improve by deselecting
scanner behavior tests.

### P2: Reduce collection and import cost

**Reason:** Collection and module-import setup is paid even when no test body
runs. Moving side effects into explicit fixtures and keeping one selection
authority reduces latency without changing which contracts exist.

- Profile collection per module and import time before editing tests.
- Move expensive executable loading, compiler probing, and decompiler setup out
  of module import scope into explicit fixtures.
- Split collection-safe unit modules from corpus/integration modules using
  registered markers and explicit Makefile lanes. Marker assignment must not
  remove any test from `quality-hard`.
- Keep test selection in one structured manifest and generate Makefile targets
  from it, avoiding a second manually maintained authority.

Target: full-tree collection below 5 s and focused-lane collection below 2 s.

**DoD:** Import-time profiles identify every material cost;
expensive loading/probing occurs only in owned fixtures; markers are registered
and every marked lane is included by `quality-hard`; selection derives from one
structured manifest; three collection-only repetitions meet the targets or
record an evidenced revised target with identical node IDs.

**Definition of failure:** Node IDs disappear, import or fixture order changes
behavior, a marker creates an uncovered lane, the Makefile and manifest become
competing authorities, or collection improves only by hiding import/collection
errors.

### P3: Cache expensive test artifacts safely

**Reason:** Identical decompiler/toolchain inputs are rebuilt across tests and
xdist workers. Content-addressed artifacts can share expensive facts while
forcing every assertion and validation contract to execute on each run.

- Inventory tests that rebuild MS C fixtures, rediscover functions, load angr
  projects, lift identical bytes, or regenerate decompiled C.
- Use content-addressed artifacts keyed by all semantic inputs: binary digest,
  code/config digest, tool version, Python ABI, and decompiler options.
- Use atomic writes and per-key locks so xdist workers cannot consume partial
  artifacts.
- Cache facts and generated artifacts, never pass/fail verdicts. Assertions must
  execute every run against the cached facts.
- Add corruption, stale-key, concurrent-writer, and cold-cache equivalence tests.

**DoD:** Cache keys cover every semantic input and tool/runtime
identity; writes are atomic and per-key locked; cold and warm outputs,
diagnostics, validation facts, compiler results, and exit codes are equivalent;
corrupt and stale entries are refused; concurrent workers create one valid
artifact per key while all assertions still run.

**Definition of failure:** A semantic mode shares an invalid key, a partial or
stale artifact is consumed, a cached verdict replaces current assertions,
concurrent producers duplicate expensive work without a measured reason, or a
warm run changes generated C or acceptance evidence.

### P3: Balance xdist by measured workload

**Reason:** Worker count and grouping affect critical-path balance and aggregate
memory. They must be selected after cache behavior is correct so scheduling
does not merely mask duplicate work.

- Emit historical duration data by node ID and use it to keep long integration
  tests from landing on one final worker.
- Mark tests that must share an expensive fixture with `xdist_group`; leave
  independent fast tests distributable.
- Cap workers from measured aggregate memory, not CPU count alone. Seven workers
  are a hypothesis, not a permanent constant.
- Benchmark three uninterrupted repetitions for each candidate scheduler and
  worker count after caches are correct.

**DoD:** Candidate schedulers and worker counts are compared over
three uninterrupted repetitions using identical node selection, cold/warm
state, worker durations, critical-path wall time, and aggregate peak RSS; the
chosen default has the best defensible median within the 2 GiB budget and keeps
required fixture groups explicit.

**Definition of failure:** Any candidate loses or duplicates nodes, introduces
order dependence, exceeds the memory budget, worsens median runtime, relies on
unexplained grouping, or is selected from one run or CPU utilization alone.

### P0: Build a test-purpose and cost inventory before deleting anything

**Reason:** Similar test names, addresses, or Python coverage do not prove that
tests protect the same semantic contract. Deletion decisions require a complete
purpose, input, evidence, and cost map first.

- Collect every test with a stable node ID, duration, setup/call/teardown time,
  subprocess count, binary/function address, command-line options, environment
  switches, cache key, validation verdict, compiler/recompile step, and exit
  code.
- Classify each test as unit invariant, layer/ownership contract, negative
  refusal, single-function semantic regression, whole-file acceptance, or
  external toolchain contract.
- Mark tests that appear to exercise the same binary/function, but keep them in
  the inventory until their assertions and evidence surfaces are compared.
- Record fixture construction and temporary-file identity. A test that uses a
  different sidecar, option, source oracle, or failure mode is not a duplicate
  merely because it invokes the same address.

**DoD:**

- one machine-readable inventory covers every collected test;
- every test has an owner layer, purpose, and required acceptance evidence;
- the inventory identifies the top 50 tests by wall time and by cumulative
  subprocess/decompiler time;
- no test is deleted, skipped, or weakened during inventory creation.

**Definition of failure:** Any collected node is absent or lacks a reviewed
owner, purpose, or acceptance-evidence record; distinct options, sidecars,
oracles, validation modes, or exit-code checks are collapsed; or producing the
inventory changes selection, execution, or outcomes.

### P1: Find exact duplicates and superseded tests

**Reason:** Removing redundant tests can shorten the suite, but line-coverage
overlap alone cannot prove equivalent failure sensitivity or end-to-end
evidence.

- Run `/home/xor/pytest_deduplicate` on a representative unit lane and the
  decompiler integration lane separately, because mixing them creates noisy
  coverage sets.
- Treat identical coverage as a candidate only. Compare assertions, fixtures,
  environment, binary identity, function address, output channel, validation
  requirement, compiler check, and expected exit code.
- For a suspected superseded test, prove that the retained test covers every
  semantic branch and failure assertion of the removed candidate, not merely
  the same Python implementation lines.
- Prefer merging repeated subprocess tests into one artifact-producing test
  plus several cheap assertion tests when the artifact contains all required
  evidence. Assertions must still execute on every run.

**DoD:**

- each candidate is labelled `exact_duplicate`, `superseded`,
  `complementary`, or `false_positive` with evidence;
- a deletion or merge has a before/after node inventory and unchanged required
  coverage/contract matrix;
- mutation tests show that the retained test fails when the candidate's
  protected behavior is broken;
- full and focused pass counts do not decrease except for documented removals,
  and all removals have reviewable rationale.

**Definition of failure:** A candidate is classified from coverage alone, a
retained test omits an assertion or semantic mode, mutation of the supposedly
covered behavior survives, or a deletion lacks a documented before/after
contract and node inventory.

### P1: Investigate slow-test root causes

**Reason:** The slowest outer tests combine decompiler phases, subprocess and
compiler startup, cache behavior, lock waits, timeouts, and scheduler idle time.
The owning bottleneck must be measured before code is optimized.

- Profile the top 50 tests in isolation and under `-n 7`, recording CPU time,
  peak RSS, child-process time, cache hit/miss, and lock wait time.
- Compare cold, warm, and concurrent-warm runs. Identify thundering-herd cache
  misses when several workers request the same content/options key.
- Trace each expensive CLI invocation into load/lift, analysis, structuring,
  validation, rendering, GCC, and process startup. Do not optimize based only
  on the outer pytest duration.
- Compare `load`, `loadgroup`, and measured duration-aware scheduling after
  grouping constraints are listed. A group is justified only when shared state
  or fixture serialization is required.
- Audit timeout scaling separately from actual runtime. A larger timeout may
  hide a slow path but must not be mistaken for a performance fix.

**DoD:**

- every top-50 test has a measured dominant phase and a proposed owner for the
  fix;
- duplicate work, required work, scheduler wait, and timeout wait are reported
  separately;
- three cold/warm/concurrent repetitions exist for each proposed optimization;
- peak aggregate memory remains within the 2 GiB development budget.

**Definition of failure:** A top-50 node lacks phase or resource evidence, cold
and warm states are mixed, lock/timeout waits are counted as useful CPU work,
results cannot be reproduced, or a proposed fix is assigned to a layer from
test names or rendered output rather than traced execution.

### P2: Reduce repeated integration setup without reducing proof

**Reason:** Several integration tests need different assertions over the same
expensive exact decompilation. Sharing a typed artifact can remove repeated
setup while preserving every independently evaluated contract.

- Introduce a typed, content-addressed decompilation artifact containing the
  accepted C payload, declarations, diagnostics, validation facts, compiler
  result, and relevant metadata. Cache facts/artifacts, never a pass verdict.
- Add per-key locks and corruption/stale-key tests so xdist workers wait for or
  reuse one valid producer instead of duplicating a cold decompilation.
- Share one artifact among tests that assert different properties of the same
  exact input/options while retaining each assertion as an independent test.
- Keep tests with different semantic modes separate: sidecar-free versus
  sidecar-backed, alternate-source versus normal C, typed-switch enabled versus
  disabled, and behavior/exit-code versus syntax-only checks.

**DoD:**

- cold runs preserve the existing behavior and diagnostics;
- warm runs reuse artifacts without bypassing validation or assertions;
- concurrent workers produce one valid artifact per key;
- the critical path is below 300 seconds in three repetitions, with no new
  failures, skips, or semantic coverage gaps.

**Definition of failure:** The artifact omits evidence required by a consumer,
different semantic modes share an artifact, validation or compiler assertions
are replaced by a stored verdict, concurrent production is unsafe, or timing
improves with any output, diagnostic, exit-code, or coverage regression.

### P2: Compile measured decompiler hot spots with mypyc

**Reason:** mypyc can reduce CPU-bound owned code after duplicate work and cache
contention are removed. Compiling earlier obscures the true hotspot and may
trade runtime for startup or memory regressions.

- Use phase profiles to identify CPU-hot functions in loading/lifting, aliasing,
  widening, typing, structuring, validation, and cache serialization. Select
  candidates from measurements, not module size or intuition.
- Confirm each candidate has complete explicit types and stable owned
  contracts. Fix typing and documentation debt at the owning layer before
  compiling it; do not weaken annotations for mypyc compatibility.
- Compile one narrow candidate at a time with the project mypyc build, keeping
  the pure-Python implementation available for unsupported platforms,
  debugging, and differential testing.
- Compare pure-Python and mypyc outputs using deterministic IR/C output,
  validation facts, diagnostics, exceptions, exit status, and cache keys.
- Measure compilation overhead, cold-start time, warm runtime, peak RSS, and
  parallel worker behavior. A compiled module is not an improvement if process
  startup or memory pressure makes the suite slower.
- Keep dynamic third-party/angr boundaries outside compiled ownership paths or
  isolate them behind typed adapters. Do not introduce `getattr`/`setattr` to
  make owned code compile.

**DoD:**

- each compiled hotspot has a profile showing it is a material contributor;
- mypy passes for the candidate and its owned contracts;
- pure-Python and mypyc differential tests agree on generated output,
  validation, diagnostics, and failure behavior;
- focused tests, MS C full-pipeline tests, and full pytest pass in both modes;
- three-run timing evidence shows a real wall-time or CPU improvement with
  acceptable RSS and no semantic regression;
- the build can disable mypyc cleanly and still execute the same tests.

**Definition of failure:** A candidate is selected without phase evidence;
typing or documentation is weakened; owned contracts gain dynamic
`getattr`/`setattr`; Python and compiled behavior, diagnostics, validation, or
cache identity differ; or three-run wall time/RSS does not improve.

### P2: Remove only proven redundant tests

**Reason:** Test deletion is justified only when another retained contract has
the same failure sensitivity. End-to-end MS C and decompiler acceptance proof
must be optimized, not discarded.

- Delete an exact duplicate only when its contract is fully represented by the
  retained test and the deletion is recorded in the inventory.
- Replace a superseded test with a narrower retained assertion only when
  mutation testing demonstrates equivalent failure sensitivity.
- Keep complementary tests when they differ in layer, failure mode, source
  evidence, output channel, cache behavior, or runtime/exit-code proof.
- Keep at least one end-to-end test per required MS C tiny example and per
  decompiler acceptance contract; optimize its setup rather than deleting the
  contract.

**DoD:**

- the reduced suite passes serially and with `-n 7`;
- all mandatory layer, type, documentation, lint, tail-validation, recompilation,
  and MS C full-pipeline gates remain active;
- the test inventory and plan explain every removed or merged node;
- a deliberate mutation of each retired test's former contract is detected by
  the retained suite.

**Definition of failure:** A retired contract has no explicit replacement,
mutation survives, serial and xdist selection diverge, a mandatory type/doc/
lint/validation/recompilation gate disappears, or count reduction is used as
evidence of equivalent coverage.

## Recommended order

The shortest implementation path is below. Every step must satisfy its DoD
before the next step starts.

### 1. Freeze the baseline and inventory

**Reason:** We need to distinguish required semantic proof from duplicate
runtime before changing tests or cache behavior.

**DoD:** A machine-readable inventory records every test's node ID, purpose,
owner layer, inputs, options, assertions, duration, subprocess count, cache
key, memory, and required pipeline evidence. Full and focused baselines are
captured with three repetitions.

**Definition of failure:** Any collected test lacks an owner/purpose/evidence
record, baseline runs differ without explanation, or inventory generation
changes test selection or pass/fail behavior.

### 2. Close the existing xdist diagnosis

**Reason:** Scheduler changes are meaningless while broad collection can fail
with a no-tests or worker-startup problem.

**DoD:** The historical broad command either runs reliably with recorded
worker/RSS evidence or has a deterministic reproducer narrowed to a documented
target and worker count.

**Definition of failure:** Collection loses tests, exits with status 5, has
worker crashes, or produces different selection/results across repetitions.

### 3. Apply cheap structural wins

**Reason:** Request-local AST indexes and removal of duplicate global scans have
low semantic risk and improve every later measurement.

**DoD:** Architecture and ownership checks preserve exact violations, ordering,
and exit status; each repository-wide scan runs once per gate; focused and full
test counts do not regress; linters, types, and architecture checks pass.

**Definition of failure:** A violation is lost/reordered, a scanner uses stale
data, a worker still repeats the global scan unnecessarily, or any gate is
weakened to obtain the speedup.

### 4. Fix repeated decompilation work

**Reason:** Repeated cold SortDemo subprocesses are the largest measured source
of wall time and can be reduced without deleting semantic assertions.

**DoD:** Content-addressed artifacts reuse equivalent inputs/options; per-key
locks prevent concurrent duplicate producers; atomic/corrupt/stale-key tests
pass; cold, warm, and concurrent-warm results preserve C, diagnostics,
validation, compiler checks, and exit codes.

**Definition of failure:** A partial artifact is consumed, a stale artifact is
accepted, concurrent workers duplicate production without explanation, cache
hits bypass validation, or any generated behavior changes.

### 5. Re-profile real hotspots

**Reason:** Outer pytest duration cannot distinguish decompiler CPU, compiler
work, process startup, cache contention, timeout waiting, and xdist imbalance.

**DoD:** The top 50 tests have phase-level timings, CPU/RSS data, cache status,
and scheduler/lock wait measurements. Each proposed optimization has an owner
layer and a measured target.

**Definition of failure:** A proposed fix is based only on test name or wall
time, profiles cannot be repeated, or the measurement cannot separate required
work from duplicated work.

### 6. Compile proven CPU hotspots with mypyc

**Reason:** mypyc can reduce CPU cost after repeated-work fixes, but compiling
before cache stabilization obscures the benefit and can increase startup/RSS.

**DoD:** Each candidate has a hotspot profile, complete types/docs, mypy pass,
pure-Python/mypyc differential tests, three-run timing evidence, acceptable
RSS, and a working pure-Python fallback. Full pipeline and semantic output
remain equivalent.

**Definition of failure:** The candidate is not a measured hotspot, mypyc and
Python differ in output/diagnostics/validation, startup or memory regresses,
or compilation requires weakening types or adding owned-object `getattr`/
`setattr` workarounds.

### 7. Run duplicate/supersession analysis

**Reason:** Once artifact reuse is working, coverage overlap can be evaluated
without confusing expensive repeated setup with a reason to delete proof.

**DoD:** Unit and integration lanes are analyzed separately with
`/home/xor/pytest_deduplicate`; every candidate is classified as exact
duplicate, superseded, complementary, or false positive against the purpose
and evidence matrix.

**Definition of failure:** A candidate is labelled duplicate solely because it
has identical Python coverage, or the analysis ignores sidecars, options,
source oracles, exit codes, validation, diagnostics, or failure assertions.

### 8. Remove or merge only proven redundancy

**Reason:** Deletion is irreversible coverage loss unless retained tests prove
the same contract under mutation.

**DoD:** Each retired node has a documented replacement, before/after inventory,
unchanged mandatory contracts, and mutation evidence. Serial, `-n 7`, mypy,
lint, tail-validation, recompilation, and MS C tiny-example gates pass.

**Definition of failure:** Any removed behavior is untested, mutation survives,
test selection changes unexpectedly, or a pass/skip/failure regression is
explained only by weakening an assertion.

### 9. Tune xdist last

**Reason:** Scheduling must be measured on the cached, de-duplicated workload;
otherwise more workers merely hide duplicate work or exceed memory.

**DoD:** Worker counts and schedulers are compared over three repetitions with
critical-path time, peak RSS, worker balance, and semantic results recorded.
The selected configuration stays within the 2 GiB development budget.

**Definition of failure:** A scheduler loses tests, changes ordering-sensitive
behavior, increases aggregate memory beyond budget, worsens the median, or
requires test weakening/grouping without evidence.

### 10. Run final repetitions and close all gates

**Reason:** The target is a durable project improvement, not a single fast
machine-local run.

**DoD:** Three source-stable warm full-suite repetitions complete in at most
400 seconds each, focused lanes remain green, all types/docs/linters pass, MS C
tiny examples compile, decompile, recompile, and match exit codes, and
pure-Python/mypyc outputs are equivalent. Cold-cache timing is reported
separately and is not substituted for a warm result.

**Definition of failure:** Any failure, new skip, semantic mismatch, missing
function, validation change, compiler regression, unexplained warning, or
single-run-only performance result remains.

This order front-loads measurement and low-risk reuse, while postponing
irreversible test deletion and scheduler tuning until their measurements are
meaningful.

## 2026-09-27 environment and failure audit

The latest complete partitioned report in `.cache/pytest/partitioned-summary.json`
is a failed run, not a performance acceptance: 12,774 nodes, 47 failures,
31.8 minutes, and 1.69 GiB peak RSS. Its heavy lane used 39 fresh Python
workers with only two admitted at a time and occupied 29.2 minutes. The
SortDemo regression file alone accumulated 1,334 seconds of test-call time;
the CLI and COD regression files added 514 and 249 seconds. The report cannot
authorize measured-worker concurrency because it failed.

Current local timing is not comparable to the accepted 2026-08 baseline. The
host reported load averages of roughly 24-30 and 68-78% CPU `some`
pressure during this audit. A fresh `import angr` took 18-23 seconds. A
single `SwapBars` pytest node took 139 seconds with the full-suite timeout
scale of four and failed because the MS C recompile check could not open
`/dev/kvm`; the device is absent in this sandbox. The one-timescale rerun
timed out and is not evidence of a semantic regression. The worktree also had
uncommitted source edits, which can invalidate warm decompilation caches. A complete
green, source-stable run in a KVM-capable environment is required before
claiming the ten-minute target or accepting new worker resource measurements.

The bounded `/home/xor/pytest_deduplicate` run covered 47 segmented-address
and stack-lowering tests, found 24 coverage-overlap candidates, and reported
zero tool errors. None was marked safe for automatic removal; matching
coverage does not establish equal assertions. These millisecond-scale tests
cannot explain the heavy lane's runtime. Keep their semantic contracts and
prioritize the repeated decompilation work after the environment is stable.
