# Decompiler Runtime Optimization Plan

## Goal

Reduce cold, no-sidecar decompilation time without weakening semantic recovery,
tail validation, generated-C stability, type coverage, or layer ownership.
Optimize the largest measured wall-time owner first and reject speculative
caches or replay suppression that cannot demonstrate useful hits.

Completed task bodies and rejected experiment logs were removed on 2026-08-28.
Git history through `3ca6f9497` retains their implementation and evidence.

## Current Evidence

- In the current shared-worktree snapshot, the exact no-sidecar `sub_10ce0`
  regression emits SHA-256
  `14d97d8ac34d7b95308a8855a18224c76cf2251f151304b7c265791222dc808c`,
  preserves the `0x10d2f -> 0x107b8` call as
  `sub_107b8(&g_0B4C[arg_4], &g_0B4C[arg_6])`, and reports
  `validation=passed` plus clean whole-tail validation for the focused
  function.
- The neighbor-cache slice passes 81 focused and 29 mapped tests under
  `pytest -n 7`; strict mypy, Ruff `--fix`, architecture, context, and ownership
  checks pass for the changed surface.
- The current shared-tree pipeline has 1,861 pytest passes and four unrelated
  direct-stack failures; one of three external constructs passes. The failing
  `apply_twice` external case remains status 4 with this cache disabled.
- Timing diagnostics now preserve upstream discovery/evidence cache identity
  while refusing direct, serial-worker, and function-result C reuse. An
  accepted repeated run fell from 160.85 to 46.90 seconds wall and from 119.01
  to 41.02 seconds decompilation, at 304,876 KiB RSS, with live stage timings,
  identical current C, and both validation gates passing.
- Current segment/global materialization totals about 8.2 seconds. Its first
  productive replay costs 4.74 seconds: indexed lowering is 2.61 seconds and
  runtime segment lowering is 1.39 seconds. The latter spends about 0.75 seconds
  in positive-BP argument materialization, including 0.713 seconds on the first
  all-caller argument-width census. Late stable replays total under one second.
- Complete pointer/global-source and direct-caller callsite evidence now crosses
  both project and clean-worker boundaries. On sidecar-free CMP16, worker callee
  census time fell from 1.023 to 0.002 seconds with zero range rescans; the
  previously measured 2.40-second global-source worker rebuild is also absent.
- An opt-in clean-worker cProfile of the six-function CMP16 sweep attributes
  17.64 of 33.95 profiled seconds in its slowest worker to Structuring
  validation priming, including 5.79 seconds of callsite-summary work and 2.09
  seconds of callee argument evidence. A same-checkout profiled A/B reduced 60
  neighbor-call queries to 15 collectors, helper time from 0.762 to 0.108
  seconds, and wall from 43.586 to 42.785 seconds; both runs returned status 0.
- The accepted caller-census transport profile emits byte-identical C at
  `8392efb49c84361d0e0a64f34ed7dc7415d0a98a9714e4145e8d54d8b2f57850`,
  reports `validation=passed` and clean whole-tail validation, and uses 277,140
  KiB RSS. One-function profiled wall remains within noise (41.66 versus 41.57
  seconds) because collection moved once to the parent; multi-worker sweeps no
  longer repeat that CPU cost per function.
- Caller-indexed typed summaries now cross the same project/worker boundary.
  On the accepted CMP16 profile, callsite inventory rebuilding fell from 2.80
  to 0.35 seconds, declaration reconciliation from 3.54 to 1.53 seconds, and
  the Structuring validation prime from 15.46 to 13.52 seconds (12.5%). A
  mutation-invalidated Structuring call-return index then reduced call-return
  condition materialization from 1.32 to 0.41 seconds, placement classification
  from 0.78 to 0.04 seconds, and exact bound-call counting from 0.47 to 0.004
  seconds. The combined validation prime is 13.04 seconds, 15.6% below the
  original 15.46-second profile; the shared deep iterator fell from 3.61 to
  2.85 seconds. The C
  hash remains `8392efb49c84361d0e0a64f34ed7dc7415d0a98a9714e4145e8d54d8b2f57850`;
  focused and whole-tail validation pass.
- Consecutive stable optimization passes now reuse the prior pass's exact
  after-state witness as the next before-state witness. On the accepted CMP16
  profile, optimization-owned tail-validation input builds fell from 14 to 8,
  total builds from 17 to 11, cumulative witness cost from 2.22 to 1.27
  seconds, and postprocess time from 2.71 to 1.57 seconds. A typed closed
  counter and an integration test prove one rebuild plus one reuse while a
  later falsely stable mutation is still detected, validated, rejected, and
  rolled back. Generated C remains byte-identical and both validation gates
  pass.
- Interprocedural input-storage collection now closes physical and type-class
  evidence before constructing caller SSA. On CMP16, all three logical inputs
  are typed `signedness_unknown` refusals, so the previously wasted caller-SSA
  build disappears. Refused-callsite collection fell from 1.53 to 0.001
  seconds, interface reconciliation from 1.65 to 0.12 seconds, and Structuring
  validation priming from 12.58 to 11.26 seconds (10.5%). The preflight owns
  closed raw/normalized/classified/materialized/failure accounting; generated
  C remains byte-identical and both validation gates pass.
- Runtime segment lowering now rejects impossible Structured-C node kinds
  before segmented-expression matching. The accepted CMP16 trace observed
  8,869 address probes with no matches and 82 read matches, all rooted at
  dereference unary nodes. Matcher prefiltering reduced runtime segment
  lowering from 3.015 to 2.835 seconds, the segment/global Structuring prime
  from 1.754 to 1.616 seconds, validation priming from 11.257 to 10.843
  seconds, and `_decompile_8616` from 19.676 to 19.097 seconds. Generated C is
  byte-identical at the accepted hash and both validation gates pass.
- Direct-global call-return recovery now obtains its typed Capstone projection
  from the request-owned immutable function-evidence inventory. Across the
  accepted CMP16 collector cohort, repeated ordered decode and instruction-view
  construction fell from about 0.235 to 0.090 seconds (62%); a focused test
  proves repeated reads build the projection once, while the inventory's
  existing binary-surface tests retain mutation invalidation. The concurrent
  whole-process profile was load-contaminated, so no end-to-end wall claim is
  made from that run. Generated C and both validation gates remain unchanged.
- The legacy JCC consumer now retains the frontend's typed function-instruction
  inventory instead of discarding its closed completeness result. When that
  inventory contains the exact queried instruction, the bounded byte-by-byte
  rescue is unnecessary; incomplete or missing-address evidence still takes
  the existing fallback. On accepted CMP16, linear rescans fell from 91 calls
  and 0.452 seconds to zero, call-return recovery from 0.572 to 0.080 seconds
  (86%), and decoded-JCC rewrite from 0.794 to 0.464 seconds (42%). Focused
  tests prove both the complete-evidence skip and incomplete-evidence rescue.
  Generated C is byte-identical at the accepted hash and both validation gates
  pass. Concurrent load contaminated whole-process timing, so no end-to-end
  wall claim is made from this run.
- Bounded instruction reachability now consumes the exact decoded-block
  inventory instead of bypassing it through a fresh `factory.block` lift. The
  typed inventory retains the immutable third-party block projection needed by
  reachability while remaining free of C AST, alias, type, and validation
  state. On CMP16, 174 of 314 reachability requests reused an existing block;
  combined decoded-block misses fell from 664 to 490 (26%), and the owned
  reachability cohort fell from 2.730 to 2.533 seconds despite heavier load.
  A two-entry/shared-tail test proves cross-census reuse. Generated C remains
  byte-identical and both validation gates pass; overlapping decompiler runs
  make whole-process wall and RSS unsuitable for an acceptance claim.
- Tail-validation input normalization now uses one request-local, cycle-aware
  atom builder. Repeated acyclic evidence subgraphs reuse their exact atom;
  any ancestor cycle marks the containing projection non-cacheable, and no
  atom survives into a later top-level generation request. On accepted CMP16,
  dynamic atom calls fell 60%, tail-validation input generation from 1.982 to
  0.685 seconds (65%), optimization witnesses from 1.686 to 0.582 seconds
  (65%), and postprocess from 2.318 to 1.281 seconds (45%). Generated C is
  byte-identical at the accepted hash, both validation gates pass, wall is
  41.76 seconds, and RSS is 327,116 KiB. Focused tests prove acyclic reuse,
  path-sensitive cycle preservation, and mutation visibility across requests.
- Register-source recovery now retains only immutable decoded CFG inputs under
  an exact block/predecessor generation, resolves each CALL target from the
  already-decoded instruction once, and reuses frontend leaf-block decode
  evidence. Semantic register and CALL effects are still recomputed on every
  query. Lowering also consumes a complete registered IR condition artifact
  before considering its exact-byte relift fallback. On accepted CMP16,
  register-source recovery fell from 2.043 to 0.653 seconds (68%), condition
  artifact collection from 2.191 to 0.788 seconds (64%), block transfer from
  1.428 to 0.449 seconds (69%), and block-based direct-target recovery from
  1,747 calls / 0.562 seconds to 67 calls / 0.084 seconds. The same 3,300
  semantic transfers still execute, proving the optimization did not cache an
  Alias verdict. Generated C remains byte-identical at the accepted hash,
  focused and whole-tail validation pass, RSS is 328,120 KiB, and
  `_decompile_8616` measured 19.293 seconds versus 22.941 seconds in the prior
  profile. The latter comparison is diagnostic because the shared worktree
  changed between profiles; the owned recovery cohort is the acceptance
  evidence.
- Callsite attachment now consumes the existing complete, caller-indexed
  program summary artifact and invokes binary summarization only for exact
  missing coordinates. Across accepted CMP16, attachment-owned
  `summarize_x86_16_callsite` calls fell from 84 to 6 (93%); total summary
  calls fell from 126 to 43, although that broader count also reflects
  concurrent shared-tree changes. The six attachment requests fell from 1.661
  to 0.785 seconds despite severe concurrent load, and thirteen
  retained-evidence lookups cost 0.003 seconds. Focused tests prove both
  complete-evidence reuse and
  missing-coordinate fallback. Generated C remains byte-identical at the
  accepted hash, both validation gates pass, and profiled RSS is 328,320 KiB.
  The run was load-contaminated, so no whole-process wall claim is made.
- Direct-call patching now consumes the complete typed frontend instruction
  inventory and retains its block-by-block lift only for incomplete evidence.
  Across the accepted CMP16 cohort, eleven `patch_direct_call_sites` calls fell
  from 0.313 to 0.185 seconds (41%), while generated C remained byte-identical
  at the accepted hash and both validation gates passed. Focused tests prove
  complete-inventory reuse and the incomplete-inventory fallback. Concurrent
  decompilers contaminated wall and RSS, so neither is used for acceptance.
- The mandatory runtime layer-import guard now stores typed, content-addressed
  verdicts per guarded file instead of treating every source edit as a reason
  to parse all 507 guarded modules again. A cold fresh-process scan measured
  19.43 seconds and 373,152 KiB RSS; a fresh process with one file verdict
  invalidated measured 0.57 seconds and 35,272 KiB RSS, a 97% feedback-loop
  reduction. Cached violations remain violations and still stop startup;
  changes to checker code invalidate every stored verdict. Focused tests prove
  one-file invalidation, violation retention, and checker-wide invalidation.
- Structuring condition recovery now builds exact subtree entry-tag projections
  bottom-up once per current AST generation and invalidates the full index at
  every reported mutation. On accepted CMP16, 52 expensive subtree walks became
  two complete index builds with no fallback; block-tag query time fell from
  1.426 to 0.210 seconds (85%) and condition-chain materialization from 2.460
  to 0.497 seconds (80%). The index has closed build/query accounting and a
  cycle-safe exact fallback. Generated C remains byte-identical at the accepted
  hash and both validation gates pass.
- Runtime segment lowering now suppresses the annotation materializer's nested
  positive-BP fallback because the orchestrator immediately invokes that same
  lowering owner itself. On current CMP16, positive-BP materialization fell
  from 14 calls / 1.271 seconds to 8 calls / 0.739 seconds (42% cumulative),
  and runtime segment lowering fell from 4.591 to 3.199 seconds (30%). A
  same-tree A/B emitted byte-identical C at
  `d5330341b1caf48ab90d15dd2921fe0482b575fcc048af758356a17614e77b79`;
  function and whole-tail validation pass. Profiled wall improved only from
  31.46 to 30.86 seconds, so this is accepted as a local traversal reduction,
  not a material end-to-end speedup.
- Callsite attachment now reuses its exact same-codegen summary inventory when
  call-name metadata did not change; name-changing passes and missing
  coordinates still rebuild from binary evidence. On current CMP16, the second
  attachment replay removed 14 of 28 attachment-owned summary calls. Attachment
  time fell from 0.733 to 0.656 seconds despite a heavily load-contaminated
  comparison run. Current-tree C remains byte-identical at
  `d5330341b1caf48ab90d15dd2921fe0482b575fcc048af758356a17614e77b79`,
  and function plus whole-tail validation pass. The remaining 54 summary calls are
  owned by program-inventory construction, callee census, and range facts and
  require scope analysis before consolidation.
- Complete direct-caller censuses and their caller-indexed typed summary
  projection now use a separate content-addressed program-callsite artifact.
  The cache has its own narrow discovery/Alias/callsite source scope and refuses
  incoherent projections. The artifact also persists canonical caller-range
  coverage and refuses creation or attachment when that coverage is absent or
  changed, so a partial caller inventory cannot masquerade as complete. On
  sidecar-free SORTD `sub_109e8`, warm callee
  argument evidence fell from 11.632 to 0.013 seconds, callee census collection
  from 11.621 to 0.010 seconds, and target-specific range/boundary rescans
  disappeared from the profile. Generated C remains byte-identical at
  `895a5c723e70aad6f98d4cd42249816fc8eecebc50f0d3c4875745b5eededaf9`;
  function and whole-tail validation pass at 328,780 KiB profiled RSS. The
  first run paid 52 seconds before decompilation to build the reusable artifact;
  the warm whole-process profile measured 78.14 seconds wall, including 14.06
  seconds of Python imports and 51.81 seconds waiting for the forked job, so no
  end-to-end speedup is claimed from the load-variable comparison.
- Exact raw function IR now crosses the existing program-owned SSA registry
  boundary instead of being rebuilt when Structuring attaches VEX evidence.
  The registry accepts only complete refusal-free artifacts, rejects divergent
  artifacts at the same address, and keeps semantic-stage SSA from being
  downgraded by a later raw consumer. On sidecar-free SORTD `sub_109e8`,
  `apply_x86_16_vex_ir_artifact` fell from 1.694 to 0.002 seconds and the
  Structuring validation prime from 17.719 to 3.721 seconds. Two current runs
  measured 43.55 and 46.49 seconds wall at 334,724 and 335,016 KiB RSS;
  focused decompilation measured 11.70 seconds on the warm profile. Generated
  C remains byte-identical at
  `895a5c723e70aad6f98d4cd42249816fc8eecebc50f0d3c4875745b5eededaf9`;
  function and whole-tail validation pass. The eliminated relift is the
  accepted speedup; older whole-process wall comparisons remain load-variable.
- Raw IR construction now captures typed branch-condition evidence inside the
  already-required frontend block lift and accepts it only when the normalized
  block inventory and every expected conditional owner close. Incomplete or
  cache-skipped capture still falls back to isolated exact-byte relifting. On a
  same-tree sidecar-free SORTD `sub_109e8` profile, 21 function IR artifacts
  went from 376 direct relifts and 4.200 seconds in the relift owner to zero
  direct relifts; raw IR construction fell from 21.248 to 17.429 seconds (18%).
  The complete capture test covers all 12 `Sleep` blocks and three conditional
  owners. Disabled/enabled runs emitted byte-identical C at
  `f4b9c76a0cce4c322d19ab866a57941d89db9e30c1c69f6a5043fe11df5b310a`;
  function and whole-tail validation pass. Profiled wall was 64.63 seconds off
  versus 62.71 on, but whole-process variance remains too large for a broader
  wall-time claim. The exact-byte artifact cache now owns its synchronization
  instead of relying on one caller's outer lift lock.
- VEX binary temporary import now normalizes each operand once and constructs
  the resulting typed value from those same operands. The previous path
  converted both operands, classified the condition, then recursively
  converted the binary root and both operands again. On consecutive
  `sub_109e8` profiles, `_expr_to_value` calls fell from 129,486 to 82,146
  (37%), statement import fell from 7.386 to 6.210 seconds (16%), block import
  from 7.897 to 6.671 seconds (16%), and full raw IR construction from 17.429
  to 14.951 seconds (14%). Profiled wall fell from 62.71 to 57.75 seconds.
  Generated C remains byte-identical at
  `f4b9c76a0cce4c322d19ab866a57941d89db9e30c1c69f6a5043fe11df5b310a`;
  function and whole-tail validation pass. A focused call-count regression
  prevents reintroducing recursive binary-root conversion.
- VEX condition import now publishes a typed, fail-closed direct-exit demand
  artifact before statement conversion. Comparisons remain eagerly classified
  because later flag formulas consume their temporal provenance; And/Or/ITE
  formulas are eager only when their temporary directly owns a conditional
  exit. On the production-base 20-function SORTD census, condition calls fell
  from 3,662 to 570 (84%), condition-classification time from 1.608 to 0.060
  seconds (96%), and 399-block import from 6.437 to 3.885 seconds (40%). Every
  imported block result was exactly equal. A complete normal `sub_109e8` run
  and the legacy-eager comparison emitted identical C at
  `fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`;
  function and whole-tail validation pass. Shared decompiler load and different
  profiler modes make the full-run wall values unsuitable for an end-to-end
  speed claim.
- Cold source-region discovery now decodes its exact caller ranges once into a
  request-owned Frontend artifact and keeps target-specific return-use
  classification in the existing semantic owner. On the 20-function
  sidecar-free SORTD census, target queries fell from 3.431 to 0.184 seconds;
  the one-time artifact build cost 0.151 seconds, reducing the owned cohort to
  0.335 seconds (90%). Direct-call index construction fell from 20 builds to
  one. Legacy and shared-artifact results were exactly equal across all 20
  targets and 21 caller ranges. A complete `sub_109e8` run remains
  byte-identical at
  `fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`;
  function and whole-tail validation pass. Concurrent decompilation load makes
  whole-process wall time unsuitable for a broader speed claim.
- Terminal AX return classification now publishes one immutable Semantics
  result through the exact function-binary evidence inventory. Byte, word,
  wide, and return-type consumers reuse both complete evidence and typed
  refusals until the function block surface changes. On the 20-function
  sidecar-free SORTD census, semantic collections fell from 80 to 21 and
  decoded-block requests from 5,245 to 1,353, both 74%; cache surface checks
  cost 0.099 seconds across 80 requests. Seven concurrent clean workers made
  the surviving collections substantially slower, so no wall-time claim is
  made from that run. A complete `sub_109e8` run remains byte-identical at
  `fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`;
  function and whole-tail validation pass.
- Terminal AX return semantics now consumes a complete exact-byte Frontend
  block-decode artifact instead of entering VEX merely to obtain Capstone
  instructions. The artifact owns graph extents, byte-content identity, typed
  refusal reasons, closed fact accounting, and mutation-aware request reuse;
  Semantics owns only balanced entry-save/terminal-restore classification. The
  previous 20-function profile attributed 14.534 seconds across 21 materialized
  terminal-return collections, including 13.935 seconds to restore-site
  decoding. In the focused current `sub_109e8` profile, terminal-return
  collection cost 0.018 seconds, its one real semantic materialization cost
  0.007 seconds, direct artifact construction cost 0.010 seconds, and the owner
  made zero legacy VEX-backed block-decode calls. The complete acceptance run
  returned status 0 in 67.94 load-contaminated seconds, emitted byte-identical
  C at
  `fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`,
  and passed function plus whole-tail validation. Focused tests prove exact
  Capstone parity, no VEX entry, content-mutation invalidation, graph-surface
  refusal, cached reuse, and equality with the legacy VEX-backed semantic
  result. Profile scope and concurrent decompiler load differ, so the locally
  accepted claim is removal of the owned VEX work, not an end-to-end wall
  ratio. The required shared-tree pipeline passed 1,896 Python tests and its
  Ultra QuickC lane, but the MS C lane remains red with only `loops_jumps` and
  `storage_classes` passing. A changed-surface anchor gate also found seven far
  CALL/JMP/RET/IRET address failures while `lift_86_16.py` had concurrent
  uncommitted edits. These broad failures are not hidden or attributed by this
  focused evidence; the current checkout does not have a globally green gate.
- Raw bytes-to-VEX and pristine VEX-to-AIL caches were measured and rejected at
  their current boundaries. On a realistic sidecar-free SORTD `sub_109e8`
  run, 1,901 custom-lifter requests contained only 67 exact repeated
  byte/address/options/architecture keys, a 3.5% hit opportunity. A
  representative 15-byte, 200-statement block averaged 19.94 ms to lift and
  1.49 ms to deserialize into an isolated IRSB, limiting the measured
  theoretical saving to about 1.2 seconds before lookup and evidence replay.
  More importantly, a CMP/JCC differential experiment produced byte-identical
  VEX after deserialization but lost its required typed `ConditionIR` fact:
  one fact on the real lift and zero on the raw cache hit. The same profile
  attributed only 0.048 seconds to Clinic VEX-to-AIL conversion out of 0.713
  seconds total Clinic time. Do not add either raw cache. A future experiment
  must cache a complete immutable function-level frontend artifact containing
  VEX plus closed typed condition, access, and flag evidence, and must first
  demonstrate materially repeated complete requests.
- Cold indexed-Alias construction has a typed bounded-fork experiment with an
  exact serial fallback and a three-worker, roughly 1.13 GiB aggregate cap.
  Two stable serial SORTD `sub_109e8` runs measured 27.39 and 27.31 seconds;
  idle three-worker runs measured 25.51 and 30.12 seconds while increasing CPU
  from 26.63 to 32.52-36.38 seconds. C remained byte-identical at
  `85b457b8f7e3a9ebf8c91f9fd66aef4c7402b8cc2bbe84ec86645eec49950754`
  and both validation gates passed, but the speedup did not repeat. Serial
  therefore remains the default; `INERTIA_INDEXED_ALIAS_WORKERS` is explicit
  opt-in evidence gathering for larger function censuses.
- Complete project callsite collection builds one immutable typed target
  inventory per function and now keeps terminal-cleanup plus callee-save facts
  in its request-local Semantics cache. Exact containing, next, and direct-jump
  blocks consume the existing Frontend block inventory; sized linear windows
  retain their distinct fail-closed factory fallback. The accepted sidecar-free
  SORTD `sub_109e8` profile reduced total callsite summarization from 6.441 to
  1.908 seconds (70%), containing-block lookup from 1.311 to 0.023 seconds,
  next-block lookup from 2.596 to 0.006 seconds, direct-jump following from
  0.707 to 0.055 seconds, and callee-save recovery from 0.769 to 0.078 seconds.
  Generated C remains byte-identical at
  `caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`;
  function and whole-tail validation pass. IR/SSA construction rose to 25.118
  seconds in that run, so the owner reduction is accepted but no whole-process
  wall-time speedup is claimed. The cache and wiring have 122 focused tests.
- Request-local Capstone-only block inventory now decodes bounded loaded bytes
  directly and enters the VEX-backed factory only on a typed refusal. An
  initial differential found 24 of 646 boundaries incorrectly crossing
  repeat-prefixed string instructions; the frontend now mirrors the custom
  lifter's proven boundary before a non-leading repeat and after a leading
  repeat. The accepted current census matches 54 of 54 active factory blocks
  with zero refusals, and synthetic parity covers RET, JCC, JMP, CALL, LOOP,
  INT, repeat-at-entry, repeat-after-leading, and a 100-instruction straight
  line. On the accepted warm `sub_109e8` profile, 55 block-inventory requests
  cost 0.0205 seconds, including 54 direct decodes at 0.0193 seconds, with no
  inventory-owned VEX fallback. The remaining 51 VEX lifts and 0.555 seconds
  belong to semantic consumers outside this projection. Generated C remains
  byte-identical at
  `fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`;
  function and whole-tail validation pass. Cache warmth and request population
  differ from the prior 2,249-request / 10.210-second profile, so only the
  closed owner-level VEX elimination is accepted, not a wall-time ratio.
- Exact-region function stitching now consumes that same typed block inventory
  instead of entering VEX merely for block bytes, instructions, and successor
  edges. A same-process sidecar-free SORTD census replayed all 20 requested
  ranges through the forced VEX fallback: every block byte/instruction shape
  and every edge matched. Direct evidence served 357 of 399 blocks; typed
  refusals retained VEX for the remaining 42. The stitched-discovery owner fell
  from 1.623 to 0.093 seconds (94%). An isolated prior-baseline worktree, with
  only the already-required untracked module dependencies and their GP-state
  helper, produced status 0 through both direct and forced-fallback discovery,
  byte-identical C at
  `fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`,
  and passing function plus whole-tail validation. The owner-level optimization
  is accepted. The current shared tree is not globally green: concurrent
  unstaged lowering/return work makes both paths fail identically with
  unresolved stack locals, status 4, C hash
  `368c0e02271f7a8b24796546a4f680c0ecea0dd221693f97caad65c03788b0a6`,
  and no function validation. The changed-file gate passes, as do 12 existing
  stitched/exact-region tests, 1,906 curated fast-pipeline tests, and all three
  external quality constructs. The full CLI file has one unrelated live-tree
  failure because the concurrent untracked affine cleanup assumes a synthetic
  test codegen has a statement root.
- Recovery-metadata helpers now obtain their Capstone-only block view from the
  typed frontend inventory and retain VEX only on a typed direct-decode
  refusal. All ten callers consume instruction views rather than VEX or AIL.
  On a same-checkout cold sidecar-free SORTD `sub_109e8` profile, 3,155 helper
  requests fell from 5.750 to 0.050 seconds (99%), custom-lifter requests fell
  from 1,832 to 1,601, indexed Alias context preparation from 30.641 to 28.894
  seconds, and project callsite collection from 8.075 to 6.337 seconds.
  Generated C was unchanged and function plus whole-tail validation passed.
  The patched run also paid a fresh 9.33-second architecture attestation after
  its source change, so only owner and main-CLI reductions are accepted, not
  the profiler's process-total comparison. Strict file gates, 93 focused
  frontend/callsite tests, 1,906 curated fast-pipeline tests, and all three
  external quality constructs pass.
- Semantic cache identity now excludes the execution-only
  `INERTIA_DECOMPILE_VENV` handoff marker and the diagnostic-only
  `INERTIA_CORE_CPROFILE_PATH`. Before the fix, the profiled `sub_109e8`
  request spent 36 seconds before the binary report and 58.29 seconds wall
  because it built a separate IR/SSA and Alias cache family. After one normal
  population, the profiled variant reached the binary report in about one
  second and finished in 31.19 seconds despite larger core-profile overhead;
  direct venv execution reused the same family, finished in 13.99 seconds, and
  emitted byte-identical C at
  `caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`.
  Function and whole-tail validation pass, and 45 focused cache tests preserve
  semantic-environment invalidation.
- Function IR/SSA persistence no longer computes a duplicate JSON projection
  digest and now stores only raw IR, rebuilding deterministic IR-stage SSA on
  hydration while retaining payload, ownership, identity, coherence, and source
  checks. A representative payload fell from 962,320 to 463,100 bytes (52%);
  the forced 20-function path fell from 36.39 to 28.04 seconds wall and from
  about 22 to 14 seconds before decompilation. A cold profile then attributed
  24.406 seconds to 21 raw IR builds and 22.209 to lifting, versus 1.405 for all
  20 record writes, confirming lifting as the remaining owner. Prefork framing
  also copied every remaining byte suffix after each partial write: a 4 MiB/8
  KiB synthetic partial-write probe fell from 0.253 to 0.00058 seconds with one
  `memoryview`; normal blocking-pipe throughput was flat, so this is a safeguard
  rather than a wall-time claim. Workers now return raw IR only and rebuild SSA
  on the parent; the largest SORTD Alias result was 1,246 bytes versus 422,404
  bytes of IR and 534,393 bytes of redundant SSA. The representative artifact
  is 52% smaller and serialize/load plus rebuild measured 0.689 versus 0.715
  seconds. A load-contaminated cold three-worker run finished in 32.59 seconds,
  emitted accepted C at `caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`,
  and passed both validation gates. Worker count is execution-only cache
  context; automatic parallelism remains disabled pending a clean A/B. The
  changed surface passes 71 mapped tests.
- Function IR/SSA source invalidation now follows a versioned positive owner
  manifest instead of hashing nearly every root x86-16 module. The source
  surface fell from 260 files to 129 while adding the previously omitted IR
  frame-analysis modules and top-level pyvex compatibility owner. Callsite,
  Lowering, Structuring, and Rewrite edits no longer invalidate all 21 SORTD
  function artifacts. After the one-time schema rebuild, a source-stable live
  `sub_109e8` run that bypassed final-C reuse took 9.88 seconds versus 21.94
  seconds for the cold rebuild. Both runs emitted the accepted C hash
  `caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`;
  function and whole-tail validation pass. Scope tests enforce required IR,
  Frontend, Analysis, and Semantics owners plus downstream exclusions.
- Indexed Alias/Widening persistence now composes that exact IR/SSA scope with
  explicit discovery, loader, sidecar, Alias, and Widening owners instead of
  inheriting the generic 280-file discovery surface. Its source identity fell
  from 306 files to 203; changes confined to callsite semantics, Lowering,
  Structuring, or Rewrite no longer discard the program-wide layout. The same
  source-stable 21.94-second cold and 9.88-second warm SORTD pair exercised
  this cache family, bypassed final-C reuse, preserved the accepted C hash,
  and passed function plus whole-tail validation. Regression tests require the
  full IR/SSA subset and every direct artifact owner while rejecting those
  downstream layers.
- The mandatory runtime architecture guard no longer imports pytest while it
  loads the AST-only source index. Pytest's runtime types are now imported only
  when test-inventory collection asks for concrete parametrized addresses. Five
  fresh guard imports fell from 0.27-0.29 seconds and about 33 MiB RSS to
  0.08-0.09 seconds and about 20 MiB RSS. Ten source-index tests, eight runtime
  guard tests, changed-file linters and typing, and the startup architecture
  gate pass. The concurrent shared tree still makes the current SORTD cache-miss
  path fail direct validation, so no end-to-end decompilation claim is made.
- The focused architecture gate now consumes that same content-addressed
  import attestation for the default tree instead of reparsing all guarded
  modules. Custom roots still run all import checks directly, cached violations
  remain visible, and every non-import startup rule still executes. A concurrent
  same-window A/B reduced `architecture-check-fast` from 13.38 to 10.67 seconds
  wall (20%) and from 503,972 to 390,116 KiB RSS (23%). Editing checker rules
  deliberately invalidates all file verdicts and therefore retains a slower
  one-time cold rebuild. Seventy-four focused tests plus changed-file Ruff,
  strict mypy, and the fast architecture gate pass.
- The complete default-tree startup architecture verdict is now persisted
  under an exact content fingerprint covering X86_16, CLI package, entrypoint,
  checker, and cache implementation sources. Cached violations remain
  violations; custom roots execute directly; and a source change during an
  uncached check fails closed without storing evidence. After a checker change,
  the cold rebuild took 8.891 seconds; two fresh-process warm runs took 0.217
  and 0.232 seconds, a roughly 97.5% feedback-loop reduction. Nine focused
  cache tests, strict mypy, Ruff, full architecture, context, and ownership
  gates pass.
- The optimization quality guard now distinguishes importable in-place mypyc
  extensions from isolated build-cache artifacts. When `default` and
  `pure_python` have the same active import surface, it runs decompilation once
  and compares two typed result views; an active extension still requires two
  independent executions. Cached `.cache/mypyc/lib` artifacts are no longer
  renamed despite being unreachable from the normal decompiler import path.
  On the current failing CMP16 shared-tree snapshot, guard wall time fell from
  26.95 to 11.88 seconds (55.9%) while preserving the same return-code,
  function-count, and validation failures. Twenty-eight focused tests, Ruff,
  strict mypy, type ratchet, startup architecture, context, and ownership gates
  pass; no semantic decompiler acceptance is claimed from the failing snapshot.
- The no-change mypyc development gate now reuses a successful import-smoke
  attestation only when exact package-source copies, native artifacts, module
  cohort, Python ABI, schema, and controlling files remain unchanged. Changed,
  missing, malformed, or concurrently mutated evidence runs package mirroring
  and the full 39-module import smoke; package mirroring removes stale copied
  Python files while preserving native extensions. The prior steady gate took
  16.75 seconds and 208,472 KiB RSS, including 14.12 seconds for import smoke
  and 1.53 seconds for unconditional source copying. Three fresh attested
  processes now take 0.55-0.60 seconds (0.57 median) and about 27 MiB RSS, a
  96.6% median wall reduction. Thirty-two focused tests, Ruff, and strict mypy
  pass; no native build or first changed-input smoke is skipped.
- Generated-C quality metrics now live in the CLI/reporting-owned acceptance
  scorecard instead of forcing reporting tools through the X86_16 frontend
  package bootstrap. The historical `inertia.cli.acceptance_scorecard` module is
  a typed compatibility re-export, and an identity test proves both APIs expose
  the same objects. Fresh direct frontend-quality imports previously took
  3.94-5.89 seconds and about 198 MiB RSS; the reporting owner takes 0.05
  seconds and about 13 MiB, while quality-guard help starts in 0.10-0.12
  seconds. The focused reporting test file under required `pytest -n 7` fell
  from 15.38 to 5.30 seconds (65.5%), with the single compatibility test paying
  frontend bootstrap only in its executing worker. All twenty tests pass and
  no production reporting consumer retains the heavyweight import.
- Pytest target validation now builds only selector and skip/xfail structure;
  assertion, subprocess, and evidence facts are memoized on first inventory
  access. The 74-file profiled index path fell from 2.208 to 1.244 seconds
  (43.7%), with no full-fact builds in the architecture lane. Its DoD is met:
  exact source, skip-policy, parser implementation, and Python ABI identities
  guard a bounded persistent structure record; malformed records and same-size
  content changes reparse; full facts are never serialized. The ownership gate
  measured 3.89 seconds cold and 0.31 warm (92.0%), and a warm profile contained
  zero `ast.parse` calls. Lazy facts build once, and 77 source-index, inventory,
  profile, and ownership tests pass. A 448 KiB one-file check measured 0.306
  seconds cold, 0.002 warm, and 0.298 after content invalidation. An
  explicit-stack AST walker was rejected because profiler allocation cost made
  the same path slower; restoring it without contrary aggregate evidence is a
  failure.
- The 17,901-line `decompiler_postprocess_stage.py` remains a development,
  review, and typing cost, but is no longer the leading runtime owner.
- CPython 3.14.7 reports `sys._jit.is_available() == False`; `PYTHON_JIT=1` is
  inert, so mypyc remains the available native-compilation experiment.

All measurements are checkout-specific; refresh them after correctness is restored before claiming a speedup.

## Remaining Problem Impact

| Priority | Problem | User-visible impact | Development impact |
| --- | --- | --- | --- |
| P1 | Structuring validation priming measured 1.49 seconds in the current instrumented live run | Large functions still pay repeated semantic consumer work | All three direct-stack replays and all three segment/global replays were productive on `sub_109e8`; the next skip needs a narrower authoritative mutation impact, not call-order memoization |
| P1 | Cold indexed Alias/Widening context construction still spends about 14 seconds before decompilation on a forced current rebuild | Fully invalidated no-sidecar runs remain much slower than stable-cache runs | Duplicate cache families, projection hashing, persisted/transported SSA duplication, and quadratic pipe suffix copying are removed; typed IR import, SSA construction, and Alias/Widening remain |
| P1 | Stable semantic consumers outside the accepted optimization transaction still rebuild full AST witnesses before some skips | Large functions decompile slowly and reach timeout/fallback more often | Five direct-stack requests skip consumer work but still pay generation cost |
| P1 | Deep C-AST traversal remains a major profiled owner | Adds latency to every large-function run | Encourages repeated ad hoc scans unless accepted mutation generations own index validity |
| P1 | Fresh-process architecture checks still parse 361 files and walk about 1.2 million AST nodes | No decompilation semantic impact | The latest profile attributes 5.34 seconds to repeated checker walks and 3.39 seconds to parsing; the checker is currently foreign-dirty, so shared AST caching is blocked until ownership clears |
| P1 | A fully invalidated run reaches about 677 MiB RSS | Aggressive outer parallelism can exceed the 2 GB aggregate budget | Four cold workers can exceed the budget before process overhead |
| P2 | Persistent cache storage is unbounded; the existing cache occupies about 1.7 GiB, including 1.3 GiB of legacy paired IR/SSA records | New raw-IR records are about 52% smaller, but stale generations still consume disk | Any eviction policy must avoid a directory scan on every write and remain race-safe across workers |
| P1 | The postprocess stage is 17,846 lines | No direct semantic failure, but ownership mistakes are easier to introduce | Slow comprehension, review, typing, and agent handoff |
| P2 | A current fresh full-CLI import costs about 4.25 seconds across 2,961 modules | Every uncached CLI invocation has a fixed startup cost | One accidental pytest dependency is removed, cutting isolated guard import by about 0.19 seconds and 13 MiB; remaining import refactoring is lower priority than repeated lifting |
| P2 | JIT is unavailable in the installed interpreter | No runtime improvement from `PYTHON_JIT=1` | Repeated JIT trials waste time; profile-guided mypyc is the only current native path |

## Acceptance Invariants

- Preserve `IR -> Alias -> Widening -> Types -> Structuring -> Rewrite`.
- Introduce semantics at their earliest authoritative owner, never in Rewrite
  or CLI fallback.
- Unknown evidence is `UNKNOWN_REFUSE`; it is never permission to delete code.
- Identical input and options produce deterministic C and status output.
- Preserve calls, branches, memory/return effects, and `validation=passed`.
- No test, validator, architecture check, ownership check, or typing rule is
  weakened to obtain a speedup.
- Benchmarks record checkout, command, wall, RSS, C hash, and validation.
- Keep aggregate decompiler worker memory at or below 2 GB.

## Ordered Work

### 1. Publish Consumer-Specific Mutation Generations

**Status:** in progress; exact direct-stack projection, immutable program
callsite-summary reuse, and exact raw-IR/IR-stage-SSA reuse are accepted, but
callers still lack a complete authoritative AST mutation generation scope

**Reason:** Exact full-AST fingerprints can prove stability but cost seconds on
productive Structuring rounds. Call order, object identity, and pass booleans
cannot prove that direct-stack or segment/global inputs are unchanged. The same
generation contract is required before validation-prime replays can be removed.

**Work:**

- Define typed mutation impacts for callsite summaries, stack objects,
  segment/global facts, declarations, condition artifacts, and subtree
  replacement.
- Publish generations only at the authoritative Structuring and Types/Lowering
  mutation owners.
- Route semantic consumers through one facade that records which generation
  each replay consumed.
- Retain exact AST witnessing only for paths not yet covered by authoritative
  generations.
- Keep closed counters for executed, changed, skipped-stable, and failed work.
- Preserve the accepted direct-stack projection matcher: it uses instruction
  provenance plus destination and source storage identity, rejects adjacent
  machine-BP offsets, and never relies on rendered names or text.
- Move the next skip boundary ahead of full-AST regeneration only after every
  relevant mutation in that caller advances the direct-stack consumer
  generation.
- Remove or narrow a validation-prime replay only when no relevant generation
  changes before the authoritative later replay.

**DoD:** At least one formerly repeated expensive replay is skipped without a
full-AST fingerprint; every relevant mutation advances the corresponding
consumer generation; counters close; focused mutation/misreport tests pass;
validation-prime time falls by at least 10%; accepted C and both validation
gates remain unchanged.

**Definition of Failure:** Stability is inferred from rendered text, call
order, object identity, or an unverified `changed` result; a relevant mutation
does not invalidate its consumer; generations are owned by CLI/Rewrite for
earlier semantics; accounting does not close; or productive work is skipped.

### 2. Bound Remaining C-AST Traversal

**Status:** in progress; mutation-invalidated call-return index, exact
runtime-segment candidate dispatch, immutable direct-global instruction and
register-source CFG projections, typed complete-instruction JCC and direct-call
patch dispatch, bottom-up condition-subtree tag indexing, and shared exact
frontend block decode reuse accepted; request-local bounded block inventories
also bypass VEX when direct Capstone evidence closes with custom-lifter boundary
parity; exact-region stitching consumes the same projection with owner-level
parity and isolated-baseline validation accepted while the live shared gate is
blocked by unrelated concurrent changes;
recovery-metadata instruction consumers use the same typed direct block
projection with VEX fallback and measured owner-level reduction;
terminal-return semantics consumes one complete exact-byte Frontend block
artifact without entering VEX; raw IR reuses complete typed condition capture
from its existing frontend lift;
duplicate positive-BP fallback removed from runtime segment orchestration; raw
VEX import classifies logical condition formulas only for typed direct-exit
demand while preserving every comparison required by flag provenance

**Reason:** The accepted call-return index reduced the current benchmark's
shared deep iterator from 3.61 to 2.85 seconds, but other traversal consumers
remain. A previous broader profile attributed 23.440 seconds to deep iteration
and 9.558 seconds to child replacement, so each next index still needs a newly
measured consumer rather than a generic cache.

**Work:**

- Re-profile after replay suppression and rank traversal consumers by
  cumulative time and call count.
- Add a typed query projection only for a read-only consumer with repeated
  queries over one accepted generation.
- Keep deterministic node order and explicit missing/unique/ambiguous results.
- Rebuild immediately after an accepted or witnessed mutation; mutating walks
  remain uncached.
- Stop a cohort if aggregate traversal time does not improve materially.

**DoD:** A current profile shows a material reduction in the 23.440-second
iterator owner; index construction occurs once per unchanged generation;
indexed and uncached results are equivalent; output, validation, determinism,
and the 2 GB memory budget are preserved.

**Definition of Failure:** Cached nodes survive mutation; a mutating consumer
receives cached nodes; semantic facts are inferred from C text or shape alone;
only a microbenchmark improves; aggregate traversal time is flat; memory is
unbounded; or ordering changes.

### 3. Make Validation Transactions Dirty-Pass Driven

**Status:** in progress; exact consecutive optimization witnesses reuse a
transaction-local proven after-state, and each exact witness now memoizes only
cycle-free shared evidence within its request

**Reason:** Validation is authoritative, but a provably stable pass should not
pay changed-pass regeneration, snapshot, cycle-scan, and tail-summary costs.
This follows Step 2 because reliable mutation generations are the safety
boundary.

**Work:**

- Finish extracting the guarded pass transaction into a typed postprocess
  orchestration owner.
- Use authoritative mutation generations plus the independent mutation witness
  to detect a pass that falsely reports stability.
- Retain the accepted transaction-local exact-witness cache: every optimization
  pass still computes an after-state witness; reuse applies only to the next
  before-state, and every reported or witnessed mutation invalidates it.
- Delay expensive snapshots and summaries only where rollback safety permits.
- Share unchanged-generation cycle and traversal results.
- Preserve unconditional validation for reported or witnessed mutations.

**DoD:** Truly stable passes skip regeneration and tail-summary collection;
mutating and misreporting passes still snapshot, validate, and roll back;
metadata and AST restore coherently; focused snapshot, witness, and tail tests
pass; accepted output and validation remain stable.

**Definition of Failure:** Any mutation bypasses validation; rollback cannot
restore metadata and AST together; declaration or typed-input changes are
missed; validator strength is reduced; or saved work is not visible in a
current profile.

### 4. Split and Type the Postprocess Stage

**Status:** in progress; secondary runtime priority; tail-validation atom
normalization extracted into a typed module below 350 lines

**Reason:** The 17,846-line stage materially slows comprehension, review, type
checking, and safe agent work. Extraction must improve ownership rather than
move lines cosmetically, and it must not displace the current P0/P1 runtime
work.

**Work:**

- Extract the remaining pass transaction and validation-delta contracts to
  their authoritative postprocess/validation owners.
- Move Structuring/Lowering compatibility shims to their authoritative owners
  and delete redundant wrappers.
- Replace avoidable `getattr`/`setattr` on owned contracts with typed dot access.
- Keep new modules below 350 lines where practical and prevent net stage growth.
- Run strict mypy independently on every extracted production module.

**DoD:** The stage is materially smaller; every extracted module states
`Layer:` and `Responsibility:`, has explicit types and useful public docstrings,
and passes strict mypy; architecture/import/ownership tests pass; generated C
and validation remain unchanged.

**Definition of Failure:** Lines move without clearer ownership; casts hide an
untyped owned contract; semantic recovery moves into Rewrite; the stage grows;
public behavior exists only as implementation detail; or focused gates fail.

### 5. Compile Only a Reprofiled Hotspot With mypyc

**Status:** pending after Steps 1-4

**Reason:** Previous `c_ast_utils` and `vex_import` native experiments produced
no repeatable runtime gain and increased memory or build cost. mypyc is useful
only for a stable, strict-typed CPU hotspot that remains hot after algorithmic
work.

**Work:**

- Re-profile the accepted baseline after replay and traversal reductions.
- Select a small typed hotspot with low dynamic angr-boundary density.
- Compare source and native execution with identical input, caches, worker
  count, and validation.
- Preserve incremental native builds and Python fallback execution.

**DoD:** The candidate passes strict mypy and produces identical results; three
comparable runs show a repeatable hotspot or end-to-end gain exceeding
build/import overhead; RSS remains inside the aggregate budget; Python fallback
continues to pass.

**Definition of Failure:** A module is selected because it is merely large;
`Any` is hidden to satisfy mypyc; output or validation changes; build/startup
cost consumes the gain; memory materially regresses; or timing is noise.

### 6. Tune Outer Function Parallelism

**Status:** pending after single-function memory and time fall

**Reason:** Independent functions are the correct parallel boundary, but one
mutable function remains single-owner. At the current roughly 675 MiB peak per
large function, four equivalent workers can exceed the 2 GB budget.

**Work:**

- Compare 1, 2, 3, 4, and bounded N-1 workers on a multi-function binary after
  hotspot fixes.
- Enforce deterministic output ordering and an aggregate-memory-derived worker
  cap.
- Record utilization, wall time, peak aggregate RSS, failures, timeouts, and
  fallback counts.
- Keep focused pytest execution at `-n 7`; decompiler worker policy is a
  separate memory-bounded decision.

**DoD:** The default chooses the fastest stable setting within 2 GB; all
functions remain present; output order and hashes are deterministic; validation,
failure, timeout, and fallback counts do not regress.

**Definition of Failure:** A mutable AST is shared; memory is unbounded; timing
improves because functions disappear or fall back; output order changes;
timeouts increase; or worker overhead makes the default slower.

### 7. Final Regression and Performance Ratchet

**Status:** pending

**Reason:** Local microbenchmarks and profiler totals are diagnostic evidence,
not final proof that the decompiler improved.

**Work:**

- Run changed-file Ruff with `--fix`, strict typing, architecture, ownership,
  focused semantic tests, and `make quality-dev`.
- Run `make test-pipeline` before claiming semantic safety.
- Run the accepted cold target three times and report median, range, RSS,
  output hash, function validation, and whole-tail validation.
- Add a non-flaky performance ratchet only after variance is measured.

**DoD:** All required checks pass; three cold runs preserve semantic output and
show a repeatable material wall-time reduction; no function disappears; the
final evidence records remaining bottlenecks and bounded worker policy.

**Definition of Failure:** Any gate is skipped without disclosure; tests or
validators are weakened; timing uses one warm run; output or validation
regresses; or the ratchet is tighter than observed machine variance.

## Progress Rule

Current estimated completion is 61%. Finishing the remaining acceptance work
is estimated at 5-9 focused engineering days: 2-4 days for Steps 1-3, 1-2
days for Step 4, and about one day each for Steps 5, 6, and 7. Re-estimate after
each top-level DoD closes; shared-worktree changes can invalidate timing but do
not change the acceptance criteria.

Work on the first incomplete step unless a blocker is explicitly recorded.
After every accepted change, update the relevant status and current evidence,
run changed-surface linters together, and re-run the focused semantic gate.
Re-profile before changing optimization targets. Remove completed step bodies
from this active plan; retain durable evidence in tests, typed contracts,
documentation, commit messages, and git history.
