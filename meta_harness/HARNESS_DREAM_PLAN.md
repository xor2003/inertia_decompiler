# Meta Harness Dream Plan

## Purpose

This document is the execution roadmap for turning `meta_harness/` from a useful autonomous loop into a deterministic, self-healing, operator-grade harness.

The plan is ordered by expected leverage:

1. reduce wasted cycles and wasted tokens first
2. make failure modes machine-classifiable
3. make progress deterministic at the current plan-item level
4. make the system reproducible under scripted tests
5. only then widen autonomy, UX, and advanced integrations

This is intentionally a separate plan from repository decompiler goals. It is about the harness itself.

## Mission

Build a harness that:

- can run for long periods without manual babysitting
- explains what it is doing in structured state, not only logs
- detects when it is stuck on one item and changes strategy automatically
- spends tokens and wall-clock time intentionally
- can be tested deterministically without relying on live model behavior
- gives the operator a truthful live control room

## Non-Goals

- do not optimize for clever prompts before state and policy are explicit
- do not add more role loops if the current loops are still under-classified
- do not add fancy UI ahead of typed events, recovery policy, and deterministic tests
- do not make the harness more autonomous unless the next action is explainable and testable

## Repo-Specific Extra Tasks

These are not generic harness features. They are explicit standing tasks the harness should keep visible for this repository when it helps choose the next worker focus.

1. Keep whole-tail validation disabled by default for direct user-facing `decompile.py` runs unless explicitly forced by environment or metadata handoff.
2. Keep whole-tail validation active in automated tests and `.COD`-driven lanes so COD regressions continue to be found and fixed.
3. Make planner cycles read the latest debug logs plus COD tail-validation summaries/detail artifacts before they choose the next fix.
4. Prefer continuing tail-validation fixes against bounded `.COD` corpora and focused regression tests before re-enabling it for general direct decompile runs.

## Current Baseline

The harness already has these useful foundations:

- step pipeline: `full-sweep -> checker -> planner -> worker -> reviewer`
- cycle persistence via `cycle.state.json`
- stall detection and direct worker resume
- stronger worker model escalation on repeated timeout/stall
- current plan item tracking and planner rewrite handoff
- live web UI, last-log tailing, chat, resource view
- structured runtime records:
  - `history.jsonl`
  - `preflight.json`
  - `sessions.jsonl`

These are good foundations, but they are not yet a full event/policy/recovery system.

## Global Execution Rules

These rules apply to the whole roadmap:

1. Later phases must not start before earlier phase acceptance criteria pass.
2. Every new behavior must be represented in machine-readable state, not only terminal text.
3. Every non-trivial orchestration rule must have at least one deterministic test.
4. Every autonomous recovery must be bounded:
   - one known recipe
   - one max-attempt policy
   - one explicit escalation rule
5. Every plan-item execution loop must answer:
   - what exact item is active
   - what changed since the previous attempt
   - why the harness chose the next action

## Milestone Map

| Phase | Priority | Theme | Main Result |
|---|---|---|---|
| 0 | P0 | Contracts and visibility | Freeze core schemas and make state truthful |
| 1 | P0 | Typed events and failure taxonomy | Stop reasoning from raw prose logs |
| 2 | P0 | Recovery recipes and policy engine | Turn repeated failures into deterministic actions |
| 3 | P0 | Task packet and item-locked execution | Make worker progress concrete and narrow |
| 4 | P1 | Deterministic mock harness | Reproduce failure loops without live models |
| 5 | P1 | Token economy and context compaction | Cut wasted tokens and repeated work |
| 6 | P1 | Verification contracts and green levels | Know what "done" means at each layer |
| 7 | P2 | Operator control room | Upgrade UI from status page to operations console |
| 8 | P2 | Controlled autonomy | Auto-commit, branch freshness, cleanup, bounded follow-through |
| 9 | P3 | Dream-harness layer | Background self-improvement, overnight compaction, wider integrations |

## Phase 0 - Contracts And Visibility

### Goal

Freeze the core harness state surfaces so future automation is built on stable contracts rather than ad hoc strings.

### Tasks

1. Define canonical JSON shapes for:
   - cycle state
   - preflight state
   - session ledger row
   - history event row
2. Add a single version field to each persisted schema.
3. Add a compact `docs/state_contracts.md` or equivalent section in `meta_harness/README.md`.
4. Ensure the web UI reads only documented fields for those artifacts.

### Target files

- `meta_harness/config.py`
- `meta_harness/orchestrator.py`
- `meta_harness/runtime_records.py`
- `meta_harness/webui.py`
- `meta_harness/README.md`

### Done when

- persisted runtime files include explicit schema version fields
- a new developer can inspect one document and know what each artifact contains
- UI still renders correctly if artifact fields appear in different order
- tests assert schema presence and field stability

### Verification

- `pytest meta_harness/tests/test_config.py`
- `pytest meta_harness/tests/test_orchestrator.py`
- `pytest meta_harness/tests/test_webui.py`

## Phase 1 - Typed Events And Failure Taxonomy

### Goal

Replace fuzzy category/message logging with explicit typed harness events and a shared failure classification model.

### Why this is first

Without canonical events, the harness cannot make reliable policy decisions or truthful operator summaries.

### Tasks

1. Introduce a typed event schema, for example:
   - `cycle.started`
   - `cycle.resumed`
   - `role.started`
   - `role.finished`
   - `role.timed_out`
   - `role.failed`
   - `worker.stalled`
   - `planner.rewrite_requested`
   - `sweep.started`
   - `sweep.failed`
   - `harness.restarting`
2. Add explicit failure classes, for example:
   - `provider_failure`
   - `worker_timeout`
   - `worker_no_progress`
   - `plan_item_too_broad`
   - `reviewer_plan_mismatch`
   - `sweep_failure`
   - `resource_blocked`
   - `restart_required`
   - `ui_visibility_failure`
3. Replace free-form `record_event(category, message, ...)` with structured event helpers.
4. Render the latest typed events in the UI.
5. Make the operator-visible status line derived from typed events where possible.

### Target files

- `meta_harness/orchestrator.py`
- `meta_harness/runtime_records.py`
- `meta_harness/webui.py`
- `meta_harness/tests/test_orchestrator.py`
- `meta_harness/tests/test_webui.py`

### Done when

- every recovery-relevant transition emits a typed event
- recent events in the UI are renderable without inspecting raw text
- at least 10 canonical event names are covered by tests
- at least 8 failure classes are defined and used

### Verification

- deterministic tests create events and assert exact event payloads
- UI API payload exposes event names and failure classes directly

## Phase 2 - Recovery Recipes And Policy Engine

### Goal

Turn repeated harness pain points into deterministic, bounded automatic recoveries instead of ad hoc branchy logic.

### Why this is the highest-value behavioral upgrade

The harness currently knows some stuck patterns, but policy is still spread across `if` chains in `orchestrator.py`. That makes it harder to extend, test, and trust.

### Tasks

1. Introduce a `policy` layer with:
   - context
   - rules
   - actions
2. Introduce recovery recipes for known scenarios:
   - worker timed out
   - worker repeated same failing test
   - worker made no diff-progress on current item
   - current item is too broad
   - sweep failed but evidence exists
   - harness restart required
3. Encode one automatic recovery attempt before escalation for each bounded scenario.
4. Record recovery attempts as typed events.
5. Replace stall-specific one-off branches with policy-driven actions where practical.

### Initial policy actions

- `retry_worker_fresh`
- `resume_worker`
- `switch_worker_model`
- `reduce_failure_limit`
- `rewrite_current_item`
- `skip_redundant_sweep`
- `restart_harness`
- `escalate_to_reviewer`
- `stop_with_reason`

### Target files

- `meta_harness/orchestrator.py`
- `meta_harness/runtime_records.py`
- `meta_harness/tests/test_orchestrator.py`

### Done when

- policy decisions are represented as data before execution
- at least 5 known failure scenarios are handled by recipe/rule instead of bespoke inline branching
- every automatic recovery emits:
  - scenario
  - chosen action
  - attempt count
  - escalation condition

### Verification

- deterministic tests for each initial recovery recipe
- no recipe retries forever
- one failed recipe cleanly escalates with explicit reason

## Phase 3 - Task Packet And Item-Locked Execution

### Goal

Make the worker operate on one explicit, machine-readable task packet instead of a large natural-language plan blob.

### Why this matters

This is the direct fix for the main operational pain: worker technically runs, but does not close a plan item reliably.

### Tasks

1. Define a `TaskPacket` for the current plan item with fields such as:
   - `item_id`
   - `objective`
   - `scope`
   - `target_files`
   - `acceptance_tests`
   - `done_conditions`
   - `retry_notes`
   - `escalation_policy`
2. Update planner so top-level plan items are worker-sized by default.
3. Parse `PLAN.md` into stable item records, not only raw strings.
4. Persist the current active task packet in cycle state.
5. Make worker prompts derive from the active task packet.
6. Make reviewer report status against the active packet:
   - done
   - partial
   - blocked
   - needs rewrite
7. If the same packet stalls twice, force packet rewrite before more worker attempts.

### Target files

- `meta_harness/prompts.py`
- `meta_harness/orchestrator.py`
- `meta_harness/tests/test_prompts.py`
- `meta_harness/tests/test_orchestrator.py`

### Done when

- worker always has one active packet
- reviewer always reports against that packet explicitly
- planner rewrite is packet-specific, not whole-plan vague
- active packet is visible in cycle state and UI

### Verification

- tests parse representative `PLAN.md` content into packet structure
- tests assert worker prompt includes packet fields, not only raw plan text
- tests assert stalled packet triggers rewrite after configured threshold

## Phase 4 - Deterministic Mock Harness

### Goal

Make harness failures reproducible without relying on live Codex behavior.

### Why this is critical

Without deterministic replay, every orchestration bug costs live time, live tokens, and operator patience.

### Tasks

1. Add a scripted provider/mock runtime for harness tests.
2. Support scenario scripts such as:
   - planner returns 3 items
   - worker times out twice
   - reviewer says item still open
   - harness restarts
   - next cycle resumes worker directly
3. Add scenario assertions for:
   - exact event sequence
   - exact cycle-state transitions
   - exact policy action chosen
4. Add a single `mock_harness` test entrypoint for end-to-end deterministic replay.

### Target files

- `meta_harness/llm.py`
- `meta_harness/orchestrator.py`
- `meta_harness/tests/test_orchestrator.py`
- `meta_harness/tests/` new scenario-driven test module

### Done when

- at least 5 real harness failure loops are reproducible without network or live models
- a regression in restart/stall handling can be caught by one deterministic test
- CI can run those scenarios quickly

### Verification

- mock scenarios pass in CI
- no external provider dependency for core orchestration regression tests

## Phase 5 - Token Economy And Context Compaction

### Goal

Cut wasted token spend by making retries smaller, smarter, and more stateful.

### Tasks

1. Add compact per-role summaries derived from:
   - task packet
   - recent events
   - previous attempt outcome
2. Add repeated-command suppression heuristics:
   - same focused test rerun without code/hypothesis change
   - repeated large file rereads
3. Add compaction for retry/resume prompts.
4. Add session-ledger based token budgets:
   - warn
   - tighten context
   - escalate strategy
5. Add operator-visible token/time budget per active item.

### Target files

- `meta_harness/prompts.py`
- `meta_harness/orchestrator.py`
- `meta_harness/runtime_records.py`
- `meta_harness/webui.py`

### Done when

- worker retries do not resend whole-plan context
- reviewer/planner runs reuse structured state instead of broad repo rediscovery
- UI shows per-role token totals from session ledger
- repeated no-op retry behavior is detectable and blocked

### Verification

- targeted tests for context compaction
- log-based tests for repeated-test suppression
- UI tests for token and cost summary visibility

## Phase 6 - Verification Contracts And Green Levels

### Goal

Make "done" explicit and layered, not a vague mix of partial tests and reviewer prose.

### Tasks

1. Define green levels:
   - focused-item green
   - file-scope green
   - cycle green
   - merge-safe green
2. Make reviewer and worker report at one of those levels.
3. Attach green level to task packet completion.
4. Stop claiming completion when only partial validation passed.
5. Surface green level in UI and event stream.

### Target files

- `meta_harness/orchestrator.py`
- `meta_harness/prompts.py`
- `meta_harness/webui.py`

### Done when

- reviewer output maps to explicit green levels
- cycle closure depends on the correct level, not just `remaining=0`
- UI shows current green level for active item/cycle

### Verification

- tests for each green level transition
- tests that false "done" states are rejected

## Phase 7 - Operator Control Room

### Goal

Turn the web UI into a truthful operator console instead of a pleasant status page.

### Tasks

1. Add panels for:
   - current task packet
   - current policy decision
   - current blocker/failure class
   - current green level
   - recent recovery attempts
2. Add per-role session timeline view.
3. Add searchable event stream.
4. Add "why this next action" explanation from policy output.
5. Add direct links to current cycle artifacts and logs.

### Target files

- `meta_harness/webui.py`
- `meta_harness/tests/test_webui.py`

### Done when

- an operator can answer "what is it doing and why?" without reading raw logs
- current active task packet is visible
- current blocker is visible
- current recovery step is visible

### Verification

- UI API returns all above fields
- HTML tests cover rendering of those sections

## Phase 8 - Controlled Autonomy

### Goal

Let the harness close the loop more often without making unsafe or confusing decisions.

### Tasks

1. Add conservative auto-commit policy:
   - only when task packet is complete
   - only when green level is high enough
   - only when worktree policy allows it
2. Add branch freshness checks before broad verification.
3. Add stale-session cleanup and archival policy.
4. Add explicit closeout policy per cycle:
   - continue
   - rewrite
   - commit
   - stop
   - escalate
5. Add bounded unattended continuation policy.

### Target files

- `meta_harness/orchestrator.py`
- `meta_harness/config.py`
- `meta_harness/webui.py`

### Done when

- auto-commit is opt-in and safe
- branch freshness is visible before large validation runs
- closeout action is explicit and logged as policy output

### Verification

- tests for clean-worktree and dirty-worktree commit behavior
- tests for stale-branch policy decisions

## Phase 9 - Dream Harness Layer

### Goal

Add higher-order autonomy only after the harness is already deterministic, testable, and economically sane.

### Tasks

1. Add idle-time compaction/background maintenance:
   - summarize sessions
   - prune duplicate context
   - prepare next retry packet
2. Add background self-review of harness telemetry:
   - identify top token sinks
   - identify repetitive failure recipes
   - propose configuration changes
3. Add optional wider integrations:
   - GitHub hooks
   - external notifications
   - scheduled health checks
4. Add operator policies for unattended windows:
   - allowed hours
   - allowed actions
   - escalation channels

### Target files

- `meta_harness/orchestrator.py`
- `meta_harness/runtime_records.py`
- `meta_harness/webui.py`
- optional new integration modules

### Done when

- idle/background work is bounded and observable
- the harness can improve its own future retries from telemetry
- no background process acts without explicit operator policy

### Verification

- tests for idle-time compaction triggers
- tests for bounded background actions

## Immediate Execution Order

This is the deterministic order to execute from now:

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7
9. Phase 8
10. Phase 9

Do not reorder this unless one of these becomes true:

- a later phase is required to complete an earlier phase cleanly
- a blocking production bug forces a surgical fix
- the operator explicitly reprioritizes

## Highest-Leverage Near-Term Work

If only the next few items are funded with attention, do these in order:

1. typed events and failure taxonomy
2. policy engine and recovery recipes
3. task packet and item-locked execution
4. deterministic mock harness
5. token compaction and repeated-work suppression

These five together should deliver the largest real improvement in:

- less babysitting
- fewer useless loops
- fewer wasted tokens
- clearer operator trust
- easier harness self-healing

## Success Criteria For "Harness Dream v1"

The harness reaches the first real "dream harness" checkpoint when all of these are true:

- every important transition is visible as a typed event
- every common failure path is machine-classified
- every worker run is bound to one explicit task packet
- repeated no-progress loops trigger deterministic policy changes
- orchestration bugs can be replayed in deterministic tests
- the UI shows current item, current blocker, current policy, and current recovery action
- token and cost accounting are first-class and visible
- unattended continuation is bounded, policy-driven, and explainable

## Anti-Regression Checklist

Every major harness change should answer yes to all:

- does this reduce ambiguity instead of adding it?
- does this produce structured state, not only prettier text?
- does this have a deterministic test?
- does this lower repeated token waste or at least not increase it?
- does this help the operator understand what the harness is doing?
- does this make self-healing more bounded and explicit?
