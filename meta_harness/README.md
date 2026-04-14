# Meta Harness

Small reusable autonomous-improvement harness for repository work.

## Recommended step order

1. `sweep`
   Gather fresh project evidence and generated artifacts.
2. `checker`
   Validate the current evidence only. No code changes.
3. `planner`
   Update `PLAN.md` using the checked evidence. No implementation.
4. `worker`
   Implement unfinished plan items. This is the only role that should spend most of the time changing code.
5. `reviewer`
   Audit completed work, prune finished plan items, and improve the harness itself when useful.
6. `crash-reviewer`
   Runs only when the harness crashes or fails unexpectedly.

This separation helps reduce role confusion:

- `checker` avoids premature planning drift.
- `planner` avoids mixing planning with implementation.
- `worker` stays focused on code and verification.
- `reviewer` keeps the plan honest and can improve the harness loop itself.

Harness architecture rule:

- if the harness/control loop is the blocker, simplify it
- prefer fewer moving parts over more retries, more policy, or more role-specific branching
- use complexity only when it buys a clear quality or reliability win
- if the current decompiler issue is blocked by project architecture, the harness may route work into project-architecture improvement instead of forcing a local patch
- compare candidate fixes by earliest correct layer and lowest long-term semantic debt

## Layout

- `config.py`
  Runtime and backend configuration.
- `prompts.py`
  Role prompts and step responsibilities.
- `llm.py`
  Backend adapters and local-model validation.
- `orchestrator.py`
  Main cycle orchestration, resources, artifacts, restarts.
- `cli.py`
  Main entry point used by `python -m meta_harness`.

## State Contracts

The harness persists a small set of machine-readable runtime artifacts under `.codex_automation/`.

- `cycles/*/cycle.state.json`
  Canonical cycle state with `schema_version=meta_harness.cycle_state.v1`, step statuses, current plan item, current task packet, current green level, last policy decision, and next-cycle handoff hints.
- `preflight.json`
  Preflight and resource readiness snapshot with `schema_version=meta_harness.preflight.v1`.
- `sessions.jsonl`
  One JSON row per role run with `schema_version=meta_harness.session.v1`, role/model/provider, duration, outcome, and parsed token/cost usage when available.
- `history.jsonl`
  Typed event stream with `schema_version=meta_harness.event.v1`.
- `maintenance.json`
  Bounded autonomy and maintenance summary with `schema_version=meta_harness.maintenance.v1`.

`history.jsonl` rows use these stable fields:

- `event`
  Canonical event name such as `cycle.started`, `cycle.resumed`, `branch.stale_against_main`, `role.started`, `role.finished`, `role.timed_out`, `worker.stalled`, `planner.rewrite_requested`, `sweep.started`, `sweep.finished`, `sweep.failed`, `harness.restarting`.
- `status`
  One of `running`, `ready`, `retrying`, `blocked`, `completed`, `failed`, `warning`.
- `failure_class`
  Empty for non-failures, otherwise a canonical class such as `provider_failure`, `worker_timeout`, `worker_no_progress`, `plan_item_too_broad`, `reviewer_plan_mismatch`, `sweep_failure`, `resource_blocked`, `restart_required`.
- `details`
  Structured event-specific context.

The web UI should treat these persisted files as the source of truth for runtime visibility rather than scraping raw terminal prose.

The most important cycle-state fields beyond step statuses are:

- `current_task_packet`
  Structured representation of the active numbered plan item.
- `current_task_packet_status`
  Reviewer classification for the active packet: `done`, `partial`, `blocked`, or `rewrite`.
- `current_green_level`
  Current verification level, for example `red`, `focused-item-green`, or `cycle-green`.
- `last_policy_decision`
  The latest machine decision chosen by the harness runtime policy.
- `last_closeout_action`
  The latest autonomy closeout action, for example `continue`, `rewrite`, `stop`, or `commit`.
- `git_clean_start`
  Whether the cycle started from a clean worktree.
- `branch_name` and `branch_freshness`
  Branch identity plus ahead/behind/stale state versus `main`.

`maintenance.json` summarizes bounded unattended behavior:

- aggregated session usage and cost
- recent typed event counts
- recent failure counts
- lightweight next-step recommendations for the harness

Useful autonomy controls:

- `AUTO_COMMIT_ENABLED=1`
  Allow conservative harness-managed auto-commit after a successful green cycle.
- `AUTO_COMMIT_REQUIRE_CLEAN_START=1`
  Require the cycle to begin from a clean worktree before auto-commit is allowed.
- `UNATTENDED_MAX_CYCLES=N`
  Stop intentionally after `N` open cycles so unattended runs stay bounded.
- `BACKGROUND_MAINTENANCE_ENABLED=1`
  Keep maintenance compaction and recommendation generation enabled.
- `MAINTENANCE_COMPACTION_LIMIT=N`
  Limit how many recent session/event rows are compacted into the maintenance summary.

The web UI now exposes bounded operator actions:

- `Pause`
  Creates the repo `STOP` signal so the harness stops cleanly at the next guard point.
- `Resume`
  Clears the `STOP` signal.
- `Force Planner Rewrite`
  Schedules the next cycle to route through planner for the current task packet.
- `Force Stronger Worker`
  Applies a live worker model/failure-limit override using the configured stall model policy.
- `Run Maintenance`
  Refreshes the maintenance summary and compaction data immediately.

The UI also keeps a dedicated `Operator Action History` panel sourced from typed runtime events, so manual interventions stay visible after polling refreshes.

When `AUTO_COMMIT_ENABLED=1`, the harness can now commit at two scopes:

- whole successful cycle: `meta_harness: cycle NNN complete`
- completed task packet with focused green status: `meta_harness: packet X complete`

Packet-level auto-commit is intentionally narrow:

- it requires `target_files` on the completed task packet
- it stages only those files
- it refuses to commit if tracked changes exist outside the packet scope

Scheduled maintenance controls:

- `SCHEDULED_MAINTENANCE_INTERVAL_CYCLES=N`
  Run an explicit scheduled maintenance interval every `N` open cycles during unattended operation.

## Token efficiency

The harness now tries to stay cheap by default:

- `planner` defaults to `gpt-5.4`.
- `checker`, `worker`, and `reviewer` default to `gpt-5.4-mini`.
- Prompts are compact by default instead of repeating a long role preamble.
- `codex resume` uses a short continuation prompt instead of resending the full role prompt.
- Local Python one-liners launched from the repo root inherit the repo memory guard.

The harness policy is to save tokens only when quality does not drop. In
practice that means:

- keep persistent runtime state in machine-readable artifacts under
  `.codex_automation/` instead of replaying full history
- feed models task packets, typed summaries, and exact artifact paths rather
  than raw logs or long chat transcripts
- prefer lazy loading and exact slices over broad repository scans or full-file
  dumps
- suppress repeated prompt boilerplate, repeated evidence excerpts, and repeated
  test reruns
- trim tool output to the signal before it returns to a model
- keep visible model output short and structured; do not spend tokens on
  narrative
- use stronger models only for steps that need them; use cheaper models for
  routing, checking, pruning, and summarization
- keep token-saving tricks subordinate to correctness, attribution, and
  debuggability

Concretely, for this harness:

- the role prompt is sent once in compact form, then resumes use delta prompts
- the active task packet is the main work unit; full plan/history replay is not
  the default
- checker/planner should read current evidence artifacts before doing new broad
  exploration
- worker should prefer the smallest repro and smallest proving test
- reviewer should prune done plan items instead of carrying dead text forward

The main knobs are:

- `COMPACT_PROMPTS=1`
- `DELTA_RESUME_PROMPTS=1`
- `PLANNER_MODEL`
- `CHECKER_MODEL`
- `WORKER_MODEL`
- `REVIEWER_MODEL`
- `CRASH_REVIEWER_MODEL`

## Tests

Run:

```bash
python -m pytest -q meta_harness/tests
```

## Resume

If a cycle is interrupted, the harness writes `cycle.state.json` inside the
latest cycle directory. Re-run with:

```bash
python -m meta_harness --resume
```

to continue from the first unfinished step, or `--fresh` to ignore the saved
state and start a new cycle.

The harness also respects a root-level `STOP` file. If `STOP` exists, the next
run will stop before advancing the current cycle. Remove `STOP` before running
again if you want the harness to continue.

## Repo-local sweep override

By default, the harness falls back to the curated COD evidence sweep wired in
`meta_harness/config.py`.

To retarget a repository without editing Python defaults, create a repo-local
`.codex_harness.conf`. The harness now loads that file automatically before it
builds `RuntimeConfig` and `LlmConfig`, while still letting real environment
variables win.

For this repo, the local override is used to keep the sweep focused on
`LIFE2.EXE` instead of staging COD files. Any repo-specific goals should live
in the repo-local `.codex_harness.conf`, not in the shared harness defaults or
generic harness documentation. `LIFE.EXE` remains compare-only oracle
evidence, not part of the live lane. Before running `python -m meta_harness
--fresh`, make sure no active process owns `.codex_automation/run.lock`:

For this repo's active lane, the intended prioritization is:

- fix the most silly visible `LIFE2.EXE` outputs first
- prefer empty/failed output, raw asm fallback, and obviously wrong fallback
  families over subtle cleanup
- keep architectural placement correct, but do not let subsystem purity outrank
  a clearly worse emitted result

```bash
python - <<'PY'
from meta_harness.config import RuntimeConfig
cfg = RuntimeConfig.from_env([])
print(cfg.sweep_label)
print(cfg.evidence_input_files)
print(cfg.sweep_cmd)
PY
```

If you see `curated evidence sweep` or `scripts/decompile_cod_dir.py`, then the
repo-local config was not loaded and the harness is back on the fallback lane.
If `cfg.compare_input_description` does not mention the repo's expected
compare-only oracle setup, the repo-local config was not loaded.
