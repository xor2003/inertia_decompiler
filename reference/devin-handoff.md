# Devin Batch Handoff

Only when the user authorizes delegation. These rules moved from `AGENTS.md`;
that file remains the canonical architecture and acceptance contract, and this
guide owns the detailed Devin launch and review instructions.

Standing user preference for this compiler-coverage plan: use Devin for suitable
bounded work to reduce Codex token usage, with parent review before acceptance.

Use Devin for independent, bounded tasks with disjoint file ownership; keep the
parent responsible for integration, evidence review, and acceptance. Do not hand
it the whole compiler-coverage plan or let two workers edit the same files.
Before launch, record the current baseline and write a task-specific prompt
under ignored `.cache/devin-prompts/`. Start each CLI process with
`ulimit -v 4194304` (KiB: 4 GiB), use a separate batch invocation per task,
and retain its output/session ID.

Writable staging/type-check overlays must use private regular-file copies.
Never copy or write staged replacements through symlinks or hardlinks to shared
source: that mutates production before review. Verify destination paths and
link identity before creating an overlay; retain exact pre-run source hashes.

Do not stash, reset, or check out shared source to obtain a baseline. Compare
the saved pre-run sources in an isolated process; clean HEAD is not the dirty
pre-run baseline. If a failure cannot be classified within one bounded baseline
attempt, report it as unresolved and hand it back instead of expanding the task.

In this workspace, after verifying the outer sandbox described below, the
current CLI pattern is:

```sh
devin_repo=/home/xor/vextest
ulimit -v 4194304
rtk proxy "$devin_repo/.venv/bin/python" \
  "$devin_repo/tools/dev/workspace_sandbox.py" -- \
  env PATH="$devin_repo/.venv/bin:$PATH" \
  XDG_CONFIG_HOME="$devin_repo/.cache/devin-config" \
  XDG_DATA_HOME="$devin_repo/.cache/devin-data" \
  XDG_STATE_HOME="$devin_repo/.cache/devin-state" \
  XDG_CACHE_HOME="$devin_repo/.cache/devin-cache" \
  TMPDIR="$devin_repo/.cache" \
  devin --config /home/xor/.config/devin/config.json --model swe-2-high \
  --permission-mode dangerous --respect-workspace-trust false \
  --prompt-file "$devin_repo/.cache/devin-prompts/TASK.md" -p
```

In a restricted Codex workspace where Devin's default user-state directory is
not writable, point `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`XDG_CACHE_HOME`, and `TMPDIR` at ignored directories under this repository's
`.cache/`. Preserve the authenticated data root when resuming; a fresh data
root is not automatically logged in. Keep CLI
credentials private (mode 0600); never paste them into prompts or commit them.
Use `--permission-mode dangerous --respect-workspace-trust false` for unattended
batch runs **only after verifying an outer filesystem sandbox limits writes to
this working directory**. Without that boundary, use restricted permissions;
do not treat the flag as authorization for host-wide access.

The explicit Bubblewrap boundary above is verified locally: host mounts are
read-only, this repository's bind mount is writable, and the child inherits
the 4 GiB address-space limit. Private `/proc` and `/dev` permit normal process
and device setup without exposing writable host directories. Omitting
`--dev /dev` makes this CLI's ACP child fail when opening `/dev/null`.
For a job that executes DOS tools or recompilation validation, add
`--with-kvm` before the launcher's `--`. The launcher opens the host device in
Python, verifies both path and opened descriptor are character10:232/API12,
and retains FD33 across the private `/dev` setup. The corresponding scoped
`--dev-bind /proc/self/fd/33 /dev/kvm` was independently checked with child
API12, rootRO/repoRW and4GiB. Direct pathname and shell-FD attempts did not
preserve that device in this restricted environment; do not substitute them
without the exact identity/API check. Missing KVM fails loudly: do not expose
other host devices or remove the read-only-host boundary. A run without the
required device is environment-limited, not comparable decompiler acceptance.
Static-only staging tasks use the default launcher, which exposes no host KVM.
If Bubblewrap is unavailable, do not silently remove the boundary. Session-lock
PIDs inside a PID namespace are not host PIDs: identify the owned process tree
and check `NSpid` before using a lock for liveness or sending a signal.

Copy and fill this handoff prompt for each job:

```text
You are one worker in /home/xor/vextest; other agents are editing concurrently.
Read AGENTS.md and its required startup references. Preserve all existing edits.
Goal slice: <one concrete acceptance obligation and current baseline>.
Ownership: edit only <exact files>; do not edit other files, docs, or artifacts.
Evidence: <graph project/generation/tier, checked paths and coverage caveats,
          exact source or binary facts already established, unresolved question>.
Implementation: fix the earliest correct layer; use typed evidence and fail
closed. No COD/source/name/rendered-C semantic proof or sample-specific hacks.
Validation: show a focused red regression, the green result, and scoped lint/type
checks. Do not run broad gates, round trips, commit, or publish a claim of
validation=passed; the parent coordinates those checks after review.
Handoff: report changed files, invariant, test commands/results, evidence counts,
and remaining refusals or blockers. Do not revert anyone else's work.
```

After Devin exits, the parent must review its report and compare every owned
file against the recorded pre-run baseline. Identify Devin's exact delta in the
shared dirty tree; reject unrelated edits, unsupported proof claims, semantic
repairs in rewrite, and any weakened validation or refusal gate. Independently
read the changed code and tests, reproduce the focused red/green result, and
check the binary-derived evidence and failure counts. Then rerun relevant
focused checks on the final shared tree and project gates at the semantic
checkpoint. If Devin made no patch, verify its diagnostic claims before using
them. A Devin answer or passing unit test alone is not decompiler acceptance;
only the parent may claim a function fixed after the required tail validation,
call-semantics check, output-shape comparison, and applicable round trip.
