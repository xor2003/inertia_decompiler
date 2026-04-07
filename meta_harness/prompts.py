from __future__ import annotations

from .config import RuntimeConfig


def _style_contract() -> str:
    return (
        "Response style:\n"
        "- Minimal and actionable.\n"
        "- No repetition.\n"
        "- No explanations unless needed for the role.\n"
        "- Prefer concrete results over narration.\n\n"
    )


def _token_discipline() -> str:
    return (
        "Token discipline:\n"
        "- Do not narrate progress before using tools unless a brief note is essential.\n"
        "- Read only the smallest relevant file slices; avoid dumping full files when a targeted window or `rg` hit is enough.\n"
        "- Prefer focused searches (`rg`, exact symbols, exact test names) over broad repository scans.\n"
        "- Do not rerun the same test or command without a concrete code or hypothesis change.\n"
        "- When a command already proved a point, reuse that result instead of re-reading the same evidence.\n\n"
    )


def _repo_standing_tasks(cfg: RuntimeConfig) -> str:
    tasks = [task.strip() for task in getattr(cfg, "repo_standing_tasks", ()) if isinstance(task, str) and task.strip()]
    if not tasks:
        return ""
    return "Repo standing tasks:\n" + "".join(f"- {task}\n" for task in tasks) + "\n"


def build_master_prompt(cfg: RuntimeConfig) -> str:
    if cfg.compact_prompts:
        return (
            f"Work in {cfg.root_dir}. Repo rules: {cfg.rules_file}.\n"
            f"Maintain {cfg.plan_path}. Use {cfg.evidence_log_file} as current evidence.\n\n"
            f"Priorities: 1) {cfg.primary_priority}; 2) {cfg.secondary_priority}; "
            f"3) {cfg.general_improvement_rule}; 4) {cfg.architecture_guidance}.\n"
            f"Compare against: {cfg.compare_input_description}.\n"
            "Always state current quality for correctness and recompilation.\n"
            "Use concrete repository evidence, not vague claims.\n\n"
            + _repo_standing_tasks(cfg)
            + _style_contract()
            + _token_discipline()
        )
    return (
        f"You are working on {cfg.root_dir}, a {cfg.project_description}.\n\n"
        f"Always use the repository rules from {cfg.rules_file}.\n\n"
        "Role model:\n"
        "- Checker validates current evidence only.\n"
        "- Planner updates the plan only.\n"
        "- Worker implements one or more unfinished plan steps.\n"
        "- Reviewer audits completion and may improve the harness itself.\n"
        "- Crash-reviewer diagnoses harness failures and may request a restart.\n\n"
        "Main operating goals:\n"
        f"1. Run and use {cfg.evidence_kind} as evidence.\n"
        f"2. Generate and maintain {cfg.plan_path}.\n"
        f"3. {cfg.primary_priority}\n"
        f"4. {cfg.secondary_priority}\n"
        f"5. {cfg.general_improvement_rule}\n"
        f"6. {cfg.architecture_guidance}\n\n"
        "When evaluating progress, compare:\n"
        f"- {cfg.compare_input_description}\n\n"
        "Always report current quality for:\n"
        "- correctness\n"
        "- recompilation\n\n"
        "Use concrete evidence from the project, not vague claims.\n\n"
        + _repo_standing_tasks(cfg)
        + _style_contract()
        + _token_discipline()
    )


def build_checker_prompt(cfg: RuntimeConfig) -> str:
    return build_master_prompt(cfg) + (
        "\nChecker step:\n"
        f"- Inspect {cfg.evidence_log_file} for crashes, timeouts, or obvious regressions.\n"
        "- Prefer the existing evidence, current plan, and current logs over fresh exploration.\n"
        "- Do not run pytest, corpus scans, or broad repository searches in this step unless the current evidence is missing a fact you cannot otherwise obtain.\n"
        "- Print current quality for correctness and recompilation.\n"
        "- Do not update the plan or implement code changes in this step.\n"
        "- At the end, print exactly: Global Remaining steps: N\n"
    )


def build_planner_prompt(
    cfg: RuntimeConfig,
    *,
    current_item: str = "",
    rewrite_target: str = "",
    task_packet: str = "",
) -> str:
    prompt = build_master_prompt(cfg) + (
        "\nPlanner step:\n"
        "- Analyze the current difference between relevant inputs and generated outputs.\n"
        "- Inspect the current code state.\n"
        f"- Do not rerun the evidence sweep; the sweep step already produced {cfg.evidence_log_file} and the checker step reviewed it for this cycle.\n"
        f"- Read the current evidence and debug logs first, especially {cfg.evidence_log_file}, recent stderr/debug output, and any tail-validation summary or detail-artifact paths already recorded by the sweep.\n"
        "- When tail validation is in scope, identify the concrete failing family from the logs before writing plan items; do not plan from verdict headlines alone.\n"
        "- Use the logs to determine where the problem lives: validator noise, structuring, postprocess, fallback path, or cache/policy behavior.\n"
        "- Cite the specific log file, artifact path, function name, or warning/error family that motivated each new plan item.\n"
        "- Do not claim a root cause unless the current logs or artifacts support it; otherwise plan the missing debug signal first.\n"
        f"- Create or update {cfg.plan_path} as a flat numbered checklist.\n"
        "- The plan is an execution specification, not a roadmap, status memo, or theme list.\n"
        "- Each top-level numbered item must be small enough for one focused worker cycle, not a whole theme.\n"
        "- Each item must include exact implementation steps, not just a goal statement.\n"
        "- Each item must name the target file(s) and exact source line numbers when available.\n"
        "- Each item must say what to edit in those files in execution order.\n"
        "- Each item must specify the concrete functions, tests, or scripts to change.\n"
        "- Each item must contain these explicit fields in this order: Goal, Why now, Edit targets, Required edits, Required tests, Verification commands, Definition of done, Stop conditions.\n"
        "- Required edits must be imperative and executable, not descriptive.\n"
        "- Verification commands must be concrete shell commands, not generic advice.\n"
        "- Each item must include a deterministic definition of done.\n"
        "- Keep items deterministic, short, and directly actionable.\n"
        "- Do not emit vague planner language such as investigate, improve, refine, polish, or optimize unless the same item also names the exact files, functions, tests, and concrete edit sequence.\n"
        "- Do not emit phase headers, aspirational themes, or research bullets without executable targets.\n"
        "- If you cannot fill the required fields for an item, inspect the code and existing tests until you can.\n"
        "- If a current item still contains multiple independent fixes, split it into smaller numbered items before sending it back to worker.\n"
        "- The plan must prioritize correctness first and recompilation second.\n"
        "- Preserve unfinished strategic items already present in the plan unless they are now done or clearly superseded by a more precise item.\n"
        "- Do not drop user-added unfinished goals just because the current cycle focuses on a different bug.\n"
        "- Remove any done items from the plan and leave only unfinished work.\n"
        "- Avoid spending tokens on implementation, long code excerpts, or repeated repo tours in this step.\n"
        "- Do not run pytest, corpus scans, or large validation commands in this step; use the existing evidence and repository state.\n"
        "- If the existing logs do not explain the current tail-validation failure family well enough, say that explicitly and create a plan item to improve or collect the missing debug signal.\n"
        "- Print current quality of correctness and recompilation.\n"
        "- Print exactly one line at the end as: Green level: red\n"
        "- If there is nothing meaningful left to do, say that clearly.\n"
        "- At the end, print exactly: Global Remaining steps: N\n"
    )
    if current_item.strip():
        prompt += (
            "\nCurrent plan item in progress:\n"
            "- Keep this item first unless it is done or needs to be split.\n"
            f"{current_item.strip()}\n"
        )
    if rewrite_target.strip():
        prompt += (
            "\nPlanner rewrite request:\n"
            "- Rewrite this item into smaller numbered items that are easier for worker to finish one by one.\n"
            f"{rewrite_target.strip()}\n"
        )
    if task_packet.strip():
        prompt += (
            "\nCurrent task packet:\n"
            "- Keep the updated plan aligned with this packet unless it is now done or needs rewrite.\n"
            f"{task_packet.strip()}\n"
        )
    return prompt


def build_worker_prompt(
    cfg: RuntimeConfig,
    *,
    focus_item: str = "",
    retry_context: str = "",
    task_packet: str = "",
) -> str:
    prompt = build_master_prompt(cfg) + (
        "\nWorker step:\n"
        f"- Use the most recent {cfg.evidence_log_file} and the checker review as current evidence for correctness, recompilation quality, crashes, and smoothness.\n"
        f"- Continue implementing the unfinished steps from {cfg.plan_path}.\n"
        "- Work on exactly one unfinished top-level plan item at a time.\n"
        "- Start with the first unfinished numbered plan item unless a narrower current focus item is provided below.\n"
        "- Do not move to a later top-level plan item until the current item is done or you can name the concrete blocker.\n"
        "- Work like an ongoing continuation: make real code changes, update tests, verify results, and commit often.\n"
        "- Never use source-specific hacks.\n"
        "- If the harness itself can be improved safely while you work, you may improve it too.\n"
        "- Prefer one tight edit/verify loop over many exploratory reads.\n"
        "- Run the smallest test that proves the touched behavior before considering broader validation.\n"
        "- If a focused test already failed, change code or the hypothesis before rerunning that same test.\n"
        "- Avoid repeating `git status`, large `sed`/`cat` dumps, or the same targeted test unless new changes justify it.\n"
        "- Print exactly one line at the end as: Green level: focused-item-green|cycle-green|merge-safe-green|red\n"
        "- At the end of each step, print exactly: Global Remaining steps: N\n"
    )
    if focus_item.strip():
        prompt += (
            "\nCurrent focus item:\n"
            "- Treat this as the primary task for this worker step.\n"
            f"{focus_item.strip()}\n"
        )
    if retry_context.strip():
        prompt += (
            "\nRecent worker retry context:\n"
            "- Use this to avoid repeating the same failed loop.\n"
            f"{retry_context.strip()}\n"
        )
    if task_packet.strip():
        prompt += (
            "\nActive task packet:\n"
            "- Stay inside this packet's scope until done or concretely blocked.\n"
            f"{task_packet.strip()}\n"
        )
    return prompt


def build_reviewer_prompt(cfg: RuntimeConfig, *, stall_context: str = "", task_packet: str = "") -> str:
    prompt = build_master_prompt(cfg) + (
        "\nReviewer step:\n"
        "- In a fresh session, review the current code state and current plan.\n"
        "- Check what is genuinely finished and what is not.\n"
        f"- Remove completed steps from {cfg.plan_path}.\n"
        "- Evaluate the current active task packet explicitly as done, partial, blocked, or needing rewrite.\n"
        "- You may also improve the harness itself if that reduces future failures or manual babysitting.\n"
        "- Do not run worker cycles in this step.\n"
        "- Avoid pytest, sweep reruns, or broad repository exploration unless a missing fact blocks the review.\n"
        "- Print achieved results.\n"
        "- Print exactly one line at the end as: Task packet status: done|partial|blocked|rewrite\n"
        "- Print exactly one line at the end as: Green level: focused-item-green|cycle-green|merge-safe-green|red\n"
        "- Print the true remaining step count at the end as: Global Remaining steps: N\n"
    )
    if stall_context.strip():
        prompt += (
            "\nWorker stall diagnosis for this cycle:\n"
            "- Review the recent worker timeout/failure logs listed below before deciding what remains.\n"
            "- If the worker loop is stuck, prefer tightening the plan, improving harness retry/model strategy, or both.\n"
            "- Keep the next cycle open only when there is a concrete better next step.\n"
            f"{stall_context.strip()}\n"
        )
    if task_packet.strip():
        prompt += (
            "\nActive task packet:\n"
            "- Base the review on this packet before broader plan speculation.\n"
            f"{task_packet.strip()}\n"
        )
    return prompt


def build_crash_reviewer_prompt(cfg: RuntimeConfig, current_cycle_dir: str, exit_code: int) -> str:
    return build_master_prompt(cfg) + (
        "\nCrash-review step:\n"
        f"- The harness itself exited with status {exit_code}.\n"
        "- Inspect these artifacts first:\n"
        f"  - {cfg.status_file}\n"
        f"  - {cfg.last_log_file}\n"
        f"  - {cfg.evidence_log_file}\n"
        f"  - {current_cycle_dir}\n"
        f"- You may update {cfg.run_sh_path}, {cfg.plan_path}, or other harness files if that improves stability or self-maintenance.\n"
        "- Prefer improving the harness itself over changing reviewer/worker goals.\n"
        "- Print a short crash diagnosis and concrete harness fix summary.\n"
        "- If the harness was changed and should restart with the new code, print exactly: Harness restart required\n"
    )


def build_resume_prompt(role: str, cfg: RuntimeConfig, *, comments: str = "", role_context: str = "") -> str:
    role_instructions = {
        "worker": (
            f"Continue the existing {role} session.\n"
            f"Implement the next unfinished item(s) from {cfg.plan_path}.\n"
            "Use the existing session context instead of re-deriving the whole plan.\n"
            "Keep output minimal and actionable.\n"
            "Avoid re-reading evidence already established in the session unless the code changed.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
        "planner": (
            f"Continue the existing {role} session.\n"
            f"Update only {cfg.plan_path}.\n"
            "Keep unfinished strategic items unless done or superseded.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
        "reviewer": (
            f"Continue the existing {role} session.\n"
            "Re-check the current code state and remaining plan items.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
        "checker": (
            f"Continue the existing {role} session.\n"
            f"Validate {cfg.evidence_log_file} only.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
    }
    prompt = role_instructions.get(
        role,
        f"Continue the existing {role} session.\nKeep output minimal and actionable.\n",
    )
    if comments.strip():
        prompt += "\nOperator comments to apply now:\n" + comments.strip() + "\n"
    if role_context.strip():
        prompt += "\nCurrent context:\n" + role_context.strip() + "\n"
    return prompt
