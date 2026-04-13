from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass


TASK_PACKET_SCHEMA_VERSION = "meta_harness.task_packet.v1"
PLAN_PRUNE_FINISHED_STATUSES = frozenset({"done", "completed", "superseded"})
_TASK_PACKET_MAX_TARGET_FILES = 4
_TASK_PACKET_MAX_TARGET_REFS = 3
_TASK_PACKET_MAX_ACCEPTANCE_TESTS = 2
_TASK_PACKET_MAX_DONE_CONDITIONS = 2
_TASK_PACKET_MAX_RETRY_NOTES = 2


@dataclass(frozen=True)
class TaskPacket:
    schema_version: str
    item_id: str
    objective: str
    raw_text: str
    target_files: tuple[str, ...]
    target_refs: tuple[str, ...]
    acceptance_tests: tuple[str, ...]
    done_conditions: tuple[str, ...]
    retry_notes: tuple[str, ...]
    escalation_policy: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "item_id": self.item_id,
            "objective": self.objective,
            "raw_text": self.raw_text,
            "target_files": list(self.target_files),
            "target_refs": list(self.target_refs),
            "acceptance_tests": list(self.acceptance_tests),
            "done_conditions": list(self.done_conditions),
            "retry_notes": list(self.retry_notes),
            "escalation_policy": self.escalation_policy,
        }

    def to_prompt_block(self) -> str:
        parts = [f"Task packet id: {self.item_id}", f"Objective: {_compact_objective(self.objective)}"]
        if self.target_files:
            parts.append("Target files: " + _format_limited(self.target_files, _TASK_PACKET_MAX_TARGET_FILES))
        callable_refs = tuple(ref for ref in self.target_refs if ref.endswith("()"))
        if callable_refs:
            parts.append("Callable refs: " + _format_limited(callable_refs, _TASK_PACKET_MAX_TARGET_REFS))
        if self.acceptance_tests:
            parts.append(
                "Acceptance tests: " + _format_limited(self.acceptance_tests, _TASK_PACKET_MAX_ACCEPTANCE_TESTS, sep=" | ")
            )
        if self.done_conditions:
            parts.append(
                "Done when: " + _format_limited(self.done_conditions, _TASK_PACKET_MAX_DONE_CONDITIONS, sep=" | ")
            )
        if self.retry_notes:
            parts.append("Retry notes: " + _format_limited(self.retry_notes, _TASK_PACKET_MAX_RETRY_NOTES, sep=" | "))
        return "\n".join(parts)


@dataclass(frozen=True)
class PlanPruneResult:
    original_item_count: int
    kept_item_count: int
    removed_item_count: int
    changed: bool
    updated_text: str


def _split_plan_items(plan_text: str) -> list[str]:
    lines = plan_text.splitlines()
    items: list[str] = []
    current: list[str] = []
    for raw_line in lines:
        if re.match(r"^\d+\.\s+\S", raw_line):
            if current:
                items.append("\n".join(current).strip())
                current = []
            current.append(raw_line.rstrip())
            continue
        if current and raw_line.strip():
            current.append(raw_line.rstrip())
    if current:
        items.append("\n".join(current).strip())
    return [item for item in items if item]


def split_plan_items(plan_text: str) -> list[str]:
    return _split_plan_items(plan_text)


def _split_plan_prefix_and_items(plan_text: str) -> tuple[list[str], list[str]]:
    prefix_lines: list[str] = []
    items: list[str] = []
    current: list[str] = []
    seen_item = False
    for raw_line in plan_text.splitlines():
        if re.match(r"^\d+\.\s+\S", raw_line):
            if current:
                items.append("\n".join(current).rstrip())
            current = [raw_line.rstrip()]
            seen_item = True
            continue
        if seen_item:
            current.append(raw_line.rstrip())
        else:
            prefix_lines.append(raw_line.rstrip())
    if current:
        items.append("\n".join(current).rstrip())
    return prefix_lines, [item for item in items if item]


def _target_refs(item_text: str) -> tuple[str, ...]:
    refs: list[str] = []
    for ref in re.findall(r"`([^`]+)`", item_text):
        cleaned = ref.strip()
        if not cleaned or cleaned in refs:
            continue
        if cleaned.startswith("pytest "):
            continue
        if _is_path_like_ref(cleaned) or cleaned.endswith("()"):
            refs.append(cleaned)
    return tuple(refs)


def _target_files(refs: tuple[str, ...]) -> tuple[str, ...]:
    files: list[str] = []
    for ref in refs:
        path = ref.split(":", 1)[0]
        if "/" in path or path.endswith(".py") or path.endswith(".md") or path.endswith(".sh"):
            if path not in files:
                files.append(path)
    return tuple(files)


def _acceptance_tests(item_text: str) -> tuple[str, ...]:
    commands = re.findall(r"(pytest [^`,\n]+)", item_text)
    ordered: list[str] = []
    for cmd in commands:
        cleaned = cmd.strip()
        if cleaned not in ordered:
            ordered.append(cleaned)
    return tuple(ordered)


def _done_conditions(item_text: str) -> tuple[str, ...]:
    match = re.search(r"Done when\s+(.*)", item_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ()
    text = match.group(1).strip()
    parts = [part.strip(" .") for part in re.split(r"\band\b|;", text) if part.strip()]
    return tuple(parts)


def _plan_item_status(item_text: str) -> str:
    first_line = item_text.splitlines()[0].strip() if item_text.strip() else ""
    match = re.match(r"^\d+\.\s+(.*)$", first_line)
    if not match:
        return ""
    rest = match.group(1).strip()
    bracket = re.match(r"^\[([^\]]+)\]", rest)
    if bracket:
        return bracket.group(1).strip().lower()
    colon = re.match(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*", rest)
    if colon:
        status = colon.group(1).strip().lower()
        if status in PLAN_PRUNE_FINISHED_STATUSES:
            return status
    return ""


def _plan_item_is_finished(item_text: str) -> bool:
    return _plan_item_status(item_text) in PLAN_PRUNE_FINISHED_STATUSES


def plan_item_is_finished(item_text: str) -> bool:
    return _plan_item_is_finished(item_text)


def _retry_notes(item_text: str) -> tuple[str, ...]:
    notes: list[str] = []
    if "contains no " in item_text:
        for clause in re.findall(r"contains no ([^,.;]+)", item_text):
            notes.append("avoid: " + clause.strip())
    return tuple(notes[:4])


def _is_path_like_ref(ref: str) -> bool:
    if "/" in ref:
        return True
    path_head = ref.split(":", 1)[0]
    return path_head.endswith((".py", ".md", ".sh", ".json", ".txt"))


def _compact_objective(text: str) -> str:
    compact = re.sub(r"^\[[^\]]+\]\s*", "", text.strip())
    compact = re.sub(r"^(Goal|Done|Completed)\s*:\s*", "", compact, flags=re.IGNORECASE)
    compact = re.sub(r"`[^`]+`", "", compact)
    compact = re.sub(r"\s+", " ", compact).strip(" ,.")
    return compact


def _format_limited(values: tuple[str, ...], limit: int, *, sep: str = ", ") -> str:
    if len(values) <= limit:
        return sep.join(values)
    shown = sep.join(values[:limit])
    hidden = len(values) - limit
    suffix = f"{sep}(+{hidden} more)"
    return shown + suffix


def parse_task_packet(item_text: str) -> TaskPacket:
    first_line = item_text.splitlines()[0].strip() if item_text.strip() else ""
    match = re.match(r"^(\d+)\.\s+(.*)$", first_line)
    item_id = match.group(1) if match else ""
    objective = match.group(2).strip() if match else first_line
    refs = _target_refs(item_text)
    return TaskPacket(
        schema_version=TASK_PACKET_SCHEMA_VERSION,
        item_id=item_id,
        objective=objective,
        raw_text=item_text.strip(),
        target_files=_target_files(refs),
        target_refs=refs,
        acceptance_tests=_acceptance_tests(item_text),
        done_conditions=_done_conditions(item_text),
        retry_notes=_retry_notes(item_text),
        escalation_policy="rewrite current item after repeated stall; otherwise continue focused worker retries",
    )


def parse_plan_task_packets(plan_text: str) -> list[TaskPacket]:
    return [parse_task_packet(item) for item in _split_plan_items(plan_text)]


def unfinished_plan_items_from_text(plan_text: str) -> list[str]:
    return [item for item in _split_plan_items(plan_text) if not _plan_item_is_finished(item)]


def count_remaining_plan_steps(plan_text: str) -> int | None:
    for pat in (r"Global Remaining steps:\s*(\d+)", r"Remaining steps:\s*(\d+)"):
        match = re.search(pat, plan_text)
        if match:
            return int(match.group(1))

    capture = False
    unchecked = 0
    for raw_line in plan_text.splitlines():
        line = raw_line.strip()
        if re.match(r"^##+\s+Remaining steps\b", line, re.IGNORECASE):
            capture = True
            continue
        if capture and re.match(r"^##+\s+", line):
            break
        if capture and re.match(r"^[-*]\s+\[\s\]\s+\S", line):
            unchecked += 1

    numbered = len(unfinished_plan_items_from_text(plan_text))
    if numbered or unchecked:
        return numbered + unchecked
    return None


def prune_completed_plan_text(plan_text: str) -> PlanPruneResult:
    prefix_lines, items = _split_plan_prefix_and_items(plan_text)
    kept_items = [item for item in items if not _plan_item_is_finished(item)]
    chunks: list[str] = []
    prefix_text = "\n".join(prefix_lines).rstrip()
    if prefix_text:
        chunks.append(prefix_text)
    chunks.extend(kept_items)
    updated_text = "\n\n".join(chunk for chunk in chunks if chunk).rstrip()
    if updated_text:
        updated_text += "\n"
    return PlanPruneResult(
        original_item_count=len(items),
        kept_item_count=len(kept_items),
        removed_item_count=len(items) - len(kept_items),
        changed=updated_text != plan_text,
        updated_text=updated_text,
    )


def prune_completed_plan_file(plan_path: Path) -> PlanPruneResult:
    if not plan_path.exists():
        return PlanPruneResult(0, 0, 0, False, "")
    original_text = plan_path.read_text(encoding="utf-8", errors="replace")
    result = prune_completed_plan_text(original_text)
    if result.changed:
        plan_path.write_text(result.updated_text, encoding="utf-8")
    return result
