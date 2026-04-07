from __future__ import annotations

import re
from dataclasses import dataclass


TASK_PACKET_SCHEMA_VERSION = "meta_harness.task_packet.v1"


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
        parts = [
            f"Task packet id: {self.item_id}",
            f"Objective: {self.objective}",
        ]
        if self.target_refs:
            parts.append("Target refs: " + ", ".join(self.target_refs))
        if self.acceptance_tests:
            parts.append("Acceptance tests: " + " | ".join(self.acceptance_tests))
        if self.done_conditions:
            parts.append("Done when: " + " | ".join(self.done_conditions))
        if self.retry_notes:
            parts.append("Retry notes: " + " | ".join(self.retry_notes))
        parts.append("Escalation policy: " + self.escalation_policy)
        return "\n".join(parts)


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


def _target_refs(item_text: str) -> tuple[str, ...]:
    refs = tuple(re.findall(r"`([^`]+)`", item_text))
    return refs


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


def _retry_notes(item_text: str) -> tuple[str, ...]:
    notes: list[str] = []
    if "contains no " in item_text:
        for clause in re.findall(r"contains no ([^,.;]+)", item_text):
            notes.append("avoid: " + clause.strip())
    return tuple(notes[:4])


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
