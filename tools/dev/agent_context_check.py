#!/usr/bin/env python3
"""Report agent discovery context and approved fallback guidance.

Layer: Tooling/gates.
Responsibility: report agent discovery context and approved fallback guidance.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
PROJECT_MAP: Path = REPO_ROOT / "reference" / "project-map.md"
UNDERSTAND_CONFIG: Path = REPO_ROOT / ".understand-anything" / "config.json"
GRAPH_STATUS_ENV: str = "CODEBASE_MEMORY_MCP_STATUS"


class GraphStatus(StrEnum):
    """Shell-visible codebase-memory graph status."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AgentContextReport:
    """Result of checking startup context for agents."""

    graph_status: GraphStatus
    understand_auto_update: bool | None
    fallback_flow: str
    errors: tuple[str, ...] = ()


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def _read_understand_auto_update(path: Path, repo_root: Path) -> tuple[bool | None, tuple[str, ...]]:
    if not path.exists():
        return None, (f"missing Understand-Anything config: {_display_path(path, repo_root)}",)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, (f"invalid Understand-Anything config JSON: {exc}",)
    auto_update = data.get("autoUpdate")
    if auto_update is not False:
        return bool(auto_update), ("Understand-Anything autoUpdate must stay disabled",)
    return False, ()


def _extract_fallback_flow(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    marker = "## Fallback Discovery Flow"
    start = text.find(marker)
    if start < 0:
        raise ValueError("reference/project-map.md is missing '## Fallback Discovery Flow'")
    next_heading = text.find("\n## ", start + len(marker))
    section = text[start: next_heading if next_heading >= 0 else len(text)]
    return section.strip()


def _graph_status_from_env(environ: dict[str, str]) -> GraphStatus:
    raw = environ.get(GRAPH_STATUS_ENV, "").strip().lower()
    if raw in {"1", "true", "yes", "available"}:
        return GraphStatus.AVAILABLE
    if raw in {"0", "false", "no", "unavailable", "closed", "error"}:
        return GraphStatus.UNAVAILABLE
    return GraphStatus.UNKNOWN


def build_report(
    *,
    repo_root: Path | None = None,
    environ: dict[str, str] | None = None,
) -> AgentContextReport:
    """Build the shell-visible agent context report."""
    root = REPO_ROOT if repo_root is None else repo_root
    env = os.environ if environ is None else environ
    project_map = root / "reference" / "project-map.md"
    understand_config = root / ".understand-anything" / "config.json"

    errors: list[str] = []
    auto_update, config_errors = _read_understand_auto_update(understand_config, root)
    errors.extend(config_errors)
    try:
        fallback_flow = _extract_fallback_flow(project_map)
    except (OSError, ValueError) as exc:
        fallback_flow = ""
        errors.append(str(exc))

    return AgentContextReport(
        graph_status=_graph_status_from_env(dict(env)),
        understand_auto_update=auto_update,
        fallback_flow=fallback_flow,
        errors=tuple(errors),
    )


def format_report(report: AgentContextReport) -> str:
    """Format the report for Makefile and agent startup use."""
    lines = [
        f"codebase-memory MCP graph: {report.graph_status.value}",
        f"Understand-Anything autoUpdate: {report.understand_auto_update}",
    ]
    if report.errors:
        lines.append("context errors:")
        lines.extend(f"- {error}" for error in report.errors)
    if report.graph_status is not GraphStatus.AVAILABLE and report.fallback_flow:
        lines.append("")
        lines.append("approved fallback discovery flow:")
        lines.append(report.fallback_flow)
        lines.append("")
        lines.append(
            f"Set {GRAPH_STATUS_ENV}=available only after a codebase-memory MCP call "
            "such as list_projects/search_graph succeeds in this agent session."
        )
    return "\n".join(lines)


def format_compact_report(report: AgentContextReport) -> str:
    """Format one successful context-check summary line."""
    return (
        f"agent context check passed: graph={report.graph_status.value}, "
        f"Understand-Anything autoUpdate={report.understand_auto_update}"
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check agent discovery context.")
    parser.add_argument(
        "--require-graph",
        action="store_true",
        help="fail if codebase-memory MCP graph availability is not confirmed",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="print one summary line on success while retaining full failure details",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the agent context check and return a process exit code."""

    args = _parse_args(argv)
    report = build_report()
    if report.errors:
        print(format_report(report))
        return 2
    if args.require_graph and report.graph_status is not GraphStatus.AVAILABLE:
        print(format_report(report))
        return 1
    print(format_compact_report(report) if args.compact else format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
