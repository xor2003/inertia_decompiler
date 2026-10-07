from __future__ import annotations

from pathlib import Path

from tools.dev import agent_context_check


def _write_context_files(tmp_path: Path, *, auto_update: bool = False) -> None:
    reference = tmp_path / "reference"
    reference.mkdir()
    (reference / "project-map.md").write_text(
        "\n".join(
            (
                "# Project Map",
                "",
                "## Fallback Discovery Flow",
                "",
                "Use this flow when `codebase-memory-mcp` is unavailable:",
                "",
                "1. Read `AGENTS.md`, then `reference/project-map.md`.",
                "2. Use `rg` only after the map identifies the likely owner.",
                "3. Run `make check-files PYTHON=./.venv/bin/python FILES=\"...\"` so focused linters, the changed-file module/doc/type/dot-access ratchet, architecture/context guards, ownership-manifest validation, and owned tests run together.",
                "",
                "## Checks",
                "",
                "- `make agent-context-check PYTHON=./.venv/bin/python`",
            )
        ),
        encoding="utf-8",
    )
    config = tmp_path / ".understand-anything" / "config.json"
    config.parent.mkdir()
    config.write_text(f'{{"autoUpdate": {str(auto_update).lower()}}}\n', encoding="utf-8")


def test_agent_context_report_prints_fallback_when_graph_unknown(tmp_path):
    _write_context_files(tmp_path)

    report = agent_context_check.build_report(repo_root=tmp_path, environ={})
    output = agent_context_check.format_report(report)

    assert report.graph_status is agent_context_check.GraphStatus.UNKNOWN
    assert "approved fallback discovery flow:" in output
    assert "Read `AGENTS.md`, then `reference/project-map.md`" in output
    assert "changed-file module/doc/type/dot-access ratchet" in output
    assert "architecture/context guards, ownership-manifest validation" in output
    assert "make agent-context-check" not in report.fallback_flow


def test_agent_context_report_suppresses_fallback_when_graph_available(tmp_path):
    _write_context_files(tmp_path)

    report = agent_context_check.build_report(
        repo_root=tmp_path,
        environ={agent_context_check.GRAPH_STATUS_ENV: "available"},
    )
    output = agent_context_check.format_report(report)

    assert report.graph_status is agent_context_check.GraphStatus.AVAILABLE
    assert "approved fallback discovery flow:" not in output


def test_agent_context_report_rejects_understand_auto_update(tmp_path):
    _write_context_files(tmp_path, auto_update=True)

    report = agent_context_check.build_report(repo_root=tmp_path, environ={})

    assert "Understand-Anything autoUpdate must stay disabled" in report.errors


def test_agent_context_main_requires_graph(monkeypatch, tmp_path, capsys):
    _write_context_files(tmp_path)
    monkeypatch.setattr(agent_context_check, "REPO_ROOT", tmp_path)
    monkeypatch.delenv("CODEBASE_MEMORY_MCP_STATUS", raising=False)

    rc = agent_context_check.main(["--require-graph"])
    output = capsys.readouterr().out

    assert rc == 1
    assert "codebase-memory MCP graph: unknown" in output


def test_agent_context_main_compacts_only_success(monkeypatch, tmp_path, capsys):
    _write_context_files(tmp_path)
    monkeypatch.setattr(agent_context_check, "REPO_ROOT", tmp_path)

    rc = agent_context_check.main(["--compact"])
    output = capsys.readouterr().out

    assert rc == 0
    assert output.startswith("agent context check passed:")
    assert "approved fallback discovery flow:" not in output
