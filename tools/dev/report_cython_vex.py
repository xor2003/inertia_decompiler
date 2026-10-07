#!/usr/bin/env python3
"""Layer: Tooling/performance.

Responsibility: correlate Cython Python-interaction annotations with measured CPU hotspots.
Source parsing is diagnostic only; it never supplies recovered instruction semantics.
"""

from __future__ import annotations

import argparse
import ast
import pstats
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, cast


class AnnotationScores(HTMLParser):
    """Read Cython's per-source-line interaction scores, excluding generated C."""

    def __init__(self) -> None:
        """Initialize a bounded source-line accumulator."""
        super().__init__()
        self.scores: dict[int, int] = {}
        self._score: int | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Begin only a source-line preformatted block."""
        if tag != "pre":
            return
        classes = (dict(attrs).get("class") or "").split()
        if "line" in classes and "cython" in classes:
            self._score = int(next(value.removeprefix("score-") for value in classes if value.startswith("score-")))
            self._text = []

    def handle_data(self, data: str) -> None:
        """Collect the displayed source line number and text."""
        if self._score is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        """Commit one annotation score by its authoritative source line."""
        if tag == "pre" and self._score is not None:
            number = "".join(self._text).split(":", 1)[0].lstrip("+\u2212 \xa0")
            self.scores[int(number)] = self._score
            self._score = None


def _function_index(source: Path) -> dict[int, ast.FunctionDef]:
    """Match profiler line numbers to definitions and their decorator starts."""
    functions: dict[int, ast.FunctionDef] = {}
    for node in ast.walk(ast.parse(source.read_text())):
        if isinstance(node, ast.FunctionDef):
            functions[node.lineno] = node
            for decorator in node.decorator_list:
                functions[decorator.lineno] = node
    return functions


def report(source: Path, annotation: Path, profile: Path) -> str:
    """Rank measured Python functions alongside their compiled interaction heat."""
    parser = AnnotationScores()
    parser.feed(annotation.read_text())
    functions = _function_index(source)
    stats = pstats.Stats(str(profile))
    rows: list[tuple[float, str]] = []
    # pstats' dynamically populated stats table is an external profiler boundary.
    for (filename, line, name), (_primitive, calls, self_time, cumulative, _callers) in cast(Any, stats).stats.items():
        if Path(filename).resolve() != source.resolve() or line not in functions:
            continue
        function = functions[line]
        if function.name != name:
            continue
        scores = [parser.scores.get(number, 0) for number in range(function.lineno, (function.end_lineno or line) + 1)]
        interacting = sum(score > 0 for score in scores)
        row = f"| {name}:{function.lineno} | {calls} | {self_time:.3f} | {cumulative:.3f} | {interacting} | {max(scores, default=0)} |"
        rows.append((self_time, row))
    rows.sort(reverse=True)
    if not rows:
        raise ValueError("No lifter functions matched; profile the current interpreted source before correlating annotations")
    return "\n".join([
        "# Cython lifter interaction and runtime profile", "",
        f"Source: `{source}`", f"Annotation: `{annotation}`", f"Profile: `{profile}`", "",
        "Ranked by measured self CPU time from the interpreted authoritative source.",
        "Cumulative time includes callees and overlaps across rows. Annotation scores",
        "show static Python C-API interaction, not time or dynamic call counts.",
        "The production extension has profiling disabled; these timings are not a",
        "measurement of compiled function speed. Pair with unprofiled backend benchmarks.", "",
        "| Function:line | Calls | Self seconds | Cumulative seconds | Lines using Python API | Peak annotation score |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        *[row for _time, row in rows[:25]], "",
    ])


def main() -> None:
    """Save a compact reviewable report beside the annotated HTML."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("inertia/frontend/x86_16/lift_86_16.py"))
    parser.add_argument("--annotation", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(report(args.source, args.annotation, args.profile))
    print(args.out)


if __name__ == "__main__":
    main()
