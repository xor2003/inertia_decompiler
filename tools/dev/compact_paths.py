#!/usr/bin/env python3
"""Shorten repository paths in a human-readable view of a saved log.

Layer: Tooling/reporting.
Responsibility: stream a display-only path projection without modifying source,
raw logs, proof receipts, diagnostic details, or subprocess exit statuses.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TextIO

PATH_ALIASES: tuple[tuple[str, str], ...] = (
    ("inertia/", "INERTIA/"),
    ("tests/", "TEST/"),
    ("tools/dosunit/", "DU/"),
    ("reference/", "REF/"),
    ("scripts/", "SCRIPTS/"),
)


class PathCompactor:
    """Replace only complete known path prefixes at a path boundary."""

    def __init__(self, repo: Path) -> None:
        """Build one longest-prefix matcher for absolute and relative paths."""
        root = repo.resolve().as_posix().rstrip("/") + "/"
        self.replacements: dict[str, str] = {root: "./"}
        for prefix, alias in PATH_ALIASES:
            self.replacements[prefix] = alias
            self.replacements["./" + prefix] = alias
            self.replacements[root + prefix] = alias
        alternatives = "|".join(
            re.escape(prefix)
            for prefix in sorted(self.replacements, key=lambda item: (-len(item), item))
        )
        # Do not shorten a suffix inside a foreign path or another identifier.
        self.pattern: re.Pattern[str] = re.compile(r"(?<![\w./\\-])(?:" + alternatives + ")")

    def line(self, text: str) -> str:
        """Preserve all text except recognized repository path prefixes."""
        return self.pattern.sub(lambda match: self.replacements[match.group()], text)


def compact_stream(source: TextIO, destination: TextIO, repo: Path) -> None:
    """Write a line-at-a-time display projection; leave the input untouched."""
    compactor = PathCompactor(repo)
    for line in source:
        destination.write(compactor.line(line))


def main(argv: list[str] | None = None) -> int:
    """Read stdin and emit a compact log view, optionally with an alias legend."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--legend", action="store_true")
    args = parser.parse_args(argv)
    if args.legend:
        print(f"./ = {args.repo.resolve()}/")
        for prefix, alias in PATH_ALIASES:
            print(f"{alias} = {prefix}")
    compact_stream(sys.stdin, sys.stdout, args.repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
