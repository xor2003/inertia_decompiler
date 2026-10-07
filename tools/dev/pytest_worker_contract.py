"""Layer: test execution contracts.

Responsibility: describe exact pytest worker assignments without process machinery.

Package ownership contract (canonical tools/dev package):
Layer: Tooling.
Owns development infrastructure, gates, and focused test support for repository tooling.
Do not perform decompiler pipeline semantics or CLI/reporting ownership here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkerSpec:
    """One pytest process over a pre-import path and node-shard contract."""

    name: str
    paths: tuple[str, ...]
    shard_count: int = 1
    shard_index: int = 0
