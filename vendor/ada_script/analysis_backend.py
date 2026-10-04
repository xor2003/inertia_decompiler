from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AnalysisOptions:
    full: bool = False
    classify: bool = False
    xrefs: bool = False


class AnalyzerBackend(Protocol):
    def analyze(self) -> None:
        """Run analysis and populate database tables."""
