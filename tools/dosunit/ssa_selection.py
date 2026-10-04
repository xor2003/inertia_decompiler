"""Bounded catalog selection driven by freshly lowered call transfers.

Layer: dosunit SSA orchestration.
Responsibility: schedule selected catalog entries and every catalogued direct
callee, retaining all aliases and falling back to full lowering on uncertainty.
Selection limits work only; it supplies no semantic equivalence evidence.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from tools.dosunit.model import DosUnitError, parse_int


def selected_catalog_indices(
    functions: list[dict[str, Any]], roots: frozenset[str],
) -> frozenset[int]:
    """Resolve selection proposals without choosing between duplicate aliases."""
    matched = frozenset(
        index for index, function in enumerate(functions)
        if {str(function.get("id", "")), *function.get("names", [])} & roots
    )
    return frozenset(range(len(functions))) if roots and not matched else matched


class LoweringSelection:
    """Visit each catalog entry at most once in deterministic discovery order."""

    def __init__(
        self, functions: list[dict[str, Any]], roots: frozenset[str] | None,
        entry_linear: Callable[[dict[str, Any]], int],
    ) -> None:
        """Index complete addresses using the lowerer-owned coordinate resolver."""
        self.functions = functions
        self.pending: list[int] = []
        self.seen: set[int] = set()
        self.by_linear: dict[int, list[int]] = {}
        if roots is None:
            self._all()
            return
        try:
            for index, function in enumerate(functions):
                self.by_linear.setdefault(entry_linear(function), []).append(index)
        except (DosUnitError, TypeError, AttributeError, KeyError):
            self._all()
            return
        for index in sorted(selected_catalog_indices(functions, roots)):
            self._enqueue(index)

    def _enqueue(self, index: int) -> None:
        """Retain aliases as distinct catalog records without repeated work."""
        if index not in self.seen:
            self.seen.add(index)
            self.pending.append(index)

    def _all(self) -> None:
        """Keep legacy complete lowering whenever selection is uncertain."""
        for index in range(len(self.functions)):
            self._enqueue(index)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        """Consume a growing queue whose size is bounded by the catalog."""
        for index in self.pending:
            yield self.functions[index]

    def observe(self, parts: list[dict[str, Any]]) -> None:
        """Schedule all entries matching full binary-derived call addresses."""
        for part in parts:
            transfer = part.get("source", {}).get("transfer") or {}
            if transfer.get("kind") != "direct_call":
                # Direct jumps are already followed by the block scanner.
                # Unknown control retains the full catalog and its refusals.
                if transfer and transfer.get("kind") != "direct_successors":
                    self._all()
                continue
            target = transfer.get("target", {}).get("raw")
            if target is None:
                self._all()
                continue
            try:
                linear = parse_int(target, field="transfer.target.raw")
            except DosUnitError:
                self._all()
                continue
            for index in self.by_linear.get(linear, []):
                self._enqueue(index)
