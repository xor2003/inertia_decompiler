"""Mutable alias-state cells keyed by canonical storage domains.

Layer: Alias.
Responsibility: owns storage identity and versioned register/stack alias state.
Owns storage identity and versioned register/stack alias state.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .domains import DomainKey, View


@dataclass(frozen=True, slots=True)
class AliasCell:
    """Store one versioned expression for a canonical alias domain/view."""

    domain: DomainKey
    view: View
    expr: object
    needs_synthesis: bool = False
    version: int = 0

    def is_ready(self) -> bool:
        """Return whether this cell can be consumed without synthesis."""
        return not self.needs_synthesis


@dataclass(slots=True)
class AliasState:
    """Track versioned alias cells keyed by storage domain and bit view."""

    _cells: dict[tuple[DomainKey, View], AliasCell] = field(default_factory=dict)
    _versions: dict[DomainKey, int] = field(default_factory=dict)

    def version_of(self, domain: DomainKey) -> int:
        """Return the current version for a storage domain."""
        return self._versions.get(domain, 0)

    def bump_domain(self, domain: DomainKey) -> int:
        """Advance and return the version for a storage domain."""
        new_version = self.version_of(domain) + 1
        self._versions[domain] = new_version
        return new_version

    def get(self, domain: DomainKey, view: View) -> AliasCell | None:
        """Return the current alias cell for a storage domain/view pair."""
        return self._cells.get((domain, view))

    def set(
        self, domain: DomainKey, view: View, expr: object, *, needs_synthesis: bool = False, version: int | None = None
    ) -> AliasCell:
        """Store and return an alias cell for a storage domain/view pair."""
        if version is None:
            version = self.version_of(domain)
        cell = AliasCell(domain, view, expr, needs_synthesis=needs_synthesis, version=version)
        self._cells[(domain, view)] = cell
        return cell

    def mark_needs_synthesis(self, domain: DomainKey, view: View) -> None:
        """Mark an existing alias cell as requiring later synthesis."""
        cell = self.get(domain, view)
        if cell is not None:
            self._cells[(domain, view)] = AliasCell(
                cell.domain, cell.view, cell.expr, needs_synthesis=True, version=cell.version
            )

    def clear_domain(self, domain: DomainKey) -> None:
        """Remove every alias cell associated with a storage domain."""
        doomed = [key for key in self._cells if key[0] == domain]
        for key in doomed:
            del self._cells[key]


__all__ = ["AliasCell", "AliasState"]
