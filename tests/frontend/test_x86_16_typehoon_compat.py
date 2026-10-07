"""Focused tests for the X86_16 Typehoon compatibility boundary.

Layer: frontend compatibility
Responsibility: preserve 16-bit Typehoon semantics while bounding redundant solver work.
"""

from angr.analyses.typehoon.simple_solver import SimpleSolver

from inertia.frontend.x86_16.typehoon_compat import apply_x86_16_typehoon_compatibility


class _ConnectedSolverProbe8616:
    """Minimal dynamic solver surface for connected-root traversal."""

    bits = 16

    def __init__(self) -> None:
        self._equivalence: dict[object, object] = {}
        self._solution_cache: dict[object, object] = {}
        self.determine_calls: list[object] = []

    def _determine(
        self,
        typevar: object,
        _sketch: object,
        _equivalence_classes: dict[object, object],
        solution: dict[object, object],
        *,
        nodes: object,
    ) -> None:
        """Model one connected solve that materializes both pending roots."""
        assert nodes is None
        self.determine_calls.append(typevar)
        solution["first"] = "word"
        solution["second"] = "word"


def test_typehoon_determine_skips_roots_solved_by_connected_16_bit_traversal() -> None:
    """Do not repeat an equivalent root after its solution is already materialized."""
    apply_x86_16_typehoon_compatibility()
    solver = _ConnectedSolverProbe8616()
    solution: dict[object, object] = {}

    determine = SimpleSolver.determine
    determine(
        solver,  # type: ignore[arg-type]
        {"first": object(), "second": object()},
        ("first", "second"),
        {},  # type: ignore[arg-type]
        solution,
    )

    assert solver.determine_calls == ["first"]
    assert solution == {"first": "word", "second": "word"}
