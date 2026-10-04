"""Static regressions for bounded invocation-inventory input consumption.

Layer: tests.
Responsibility: prove ``frontend_invocation_inventory`` consumes
caller-supplied root iterables and decoded boundary instructions only
inside typed budgets. Duplicate floods, infinite generators, overflow
items and over-budget censuses refuse with typed statuses and honest
open accounting instead of hanging, expanding without limit, or
silently truncating into READY. The module under test is loaded through
a private importlib package with stubbed sibling owners so these checks
run without angr or any native lift; path resolution works from either
the staged overlay or the in-tree tests directory.
"""

from __future__ import annotations

import importlib.util
import itertools
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

_ENTRY = 0x100
_LOWER = 0x100
_UPPER = 0x1FFF


def _module_path() -> Path:
    """Locate the production inventory owner without environment overrides."""
    return (
        Path(__file__).resolve().parent.parent
        / "angr_platforms"
        / "X86_16"
        / "frontend_invocation_inventory.py"
    )


class _FarTarget:
    """Stub of ``DecodedFarCallTarget8616`` for isinstance resolution."""

    def __init__(self, target_addr: int) -> None:
        """Retain the exact far target coordinate."""
        self.target_addr = target_addr


class _Index:
    """Stub decoded index recording the ranges it was built over."""

    def __init__(self, decoded_ranges: object) -> None:
        """Record the decoded ranges for later assertions."""
        self.decoded_ranges = decoded_ranges


def _build_index(
    decoded_ranges: object,
    *,
    direct_target_resolver: object,
    instruction_address_resolver: object,
) -> _Index:
    """Stand in for the decoded callsite index on the READY path."""
    return _Index(decoded_ranges)


class _Insn:
    """Fake decoded instruction with an optional direct-call target."""

    def __init__(self, address: int, target: int | _FarTarget | None = None) -> None:
        """Retain an exact address and an optional scripted call target."""
        self.address = address
        self.target = target


class _Capstone:
    """Fake disassembly surface exposing a lazy insn iterable."""

    def __init__(self, insns: object) -> None:
        """Retain the supplied instruction iterable verbatim."""
        self.insns = insns


class _Block:
    """Fake reachable block keyed by its start address."""

    def __init__(self, addr: int, insns: object) -> None:
        """Retain the block address and lazy disassembly."""
        self.addr = addr
        self.capstone = _Capstone(insns)


class _Boundary:
    """Fake closed boundary honoring the exact-surface contract."""

    def __init__(
        self,
        project: object,
        addr: int,
        blocks: tuple[_Block, ...],
        covered: tuple[int, ...],
    ) -> None:
        """Bind a closed census: owning project, blocks, coverage."""
        self.project = project
        self.addr = addr
        self.size = (max(covered) - addr + 1) if covered else 0
        self.blocks = blocks
        self.reachable_instruction_addrs = frozenset(covered)


class _Image:
    """Fake loaded object with inclusive mapped bounds."""

    def __init__(self, min_addr: int, max_addr: int) -> None:
        """Retain inclusive mapped bounds."""
        self.min_addr = min_addr
        self.max_addr = max_addr


class _Loader:
    """Fake loader resolving only inside its mapped image."""

    def __init__(self, image: _Image) -> None:
        """Bind this loader to one mapped image."""
        self._image = image

    def find_object_containing(self, address: int) -> _Image | None:
        """Return the image only when the address is mapped."""
        if self._image.min_addr <= address <= self._image.max_addr:
            return self._image
        return None


class _Project:
    """Fake project exposing only the loader boundary."""

    def __init__(self, image: _Image) -> None:
        """Expose the scripted image through a fake loader."""
        self.loader = _Loader(image)


class _PullCount:
    """Single-pass iterator recording how many items a consumer drew."""

    def __init__(self, items: object) -> None:
        """Wrap any iterable; drawing is what the budget tests measure."""
        self._items = iter(items)
        self.drawn = 0

    def __iter__(self) -> _PullCount:
        """Return itself so one pass counts every drawn item."""
        return self

    def __next__(self) -> object:
        """Deliver the next wrapped item and count the draw."""
        item = next(self._items)
        self.drawn += 1
        return item


def _resolver(instruction: _Insn) -> int | _FarTarget | None:
    """Resolve fake instructions to their scripted direct target."""
    return instruction.target


def _load_inventory() -> types.ModuleType:
    """Load the inventory owner under a private package with stub siblings."""
    package = "_inventory_budget_stub_8616"
    for name in (
        package,
        f"{package}.frontend_direct_callsite_index",
        f"{package}.frontend_function_boundary",
        f"{package}.frontend_invocation_inventory",
    ):
        sys.modules.pop(name, None)
    pkg = types.ModuleType(package)
    pkg.__path__ = []
    sys.modules[package] = pkg
    index_module = types.ModuleType(f"{package}.frontend_direct_callsite_index")
    index_module.DecodedDirectCallsiteIndex8616 = _Index
    index_module.DecodedFarCallTarget8616 = _FarTarget
    index_module.DirectCallTargetResolver8616 = Callable
    index_module._boundary_instruction_address_8616 = lambda insn: insn.address
    index_module.build_decoded_direct_callsite_index_8616 = _build_index
    sys.modules[index_module.__name__] = index_module
    boundary_module = types.ModuleType(f"{package}.frontend_function_boundary")
    boundary_module.mapped_entry_function_boundary_8616 = lambda p, h: None
    sys.modules[boundary_module.__name__] = boundary_module
    spec = importlib.util.spec_from_file_location(
        f"{package}.frontend_invocation_inventory", _module_path()
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_BoundarySpec = tuple[tuple["_Block", ...], tuple[int, ...]]


def _world() -> tuple[_Project, dict[int, _BoundarySpec], list[int]]:
    """Return a mapped project plus a scriptable boundary provider table."""
    project = _Project(_Image(_LOWER, _UPPER))
    table: dict[int, _BoundarySpec] = {}
    calls: list[int] = []
    return project, table, calls


def _install_provider(
    inv: types.ModuleType,
    table: dict[int, _BoundarySpec],
    calls: list[int],
) -> None:
    """Bind a scripted mapped-boundary provider that records its calls."""

    def provider(project: object, head: int) -> _Boundary | None:
        """Close a scripted boundary or report the head unclosable."""
        calls.append(head)
        spec = table.get(head)
        if spec is None:
            return None
        blocks, covered = spec
        return _Boundary(project, head, blocks, covered)

    inv.mapped_entry_function_boundary_8616 = provider


def _leaf_spec(addr: int) -> _BoundarySpec:
    """One self-covering boundary with a single decoded instruction."""
    return ((_Block(addr, [_Insn(addr)]),), (addr,))


def test_finite_covered_roots_close_ready() -> None:
    """Positive: a finite deduplicated root iterable still closes READY."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = ((_Block(_ENTRY, [_Insn(_ENTRY), _Insn(0x150), _Insn(0x160)]),), (_ENTRY, 0x150, 0x160))
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        extra_entries=(0x160, 0x150, 0x160),
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=4, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.READY
    assert inventory.ready
    assert inventory.boundary_heads == (_ENTRY,)
    assert inventory.instruction_count == 3
    assert inventory.stats.covered_count == 2
    assert inventory.stats.closed


def test_discovered_and_far_targets_traverse_in_order() -> None:
    """Positive: near and far decoded targets still become queued roots."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = (
        (_Block(_ENTRY, [_Insn(_ENTRY, 0x200), _Insn(0x110, _FarTarget(0x300))]),),
        (_ENTRY, 0x110),
    )
    table[0x200] = _leaf_spec(0x200)
    table[0x300] = _leaf_spec(0x300)
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.READY
    assert inventory.boundary_heads == (_ENTRY, 0x200, 0x300)


def test_extra_roots_materialize_in_first_seen_order() -> None:
    """Determinism: deduplicated roots keep first-seen traversal order."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    table[0x160] = _leaf_spec(0x160)
    table[0x150] = _leaf_spec(0x150)
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        extra_entries=(0x160, 0x150, 0x160),
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.READY
    assert inventory.boundary_heads == (_ENTRY, 0x160, 0x150)
    assert calls == [_ENTRY, 0x160, 0x150]


def test_duplicate_flood_refuses_without_traversal() -> None:
    """Adversarial: infinite duplicate roots refuse on the draw cap."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        extra_entries=itertools.repeat(0x150),
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.BUDGET_ROOT_INPUTS
    assert not inventory.ready
    assert inventory.refusal_addr == 0x150
    assert inventory.stats.raw_fact_count == 2
    assert inventory.stats.normalized_fact_count == 0
    assert not inventory.stats.closed
    assert calls == []


def test_infinite_distinct_root_generator_bounded() -> None:
    """Adversarial: an unbounded distinct-root generator stops at cap+1."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)
    pulled = _PullCount(itertools.count(0x300))
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        extra_entries=pulled,
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.BUDGET_ROOT_INPUTS
    assert inventory.refusal_addr == 0x300 + 8
    assert pulled.drawn == 9
    assert inventory.stats.raw_fact_count == 10
    assert not inventory.stats.closed
    assert calls == []


def test_root_cap_boundary_exact_and_overflow() -> None:
    """Boundary: exactly cap drawn items pass; cap+1 distinct refuses."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = (
        (_Block(_ENTRY, [_Insn(_ENTRY), _Insn(0x150)]),),
        (_ENTRY, 0x150),
    )
    _install_provider(inv, table, calls)
    at_cap = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        extra_entries=(0x150,) * 8,
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert at_cap.status is inv.InvocationInventoryStatus8616.READY
    assert at_cap.stats.covered_count == 1
    over_cap = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        extra_entries=tuple(range(0x300, 0x300 + 9)),
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=8, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert over_cap.status is inv.InvocationInventoryStatus8616.BUDGET_ROOT_INPUTS
    assert over_cap.refusal_addr == 0x308
    assert over_cap.stats.raw_fact_count == 10


@pytest.mark.parametrize("bad", (None, -1, True, "0x150", 1.5))
def test_malformed_root_values_raise(bad: object) -> None:
    """Contract: non-int or negative roots are loud caller errors."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)
    with pytest.raises(TypeError):
        inv.build_invocation_inventory_8616(
            project,
            _ENTRY,
            extra_entries=(bad,),
            direct_target_resolver=_resolver,
        )


def test_malformed_overflow_position_still_raises() -> None:
    """Contract: a malformed item past the cap fails loudly, not as budget."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)
    with pytest.raises(TypeError):
        inv.build_invocation_inventory_8616(
            project,
            _ENTRY,
            extra_entries=(*((0x150,) * 8), None),
            budget=inv.InvocationInventoryBudget8616(
                max_boundaries=8, max_instructions=8, max_root_inputs=8
            ),
            direct_target_resolver=_resolver,
        )


def test_generator_defect_propagates_loudly() -> None:
    """Loud exceptions: a failing root iterable is never swallowed."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)

    def defective() -> Iterator[int]:
        """Yield one valid root, then fail inside the iterable."""
        yield 0x150
        raise RuntimeError("root iterable defect")

    with pytest.raises(RuntimeError):
        inv.build_invocation_inventory_8616(
            project,
            _ENTRY,
            extra_entries=defective(),
            direct_target_resolver=_resolver,
        )


def test_non_iterable_extra_entries_raise() -> None:
    """Contract: a non-iterable root source is a loud caller error."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)
    with pytest.raises(TypeError):
        inv.build_invocation_inventory_8616(
            project,
            _ENTRY,
            extra_entries=0x150,
            direct_target_resolver=_resolver,
        )


def test_instruction_budget_limits_drawn_census() -> None:
    """Adversarial: an oversized census draws at most remaining+1 insns."""
    inv = _load_inventory()
    project, table, calls = _world()
    counted = _PullCount([_Insn(0x100 + off) for off in range(5)])
    table[_ENTRY] = ((_Block(_ENTRY, counted),), (_ENTRY, 0x104))
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=2, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.BUDGET_INSTRUCTIONS
    assert inventory.refusal_addr == _ENTRY
    assert counted.drawn == 3
    assert inventory.instruction_count == 0
    assert not inventory.ready


def test_instruction_budget_exact_fit_stays_ready() -> None:
    """Boundary: a census equal to the remaining budget still closes."""
    inv = _load_inventory()
    project, table, calls = _world()
    insns = [_Insn(0x100 + off) for off in range(5)]
    table[_ENTRY] = ((_Block(_ENTRY, insns),), tuple(insn.address for insn in insns))
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=5, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.READY
    assert inventory.instruction_count == 5
    assert inventory.stats.closed


def test_instruction_budget_refuses_second_boundary() -> None:
    """Adversarial: committed boundaries account before the next census."""
    inv = _load_inventory()
    project, table, calls = _world()
    first = [
        _Insn(0x100),
        _Insn(0x101),
        _Insn(0x102),
        _Insn(0x103, 0x200),
    ]
    second_counted = _PullCount([_Insn(0x200 + off) for off in range(4)])
    table[_ENTRY] = (
        (_Block(_ENTRY, first),),
        tuple(insn.address for insn in first),
    )
    table[0x200] = (
        (_Block(0x200, second_counted),),
        tuple(0x200 + off for off in range(4)),
    )
    _install_provider(inv, table, calls)
    inventory = inv.build_invocation_inventory_8616(
        project,
        _ENTRY,
        budget=inv.InvocationInventoryBudget8616(
            max_boundaries=8, max_instructions=5, max_root_inputs=8
        ),
        direct_target_resolver=_resolver,
    )
    assert inventory.status is inv.InvocationInventoryStatus8616.BUDGET_INSTRUCTIONS
    assert inventory.refusal_addr == 0x200
    assert inventory.instruction_count == 4
    assert inventory.boundary_heads == (_ENTRY,)
    assert second_counted.drawn == 2
    assert not inventory.stats.closed


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_boundaries", 0),
        ("max_instructions", 0),
        ("max_root_inputs", 0),
        ("max_root_inputs", -3),
        ("max_root_inputs", True),
        ("max_root_inputs", "8"),
        ("max_root_inputs", None),
    ),
)
def test_budget_validation_rejects_nonpositive_limits(field: str, value: object) -> None:
    """Contract: every typed budget limit must be a positive int."""
    inv = _load_inventory()
    with pytest.raises(ValueError):
        inv.InvocationInventoryBudget8616(**{field: value})


def test_untyped_budget_and_resolver_raise() -> None:
    """Contract: untyped budgets and resolvers remain loud errors."""
    inv = _load_inventory()
    project, table, calls = _world()
    table[_ENTRY] = _leaf_spec(_ENTRY)
    _install_provider(inv, table, calls)
    with pytest.raises(TypeError):
        inv.build_invocation_inventory_8616(
            project, _ENTRY, budget=object(), direct_target_resolver=_resolver
        )
    with pytest.raises(TypeError):
        inv.build_invocation_inventory_8616(
            project, _ENTRY, direct_target_resolver=None
        )
