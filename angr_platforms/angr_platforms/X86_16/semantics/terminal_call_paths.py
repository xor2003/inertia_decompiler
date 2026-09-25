"""Prove AX-preserving paths from direct calls to function returns.

Layer: Semantics.
Responsibility: classify binary CFG paths that preserve a call result through
stack cleanup and frame teardown until an exact return.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from .branch_target_return import TerminalAxReturnEffectKind8616, terminal_ax_return_effect_8616
from .terminal_boundary_paths import boundary_terminal_callbacks_8616

__all__ = (
    "TerminalCallPathCallbacks8616",
    "TerminalCallPathResult8616",
    "TerminalCallPathStatus8616",
    "angr_terminal_call_path_callbacks_8616",
    "prove_terminal_call_path_8616",
)


class TerminalCallPathStatus8616(Enum):
    """Typed verdict for one call-to-return CFG path."""

    PROVEN = "proven"
    CALL_BLOCK_MISSING_OR_AMBIGUOUS = "call_block_missing_or_ambiguous"
    CALL_INSTRUCTION_MISSING_OR_AMBIGUOUS = "call_instruction_missing_or_ambiguous"
    CFG_PATH_AMBIGUOUS = "cfg_path_ambiguous"
    UNSAFE_POST_CALL_EFFECT = "unsafe_post_call_effect"
    RETURN_NOT_REACHED = "return_not_reached"


@dataclass(frozen=True, slots=True)
class TerminalCallPathCallbacks8616:
    """Dynamic adapters required by the owned terminal-call proof."""

    function_block_ranges: Callable[[], Iterable[tuple[int, int]]]
    load_block: Callable[[int, int], object | None]
    successor_addrs: Callable[[int], Iterable[int]]
    branch_target_imm: Callable[[object], int | None]


@dataclass(frozen=True, slots=True)
class TerminalCallPathResult8616:
    """Structured result of one terminal-call path proof."""

    status: TerminalCallPathStatus8616
    path_block_addrs: tuple[int, ...] = ()
    call_target_addr: int | None = None
    return_instruction_addr: int | None = None


class _AngrProjectSurface8616(Protocol):
    """Third-party project fields needed by the callback adapter."""

    factory: object


def _dynamic_tuple_8616(value: object) -> tuple[object, ...]:
    """Normalize one third-party iterable boundary to an owned tuple."""
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return tuple(value)
    return ()


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Read one field at the dynamic third-party angr/Capstone boundary."""
    return getattr(obj, name, default)


def _instruction_surface_8616(insn: object) -> object:
    """Return the underlying Capstone instruction from an angr wrapper."""
    return _dynamic_attr_8616(insn, "insn", insn)


def _instruction_operands_8616(insn: object) -> tuple[object, ...]:
    """Return normalized operands for one third-party instruction."""
    return _dynamic_tuple_8616(_dynamic_attr_8616(_instruction_surface_8616(insn), "operands", ()))


def _direct_call_target_8616(insn: object) -> int | None:
    """Return one unambiguous immediate target from a direct CALL boundary."""
    mnemonic = str(_dynamic_attr_8616(insn, "mnemonic", "")).lower()
    if mnemonic not in {"call", "lcall"}:
        return None
    immediates = tuple(
        _dynamic_attr_8616(operand, "imm", None)
        for operand in _instruction_operands_8616(insn)
        if _dynamic_attr_8616(operand, "type", -1) == 2
    )
    return immediates[0] if len(immediates) == 1 and isinstance(immediates[0], int) else None


def _register_name_8616(insn: object, operand: object) -> str:
    """Return a canonical register name through Capstone's dynamic API."""
    register_id = _dynamic_attr_8616(operand, "reg", None)
    register_name = _dynamic_attr_8616(_instruction_surface_8616(insn), "reg_name", None)
    if not isinstance(register_id, int) or not callable(register_name):
        return ""
    try:
        return str(register_name(register_id)).lower()
    except Exception:
        return ""


def _stack_adjust_8616(insn: object) -> bool:
    """Return whether an instruction is exact caller stack cleanup."""
    operands = _instruction_operands_8616(insn)
    return (
        str(_dynamic_attr_8616(insn, "mnemonic", "")).lower() == "add"
        and len(operands) == 2
        and _dynamic_attr_8616(operands[0], "type", -1) == 1
        and _register_name_8616(insn, operands[0]) == "sp"
        and _dynamic_attr_8616(operands[1], "type", -1) == 2
    )


def _frame_teardown_8616(insn: object) -> bool:
    """Return whether an instruction preserves an AX-family call result."""
    mnemonic = str(_dynamic_attr_8616(insn, "mnemonic", "")).lower()
    operands = _instruction_operands_8616(insn)
    if mnemonic in {"leave", "nop"}:
        return True
    if mnemonic == "pop" and len(operands) == 1 and _dynamic_attr_8616(operands[0], "type", -1) == 1:
        register = _register_name_8616(insn, operands[0])
        return bool(register) and register not in {"eax", "ax", "al", "ah", "edx", "dx", "dl", "dh"}
    return (
        mnemonic == "mov"
        and len(operands) == 2
        and all(_dynamic_attr_8616(operand, "type", -1) == 1 for operand in operands)
        and _register_name_8616(insn, operands[0]) == "sp"
        and _register_name_8616(insn, operands[1]) == "bp"
    )


def _graph_node_census_8616(
    nodes: tuple[object, ...],
) -> tuple[dict[int, list[object]], list[tuple[int, int]]]:
    """Index graph nodes by address and record exact block ranges."""
    nodes_by_addr: dict[int, list[object]] = {}
    block_ranges: list[tuple[int, int]] = []
    for node in nodes:
        node_addr = _dynamic_attr_8616(node, "addr", None)
        node_size = _dynamic_attr_8616(node, "size", None)
        if not isinstance(node_addr, int) or not isinstance(node_size, int) or node_size <= 0:
            continue
        nodes_by_addr.setdefault(node_addr, []).append(node)
        block_ranges.append((node_addr, node_size))
    return nodes_by_addr, block_ranges


@dataclass(frozen=True, slots=True)
class _AngrGraphCallbacks8616:
    """Bound angr function-graph adapters for the typed path proof."""

    graph: object
    nodes_by_addr: dict[int, list[object]]
    project_surface: _AngrProjectSurface8616

    def load_block(self, block_addr: int, block_size: int) -> object | None:
        """Load one exact-size block through the active project factory."""
        block_builder = _dynamic_attr_8616(self.project_surface.factory, "block", None)
        if not callable(block_builder):
            return None
        return cast(object | None, block_builder(block_addr, size=block_size))

    def successor_addrs(self, block_addr: int) -> tuple[int, ...]:
        """Return exact in-function successor addresses or raise on ambiguity."""
        candidates = tuple(self.nodes_by_addr.get(block_addr, ()))
        successor_reader = _dynamic_attr_8616(self.graph, "successors", None)
        if len(candidates) != 1 or not callable(successor_reader):
            raise ValueError(f"ambiguous function graph node at {block_addr:#x}")
        successors = _dynamic_tuple_8616(successor_reader(candidates[0]))
        addresses: list[int] = []
        for successor in successors:
            successor_addr = _dynamic_attr_8616(successor, "addr", None)
            if not isinstance(successor_addr, int):
                raise ValueError(f"missing successor address at {block_addr:#x}")
            addresses.append(successor_addr)
        return tuple(addresses)

    @staticmethod
    def branch_target_imm(insn: object) -> int | None:
        """Return one exact direct branch target through Capstone operands."""
        operands = _instruction_operands_8616(insn)
        if not operands or _dynamic_attr_8616(operands[0], "type", -1) != 2:
            return None
        immediate = _dynamic_attr_8616(operands[0], "imm", None)
        return immediate if isinstance(immediate, int) else None


def angr_terminal_call_path_callbacks_8616(
    project: object,
    function: object,
) -> TerminalCallPathCallbacks8616:
    """Adapt an active angr function graph to the typed semantic proof."""
    graph = _dynamic_attr_8616(function, "graph", None)
    nodes_view = _dynamic_attr_8616(graph, "nodes", ()) if graph is not None else ()
    try:
        raw_nodes = nodes_view() if callable(nodes_view) else nodes_view
        nodes = _dynamic_tuple_8616(raw_nodes)
    except Exception:
        nodes = ()
    nodes_by_addr, block_ranges = _graph_node_census_8616(nodes)

    adapters = _AngrGraphCallbacks8616(
        graph, nodes_by_addr, cast(_AngrProjectSurface8616, project)
    )
    callbacks = TerminalCallPathCallbacks8616(
        function_block_ranges=lambda: tuple(block_ranges),
        load_block=adapters.load_block,
        successor_addrs=adapters.successor_addrs,
        branch_target_imm=adapters.branch_target_imm,
    )
    return boundary_terminal_callbacks_8616(function, callbacks)


def _first_block_call_site_8616(
    insns: tuple[object, ...],
    call_ins_addr: int,
) -> tuple[int, int | None] | None:
    """Resolve the exact call instruction inside the containing block."""
    exact_call_indexes = tuple(
        index
        for index, insn in enumerate(insns)
        if _dynamic_attr_8616(insn, "address", -1) == call_ins_addr
        and terminal_ax_return_effect_8616(insn).kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER
    )
    if len(exact_call_indexes) != 1:
        return None
    return exact_call_indexes[0] + 1, _direct_call_target_8616(insns[exact_call_indexes[0]])


@dataclass(slots=True)
class _PostCallInsnScan8616:
    """Scan one block's post-call instructions for a proven path edge."""

    callbacks: TerminalCallPathCallbacks8616
    block_ranges: tuple[tuple[int, int], ...]
    saw_return: bool = False
    saw_jump: bool = False
    saw_external_conditional_jump: bool = False
    return_instruction_addr: int | None = None
    jump_target: int | None = None
    conditional_fallthrough: int | None = None

    def run(
        self,
        insns: tuple[object, ...],
        scan_start: int,
    ) -> TerminalCallPathStatus8616 | None:
        """Scan instructions after the call; return a failure status or None."""
        for index, insn in enumerate(insns[scan_start:], start=scan_start):
            status = self._process(insn, index, len(insns))
            if status is not None:
                return status
        return None

    def _process(
        self,
        insn: object,
        index: int,
        insn_count: int,
    ) -> TerminalCallPathStatus8616 | None:
        """Classify one post-call instruction and record path edge state."""
        mnemonic = str(_dynamic_attr_8616(insn, "mnemonic", "")).lower()
        if mnemonic in {"ret", "retf", "iret"}:
            return self._ret(insn, index, insn_count)
        if mnemonic in {"jmp", "ljmp"}:
            return self._jmp(insn, index, insn_count)
        if mnemonic.startswith("j"):
            return self._jcc(insn, index, insn_count)
        if _stack_adjust_8616(insn) or _frame_teardown_8616(insn):
            return None
        return TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT

    def _ret(self, insn: object, index: int, insn_count: int) -> TerminalCallPathStatus8616 | None:
        """Accept a block-terminal machine return and record its address."""
        if index != insn_count - 1:
            return TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT
        self.saw_return = True
        decoded_return_addr = _dynamic_attr_8616(insn, "address", None)
        self.return_instruction_addr = (
            decoded_return_addr if isinstance(decoded_return_addr, int) else None
        )
        return None

    def _jmp(self, insn: object, index: int, insn_count: int) -> TerminalCallPathStatus8616 | None:
        """Accept a block-terminal direct jump and record its target."""
        if index != insn_count - 1:
            return TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT
        try:
            self.jump_target = self.callbacks.branch_target_imm(insn)
        except Exception:
            return TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS
        if self.jump_target is None:
            return TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS
        self.saw_jump = True
        return None

    def _jcc(self, insn: object, index: int, insn_count: int) -> TerminalCallPathStatus8616 | None:
        """Accept a block-terminal out-of-function conditional jump."""
        if index != insn_count - 1:
            return TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT
        try:
            self.jump_target = self.callbacks.branch_target_imm(insn)
        except Exception:
            return TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS
        instruction_addr = _dynamic_attr_8616(insn, "address", None)
        instruction_size = _dynamic_attr_8616(insn, "size", None)
        if (
            self.jump_target is None
            or not isinstance(instruction_addr, int)
            or not isinstance(instruction_size, int)
            or instruction_size <= 0
            or any(
                block_addr <= self.jump_target < block_addr + block_size
                for block_addr, block_size in self.block_ranges
            )
        ):
            return TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS
        self.conditional_fallthrough = instruction_addr + instruction_size
        self.saw_external_conditional_jump = True
        return None


def _path_tail_8616(
    scan: _PostCallInsnScan8616,
    successors: tuple[int, ...],
    call_target_addr: int | None,
    path: list[int],
) -> TerminalCallPathResult8616 | int:
    """Return the terminal result or the next block address for the path."""
    if scan.saw_return:
        status = (
            TerminalCallPathStatus8616.PROVEN
            if not successors and scan.return_instruction_addr is not None
            else TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS
        )
        return TerminalCallPathResult8616(
            status,
            tuple(path),
            call_target_addr,
            scan.return_instruction_addr,
        )
    if len(successors) != 1:
        status = (
            TerminalCallPathStatus8616.RETURN_NOT_REACHED
            if not successors
            else TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS
        )
        return TerminalCallPathResult8616(status, tuple(path))
    if scan.saw_external_conditional_jump and successors[0] != scan.conditional_fallthrough:
        return TerminalCallPathResult8616(
            TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS,
            tuple(path),
        )
    if scan.saw_jump and scan.jump_target != successors[0]:
        return TerminalCallPathResult8616(TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS, tuple(path))
    return successors[0]


def _block_instructions_8616(
    callbacks: TerminalCallPathCallbacks8616,
    size_by_addr: dict[int, int],
    current_addr: int,
) -> tuple[object, ...] | None:
    """Load and decode one path block's instructions, or None on ambiguity."""
    block_size = size_by_addr.get(current_addr)
    if block_size is None:
        return None
    try:
        block = callbacks.load_block(current_addr, block_size)
    except Exception:
        return None
    if block is None:
        return None
    capstone = _dynamic_attr_8616(block, "capstone", None)
    return _dynamic_tuple_8616(_dynamic_attr_8616(capstone, "insns", ()))


def prove_terminal_call_path_8616(
    call_ins_addr: int,
    callbacks: TerminalCallPathCallbacks8616,
) -> TerminalCallPathResult8616:
    """Prove one AX-preserving CFG path from an exact call to return."""
    block_ranges = tuple(
        sorted(
            {
                (int(block_addr), int(block_size))
                for block_addr, block_size in callbacks.function_block_ranges()
                if int(block_size) > 0
            }
        )
    )
    containing = tuple(
        (block_addr, block_size)
        for block_addr, block_size in block_ranges
        if block_addr <= call_ins_addr < block_addr + block_size
    )
    if len(containing) != 1:
        return TerminalCallPathResult8616(TerminalCallPathStatus8616.CALL_BLOCK_MISSING_OR_AMBIGUOUS)

    size_by_addr = dict(block_ranges)
    current_addr = containing[0][0]
    first_block = True
    call_target_addr: int | None = None
    path: list[int] = []
    visited: set[int] = set()
    while current_addr not in visited and len(path) <= len(block_ranges):
        visited.add(current_addr)
        path.append(current_addr)
        insns = _block_instructions_8616(callbacks, size_by_addr, current_addr)
        if insns is None:
            return TerminalCallPathResult8616(TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS, tuple(path))
        scan_start = 0
        if first_block:
            call_site = _first_block_call_site_8616(insns, call_ins_addr)
            if call_site is None:
                return TerminalCallPathResult8616(
                    TerminalCallPathStatus8616.CALL_INSTRUCTION_MISSING_OR_AMBIGUOUS,
                    tuple(path),
                )
            scan_start, call_target_addr = call_site
            first_block = False

        scan = _PostCallInsnScan8616(callbacks, block_ranges)
        status = scan.run(insns, scan_start)
        if status is not None:
            return TerminalCallPathResult8616(status, tuple(path))

        try:
            successors = tuple(sorted({int(addr) for addr in callbacks.successor_addrs(current_addr)}))
        except Exception:
            return TerminalCallPathResult8616(TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS, tuple(path))
        step = _path_tail_8616(scan, successors, call_target_addr, path)
        if isinstance(step, TerminalCallPathResult8616):
            return step
        current_addr = step
    return TerminalCallPathResult8616(TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS, tuple(path))
