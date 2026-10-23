"""Layer: Frontend/runtime.
Responsibility: consume conditional native control in a private Clinic CFG.

The declaration stays attached to this consumer. Neither execution VEX nor the
unconditional Function graph receives the scoped successors.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from inertia.ir.entry_projection_mode import entry_projection_mode_for_scope_8616
from inertia.pipeline.errors import PipelineHardError

from .clinic_conversion_source import ClinicControlSurface8616, ClinicConversionContext8616, _graph_surface
from .clinic_entry_jump_transport import ClinicConvertedBlockCapture8616, _captures_8616, _context_is_current_8616
from .clinic_terminal_control import (
    _bound_next_operand_8616,
    _terminal_instruction_mark_8616,
    rebind_terminal_jump_8616,
)

if TYPE_CHECKING:
    import networkx as nx
    from angr import ailment

    from inertia.ir.declared_entry_pipeline import DeclaredEntryInput8616, DeclaredEntryPipeline8616
    from inertia.ir.entry_jump_domain import AdmittedScopedCallTarget8616, AdmittedTerminalJump8616
    from inertia.ir.entry_jump_transport import EntryJumpTransportProof8616
    from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616


class _Node8616(Protocol):
    """Native graph node coordinates at the third-party Clinic boundary."""
    addr: int
    size: int


class _ScopedProjectLike8616(Protocol):
    """Typed consuming scope carrying the authenticating project identity."""
    project: object


class _ScopedEntryLike8616(Protocol):
    """Entry variant carrying a typed consuming scope with a project."""

    @property
    def scope(self) -> _ScopedProjectLike8616:
        """Expose the typed consuming scope."""
        ...


class _Function8616(_Node8616, Protocol):
    """Unchanged recovered function graph at the third-party boundary."""
    graph: nx.DiGraph


class _Manager8616(Protocol):
    """Third-party atom allocator used by the existing binding owner."""
    def next_atom(self) -> int:
        """Allocate a new AIL atom identity."""
        ...


class _Clinic8616(Protocol):
    """Private conversion products retained by third-party Clinic."""
    project: object
    function: _Function8616
    _func_graph: nx.DiGraph
    _blocks_by_addr_and_size: dict[tuple[int, int], ailment.Block]
    _ail_manager: _Manager8616
    _inertia_clinic_scoped_partition_8616: ClinicScopedPartition8616


def transport_clinic_scoped_control_8616(
    clinic: object, entry: DeclaredEntryPipeline8616 | NativeNearCallPipeline8616,
) -> None:
    """Atomically bind exact AIL terminals and their scoped successor edges.

    Every input is reauthenticated before staging copies. Missing/ambiguous
    nodes or a failed binding refuses the whole operation without publishing
    any conditional operand or edge. Declared entries consume control only:
    their captured native AIL calls remain unchanged. Native near-call entries
    separately request authenticated outgoing-target rewrites.
    """
    from inertia.ir.declared_entry_pipeline import (
        DeclaredEntryPipeline8616 as _DeclaredEntryPipeline8616,
    )
    from inertia.ir.declared_entry_pipeline import (
        retain_declared_entry_pipeline_8616,
    )
    from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616 as _NativeNearCallPipeline8616

    if type(entry) is not _DeclaredEntryPipeline8616 and type(entry) is not _NativeNearCallPipeline8616:
        raise TypeError("scoped Clinic control transport requires a proved conditional entry")
    mode = entry_projection_mode_for_scope_8616(entry.scope)
    projection = entry.view.cfg_projection_for(entry.scope, mode=mode)
    captures = _captures_8616(clinic)
    boundary = cast(_Clinic8616, clinic)
    if (entry.scope.project is not boundary.project
            or entry.view.boundary.project is not boundary.project
            or entry.bundle.artifact is not entry.view.source_artifact
            or boundary.function.addr != entry.bundle.artifact.function_addr):
        raise PipelineHardError("scoped Clinic authority differs", layer="frontend")
    # Dynamic third-party boundary: this optional receipt attaches to angr Clinic.
    receipt = getattr(clinic, "_inertia_clinic_scoped_partition_8616", None)
    if receipt is not None and (type(receipt) is not ClinicScopedPartition8616 or receipt.entry is not entry):
        raise PipelineHardError("scoped Clinic partition receipt is foreign", layer="frontend")
    if projection is None or not _context_is_current_8616(clinic, captures, scoped_partition=receipt):
        raise PipelineHardError("scoped Clinic control source changed", layer="frontend")
    graph = boundary._func_graph.copy()
    nodes = {node.addr: node for node in graph.nodes}
    expected = {block.addr for block in projection.blocks}
    if (len(nodes) != len(graph.nodes) or set(nodes) != expected
            or any(projection.pending.values())):
        raise PipelineHardError("scoped Clinic block census differs", layer="frontend")
    edges = {(addr, target) for addr, targets in projection.successors.items() for target in targets}
    if any(target not in nodes for _, target in edges) or any(
        (source.addr, target.addr) not in edges for source, target in graph.edges
    ):
        raise PipelineHardError("scoped Clinic successor census differs", layer="frontend")
    converted = _bound_blocks_8616(boundary, entry, projection.applied, captures, nodes)
    _bind_call_targets_8616(boundary, projection.call_targets, captures, converted, nodes)
    for source, target in edges:
        if not graph.has_edge(nodes[source], nodes[target]):
            graph.add_edge(nodes[source], nodes[target], type="transition")
    boundary._func_graph = graph
    boundary._blocks_by_addr_and_size = converted
    retain_declared_entry_pipeline_8616(clinic, entry)


def _bound_blocks_8616(
    boundary: _Clinic8616, entry: DeclaredEntryPipeline8616 | NativeNearCallPipeline8616,
    admissions: tuple[AdmittedTerminalJump8616, ...],
    captures: dict[tuple[int, int], ClinicConvertedBlockCapture8616],
    nodes: dict[int, _Node8616],
) -> dict[tuple[int, int], ailment.Block]:
    """Stage converted copies; a failed terminal binding cannot escape."""
    converted = dict(boundary._blocks_by_addr_and_size)
    for admission in admissions:
        node = nodes.get(admission.block_addr)
        record = None if node is None else captures.get((node.addr, node.size))
        if record is None:
            raise PipelineHardError("scoped Clinic native block is absent", layer="frontend")
        decoded = entry.bundle.terminal_evidence[admission.block_addr].decoded
        if decoded is None or decoded.head != admission.head:
            raise PipelineHardError("scoped Clinic decoded terminal differs", layer="frontend")
        offset = decoded.head - record.addr
        if offset < 0 or record.source_bytes[offset:] != decoded.encoding:
            raise PipelineHardError("scoped Clinic terminal bytes changed", layer="frontend")
        original = cast("ailment.Block", record.converted)
        block = original.copy(statements=list(original.statements))
        binding = rebind_terminal_jump_8616(
            block, record.vex, decoded, admission.target,
            next_atom=boundary._ail_manager.next_atom,
        )
        if not binding.applied:
            raise PipelineHardError("scoped Clinic terminal binding refused", layer="frontend",
                                    details={"refusal": binding.refusal, "detail": binding.detail})
        converted[(record.addr, record.size)] = block
    return converted


def _bind_call_targets_8616(
    boundary: _Clinic8616,
    calls: tuple[AdmittedScopedCallTarget8616, ...],
    captures: dict[tuple[int, int], ClinicConvertedBlockCapture8616],
    converted: dict[tuple[int, int], ailment.Block],
    nodes: dict[int, _Node8616],
) -> None:
    """Stage only the exact VEX-next CALL target under the retained premise.

    These targets came from fresh application-time selector discharge. The
    converted terminal must still carry this native call's exact next tmp,
    byte encoding and instruction mark. Nothing changes call prototypes or
    the unconditional function graph.
    """
    import pyvex
    from angr import ailment

    for call in calls:
        node = nodes.get(call.block.addr)
        record = None if node is None else captures.get((node.addr, node.size))
        if record is None:
            raise PipelineHardError("scoped Clinic CALL block missing", layer="frontend")
        original = converted[(record.addr, record.size)]
        terminal = original.statements[-1] if original.statements else None
        vex = cast(pyvex.IRSB, record.vex)
        mark = _terminal_instruction_mark_8616(vex)
        if not isinstance(terminal, ailment.Stmt.SideEffectStatement):
            raise PipelineHardError("scoped Clinic CALL terminal absent", layer="frontend")
        if (not isinstance(terminal.expr, ailment.Expr.Call)
                or vex.jumpkind != "Ijk_Call" or mark is None
                or mark[0] != call.instruction.addr
                or terminal.tags.get("ins_addr") != call.instruction.addr):
            raise PipelineHardError("scoped Clinic CALL source differs", layer="frontend")
        expression = terminal.expr
        carrier = ailment.Stmt.Jump(terminal.idx, expression.target)
        if _bound_next_operand_8616(carrier, vex.next, vex.tyenv) is not True:
            raise PipelineHardError("scoped Clinic CALL operand differs", layer="frontend")
        offset = mark[0] - record.addr
        encoding = record.source_bytes[offset:]
        if (len(encoding) != 3 or encoding[0] != 0xE8
                or call.next_addr != mark[0] + 3
                or call.target != call.next_addr + int.from_bytes(encoding[1:], "little", signed=True)):
            raise PipelineHardError("scoped Clinic CALL encoding differs", layer="frontend")
        replacement = expression.copy()
        replacement.target = ailment.Expr.Const(
            boundary._ail_manager.next_atom(), call.target, expression.target.bits,
        )
        statement = terminal.copy()
        statement.expr = replacement
        converted[(record.addr, record.size)] = original.copy(
            statements=[*original.statements[:-1], statement],
        )


def prepare_clinic_scoped_partition_8616(
    clinic: object, entry: DeclaredEntryPipeline8616 | NativeNearCallPipeline8616,
) -> None:
    """Install the authenticated native partition before any AIL conversion.

    A selector-dependent incoming edge can target an instruction inside an
    unscoped block. Only the native boundary's independently decoded partition
    can split it; no converted statement or rendered text supplies authority.
    """
    from angr.codenode import BlockNode

    from inertia.ir.declared_entry_pipeline import (
        DeclaredEntryPipeline8616 as _DeclaredEntryPipeline8616,
    )
    from inertia.ir.declared_entry_pipeline import (
        retain_declared_entry_pipeline_8616,
    )
    from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616 as _NativeNearCallPipeline8616

    if type(entry) is not _DeclaredEntryPipeline8616 and type(entry) is not _NativeNearCallPipeline8616:
        raise TypeError("scoped Clinic partition requires a proved conditional entry")
    boundary = cast(_Clinic8616, clinic)
    projection = entry.view.cfg_projection_for(entry.scope)
    if (entry.scope.project is not boundary.project
            or entry.view.boundary.project is not boundary.project
            or entry.bundle.artifact is not entry.view.source_artifact
            or boundary.function.addr != entry.bundle.artifact.function_addr):
        raise PipelineHardError("scoped Clinic partition authority differs", layer="frontend")
    if projection is None or any(projection.pending.values()):
        raise PipelineHardError("scoped Clinic partition is unproved", layer="frontend")
    native = entry.view.boundary
    for node in boundary._func_graph.nodes:
        if (node.addr not in native.reachable_instruction_addrs
                or not native.decode_start <= node.addr < node.addr + node.size <= native.decode_end):
            raise PipelineHardError("scoped Clinic original block is foreign", layer="frontend")
    graph = boundary._func_graph.copy()
    graph.clear()
    decoded_blocks = (cast(_Node8616, block) for block in native.blocks)
    nodes = {block.addr: BlockNode(block.addr, block.size) for block in decoded_blocks}
    if len(nodes) != len(native.blocks) or set(nodes) != set(projection.successors):
        raise PipelineHardError("scoped Clinic native partition differs", layer="frontend")
    graph.add_nodes_from(nodes.values())
    for addr, targets in projection.successors.items():
        for target in targets:
            graph.add_edge(nodes[addr], nodes[target], type="transition")
    receipt = ClinicScopedPartition8616(
        entry, boundary.project, boundary.function,
        _graph_surface(boundary.function.graph), _graph_surface(graph),
    )
    boundary._func_graph = graph
    # Dynamic boundary: retain this typed conditional receipt on third-party Clinic.
    boundary._inertia_clinic_scoped_partition_8616 = receipt
    retain_declared_entry_pipeline_8616(clinic, entry)


def handoff_clinic_declared_entry_8616(clinic: object, codegen: object, project: object) -> None:
    """Rebind a Clinic-consumed conditional entry to the fresh structuring codegen.

    Clinic already proved and retained the identical typed input through the
    source-bound consumption route; attaching that same object to the fresh
    codegen lets the ordinary ``prepare_declared_entry_pipeline_8616`` consumer
    authenticate and reuse it instead of re-proving the same native surface.
    The handoff copies nothing and re-proves nothing: it only checks that the
    retained entry still owns this Clinic's project, function, original
    artifact, scope and installed source, and that the destination codegen's
    exact function address equals the retained source function. A stale,
    foreign or copied binding refuses; a Clinic that consumed no entry keeps
    the ordinary unscoped route untouched.
    """
    from inertia.ir.declared_entry_pipeline import (
        _retained_input_8616,
        retain_declared_entry_pipeline_8616,
    )
    from inertia.ir.entry_domain_call_preservation import Real16InvocationSource8616

    entry = _retained_input_8616(clinic)
    if entry is None:
        return
    boundary = cast(_Clinic8616, clinic)
    function_addr = entry.bundle.artifact.function_addr
    if boundary.project is not project or entry.view.boundary.project is not project:
        raise PipelineHardError("scoped Clinic entry handoff project differs", layer="frontend",
                                function_addr=function_addr)
    if boundary.function.addr != function_addr:
        raise PipelineHardError("scoped Clinic entry handoff function differs", layer="frontend",
                                function_addr=function_addr)
    # Dynamic third-party boundary: a real codegen always retains ``cfunc``.
    destination = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if type(destination) is not int or destination != function_addr:
        raise PipelineHardError("declared entry handoff destination differs", layer="frontend",
                                function_addr=function_addr)
    if entry.bundle.artifact is not entry.view.source_artifact:
        raise PipelineHardError("declared entry handoff artifact differs", layer="frontend",
                                function_addr=function_addr)
    # Dynamic third-party boundary: peek installed authority without intake.
    installed = getattr(project, "_inertia_real16_invocation_source_8616", None)
    if installed is not None and type(installed) is not Real16InvocationSource8616:
        raise TypeError("installed invocation source must be typed")
    if installed is None or installed is not entry.source:
        raise PipelineHardError("declared entry handoff source differs", layer="frontend",
                                function_addr=function_addr)
    _require_handoff_scope_8616(clinic, entry, project)
    existing = _retained_input_8616(codegen)
    if existing is not None and existing is not entry:
        raise PipelineHardError("declared entry handoff conflicts with consumed input",
                                layer="frontend", function_addr=function_addr)
    retain_declared_entry_pipeline_8616(codegen, entry)


def _require_handoff_scope_8616(
    clinic: object, entry: DeclaredEntryInput8616, project: object,
) -> None:
    """Check retained premise identities without replaying native proof at handoff."""
    from inertia.ir.declared_entry_pipeline import (
        DeclaredEntryPipeline8616 as _DeclaredEntryPipeline8616,
    )
    from inertia.ir.declared_entry_pipeline import (
        UnprovedDeclaredEntry8616,
    )
    from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616 as _NativeNearCallPipeline8616

    function_addr = entry.bundle.artifact.function_addr
    if type(entry) is _NativeNearCallPipeline8616:
        _require_handoff_partition_8616(clinic, entry)
        native_entry = entry
        if (native_entry.scope.project is not project
                or native_entry.scope.artifact is not native_entry.bundle.artifact
                or native_entry.view.near_call_scope is not native_entry.scope):
            raise PipelineHardError("native entry handoff scope differs", layer="frontend",
                                    function_addr=function_addr)
    elif type(entry) is _DeclaredEntryPipeline8616:
        _require_handoff_partition_8616(clinic, entry)
        if (entry.scope.project is not project
                or entry.view.invocation_scope is not entry.scope):
            raise PipelineHardError("declared entry handoff scope differs", layer="frontend",
                                    function_addr=function_addr)
    elif type(entry) is UnprovedDeclaredEntry8616:
        if entry.view.invocation_scope is not None or entry.view.near_call_scope is not None:
            raise PipelineHardError("unproved entry handoff carries scope", layer="frontend",
                                    function_addr=function_addr)


def _require_handoff_partition_8616(
    clinic: object, entry: DeclaredEntryPipeline8616 | NativeNearCallPipeline8616,
) -> None:
    """Bind the donated input to Clinic's original native partition receipt.

    This transfers a pending input, not proof authority. The ordinary IR
    consumer still authenticates current native bytes before consuming it;
    post-Clinic optimized AIL is not mistaken for the original source graph.
    """
    boundary = cast(_Clinic8616, clinic)
    # Dynamic third-party boundary: older/unscoped Clinic objects lack a receipt.
    receipt = getattr(clinic, "_inertia_clinic_scoped_partition_8616", None)
    if (type(receipt) is not ClinicScopedPartition8616
            or receipt.entry is not entry or receipt.project is not boundary.project
            or receipt.function is not boundary.function
            or receipt.source_graph != _graph_surface(boundary.function.graph)):
        raise PipelineHardError("Clinic entry handoff partition differs", layer="frontend")


@dataclass(frozen=True, slots=True)
class ClinicScopedPartition8616:
    """Bind unchanged source and consuming graphs to one explicit native entry."""
    entry: DeclaredEntryPipeline8616 | NativeNearCallPipeline8616 | EntryJumpTransportProof8616
    project: object
    function: object
    source_graph: ClinicControlSurface8616
    consuming_graph: ClinicControlSurface8616

    def authenticates(self, clinic: object, context: ClinicConversionContext8616) -> bool:
        """Check both graph snapshots and their exact typed entry authority."""
        boundary = cast(_Clinic8616, clinic)
        from inertia.ir.entry_jump_transport import EntryJumpTransportProof8616

        entry = self.entry
        authority_project = (entry.project
                             if type(entry) is EntryJumpTransportProof8616
                             else cast(_ScopedEntryLike8616, entry).scope.project)
        identities = (boundary.project is self.project is context.project
                      and boundary.function is self.function is context.function
                      and authority_project is self.project)
        surfaces = (_graph_surface(boundary.function.graph) == self.source_graph
                    and _graph_surface(boundary._func_graph) == self.consuming_graph == context.graph)
        return identities and surfaces


def prepare_clinic_universal_partition_8616(clinic: object) -> None:
    """Split only witnessed native extents under complete universal control proof.

    This uses the same entry-domain proof as post-conversion transport. The
    original recovered function graph stays unchanged; every later conversion
    context binds both graphs, and outgoing transport freshly proves the native
    graph again before any terminal target can be consumed.
    """
    from angr.codenode import BlockNode

    from inertia.ir.entry_jump_transport import prove_entry_jump_transport_8616

    from .frontend_boundary_transport import capture_function_boundary_8616, restore_function_boundary_8616

    boundary = cast(_Clinic8616, clinic)
    # Dynamic third-party boundary: a conditional partition already owns Clinic.
    if getattr(clinic, "_inertia_clinic_scoped_partition_8616", None) is not None:
        return
    witness = capture_function_boundary_8616(boundary.project, boundary.function)
    if witness is None:
        return
    native = restore_function_boundary_8616(boundary.project, witness)
    if native is None:
        return
    source_graph = _graph_surface(boundary.function.graph)
    original_graph = _graph_surface(boundary._func_graph)
    product = prove_entry_jump_transport_8616(boundary.project, boundary.function)
    if not _universal_product_complete_8616(product):
        return
    assert product.application is not None
    graph = boundary._func_graph.copy()
    graph.clear()
    decoded_blocks = (cast(_Node8616, block) for block in native.blocks)
    nodes = {block.addr: BlockNode(block.addr, block.size) for block in decoded_blocks}
    blocks = product.application.blocks
    if len(nodes) != len(blocks) or set(nodes) != {block.addr for block in blocks}:
        return
    if any(target not in nodes for block in blocks for target in block.successor_addrs):
        return
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[block.addr], nodes[target])
                         for block in blocks for target in block.successor_addrs)
    if (source_graph != _graph_surface(boundary.function.graph)
            or original_graph != _graph_surface(boundary._func_graph)
            or capture_function_boundary_8616(boundary.project, boundary.function) != witness):
        raise PipelineHardError("universal Clinic partition source changed", layer="frontend")
    if original_graph == _graph_surface(graph):
        return
    boundary._func_graph = graph
    boundary._inertia_clinic_scoped_partition_8616 = ClinicScopedPartition8616(
        product, boundary.project, boundary.function, source_graph, _graph_surface(graph))


def _universal_product_complete_8616(product: EntryJumpTransportProof8616) -> bool:
    """Require every candidate to have an unconditional source-bound admission."""
    if product.refusal is not None or product.proof is None or product.application is None:
        return False
    admitted = product.admitted_terminal_jumps()
    return (not product.proof.stats.failure_count and bool(admitted)
            and len(admitted) == len(product.pending_terminal_jumps())
            and all(jump.invocation_scope is None and jump.invocation is None
                    and jump.near_call_scope is None and not jump.call_dependencies
                    for jump in admitted))
