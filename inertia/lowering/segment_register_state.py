"""Lower proven architectural segment-register live-ins to C runtime state.

Layer: Types/Lowering.
Responsibility: materialize IR-proven CS/DS/ES/SS live-ins as explicit C globals.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

An unknown segment value at function entry is still a defined architectural
input. Emitting it as an automatic C local creates false uninitialized reads
and loses machine-state identity. This pass consumes the typed IR segment-state
artifact, replaces only proven live-in segment carriers with runtime globals,
retains exact alias-proven input versions across writes, and removes stale
automatic declarations. It does not infer segment
identity from rendered C or relax validation for unproven carriers.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimTemporaryVariable, SimVariable

from inertia.ir.core import SegmentOrigin
from inertia.ir.segment_state import SegmentStateArtifact, SegmentValueKind8616
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from inertia.lowering.terminal_return_expressions import contains_effectful_call_8616
from inertia.pipeline.errors import PipelineHardError

log: logging.Logger = logging.getLogger(__name__)

__all__ = [
    "SegmentRegisterStateLoweringStats8616",
    "is_runtime_segment_state_symbol_8616",
    "lower_architectural_segment_register_state_8616",
    "runtime_segment_name_for_variable_8616",
    "runtime_segment_push_source_cvar_8616",
    "runtime_segment_state_cvar_8616",
    "runtime_segment_state_symbol_8616",
    "runtime_segment_state_variable_matches_8616",
]

_RUNTIME_SEGMENT_STATE_SYMBOLS_8616: dict[str, str] = {
    "cs": "inertia_cs",
    "ds": "inertia_ds",
    "es": "inertia_es",
    "ss": "inertia_ss",
}
_RUNTIME_SEGMENT_STATE_ADDRESSES_8616: dict[str, int] = {
    name: 0x1_0000 + index * 2
    for index, name in enumerate(_RUNTIME_SEGMENT_STATE_SYMBOLS_8616)
}


class _ArchSegmentRegisters8616(Protocol):
    """Third-party architecture fields needed to classify physical registers."""

    register_names: Mapping[int, str]


class _ProjectSegmentRegisters8616(Protocol):
    """Third-party project fields needed by segment-state lowering."""

    arch: _ArchSegmentRegisters8616


class _SegmentVariableManager8616(Protocol):
    """Alias-owned input identities exposed by the native variable manager."""

    def input_variables(self, exclude_specials: bool = True) -> list[SimVariable]:
        """Return read input versions, excluding definitions and phi variables."""
        ...

    def set_variable_type(self, variable: SimVariable, variable_type: SimType) -> None:
        """Publish the exact type of a newly retained entry snapshot."""
        ...


class _CFunctionSegmentRegisters8616(Protocol):
    """Third-party C function fields mutated by segment-state lowering."""

    addr: int
    statements: object
    unified_local_vars: MutableMapping[object, object]
    variables_in_use: MutableMapping[SimVariable, structured_c.CVariable]
    variable_manager: _SegmentVariableManager8616

    def refresh(self) -> None:
        """Refresh local declarations after adding typed snapshot storage."""
        ...


class _CodegenSegmentRegisters8616(Protocol):
    """Dynamic codegen contract consumed by segment-state lowering."""

    cfunc: _CFunctionSegmentRegisters8616 | None
    project: _ProjectSegmentRegisters8616 | None
    _inertia_segment_state_artifact: SegmentStateArtifact
    _inertia_segment_register_state_lowering_stats_8616: SegmentRegisterStateLoweringStats8616


class _DirtySegmentCarrier8616(Protocol):
    """Dynamic fields carried by an angr virtual-variable expression."""

    category: object
    reg: object
    name: object
    varid: object
    oident: object


@dataclass(frozen=True, slots=True)
class SegmentRegisterStateLoweringStats8616:
    """Closed evidence counters for architectural segment-state lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _SegmentInputCaptureFailure8616(StrEnum):
    """Typed reasons why a register input cannot be retained as an entry value."""

    CALL_BOUNDARY_UNPROVEN = "call_boundary_unproven"
    ENTRY_ORDER_UNPROVEN = "entry_order_unproven"


def runtime_segment_state_symbol_8616(segment_name: str) -> str | None:
    """Return the C runtime-state symbol for one architectural segment."""
    return _RUNTIME_SEGMENT_STATE_SYMBOLS_8616.get(segment_name.strip().lower())


def is_runtime_segment_state_symbol_8616(name: str) -> bool:
    """Return whether a C name belongs to the segment-state runtime contract."""
    return name in _RUNTIME_SEGMENT_STATE_SYMBOLS_8616.values()


def runtime_segment_name_for_variable_8616(variable: object) -> str | None:
    """Identify lowered state by its owned category and reserved symbol, not name alone."""
    if not isinstance(variable, SimMemoryVariable) or variable.category != "inertia_segment_state":
        return None
    variable_name = variable.name
    if not isinstance(variable_name, str):
        return None
    for segment_name, symbol in _RUNTIME_SEGMENT_STATE_SYMBOLS_8616.items():
        if variable_name == symbol:
            return segment_name
    return None


def runtime_segment_state_cvar_8616(
    segment_name: str,
    *,
    codegen: object,
    variable_type: SimType | None,
    function_addr: int,
) -> structured_c.CVariable | None:
    """Materialize one proven architectural segment as explicit runtime state."""
    normalized_name = segment_name.strip().lower()
    symbol = _RUNTIME_SEGMENT_STATE_SYMBOLS_8616.get(normalized_name)
    address = _RUNTIME_SEGMENT_STATE_ADDRESSES_8616.get(normalized_name)
    if symbol is None or address is None:
        return None
    return structured_c.CVariable(
        SimMemoryVariable(
            address,
            2,
            name=symbol,
            region=function_addr,
            category="inertia_segment_state",
        ),
        variable_type=variable_type,
        codegen=codegen,
    )


def runtime_segment_state_variable_matches_8616(
    variable: object, segment_name: str, function_addr: int,
) -> bool:
    """Check an owned runtime carrier without allocating codegen nodes.

    This is the observational counterpart of runtime_segment_state_cvar_8616;
    metadata and coordinates must agree with that single construction owner.
    A spelling alone cannot identify architectural state.
    """
    normalized = segment_name.strip().lower()
    address = _RUNTIME_SEGMENT_STATE_ADDRESSES_8616.get(normalized)
    symbol = _RUNTIME_SEGMENT_STATE_SYMBOLS_8616.get(normalized)
    if type(variable) is not SimMemoryVariable or address is None or symbol is None:
        return False
    memory_variable = cast(SimMemoryVariable, variable)
    actual = (memory_variable.addr, memory_variable.size, memory_variable.name,
              memory_variable.region, memory_variable.category, memory_variable.ident)
    return type(function_addr) is int and actual == (
        address, 2, symbol, function_addr, "inertia_segment_state", None,
    )


def runtime_segment_push_source_cvar_8616(
    segment_name: str,
    *,
    codegen: object,
    variable_type: SimType | None,
    function_addr: int,
) -> structured_c.CVariable | None:
    """Materialize one instruction-proven segment PUSH as explicit runtime state."""
    return runtime_segment_state_cvar_8616(
        segment_name,
        codegen=codegen,
        variable_type=variable_type,
        function_addr=function_addr,
    )


def _physical_segment_name_8616(
    variable: object,
    project: _ProjectSegmentRegisters8616,
) -> str | None:
    """Return a supported segment name for one physical register variable."""
    if (
        not isinstance(variable, SimRegisterVariable)
        or not isinstance(variable.reg, int)
        or variable.size != 2
    ):
        return None
    register_name = project.arch.register_names.get(variable.reg)
    if not isinstance(register_name, str):
        return None
    normalized = register_name.lower()
    return normalized if normalized in _RUNTIME_SEGMENT_STATE_SYMBOLS_8616 else None


def _cvar_segment_name_8616(
    cvar: structured_c.CVariable,
    project: _ProjectSegmentRegisters8616,
) -> str | None:
    """Return the physical segment identity carried by one C variable."""
    for variable in (cvar.unified_variable, cvar.variable):
        segment_name = _physical_segment_name_8616(variable, project)
        if segment_name is not None:
            return segment_name
    return None


def _dirty_segment_name_8616(
    expression: structured_c.CDirtyExpression,
    project: _ProjectSegmentRegisters8616,
) -> str | None:
    """Return a segment identity from a register-origin virtual variable."""
    dirty = cast(_DirtySegmentCarrier8616, expression.dirty)
    try:
        category = dirty.category
        original_identifier = dirty.oident
    except AttributeError:
        return None
    if category is not VirtualVariableCategory.REGISTER or not isinstance(
        original_identifier,
        int,
    ):
        return None
    register_name = project.arch.register_names.get(original_identifier)
    if not isinstance(register_name, str):
        return None
    normalized = register_name.lower()
    return normalized if normalized in _RUNTIME_SEGMENT_STATE_SYMBOLS_8616 else None


def _entry_live_in_segments_8616(
    artifact: SegmentStateArtifact,
    function_addr: int,
) -> frozenset[str]:
    """Return segment identities proven as architectural function live-ins."""
    entry_state = artifact.entry_states.get(function_addr, {})
    return frozenset(
        segment_name
        for segment_name, state in entry_state.items()
        if segment_name in _RUNTIME_SEGMENT_STATE_SYMBOLS_8616
        and state.origin is SegmentOrigin.PROVEN
        and state.value_kind is SegmentValueKind8616.ARCHITECTURAL_LIVE_IN
        and state.source == segment_name
    )


def _runtime_segment_cvar_8616(
    segment_name: str,
    source: structured_c.CVariable,
    function_addr: int,
) -> structured_c.CVariable:
    """Build the explicit global C carrier for one architectural segment."""
    materialized = runtime_segment_push_source_cvar_8616(
        segment_name,
        codegen=source.codegen,
        variable_type=source.variable_type,
        function_addr=function_addr,
    )
    if materialized is None:
        raise ValueError(f"unsupported architectural segment register: {segment_name!r}")
    return materialized


def _runtime_segment_dirty_cvar_8616(
    segment_name: str,
    source: structured_c.CDirtyExpression,
    function_addr: int,
) -> structured_c.CVariable:
    """Build runtime segment state from a register-origin virtual variable."""
    materialized = runtime_segment_push_source_cvar_8616(
        segment_name,
        codegen=source.codegen,
        variable_type=None,
        function_addr=function_addr,
    )
    if materialized is None:
        raise ValueError(f"unsupported architectural segment register: {segment_name!r}")
    return materialized


def _dirty_carrier_debug_8616(
    dirty: _DirtySegmentCarrier8616,
) -> tuple[str | None, int | None, int | None]:
    """Extract the dynamic dirty-carrier fields for debug accounting."""
    try:
        dirty_name = dirty.name
    except AttributeError:
        dirty_name = None
    try:
        dirty_varid = dirty.varid
    except AttributeError:
        dirty_varid = None
    try:
        dirty_oident = dirty.oident
    except AttributeError:
        dirty_oident = None
    return (
        dirty_name if isinstance(dirty_name, str) else None,
        dirty_varid if isinstance(dirty_varid, int) else None,
        dirty_oident if isinstance(dirty_oident, int) else None,
    )


@dataclass
class _SegmentStateScan8616:
    """Replace proven segment live-ins and census every visited node."""

    project: _ProjectSegmentRegisters8616
    function_addr: int
    live_in_segments: frozenset[str] | set[str]
    raw_node_ids: set[int] = field(default_factory=set)
    classified_node_ids: set[int] = field(default_factory=set)
    materialized_node_ids: set[int] = field(default_factory=set)
    debug_unclassified_registers: set[tuple[str | None, int | None, int | None]] = field(default_factory=set)
    debug_dirty_segment_carriers: set[tuple[str, str | None, int | None, int | None]] = field(default_factory=set)

    def _transform_dirty(self, node: structured_c.CDirtyExpression) -> object:
        """Replace one proven register-origin dirty segment carrier."""
        dirty = cast(_DirtySegmentCarrier8616, node.dirty)
        segment_name = _dirty_segment_name_8616(node, self.project)
        if segment_name is None:
            return node
        self.raw_node_ids.add(id(node))
        dirty_name, dirty_varid, dirty_oident = _dirty_carrier_debug_8616(dirty)
        self.debug_dirty_segment_carriers.add(
            (segment_name, dirty_name, dirty_varid, dirty_oident)
        )
        if segment_name not in self.live_in_segments:
            return node
        self.classified_node_ids.add(id(node))
        self.materialized_node_ids.add(id(node))
        return _runtime_segment_dirty_cvar_8616(segment_name, node, self.function_addr)

    def _transform_cvar(self, node: structured_c.CVariable) -> object:
        """Replace one proven architectural segment CVariable."""
        segment_name = _cvar_segment_name_8616(node, self.project)
        if segment_name is None:
            variable = node.variable
            if isinstance(variable, SimRegisterVariable):
                self.debug_unclassified_registers.add(
                    (
                        variable.name if isinstance(variable.name, str) else None,
                        variable.reg if isinstance(variable.reg, int) else None,
                        variable.size if isinstance(variable.size, int) else None,
                    )
                )
            return node
        self.raw_node_ids.add(id(node))
        if segment_name not in self.live_in_segments:
            return node
        self.classified_node_ids.add(id(node))
        self.materialized_node_ids.add(id(node))
        return _runtime_segment_cvar_8616(segment_name, node, self.function_addr)

    def transform(self, node: object) -> object:
        """Dispatch one C node through the segment-state replacement arms."""
        if isinstance(node, structured_c.CDirtyExpression):
            return self._transform_dirty(node)
        if not isinstance(node, structured_c.CVariable):
            return node
        return self._transform_cvar(node)


def _capture_segment_entry_versions_8616(
    codegen: object,
    function: _CFunctionSegmentRegisters8616,
    project: _ProjectSegmentRegisters8616,
    live_ins: frozenset[str],
) -> set[int]:
    """Retain exact alias-proven entry values before architectural mutations.

    The native input registry excludes written and phi versions. A physical
    register name alone never authorizes a snapshot. Capture all uses of the
    same input identity once before local writes. An intervening CALL needs
    independent origin evidence: the input registry alone does not model its
    implicit architectural writes.
    """
    root = function.statements
    nodes = tuple(_iter_c_nodes_deep_8616(root))
    written = {
        _cvar_segment_name_8616(node.lhs, project)
        for node in nodes
        if isinstance(node, structured_c.CAssignment)
        and isinstance(node.lhs, structured_c.CVariable)
    }
    threatened = live_ins.intersection(written)
    if not threatened:
        return set()
    inputs = set(function.variable_manager.input_variables())
    sources: dict[SimRegisterVariable, structured_c.CVariable] = {}
    captured_ids: set[int] = set()
    for node in nodes:
        if (
            isinstance(node, structured_c.CVariable)
            and isinstance(node.variable, SimRegisterVariable)
            and node.variable.ident is not None
            and node.variable in inputs
            and _physical_segment_name_8616(node.variable, project) in threatened
        ):
            sources.setdefault(node.variable, node)
            captured_ids.add(id(node))
    if not sources:
        return set()
    if contains_effectful_call_8616(root):
        raise PipelineHardError(
            "segment input origin across CALL is unproven",
            layer="Types", function_addr=function.addr,
            details=_SegmentInputCaptureFailure8616.CALL_BOUNDARY_UNPROVEN,
        )
    if not isinstance(root, structured_c.CStatements):
        raise PipelineHardError(
            "segment entry snapshots require an ordered function entry",
            layer="Types", function_addr=function.addr,
            details=_SegmentInputCaptureFailure8616.ENTRY_ORDER_UNPROVEN,
        )
    variables = [*function.variables_in_use, *(
        node.variable for node in nodes if isinstance(node, structured_c.CVariable)
    )]
    next_id = 1 + max(
        (variable.tmp_id for variable in variables if isinstance(variable, SimTemporaryVariable)),
        default=-1,
    )
    replacements: dict[SimRegisterVariable, structured_c.CVariable] = {}
    assignments: list[structured_c.CAssignment] = []
    for variable, source in sources.items():
        segment = _physical_segment_name_8616(variable, project)
        assert segment is not None
        temporary = SimTemporaryVariable(next_id, 2)
        next_id += 1
        value = structured_c.CVariable(temporary, variable_type=source.variable_type, codegen=codegen)
        replacements[variable] = value
        assignments.append(structured_c.CAssignment(
            value, _runtime_segment_cvar_8616(segment, source, function.addr), codegen=codegen,
        ))
        function.variables_in_use[temporary] = value
        function.variable_manager.set_variable_type(temporary, source.variable_type)

    def replace_input(node: object) -> object:
        """Replace only the exact alias input; leave later register versions intact."""
        if isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimRegisterVariable):
            return replacements.get(node.variable, node)
        return node

    _replace_c_children_8616(root, replace_input)
    root.statements = [*assignments, *root.statements]
    function.refresh()
    return captured_ids


def lower_architectural_segment_register_state_8616(codegen: object) -> bool:
    """Materialize IR-proven segment live-ins as explicit C runtime globals."""
    typed_codegen = cast(_CodegenSegmentRegisters8616, codegen)
    cfunc = typed_codegen.cfunc
    project = typed_codegen.project
    try:
        artifact = typed_codegen._inertia_segment_state_artifact
    except AttributeError:
        artifact = None
    if cfunc is None or project is None or not isinstance(artifact, SegmentStateArtifact):
        typed_codegen._inertia_segment_register_state_lowering_stats_8616 = (
            SegmentRegisterStateLoweringStats8616(0, 0, 0, 0, 0)
        )
        return False

    live_ins = _entry_live_in_segments_8616(artifact, cfunc.addr)
    try:
        captured_ids = _capture_segment_entry_versions_8616(codegen, cfunc, project, live_ins)
    except PipelineHardError:
        typed_codegen._inertia_segment_register_state_lowering_stats_8616 = (
            SegmentRegisterStateLoweringStats8616(1, 1, 1, 0, 1)
        )
        raise
    scan = _SegmentStateScan8616(
        project=project,
        function_addr=cfunc.addr,
        live_in_segments=live_ins,
        raw_node_ids=set(captured_ids),
        classified_node_ids=set(captured_ids),
        materialized_node_ids=set(captured_ids),
    )
    root = cfunc.statements
    new_root = scan.transform(root)
    changed = bool(captured_ids) or new_root is not root
    if changed:
        cfunc.statements = new_root
    if _replace_c_children_8616(cfunc.statements, scan.transform):
        changed = True

    for variable in tuple(cfunc.unified_local_vars):
        segment_name = _physical_segment_name_8616(variable, project)
        if segment_name in scan.live_in_segments:
            del cfunc.unified_local_vars[variable]
            changed = True

    classified_count = len(scan.classified_node_ids)
    materialized_count = len(scan.materialized_node_ids)
    typed_codegen._inertia_segment_register_state_lowering_stats_8616 = (
        SegmentRegisterStateLoweringStats8616(
            raw_fact_count=len(scan.raw_node_ids),
            normalized_fact_count=len(scan.raw_node_ids),
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=max(classified_count - materialized_count, 0),
        )
    )
    if os.environ.get("INERTIA_DEBUG_SEGMENT_REGISTER_STATE"):
        log.warning(
            "[segment-register-state] function=%#x live_ins=%s raw=%d classified=%d "
            "materialized=%d dirty_candidates=%s unclassified_registers=%s",
            cfunc.addr,
            tuple(sorted(scan.live_in_segments)),
            len(scan.raw_node_ids),
            classified_count,
            materialized_count,
            tuple(sorted(scan.debug_dirty_segment_carriers)),
            tuple(
                sorted(
                    scan.debug_unclassified_registers,
                    key=lambda item: (
                        item[0] or "",
                        item[1] if item[1] is not None else -1,
                        item[2] if item[2] is not None else -1,
                    ),
                )
            ),
        )
    return changed
