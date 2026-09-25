"""Propagate proven terminal callee return types into caller prototypes.

Layer: Types/Lowering.
Responsibility: materialize a caller return type only when binary CFG evidence
proves that one typed direct callee result reaches the caller return unchanged.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Protocol, cast

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimType, SimTypeBottom, SimTypeFunction, SimTypeShort
from archinfo import Arch

from ..annotations import ANNOTATION_KEY
from ..call_target_identity import resolve_x86_16_call_target_function_8616
from ..callsite_summary import CallerReturnUseVerdict8616
from ..semantics.branch_target_return import TerminalAxReturnEffectKind8616, terminal_ax_return_effect_8616
from ..semantics.terminal_call_paths import (
    TerminalCallPathCallbacks8616,
    TerminalCallPathStatus8616,
    angr_terminal_call_path_callbacks_8616,
    prove_terminal_call_path_8616,
)
from ..semantics.terminal_return_storage import TerminalReturnStorage8616, terminal_return_storage_8616
from .argument_frame_base import msc_calling_convention_for_function_8616
from .authoritative_function_prototypes import publish_authoritative_function_prototype_8616
from .return_type_evidence import proven_function_result_observation_8616

__all__ = (
    "CalleeResultContract8616",
    "TerminalCallReturnTypeEvidence8616",
    "TerminalCallReturnTypeResult8616",
    "TerminalCallReturnTypeSource8616",
    "apply_terminal_call_return_type_evidence_8616",
    "callee_result_contract_8616",
    "collect_terminal_call_return_type_evidence_8616",
)


class _ProjectSurface8616(Protocol):
    """Third-party project fields used by terminal return typing."""

    arch: Arch


class _FunctionSurface8616(Protocol):
    """Third-party function fields used by prototype materialization."""

    addr: int
    prototype: object | None
    calling_convention: object | None
    info: object
    is_prototype_guessed: bool
    prototype_source: PrototypeSource


class _SignedTypeSurface8616(Protocol):
    """Optional signedness field exposed by concrete angr integer types."""

    signed: bool | None


class CalleeResultContract8616(Enum):
    """Typed result contract proven for one callee."""

    VALUE = "value"
    VOID = "void"
    UNKNOWN = "unknown"


class TerminalCallReturnTypeSource8616(Enum):
    """Evidence source for one terminal call-result return type."""

    CALLEE_PROTOTYPE = "callee_prototype"
    CALLEE_TERMINAL_AX_WORD = "callee_terminal_ax_word"


@dataclass(frozen=True, slots=True)
class TerminalCallReturnTypeEvidence8616:
    """Closed evidence loop for terminal call-result return typing."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    return_type: SimType | None = None
    call_ins_addrs: tuple[int, ...] = ()
    target_addrs: tuple[int, ...] = ()
    sources: tuple[TerminalCallReturnTypeSource8616, ...] = ()
    inspected_target_addrs: tuple[int, ...] = ()

    def with_materialized_count(self, count: int) -> TerminalCallReturnTypeEvidence8616:
        """Return this evidence with its consumed-fact count."""
        return replace(self, materialized_count=count)


@dataclass(frozen=True, slots=True)
class TerminalCallReturnTypeResult8616:
    """Result of applying terminal call-result return typing."""

    changed: bool
    evidence: TerminalCallReturnTypeEvidence8616


def callee_result_contract_8616(callee: object | None) -> CalleeResultContract8616:
    """Classify only an explicit, non-guessed callee result type."""
    if callee is None:
        return CalleeResultContract8616.UNKNOWN
    callee_surface = cast(_FunctionSurface8616, callee)
    if callee_surface.is_prototype_guessed:
        return CalleeResultContract8616.UNKNOWN
    prototype = callee_surface.prototype
    if not isinstance(prototype, SimTypeFunction):
        return CalleeResultContract8616.UNKNOWN
    return_type = prototype.returnty
    if isinstance(return_type, SimTypeBottom):
        return (
            CalleeResultContract8616.VOID
            if return_type.label == "void"
            else CalleeResultContract8616.UNKNOWN
        )
    return (
        CalleeResultContract8616.VALUE
        if isinstance(return_type, SimType)
        else CalleeResultContract8616.UNKNOWN
    )


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Read one field at the dynamic third-party angr/Capstone boundary."""
    return getattr(obj, name, default)


def _instruction_surface_8616(insn: object) -> object:
    """Return the underlying Capstone instruction from an angr wrapper."""
    return _dynamic_attr_8616(insn, "insn", insn)


def _instruction_operands_8616(insn: object) -> tuple[object, ...]:
    """Return normalized operands for one third-party instruction."""
    raw_operands = _dynamic_attr_8616(_instruction_surface_8616(insn), "operands", ())
    return tuple(raw_operands) if isinstance(raw_operands, Iterable) else ()


def _direct_call_target_8616(insn: object) -> int | None:
    """Return one typed direct near/far call target from Capstone operands."""
    mnemonic = str(_dynamic_attr_8616(insn, "mnemonic", "")).lower()
    operands = _instruction_operands_8616(insn)
    if mnemonic == "call" and len(operands) == 1 and _dynamic_attr_8616(operands[0], "type", -1) == 2:
        immediate = _dynamic_attr_8616(operands[0], "imm", None)
        return immediate if isinstance(immediate, int) else None
    if mnemonic == "lcall" and len(operands) == 2 and all(
        _dynamic_attr_8616(operand, "type", -1) == 2 for operand in operands
    ):
        segment = _dynamic_attr_8616(operands[0], "imm", None)
        offset = _dynamic_attr_8616(operands[1], "imm", None)
        if isinstance(segment, int) and isinstance(offset, int):
            return ((segment & 0xFFFF) << 4) + (offset & 0xFFFF)
    return None


def _return_type_key_8616(return_type: SimType) -> tuple[type[SimType], int | None, bool | None]:
    """Return the ABI-relevant identity of one scalar return type."""
    try:
        size = return_type.size
    except (AttributeError, ValueError):
        size = None
    try:
        signed = cast(_SignedTypeSurface8616, return_type).signed
    except AttributeError:
        signed = None
    return type(return_type), size if isinstance(size, int) else None, signed if isinstance(signed, bool) else None


def _has_explicit_function_prototype_8616(function: _FunctionSurface8616) -> bool:
    """Protect user/signature prototypes while allowing inferred contracts to improve."""
    try:
        source = function.prototype_source
    except AttributeError:
        return function.prototype is not None and not function.is_prototype_guessed
    try:
        info = function.info
    except AttributeError:
        info = None
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
    annotated = annotations.get("prototype") if isinstance(annotations, Mapping) else None
    return isinstance(annotated, SimTypeFunction) or source >= PrototypeSource.SIGNATURES


def _scalar_callee_return_type_8616(
    project: object,
    target_addr: int,
) -> tuple[SimType | None, TerminalCallReturnTypeSource8616 | None]:
    """Resolve a scalar callee return from typed or exact AX-width evidence."""
    callee = resolve_x86_16_call_target_function_8616(project, target_addr)
    if callee is None:
        return None, None
    callee_surface = cast(_FunctionSurface8616, callee)
    prototype = callee_surface.prototype
    if prototype is None or callee_surface.is_prototype_guessed:
        if terminal_return_storage_8616(project, callee) is not TerminalReturnStorage8616.AX:
            return None, None
        project_surface = cast(_ProjectSurface8616, project)
        return (
            SimTypeShort(signed=False).with_arch(project_surface.arch),
            TerminalCallReturnTypeSource8616.CALLEE_TERMINAL_AX_WORD,
        )
    if not isinstance(prototype, SimTypeFunction) or not isinstance(prototype.returnty, SimType):
        return None, None
    return_type = prototype.returnty
    if isinstance(return_type, SimTypeBottom):
        return None, None
    try:
        size = return_type.size
    except (AttributeError, ValueError):
        return None, None
    if not isinstance(size, int) or not 0 < size <= 16:
        return None, None
    return return_type, TerminalCallReturnTypeSource8616.CALLEE_PROTOTYPE


@dataclass(slots=True)
class _CallReturnCensus8616:
    """Mutable census over terminal call-clobber sites in one function."""

    raw_count: int = 0
    normalized_count: int = 0
    failure_count: int = 0
    classified: list[tuple[int, int, SimType, TerminalCallReturnTypeSource8616]] = field(
        default_factory=list
    )
    inspected_targets: set[int] = field(default_factory=set)

    def scan(
        self,
        project: object,
        callbacks: TerminalCallPathCallbacks8616,
    ) -> None:
        """Classify every proven terminal call-clobber site in the function."""
        for block_addr, block_size in callbacks.function_block_ranges():
            try:
                block = callbacks.load_block(int(block_addr), int(block_size))
            except Exception:
                self.failure_count += 1
                continue
            capstone = _dynamic_attr_8616(block, "capstone", None) if block is not None else None
            raw_insns = _dynamic_attr_8616(capstone, "insns", ())
            insns = tuple(raw_insns) if isinstance(raw_insns, Iterable) else ()
            for insn in insns:
                self._scan_insn(project, insn, callbacks)

    def _scan_insn(
        self,
        project: object,
        insn: object,
        callbacks: TerminalCallPathCallbacks8616,
    ) -> None:
        """Classify one candidate terminal call-clobber instruction."""
        if terminal_ax_return_effect_8616(insn).kind is not TerminalAxReturnEffectKind8616.CALL_CLOBBER:
            return
        self.raw_count += 1
        call_ins_addr = _dynamic_attr_8616(insn, "address", None)
        if not isinstance(call_ins_addr, int):
            self.failure_count += 1
            return
        path_result = prove_terminal_call_path_8616(call_ins_addr, callbacks)
        if path_result.status is not TerminalCallPathStatus8616.PROVEN:
            return
        self.normalized_count += 1
        target_addr = _direct_call_target_8616(insn)
        if isinstance(target_addr, int):
            self.inspected_targets.add(target_addr)
        return_type, source = (
            _scalar_callee_return_type_8616(project, target_addr)
            if isinstance(target_addr, int)
            else (None, None)
        )
        if return_type is None or source is None or target_addr is None:
            self.failure_count += 1
            return
        self.classified.append((call_ins_addr, target_addr, return_type, source))


def collect_terminal_call_return_type_evidence_8616(
    project: object,
    function: object,
) -> TerminalCallReturnTypeEvidence8616:
    """Classify a terminal callee result only when this result is observed."""
    function_surface = cast(_FunctionSurface8616, function)
    callbacks = angr_terminal_call_path_callbacks_8616(project, function)
    census = _CallReturnCensus8616()
    census.scan(project, callbacks)
    raw_count = census.raw_count
    normalized_count = census.normalized_count
    failure_count = census.failure_count
    classified = census.classified
    inspected_targets = census.inspected_targets

    if (
        proven_function_result_observation_8616(project, function_surface.addr)
        is not CallerReturnUseVerdict8616.USED
    ):
        return TerminalCallReturnTypeEvidence8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=failure_count,
            inspected_target_addrs=tuple(sorted(inspected_targets)),
        )
    return_keys = {_return_type_key_8616(return_type) for _, _, return_type, _ in classified}
    if len(return_keys) > 1:
        return TerminalCallReturnTypeEvidence8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=failure_count + len(classified),
            inspected_target_addrs=tuple(sorted(inspected_targets)),
        )
    return TerminalCallReturnTypeEvidence8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=len(classified),
        failure_count=failure_count,
        return_type=classified[0][2] if classified else None,
        call_ins_addrs=tuple(call_addr for call_addr, _, _, _ in classified),
        target_addrs=tuple(target_addr for _, target_addr, _, _ in classified),
        sources=tuple(source for _, _, _, source in classified),
        inspected_target_addrs=tuple(sorted(inspected_targets)),
    )


def apply_terminal_call_return_type_evidence_8616(
    project: object,
    function: object,
) -> TerminalCallReturnTypeResult8616:
    """Materialize a terminal callee type for a proven observed result."""
    project_surface = cast(_ProjectSurface8616, project)
    function_surface = cast(_FunctionSurface8616, function)
    if project_surface.arch.name != "86_16":
        return TerminalCallReturnTypeResult8616(False, TerminalCallReturnTypeEvidence8616())
    existing = function_surface.prototype
    if existing is not None and _has_explicit_function_prototype_8616(function_surface):
        return TerminalCallReturnTypeResult8616(False, TerminalCallReturnTypeEvidence8616())
    evidence = collect_terminal_call_return_type_evidence_8616(project, function)
    if evidence.classified_fact_count == 0 or evidence.return_type is None:
        return TerminalCallReturnTypeResult8616(False, evidence)

    args = list(existing.args) if isinstance(existing, SimTypeFunction) else []
    arg_names = existing.arg_names if isinstance(existing, SimTypeFunction) else None
    variadic = existing.variadic if isinstance(existing, SimTypeFunction) else False
    rebuilt = SimTypeFunction(
        args,
        evidence.return_type,
        arg_names=arg_names,
        variadic=variadic,
    ).with_arch(project_surface.arch)
    old_key = (
        _return_type_key_8616(existing.returnty)
        if isinstance(existing, SimTypeFunction) and isinstance(existing.returnty, SimType)
        else None
    )
    new_key = _return_type_key_8616(evidence.return_type)
    changed = old_key != new_key or function_surface.is_prototype_guessed
    function_surface.prototype = rebuilt
    function_surface.prototype_source = PrototypeSource.CCA_DECOMPILER
    if function_surface.calling_convention is None:
        function_surface.calling_convention = msc_calling_convention_for_function_8616(
            project, function_surface
        )
    publish_authoritative_function_prototype_8616(
        project,
        function_surface.addr,
        rebuilt,
        source=PrototypeSource.CCA_DECOMPILER,
    )
    consumed = evidence.with_materialized_count(evidence.classified_fact_count)
    if consumed.classified_fact_count > 0 and consumed.materialized_count == 0:
        raise RuntimeError("terminal call return-type evidence was classified but not materialized")
    return TerminalCallReturnTypeResult8616(changed, consumed)
