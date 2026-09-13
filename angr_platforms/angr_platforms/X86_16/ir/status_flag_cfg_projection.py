"""Project function CFG and decoder evidence into status-flag Semantics.

Layer: IR.
Responsibility: adapt function-owned angr blocks, Capstone instructions, exact
CFG successors, and recursively proven direct-callee effects to the typed
status-flag liveness solver. Unknown targets and incomplete functions remain
unknown; this adapter never mutates lifting, AIL, Structuring, or rendered C.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from capstone import CS_OP_IMM

from ..analysis_helpers import canonicalize_x86_16_padding_call_target_8616
from ..semantics.status_flag_cfg_liveness import (
    StatusFlagCFGBlock8616,
    StatusFlagCFGInstruction8616,
    StatusFlagCFGLivenessArtifact8616,
    analyze_status_flag_cfg_liveness_8616,
    summarize_status_flag_cfg_effect_8616,
)
from ..semantics.status_flag_contracts import (
    STATUS_FLAGS_8616,
    StatusFlag8616,
    StatusFlagEffect8616,
)
from ..semantics.status_flag_liveness import (
    decoded_status_flag_instruction_8616,
    status_flag_effect_8616,
)
from .status_flag_binary_cfg import summarize_binary_status_flag_entry_reads_8616
from .vex_import import build_x86_16_ir_function_artifact

_CFG_SUPPRESSION_MNEMONICS_8616 = frozenset(
    {"adc", "add", "and", "cmp", "dec", "inc", "or", "sal", "sar", "sbb", "shl", "shr", "sub", "test", "xor"}
)


class _CapstoneOperandBoundary8616(Protocol):
    """Third-party Capstone operand fields used for direct call targets."""

    type: int
    imm: int


class _CapstoneInstructionBoundary8616(Protocol):
    """Third-party Capstone instruction fields exposed by an angr block."""

    address: int
    mnemonic: str
    operands: tuple[object, ...]


class _AngrCapstoneInstructionBoundary8616(Protocol):
    """Third-party angr wrapper around one Capstone instruction."""

    insn: _CapstoneInstructionBoundary8616


class _CapstoneBlockBoundary8616(Protocol):
    """Third-party angr disassembly collection."""

    insns: tuple[object, ...]


class _BlockBoundary8616(Protocol):
    """Third-party angr block fields consumed by the projection."""

    capstone: _CapstoneBlockBoundary8616


class _FactoryBoundary8616(Protocol):
    """Third-party angr block factory used at exact CFG addresses."""

    def block(self, address: int, *, opt_level: int = 0) -> _BlockBoundary8616:
        """Lift and disassemble one exact basic block."""
        ...


class _FunctionManagerBoundary8616(Protocol):
    """Third-party angr function manager lookup surface."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function at an exact canonical address."""
        ...


class _KnowledgeBaseBoundary8616(Protocol):
    """Third-party angr knowledge-base surface."""

    functions: _FunctionManagerBoundary8616


class _ProjectBoundary8616(Protocol):
    """Third-party angr project fields consumed by the projection."""

    factory: _FactoryBoundary8616
    kb: _KnowledgeBaseBoundary8616


class _LoadedObjectBoundary8616(Protocol):
    """Third-party loaded-image bounds used to recognize rebased call targets."""

    min_addr: int
    max_addr: int


class _LoaderBoundary8616(Protocol):
    """Third-party loader surface used by rebased exact slices."""

    main_object: _LoadedObjectBoundary8616


class _RebasedProjectBoundary8616(Protocol):
    """Owned exact-slice link back to the original loaded binary."""

    loader: _LoaderBoundary8616
    _inertia_original_project: object
    _inertia_original_linear_delta: int


class _FunctionBoundary8616(Protocol):
    """Third-party angr function identity consumed by the projection."""

    addr: int


@dataclass(frozen=True, slots=True)
class _DecodedInstructionAdapter8616:
    """Expose an angr Capstone instruction through the frontend decode contract."""

    cs: _CapstoneInstructionBoundary8616


@dataclass(frozen=True, slots=True)
class StatusFlagFunctionProjection8616:
    """Function-level CFG blocks, liveness decisions, and callee summaries."""

    function_address: int
    blocks: tuple[StatusFlagCFGBlock8616, ...]
    liveness: StatusFlagCFGLivenessArtifact8616
    callee_effects: tuple[tuple[int, StatusFlagEffect8616], ...]


def _direct_call_target_8616(
    instruction: _CapstoneInstructionBoundary8616,
) -> int | None:
    """Return one Capstone-proven immediate near-call target."""
    if instruction.mnemonic.lower() != "call" or len(instruction.operands) != 1:
        return None
    operand = cast(_CapstoneOperandBoundary8616, instruction.operands[0])
    try:
        return int(operand.imm) if operand.type == CS_OP_IMM else None
    except (AttributeError, TypeError, ValueError):
        return None


class _StatusFlagFunctionSummaryResolver8616:
    """Recursively resolve direct-callee effects with cycle-safe refusal."""

    def __init__(self, project: object) -> None:
        """Bind one project-local function and block namespace."""
        self._project = cast(_ProjectBoundary8616, project)
        self._project_object = project
        self._effect_cache: dict[int, StatusFlagEffect8616] = {}
        self._blocks_cache: dict[int, tuple[StatusFlagCFGBlock8616, ...]] = {}
        self._active: set[int] = set()

    def _resolve_callee(self, target: int) -> object | None:
        """Resolve exact padding aliases to an existing canonical function."""
        canonical = canonicalize_x86_16_padding_call_target_8616(
            self._project_object,
            target,
        )
        if not isinstance(canonical, int):
            return None
        return self._project.kb.functions.function(addr=canonical, create=False)

    def _original_binary_target(self, target: int) -> tuple[object, int] | None:
        """Translate an out-of-slice near-call target to the original image."""
        try:
            rebased = cast(_RebasedProjectBoundary8616, self._project_object)
            image = rebased.loader.main_object
            image_start = int(image.min_addr)
            image_end = int(image.max_addr) + 1
            original_project = rebased._inertia_original_project
            linear_delta = int(rebased._inertia_original_linear_delta)
        except (AttributeError, TypeError, ValueError):
            return None
        if image_start <= target < image_end or linear_delta == 0:
            return None
        return original_project, target + linear_delta

    def _instruction_effect(
        self,
        instruction: _CapstoneInstructionBoundary8616,
    ) -> StatusFlagEffect8616 | None:
        """Return decoded semantics or a recursively proven direct-call effect."""
        target = _direct_call_target_8616(instruction)
        if instruction.mnemonic.lower() == "call":
            if target is None:
                return None
            callee = self._resolve_callee(target)
            if callee is not None:
                effect = self.effect_for(callee)
                if effect is not None:
                    return effect
            canonical = canonicalize_x86_16_padding_call_target_8616(
                self._project_object,
                target,
            )
            return self.effect_for_address(canonical) if isinstance(canonical, int) else None
        decoded = decoded_status_flag_instruction_8616(
            _DecodedInstructionAdapter8616(instruction)
        )
        return None if decoded is None else status_flag_effect_8616(decoded)

    def _project_wrapped_instruction(
        self,
        wrapped: object,
    ) -> StatusFlagCFGInstruction8616 | None:
        """Project one third-party Capstone wrapper, refusing malformed evidence."""
        try:
            instruction = cast(_AngrCapstoneInstructionBoundary8616, wrapped).insn
            int(instruction.address)
        except (AttributeError, TypeError, ValueError):
            return None
        return self._project_instruction(instruction)

    def _project_wrapped_effect(self, wrapped: object) -> StatusFlagEffect8616 | None:
        """Project one wrapped instruction to its typed flag effect only."""
        try:
            instruction = cast(_AngrCapstoneInstructionBoundary8616, wrapped).insn
            int(instruction.address)
        except (AttributeError, TypeError, ValueError):
            return None
        return self._instruction_effect(instruction)

    def _project_instruction(
        self,
        instruction: _CapstoneInstructionBoundary8616,
    ) -> StatusFlagCFGInstruction8616:
        """Project one decoded instruction and distinguish call-summary effects."""
        effect = self._instruction_effect(instruction)
        return StatusFlagCFGInstruction8616(
            address=int(instruction.address),
            effect=effect,
            suppression_supported=bool(
                instruction.mnemonic.lower() in _CFG_SUPPRESSION_MNEMONICS_8616
                and effect is not None
                and int(effect.overwrites) != 0
            ),
        )

    def blocks_for(self, function: object) -> tuple[StatusFlagCFGBlock8616, ...]:
        """Project one function's exact graph-owned blocks and instruction effects."""
        function_boundary = cast(_FunctionBoundary8616, function)
        function_address = int(function_boundary.addr)
        cached = self._blocks_cache.get(function_address)
        if cached is not None:
            return cached
        ir_artifact = build_x86_16_ir_function_artifact(
            self._project_object,
            function,
        )
        projected: list[StatusFlagCFGBlock8616] = []
        for ir_block in ir_artifact.blocks:
            try:
                block = self._project.factory.block(ir_block.addr, opt_level=0)
                capstone_instructions = tuple(block.capstone.insns)
            except (AttributeError, TypeError, ValueError):
                projected.append(
                    StatusFlagCFGBlock8616(
                        address=ir_block.addr,
                        instructions=(),
                        successor_addresses=ir_block.successor_addrs,
                        successors_complete=False,
                    )
                )
                continue
            instructions: list[StatusFlagCFGInstruction8616] = []
            for wrapped in capstone_instructions:
                projected_instruction = self._project_wrapped_instruction(wrapped)
                if projected_instruction is not None:
                    instructions.append(projected_instruction)
            projected.append(
                StatusFlagCFGBlock8616(
                    address=ir_block.addr,
                    instructions=tuple(instructions),
                    successor_addresses=ir_block.successor_addrs,
                )
            )
        result = tuple(projected)
        self._blocks_cache[function_address] = result
        return result

    def effect_for_address(self, function_address: int) -> StatusFlagEffect8616 | None:
        """Summarize a binary-proven callee absent from angr's Function database."""
        cached = self._effect_cache.get(function_address)
        if cached is not None:
            return cached
        if function_address in self._active:
            return None
        self._active.add(function_address)
        try:
            original_target = self._original_binary_target(function_address)
            if original_target is not None:
                original_project, original_address = original_target
                effect = _StatusFlagFunctionSummaryResolver8616(
                    original_project
                ).effect_for_address(original_address)
                if effect is not None:
                    self._effect_cache[function_address] = effect
                return effect
            summary = summarize_binary_status_flag_entry_reads_8616(
                self._project_object,
                entry_address=function_address,
                instruction_effect=self._project_wrapped_effect,
            )
            effect = StatusFlagEffect8616(reads=summary.reads, overwrites=summary.overwrites)
            self._effect_cache[function_address] = effect
            return effect
        finally:
            self._active.remove(function_address)

    def effect_for(self, function: object) -> StatusFlagEffect8616 | None:
        """Return a complete direct-callee summary, or None for recursion/absence."""
        function_address = int(cast(_FunctionBoundary8616, function).addr)
        cached = self._effect_cache.get(function_address)
        if cached is not None:
            return cached
        if function_address in self._active:
            return None
        self._active.add(function_address)
        try:
            blocks = self.blocks_for(function)
            if not blocks:
                return None
            effect = summarize_status_flag_cfg_effect_8616(
                blocks,
                entry_address=function_address,
            )
            self._effect_cache[function_address] = effect
            return effect
        finally:
            self._active.remove(function_address)

    def projection_for(
        self,
        function: object,
        *,
        exit_live: StatusFlag8616,
    ) -> StatusFlagFunctionProjection8616:
        """Build the final function projection and converged liveness artifact."""
        function_address = int(cast(_FunctionBoundary8616, function).addr)
        self._active.add(function_address)
        try:
            blocks = self.blocks_for(function)
        finally:
            self._active.remove(function_address)
        liveness = analyze_status_flag_cfg_liveness_8616(
            blocks,
            entry_address=function_address,
            exit_live=exit_live,
        )
        return StatusFlagFunctionProjection8616(
            function_address=function_address,
            blocks=blocks,
            liveness=liveness,
            callee_effects=tuple(sorted(self._effect_cache.items())),
        )


def build_status_flag_function_projection_8616(
    project: object,
    function: object,
    *,
    exit_live: StatusFlag8616 = STATUS_FLAGS_8616,
) -> StatusFlagFunctionProjection8616:
    """Project one function with conservative architectural live-out defaults."""
    return _StatusFlagFunctionSummaryResolver8616(project).projection_for(
        function,
        exit_live=exit_live,
    )


__all__ = [
    "StatusFlagFunctionProjection8616",
    "build_status_flag_function_projection_8616",
]
