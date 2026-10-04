"""Explicit public machine/ABI/domain contracts for comparator proof reports.

Layer: dosunit proof reporting.
Responsibility: declare the architecture, widths, calling convention, return
kind, observable domain and environment model that each public comparator
proof is bound to, so reports identify the actual contract instead of only
opaque hashes. These machine-state comparators assume no language calling
convention: no source-level ABI, argument-register or stack-cleanup
convention is asserted, and returns are observed as modeled machine state at
decoded exits. Each lane publishes the exact machine-state projection it
compares — which is not necessarily the whole modeled machine state (the
flat32 exit projection omits caller-clobbered ``ecx`` and the lazy-flag
``cc_*`` storage). Outcome classes carry their admission status honestly:
``refused`` only where a verified enforcing gate exists, ``not_established``
where no executed control has established admission either way.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from tools.dosunit.proof_contracts import Architecture

if TYPE_CHECKING:
    from tools.dosunit.ordered_io_environment import OrderedIoContract

DOMAIN_SCHEMA: str = "dosunit.proof_domain.v1"

#: Raw ``proof_contract`` keys flat32 drivers use for the compared exit
#: projection. Region and matched-CFG reports emit ``outputs``; leaf reports
#: emit ``output_regs``. Both name the same declaration under different keys.
BACKEND_OUTPUT_KEYS: tuple[str, ...] = ("outputs", "output_regs")


class CallingConvention(StrEnum):
    """Calling-convention basis of a proof's function boundary.

    ``NONE_MACHINE_STATE_PROJECTION`` is the honest declaration for the binary
    comparators: they assume no language ABI and compare the published
    machine-state projection of each lane. That projection is not a claim of
    whole-machine-state coverage — flat32 compares the declared output
    registers plus the whole flat byte array, omitting ``ecx`` and the
    lazy-flag ``cc_*`` registers from the exit projection.
    """

    NONE_MACHINE_STATE_PROJECTION = "none_machine_state_projection"


class ReturnKind(StrEnum):
    """How function return is observed in the proof.

    ``MACHINE_STATE_PROJECTION`` means return is compared as modeled machine
    state at decoded exits; no ABI return slot, width or cleanup is claimed.
    """

    MACHINE_STATE_PROJECTION = "machine_state_projection"


class OutcomeKind(StrEnum):
    """Outcome classes a function comparison may observe."""

    NORMAL_RETURN = "normal_return"
    NONRETURNING = "nonreturning"
    FAULT = "fault"
    EXTERNAL_EFFECT = "external_effect"


class OutcomeAdmission(StrEnum):
    """Whether an outcome class is compared, gated, or unestablished.

    ``REFUSED`` is asserted only where a verified enforcing gate exists in the
    compared code path; ``NOT_ESTABLISHED`` records that admission has not
    been established either way by executed binary-derived controls — it is a
    scope declaration, not a proof verdict.
    """

    COMPARED = "compared"
    REFUSED = "refused"
    NOT_ESTABLISHED = "not_established"


@dataclass(frozen=True, slots=True)
class OutcomeContract:
    """Admission of one outcome class plus the mechanism that enforces it.

    ``basis`` names the typed admission mechanism (for example decoded VEX
    return admission or the binary-IR environment scan), never verdict text.
    For ``NOT_ESTABLISHED`` it names the verified partial gates and the exact
    scope that remains unestablished.
    """

    kind: OutcomeKind
    admission: OutcomeAdmission
    basis: str

    def __post_init__(self) -> None:
        """Reject outcome declarations without an enforcement basis."""
        if not isinstance(self.basis, str) or not self.basis:
            raise ValueError("outcome contract requires an enforcement basis")


class AddressModel(StrEnum):
    """Memory-address model of the compared machine."""

    SEGMENTED_REAL_MODE = "segmented_real_mode"
    FLAT = "flat"


@dataclass(frozen=True, slots=True)
class MachineWidths:
    """Declared bit widths and address model of the compared machine.

    ``operand_bits`` is the lane's ISA operand width, not the loader's
    address-carrier width. ``storage_bits`` is the widest register/control storage
    component the comparison observes: real16 models 32-bit ``dflag`` and
    ``control_ip`` storage and the 386 high-half pairs even though its ISA
    operands are 16-bit. ``operand_override_bits`` lists admitted wider
    operand forms (the in-scope 386 32-bit overrides on the real16 track).
    """

    operand_bits: int
    storage_bits: int
    address_model: AddressModel
    operand_override_bits: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        """Reject non-integer or non-positive declared widths."""
        for name, value in (
            ("operand_bits", self.operand_bits),
            ("storage_bits", self.storage_bits),
            *(("operand_override_bits", item) for item in self.operand_override_bits),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer width")


class MemoryRelation(StrEnum):
    """How much of modeled memory the proof compares."""

    WHOLE_FLAT_BYTE_ARRAY = "whole_flat_byte_array"
    WHOLE_SEGMENTED_BYTE_ARRAY = "whole_segmented_byte_array"


class FlagModel(StrEnum):
    """How condition-flag state enters the comparison.

    ``LAZY_FLAG_SUMMARIES`` is the shared model of both lanes and both leaf
    and region paths: VEX lazy-flag helpers (``x86g_calculate_condition`` and
    the eflags projections) lower to bounded ``summary_*`` terms. Admitted
    (condition, arithmetic-thunk) pairs are interpreted exactly by
    ``x86_lazy_conditions`` at solver time; non-admitted pairs remain
    uninterpreted, and a counterexample depending on them refuses
    (``uninterpreted_x86_flags``) rather than reporting a spurious mismatch.
    Not all conditions are uninterpreted, and not all flag state is modeled.
    """

    LAZY_FLAG_SUMMARIES = "lazy_flag_summaries"


class ObservableScope(StrEnum):
    """Which state components the exit observation covers."""

    WHOLE_MODELED_STATE = "whole_modeled_state"
    DECLARED_OUTPUTS = "declared_outputs"


class OutputDeclarationSource(StrEnum):
    """Provenance of the published exit-observation register projection."""

    LOWERING_CONTRACT = "lowering_contract"
    BACKEND_DECLARED = "backend_declared"
    CALLER_DECLARED = "caller_declared"


@dataclass(frozen=True, slots=True)
class ObservableDomain:
    """The state components whose equality a proof establishes.

    ``register_source`` records who declared the compared projection — the
    lane's lowering contract, the backend ``proof_contract``, or the caller's
    CLI list — so a caller-declared fallback is never reported as backend
    observation.
    """

    scope: ObservableScope
    registers: tuple[str, ...]
    register_source: OutputDeclarationSource
    memory: MemoryRelation
    flag_model: FlagModel

    def __post_init__(self) -> None:
        """Reject an empty or malformed declared observable set."""
        if not self.registers or any(type(name) is not str or not name for name in self.registers):
            raise ValueError("observable domain requires a nonempty register projection")


class InstructionMemory(StrEnum):
    """Whether executable bytes are fixed for the duration of the proof."""

    IMMUTABLE = "immutable"


class InitialDataRelation(StrEnum):
    """How entry memory contents are related between the two sides."""

    SHARED_UNCONSTRAINED = "shared_unconstrained"


@dataclass(frozen=True, slots=True)
class EnvironmentModel:
    """Environment assumptions bound into the proof.

    ``premise`` retains serialized caller-declared unproved assumptions (for
    example the flat32 entry-ESP interval). An empty tuple means no additional
    entry premise is recorded here; per-verdict assumptions and the declared
    machine model still apply.
    """

    instruction_memory: InstructionMemory
    external_effects: OutcomeAdmission
    faults: OutcomeAdmission
    initial_data: InitialDataRelation
    premise: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class MachineProofDomain:
    """The complete public contract a machine-state proof report is bound to.

    ``outcomes`` is a closed inventory: exactly one :class:`OutcomeContract`
    per :class:`OutcomeKind`, so the report states the admission of every
    modeled outcome class instead of silently omitting unsupported forms.
    """

    architecture: Architecture
    widths: MachineWidths
    calling_convention: CallingConvention
    return_kind: ReturnKind
    outcomes: tuple[OutcomeContract, ...]
    observable: ObservableDomain
    environment: EnvironmentModel

    def __post_init__(self) -> None:
        """Require a closed outcome inventory covering every outcome kind."""
        kinds = [outcome.kind for outcome in self.outcomes]
        if sorted(kinds) != sorted(OutcomeKind):
            raise ValueError("domain outcomes must declare exactly one contract per outcome kind")

    def to_document(self) -> dict[str, Any]:
        """Serialize the contract deterministically for reports and sealing."""
        return {
            "schema": DOMAIN_SCHEMA,
            "architecture": self.architecture.value,
            "widths": {
                "operand_bits": self.widths.operand_bits,
                "storage_bits": self.widths.storage_bits,
                "address_model": self.widths.address_model.value,
                "operand_override_bits": list(self.widths.operand_override_bits),
            },
            "calling_convention": self.calling_convention.value,
            "return_kind": self.return_kind.value,
            "outcomes": [
                {
                    "kind": outcome.kind.value,
                    "admission": outcome.admission.value,
                    "basis": outcome.basis,
                }
                for outcome in self.outcomes
            ],
            "observable": {
                "scope": self.observable.scope.value,
                "registers": list(self.observable.registers),
                "register_source": self.observable.register_source.value,
                "memory": self.observable.memory.value,
                "flag_model": self.observable.flag_model.value,
            },
            "environment": {
                "instruction_memory": self.environment.instruction_memory.value,
                "external_effects": self.environment.external_effects.value,
                "faults": self.environment.faults.value,
                "initial_data": self.environment.initial_data.value,
                "premise": [dict(premise) for premise in self.environment.premise],
            },
        }


def declared_output_regs(value: object, *, source: str) -> tuple[str, ...]:
    """Validate a declared exit-observation register projection.

    A supplied declaration must be a nonempty sequence of distinct, exact
    register-name strings. Anything else — wrong container, empty sequence,
    non-string or whitespace-padded names, duplicates — is malformed evidence
    and rejects the domain rather than being coerced or silently replaced.
    """
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{source}: output declaration must be a register-name sequence")
    names = tuple(value)
    if not names:
        raise ValueError(f"{source}: output declaration is empty")
    for name in names:
        if type(name) is not str or not name or name != name.strip():
            raise ValueError(f"{source}: malformed register name in output declaration")
    if len(set(names)) != len(names):
        raise ValueError(f"{source}: output declaration repeats a register name")
    return names


def flat32_declared_outputs(
    backend_contract: object, cli_output_regs: object
) -> tuple[tuple[str, ...], OutputDeclarationSource]:
    """Resolve the flat32 compared exit projection and its provenance.

    Drivers publish the projection under ``outputs`` (region, matched-CFG) or
    ``output_regs`` (leaf); both keys name the same declaration. A supplied
    backend key must be a valid declaration, two supplied keys must agree, and
    a non-mapping contract is malformed — all refuse instead of guessing.
    Only when the backend supplies no declaration at all does the caller's
    ``--output-regs`` list become the published projection, reported as
    caller-declared.
    """
    if backend_contract is None:
        supplied: dict[str, object] = {}
    elif isinstance(backend_contract, Mapping):
        supplied = {key: backend_contract[key] for key in BACKEND_OUTPUT_KEYS if key in backend_contract}
    else:
        raise ValueError("backend proof_contract must be a mapping or absent")
    if supplied:
        resolved = {
            key: declared_output_regs(value, source=f"backend proof_contract[{key!r}]")
            for key, value in supplied.items()
        }
        first = next(iter(resolved.values()))
        if any(names != first for names in resolved.values()):
            raise ValueError("backend output declarations disagree across proof_contract keys")
        return first, OutputDeclarationSource.BACKEND_DECLARED
    if not isinstance(cli_output_regs, str):
        raise ValueError("caller --output-regs declaration must be a string")
    names = declared_output_regs(cli_output_regs.split(","), source="caller --output-regs")
    return names, OutputDeclarationSource.CALLER_DECLARED


def common_image_bits(images: Mapping[str, Any]) -> int | None:
    """Return the shared loaded-image width, or None when unreported.

    Any disagreement between declared image widths is contradictory evidence
    and rejects the domain rather than silently picking one side.
    """
    widths = {
        int(image["width"])
        for image in images.values()
        if isinstance(image, Mapping) and type(image.get("width")) is int
    }
    if len(widths) > 1:
        raise ValueError("loaded images disagree on architecture width")
    return widths.pop() if widths else None


def _check_image_bits(lane: str, declared: int, image_bits: int | None) -> None:
    """Reject a loaded image whose width contradicts the declared lane."""
    if image_bits is not None and image_bits != declared:
        raise ValueError(f"{lane} domain requires {declared}-bit images, got {image_bits}")


def real16_public_domain(
    *,
    registers: Sequence[str],
    image_bits: int | None = None,
    ordered_io: OrderedIoContract | None = None,
) -> MachineProofDomain:
    """Declare the actual contract of the real16 binary-comparison lane.

    ``registers`` is the actual compared register projection passed by the
    wrapper — the lane's ``INTERNAL_STATE_REGS`` lowering output set (16-bit
    registers, segments, flags, 32-bit ``dflag``/``control_ip`` storage and
    the 386 high halves) — so the published domain cannot drift from the
    compared inventory. The proof additionally compares the whole segmented
    byte array under a fault-free, environment-free model.

    ``ordered_io`` binds the declared ordered scalar port-I/O environment
    contract: covered decoded events are compared under its explicit caller
    premise — serialized into ``environment.premise`` — and every verdict
    consuming them is conditional.
    """
    if ordered_io is not None:
        ordered_io.validate_for(Architecture.REAL16)
    # The real16 project loader widens arch.bits to 32 so loaded linear
    # addresses above 64 KiB survive angr transport. It keeps arch.name=86_16
    # and 16-bit decoding; that carrier is not an ISA operand-size switch.
    if image_bits is not None and image_bits not in (16, 32):
        raise ValueError(f"real16 domain requires a 16/32-bit address carrier, got {image_bits}")
    compared = declared_output_regs(registers, source="real16 lowering contract")
    return MachineProofDomain(
        architecture=Architecture.REAL16,
        widths=MachineWidths(
            operand_bits=16,
            storage_bits=32,
            address_model=AddressModel.SEGMENTED_REAL_MODE,
            operand_override_bits=(32,),
        ),
        calling_convention=CallingConvention.NONE_MACHINE_STATE_PROJECTION,
        return_kind=ReturnKind.MACHINE_STATE_PROJECTION,
        outcomes=(
            OutcomeContract(
                OutcomeKind.NORMAL_RETURN,
                OutcomeAdmission.COMPARED,
                basis=(
                    "whole-body leaf admission requires a decoded VEX Ijk_Ret covering the "
                    "declared body (near or far) via complete_leaf_block; otherwise closed "
                    "whole-region equality over Ret/Sig terminals discharges it"
                ),
            ),
            OutcomeContract(
                OutcomeKind.NONRETURNING,
                OutcomeAdmission.NOT_ESTABLISHED,
                basis=(
                    "verified gates: leaf admission requires Ijk_Ret and call composition "
                    "refuses the modeled DOS process-terminate transfer "
                    "(unsupported_return_control); whether a top-level whole-function proof "
                    "can be admitted without a returning terminal is not established by "
                    "executed binary-derived controls — no gate is claimed either way"
                ),
            ),
            OutcomeContract(
                OutcomeKind.FAULT,
                OutcomeAdmission.REFUSED,
                basis=(
                    "fault-free environment model: post-fault machine state is outside the "
                    "modeled domain; leaf admission disqualifies trap exits and region "
                    "equality compares Ijk_Sig trap-terminal reachability as equivalence "
                    "structure only"
                ),
            ),
            OutcomeContract(
                OutcomeKind.EXTERNAL_EFFECT,
                OutcomeAdmission.COMPARED if ordered_io is not None else OutcomeAdmission.REFUSED,
                basis=(
                    "ordered scalar port IN/OUT events are compared in full ordered io "
                    "state under the declared ordered-io environment premise — an explicit "
                    "caller assumption, never a universal device-equivalence claim; "
                    "uncovered effects still refuse"
                    if ordered_io is not None else
                    "binary-IR environment scan (scan_lowered_parts / "
                    "requires_environment_contract) gates admission as "
                    "external_environment_contract_required; external effects require an "
                    "explicit declared contract"
                ),
            ),
        ),
        observable=ObservableDomain(
            scope=ObservableScope.WHOLE_MODELED_STATE,
            registers=compared,
            register_source=OutputDeclarationSource.LOWERING_CONTRACT,
            memory=MemoryRelation.WHOLE_SEGMENTED_BYTE_ARRAY,
            flag_model=FlagModel.LAZY_FLAG_SUMMARIES,
        ),
        environment=EnvironmentModel(
            instruction_memory=InstructionMemory.IMMUTABLE,
            external_effects=(
                OutcomeAdmission.COMPARED if ordered_io is not None else OutcomeAdmission.REFUSED
            ),
            faults=OutcomeAdmission.REFUSED,
            initial_data=InitialDataRelation.SHARED_UNCONSTRAINED,
            premise=(ordered_io.premise_document(),) if ordered_io is not None else (),
        ),
    )


def flat32_public_domain(
    *,
    outputs: Sequence[str],
    register_source: OutputDeclarationSource,
    image_bits: int | None = None,
    premise: Mapping[str, Any] | None = None,
    ordered_io: OrderedIoContract | None = None,
) -> MachineProofDomain:
    """Declare the actual contract of the flat32 PE32/ELF32 comparison lanes.

    ``outputs`` is the validated exit-observation register set and
    ``register_source`` its provenance (backend-declared ``proof_contract``
    keys or the caller's ``--output-regs``); the proof additionally compares
    the whole flat byte array. The projection is selected, not whole machine
    state: the driver adapter omits caller-clobbered ``ecx`` and the
    ``cc_*`` lazy-flag registers from the compared exit set. Condition-flag
    helpers are lazy-flag summaries — exact for admitted thunks,
    uninterpreted otherwise — so flag-dependent counterexamples refuse rather
    than report spurious mismatches.
    """
    if ordered_io is not None:
        ordered_io.validate_for(Architecture.FLAT32)
    _check_image_bits("flat32", 32, image_bits)
    registers = declared_output_regs(outputs, source="flat32 observable domain")
    if not isinstance(register_source, OutputDeclarationSource) or register_source is OutputDeclarationSource.LOWERING_CONTRACT:
        raise ValueError("flat32 observable domain requires its backend/caller declaration source")
    return MachineProofDomain(
        architecture=Architecture.FLAT32,
        widths=MachineWidths(
            operand_bits=32,
            storage_bits=32,
            address_model=AddressModel.FLAT,
            operand_override_bits=(),
        ),
        calling_convention=CallingConvention.NONE_MACHINE_STATE_PROJECTION,
        return_kind=ReturnKind.MACHINE_STATE_PROJECTION,
        outcomes=(
            OutcomeContract(
                OutcomeKind.NORMAL_RETURN,
                OutcomeAdmission.COMPARED,
                basis=(
                    "leaf preflight requires a decoded Ijk_Ret single block with no "
                    "exceptional exit; region and matched-CFG composition complete paths "
                    "only at Ijk_Ret terminals and compare the admitted transition system"
                ),
            ),
            OutcomeContract(
                OutcomeKind.NONRETURNING,
                OutcomeAdmission.NOT_ESTABLISHED,
                basis=(
                    "verified gates: leaf preflight requires Ijk_Ret and region/CFG "
                    "composition completes only at Ijk_Ret terminals "
                    "(call_or_exception_boundary); whole-function nonreturning admission is "
                    "not established by executed binary-derived controls — no gate is "
                    "claimed either way"
                ),
            ),
            OutcomeContract(
                OutcomeKind.FAULT,
                OutcomeAdmission.REFUSED,
                basis=(
                    "fault-free environment model: exception edges refuse at leaf preflight "
                    "and CFG lifting; trap reachability is compared only as encoded terminal "
                    "structure (TRAP_EIP), post-fault state is outside the modeled domain"
                ),
            ),
            OutcomeContract(
                OutcomeKind.EXTERNAL_EFFECT,
                OutcomeAdmission.COMPARED if ordered_io is not None else OutcomeAdmission.REFUSED,
                basis=(
                    "ordered scalar port IN/OUT events are compared in full ordered io "
                    "state under the declared ordered-io environment premise — an explicit "
                    "caller assumption, never a universal device-equivalence claim; "
                    "uncovered effects still refuse"
                    if ordered_io is not None else
                    "binary-IR environment scan (requires_environment_contract and checked "
                    "environment verdicts) refuses undeclared services and port/dirty-helper "
                    "effects; external effects require an explicit declared contract"
                ),
            ),
        ),
        observable=ObservableDomain(
            scope=ObservableScope.DECLARED_OUTPUTS,
            registers=registers,
            register_source=register_source,
            memory=MemoryRelation.WHOLE_FLAT_BYTE_ARRAY,
            flag_model=FlagModel.LAZY_FLAG_SUMMARIES,
        ),
        environment=EnvironmentModel(
            instruction_memory=InstructionMemory.IMMUTABLE,
            external_effects=(
                OutcomeAdmission.COMPARED if ordered_io is not None else OutcomeAdmission.REFUSED
            ),
            faults=OutcomeAdmission.REFUSED,
            initial_data=InitialDataRelation.SHARED_UNCONSTRAINED,
            premise=tuple(
                [dict(premise)] if premise is not None else []
            ) + ((ordered_io.premise_document(),) if ordered_io is not None else ()),
        ),
    )
