"""Layer: validation imported-call binding.

Responsibility: bind declared effects to the loaded PE's import metadata and
prove a composed target still equals its root-entry IAT value. The initial
loader binding is a published premise, never inferred from a symbol label.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pefile

from tools.dosunit.architectures.flat32_pe_loader import InclusivePE
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.compare.flat32_external_call import Flat32ExternalCall
from tools.dosunit.compare.flat32_memory_preservation import prove_region_preserved
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.runtime.pe32_import_service import parse_pe32_imports
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.ssa_output_lemmas import ScalarPreprocessing

if TYPE_CHECKING:
    import angr


@dataclass(frozen=True)
class ExternalImportBinding:
    """One real loaded IAT slot with an explicit root-entry loader premise."""

    slot: int
    contract: Flat32ExternalCall

    def declared_fields(self) -> dict[str, object]:
        """Retain both ABI effects and the unproved initial loader binding."""
        return {
            "slot": hex(self.slot),
            "entry_iat_binding_assumed": True,
            "contract": self.contract.declared_fields(),
        }


def bind_project_imports(
    project: angr.Project, contracts: tuple[Flat32ExternalCall, ...],
) -> dict[int, ExternalImportBinding]:
    """Read the PE metadata already owned by CLE, allowing only real imports.

    No disk re-open can replace the metadata of the image actually loaded.
    Unselected imports stay unmodeled and cannot route through this mapping.
    """
    if not contracts:
        return {}
    main = project.loader.main_object
    if not isinstance(main, InclusivePE):
        raise CallCompositionRefusal("external_calls_require_loaded_pe")
    parsed = pefile.PE(data=main.source_pe_bytes)
    declared = {(item.dll, item.name): item for item in contracts}
    if len(declared) != len(contracts):
        raise CallCompositionRefusal("duplicate_external_contract")
    try:
        symbols = parse_pe32_imports(parsed)
    except ValueError as error:
        raise CallCompositionRefusal(f"external_import_metadata:{error}") from error
    available = {(symbol.dll, symbol.name) for symbol in symbols}
    if declared.keys() - available:
        raise CallCompositionRefusal("external_contract_not_imported")
    bias = int(main.mapped_base) - int(parsed.OPTIONAL_HEADER.ImageBase)
    return {
        symbol.slot + bias: ExternalImportBinding(symbol.slot + bias, declared[(symbol.dll, symbol.name)])
        for symbol in symbols if (symbol.dll, symbol.name) in declared
    }


def imported_transfer_slot(project: angr.Project, address: int) -> int | None:
    """Decode only exact i386 CALL/JMP absolute-indirect six-byte encodings."""
    raw = project.loader.memory.load(address, 6)
    if len(raw) != 6 or raw[:2] not in (b"\xff\x15", b"\xff\x25"):
        return None
    return int.from_bytes(raw[2:], "little")


def terminal_import_thunk_slot(project: angr.Project, address: int, declared_size: int) -> int | None:
    """Recognize a bounded JMP-IAT leaf for depth accounting, not substitution.

    The caller still lifts and executes the entire native transfer, including
    live-IAT and return-target proofs. Prefixes, CALL wrappers and effectful
    prologues are deliberately excluded. Unreachable trailing bytes do not
    change this terminal instruction's behavior.
    """
    if declared_size < 6:
        return None
    raw = project.loader.memory.load(address, 6)
    if len(raw) != 6 or raw[:2] != b"\xff\x25":
        return None
    return int.from_bytes(raw[2:], "little")


def prove_import_target(
    target: dict[str, Any], binding: ExternalImportBinding, *,
    timeout_ms: int, input_constraints: list[dict[str, Any]] | None = None,
    path_guard: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Prove the live target equals the same slot's root-entry memory value.

    This catches writes through aliases, including CALL's own return push.
    Equality proves target preservation; the declared initial loader binding
    supplies its external identity. No current-memory substitution is allowed
    in the expected value, which always refers to the root input ``mem``.
    """
    expected: dict[str, Any] = {
        "op": "loadle", "width": 32,
        "args": [
            {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
            {"op": "const", "width": 32, "value": hex(binding.slot)},
        ],
    }
    args = target.get("args", [])
    if (target.get("op") == "loadle" and target.get("width") == 32
            and len(args) == 2 and args[1] == expected["args"][1]):
        region = prove_region_preserved(args[0], binding.slot, 4, input_constraints)
        if region is not None:
            return {"method": "disjoint_write_regions", "stores_checked": region.stores_checked}
    # This is an implication encoded as an exact observation, not a new
    # domain assumption. Off this executed path the target is unobserved.
    observed = target if path_guard is None else {
        "op": "ite", "width": 32, "args": [path_guard, target, expected]}
    documents = []
    for term in (observed, expected):
        assignments: list[dict[str, Any]] = []
        value = materialize_term(term, assignments=assignments, memo={})
        documents.append({"outputs": {"eip": value}, "assignments": assignments,
                          "inputs": input_items([value], assignments)})
    result = S._compare_functions(
        *documents, timeout_ms=timeout_ms, input_constraints=input_constraints,
        scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE,
    )
    if proof_status_from_legacy(result.get("status")) is not ProofStatus.PROVED:
        raise CallCompositionRefusal("external_import_target_not_preserved")
    return {"method": "smt_target_equality" if path_guard is None else "smt_path_guarded_target_equality"}


def import_slot_correspondence(
    oracle: angr.Project, candidate: angr.Project, contracts: tuple[Flat32ExternalCall, ...],
) -> dict[int, int]:
    """Match declared IAT storage by exact loaded DLL/export identity.

    This pairs storage coordinates, not live pointer values. Entry loader
    binding remains an explicit premise. Duplicate slots for one identity
    need an explicit storage relation and are refused here.
    """
    sides = [bind_project_imports(project, contracts) for project in (oracle, candidate)]
    identities = [{(binding.contract.dll, binding.contract.name): slot for slot, binding in side.items()}
                  for side in sides]
    if any(len(side) != len(identity) for side, identity in zip(sides, identities, strict=True)):
        raise CallCompositionRefusal("ambiguous_import_slot_correspondence")
    return {slot: identities[0][identity] for identity, slot in identities[1].items()}
