"""Layer: test support for actual-PE flat32 recursive proofs.

Responsibility: build a genuine two-section i386 PE32 embedding the direct
near32 recursive component, bind both images through the real CLE loader, and
assemble the complete proposal/domain inputs the flat32 adapters
consume. The fixture only proposes; every proof obligation remains with the
production checkers.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from tools.dosunit.tests.recursive_proof_fixtures.flat_call_continuation_inputs import TWO_FLAT_CALLS

from tools.dosunit.recursive_proofs.flat32_image_bound_domain import Flat32AccessDomain
from tools.dosunit.recursive_proofs.flat32_native_effect_binding import Flat32NativeBlockRequest
from tools.dosunit.recursive_proofs.flat32_pe_component import Flat32PeComponent, build_flat32_pe_component
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundFlat32Load, bind_flat32_file
from tools.dosunit.recursive_proofs.loaded_byte_relation import propose_loaded_byte_relation
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof, prove_loaded_byte_relation
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.contracts.register_state_relations import MachineState

IMAGE_BASE: int = 0x400000
TEXT_RVA: int = 0x1000
DATA_RVA: int = 0x2000
ENTRY: int = IMAGE_BASE + TEXT_RVA
DATA_BASE: int = IMAGE_BASE + DATA_RVA
DATA_SIZE: int = 0x1000
STACK_LO: int = DATA_BASE
STACK_HI: int = DATA_BASE + DATA_SIZE
ESP_MIN: int = DATA_BASE + 0x800
ESP_MAX: int = DATA_BASE + 0xF00
MAX_FRAMES: int = 64

BASE_CASE_FLIPPED: bytes = bytes.fromhex("e3114985c07507e8f4ffffffeb05e8edffffffc3")
"""Same shape, negated base-case condition (``jz`` -> ``jnz``)."""

PROGRESS_FLIPPED: bytes = bytes.fromhex("e3114185c07407e8f4ffffffeb05e8edffffffc3")
"""Same shape, reversed progress direction (``dec ecx`` -> ``inc ecx``)."""

ENVIRONMENT_CALL: bytes = bytes.fromhex("e8fb0f0000c3")
"""Direct call whose target lands in .data outside every declared function."""

FAULT_CODE: bytes = bytes.fromhex("ccc3")
"""A leading ``int3`` lift boundary: no normal-only near-frame evidence exists."""


def pe32_recursive_bytes(code: bytes, *, data_size: int = DATA_SIZE) -> bytes:
    """Construct a real i386 PE with executable .text and writable .data.

    The .text section holds ``code`` at RVA 0x1000 (image base 0x400000).
    A writable .data section at RVA 0x2000 provides the declared stack region
    so the access-domain proof has an actual writable mapping to consume.
    """
    if not code or len(code) > 0x200:
        raise ValueError("fixture code must fit inside one file-aligned section")
    raw_data = 0x200
    virtual_size = max(data_size, raw_data)
    data = bytearray(0x400 + raw_data)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    for offset, value in ((16, TEXT_RVA), (20, TEXT_RVA), (28, IMAGE_BASE),
                          (32, 0x1000), (36, 0x200), (56, 0x3000), (60, 0x400),
                          (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)):
        struct.pack_into("<I", data, 0x98 + offset, value)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    struct.pack_into("<8sIIIIIIHHI", data, 0x178, b".text\0\0\0", len(code), TEXT_RVA,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", data, 0x1A0, b".data\0\0\0", virtual_size, DATA_RVA,
                     raw_data, 0x400, 0, 0, 0, 0, 0xC0000040)
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


@dataclass(frozen=True, slots=True)
class Flat32PeRecursiveInputs:
    """Independent binary-derived inputs; the file/byte/mapping seals are bound."""

    system: JointSystem
    loads: tuple[BoundFlat32Load, BoundFlat32Load]
    initialized: LoadedRelationProof
    requests: tuple[tuple[Flat32NativeBlockRequest, ...], tuple[Flat32NativeBlockRequest, ...]]
    bootstrap: tuple[MachineState, MachineState]
    access: Flat32AccessDomain
    component: Flat32PeComponent


def default_access_domain() -> Flat32AccessDomain:
    """Declare the writable .data stack window and a finite recursion budget."""
    return Flat32AccessDomain(STACK_LO, STACK_HI, ESP_MIN, ESP_MAX, MAX_FRAMES)


def make_flat32_pe_recursive_inputs(
    original_code: bytes = TWO_FLAT_CALLS,
    candidate_code: bytes | None = None,
    *,
    functions: dict[int, int] | None = None,
    access: Flat32AccessDomain | None = None,
    timeout_ms: int = 120000,
) -> Flat32PeRecursiveInputs:
    """Bind two immutable PE32 images and derive every proof input from them.

    Both sides load through ``bind_flat32_file`` so bytes, mappings, entry and
    file identity come from actual CLE loading. Candidate code defaults to a
    byte-identical image; structural variants must keep equal code extents so
    the same-coordinate requirement is a proof property, not a fixture trick.
    """
    candidate = original_code if candidate_code is None else candidate_code
    loads = (bind_flat32_file(pe32_recursive_bytes(original_code)),
             bind_flat32_file(pe32_recursive_bytes(candidate)))
    component = build_flat32_pe_component(
        loads, functions if functions is not None else {ENTRY: len(original_code)})
    proposal = propose_loaded_byte_relation(loads[0].binding.snapshot, loads[1].binding.snapshot)
    initialized = prove_loaded_byte_relation(proposal, timeout_ms=timeout_ms)
    return Flat32PeRecursiveInputs(component.system, loads, initialized, component.requests,
                                   component.bootstrap, access or default_access_domain(), component)
