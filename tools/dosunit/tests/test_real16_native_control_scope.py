"""Independent native near-control coordinates against bound lifted SSA effects.

Layer: focused staged regression.
Responsibility: compare exact instruction bytes with one Unicorn step and the
full DWORD native control output under the explicit loader-linear domain.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import StrEnum

import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_IP, UC_X86_REG_SP, UC_X86_REG_SS

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_call_contracts import initial_state, prove_terms_equal
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
from tools.dosunit.recursive_proofs.real16_native_control_scope import prove_native_control_scope
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import PHYSICAL_MODEL_LIMIT
from tools.dosunit.runtime.unicorn_engine import make_guest


class NearKind(StrEnum):
    """The three decoded near-relative control encodings in this slice."""

    JMP_REL8 = "jmp_rel8"
    JMP_REL16 = "jmp_rel16"
    CALL_REL16 = "call_rel16"


@dataclass(frozen=True, slots=True)
class Vector:
    """Exact source bytes for one CS:IP and target, with no text-based oracle."""

    name: str
    cs: int
    ip: int
    target_ip: int
    jmp_rel8: bytes
    jmp_rel16: bytes
    call_rel16: bytes

    def code(self, kind: NearKind) -> bytes:
        """Select the immutable encoding for the requested transfer kind."""
        if kind is NearKind.JMP_REL8:
            return self.jmp_rel8
        if kind is NearKind.JMP_REL16:
            return self.jmp_rel16
        return self.call_rel16


VECTORS = (
    Vector("first_mib_call_boundary", 0xFFFF, 0x000D, 0x0000,
           bytes.fromhex("ebf1"), bytes.fromhex("e9f0ff"), bytes.fromhex("e8f0ff")),
    Vector("forward_wrap", 0x1234, 0xFFF0, 0x0010,
           bytes.fromhex("eb1e"), bytes.fromhex("e91d00"), bytes.fromhex("e81d00")),
    Vector("backward_wrap", 0x1234, 0x0010, 0xFFE0,
           bytes.fromhex("ebce"), bytes.fromhex("e9cdff"), bytes.fromhex("e8cdff")),
    Vector("ordinary_low", 0x0100, 0x0200, 0x0210,
           bytes.fromhex("eb0e"), bytes.fromhex("e90d00"), bytes.fromhex("e80d00")),
    Vector("ordinary_high", 0x8234, 0x2220, 0x2212,
           bytes.fromhex("ebf0"), bytes.fromhex("e9efff"), bytes.fromhex("e8efff")),
)


@dataclass(frozen=True, slots=True)
class SourceReceipt:
    """Retain the exact byte identity and native coordinate of this probe."""

    code: bytes
    sha256: str
    loaded_head: int
    cs: int
    ip: int


@dataclass(frozen=True, slots=True)
class NativeStep:
    """One actual guest transfer and, for CALL, its saved return frame."""

    visited: tuple[int, ...]
    cs: int
    ip: int
    sp: int
    return_word: int | None


def _receipt(vector: Vector, kind: NearKind) -> SourceReceipt:
    """Hash the exact bytes later supplied to both independent engines."""
    code = vector.code(kind)
    return SourceReceipt(code, hashlib.sha256(code).hexdigest(),
                         (vector.cs << 4) + vector.ip, vector.cs, vector.ip)


def _native(receipt: SourceReceipt, kind: NearKind) -> NativeStep:
    """Execute one native instruction with a valid mapped near CALL frame."""
    guest = make_guest(UC_ARCH_X86, UC_MODE_16)
    # Unicorn fetches ahead across the first-MiB boundary before executing the
    # three-byte transfer. Map the architectural real-mode address envelope.
    guest.mem_map(0, 0x110000)
    guest.mem_write(receipt.loaded_head, receipt.code)
    guest.reg_write(UC_X86_REG_CS, receipt.cs)
    guest.reg_write(UC_X86_REG_IP, receipt.ip)
    guest.reg_write(UC_X86_REG_SS, 0x3000)
    guest.reg_write(UC_X86_REG_SP, 0x1000)
    visited: list[int] = []
    guest.hook_add(UC_HOOK_CODE, lambda _guest, addr, _size, _data: visited.append(addr))
    guest.emu_start(receipt.loaded_head, 0, count=1)
    sp = int(guest.reg_read(UC_X86_REG_SP))
    saved = None
    if kind is NearKind.CALL_REL16:
        saved = int.from_bytes(guest.mem_read((0x3000 << 4) + sp, 2), "little")
    return NativeStep(tuple(visited), int(guest.reg_read(UC_X86_REG_CS)),
                      int(guest.reg_read(UC_X86_REG_IP)), sp, saved)


def _lifted(receipt: SourceReceipt) -> dict[str, dict[str, object]]:
    """Lower the identical bytes at their loaded head under explicit loader control."""
    arch = Arch86_16(control_address_domain=ControlAddressDomain.LOADER_LINEAR)
    irsb = pyvex.lift(receipt.code, receipt.loaded_head, arch,
                      max_bytes=len(receipt.code), max_inst=1, opt_level=0)
    assert irsb.size == len(receipt.code) and irsb.instructions == 1
    lowered = S._lower_irsb(irsb, output_regs=tuple(S.INTERNAL_STATE_REGS),
                            max_assignments_per_function=4096)
    assert not isinstance(lowered, S.LowerFailure), lowered
    seed = initial_state()
    seed["cs"] = {"op": "const", "width": 16, "value": hex(receipt.cs)}
    seed["ss"] = {"op": "const", "width": 16, "value": "0x3000"}
    seed["sp"] = {"op": "const", "width": 16, "value": "0x1000"}
    seed["control_ip"] = {"op": "const", "width": 32, "value": hex(receipt.loaded_head)}
    return S._compose_block_outputs(lowered, lowered["outputs"], seed)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector.name)
@pytest.mark.parametrize("kind", tuple(NearKind))
def test_coordinate_admission_agrees_with_independent_native_target(vector: Vector, kind: NearKind) -> None:
    """A known lifted coordinate mismatch cannot earn a positive certificate."""
    receipt = _receipt(vector, kind)
    native = _native(receipt, kind)
    assert native.visited == (receipt.loaded_head,)
    assert (native.cs, native.ip) == (vector.cs, vector.target_ip)
    state = _lifted(receipt)
    target = (native.cs << 4) + native.ip
    expected = {"op": "const", "width": 32, "value": hex(target)}
    equality = prove_terms_equal(state["control_ip"], expected, 3000)
    entry = initial_state()
    for name, value, width in (("cs", receipt.cs, 16), ("ss", 0x3000, 16),
                               ("sp", 0x1000, 16), ("control_ip", receipt.loaded_head, 32)):
        entry[name] = {"op": "const", "width": width, "value": hex(value)}
    proof = prove_native_control_scope(receipt.code, receipt.loaded_head, entry,
                                      Real16ScalarDomain(0x3000, receipt.cs), deadline=time.monotonic() + 15)
    assert proof.expected_targets == frozenset({target}), proof
    assert proof.complete == (equality is ProofStatus.PROVED), proof
    assert not proof.binary_equivalence_proved
    assert proof.counters.failure_count == (0 if proof.complete else 2)


def test_high_address_call_preserves_full_loader_target() -> None:
    """A near CALL keeps CS-derived high bits while saving only the return IP."""
    vector = VECTORS[0]
    receipt = _receipt(vector, NearKind.CALL_REL16)
    native = _native(receipt, NearKind.CALL_REL16)
    assert (native.cs, native.ip, native.return_word) == (0xFFFF, 0, 0x10)
    state = _lifted(receipt)
    expected = {"op": "const", "width": 32, "value": "0xffff0"}
    assert prove_terms_equal(state["control_ip"], expected, 3000) is ProofStatus.PROVED


def test_high_address_call_consumes_symbolic_selector_domain() -> None:
    """A full-width CALL certificate proves symbolic CS under its domain."""
    receipt = _receipt(VECTORS[0], NearKind.CALL_REL16)
    entry = initial_state()
    entry["control_ip"] = {"op": "const", "width": 32, "value": hex(receipt.loaded_head)}
    proof = prove_native_control_scope(
        receipt.code, receipt.loaded_head, entry,
        Real16ScalarDomain(0x3000, receipt.cs), deadline=time.monotonic() + 15,
    )
    assert proof.complete, proof
    assert proof.expected_targets == proof.native_targets == frozenset({0xFFFF0})
    assert not proof.binary_equivalence_proved


def test_high_address_call_return_leaves_first_mib_model() -> None:
    """A valid in-model CALL target does not bound the caller's terminal PC."""
    receipt = _receipt(VECTORS[0], NearKind.CALL_REL16)
    guest = make_guest(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x110000)
    guest.mem_write(receipt.loaded_head, receipt.code)
    guest.mem_write(0xFFFF0, b"\xc3")
    for register, value in ((UC_X86_REG_CS, receipt.cs), (UC_X86_REG_IP, receipt.ip),
                            (UC_X86_REG_SS, 0x3000), (UC_X86_REG_SP, 0x1000)):
        guest.reg_write(register, value)
    guest.emu_start(receipt.loaded_head, 0, count=2)
    terminal = (int(guest.reg_read(UC_X86_REG_CS)) << 4) + int(guest.reg_read(UC_X86_REG_IP))
    assert terminal == PHYSICAL_MODEL_LIMIT == 0x100000
    assert int(guest.reg_read(UC_X86_REG_SP)) == 0x1000

    state = _lifted(receipt)
    arch = Arch86_16(control_address_domain=ControlAddressDomain.LOADER_LINEAR)
    irsb = pyvex.lift(b"\xc3", 0xFFFF0, arch, max_bytes=1, max_inst=1, opt_level=0)
    lowered = S._lower_irsb(irsb, output_regs=tuple(S.INTERNAL_STATE_REGS),
                            max_assignments_per_function=4096)
    assert not isinstance(lowered, S.LowerFailure), lowered
    returned = S._compose_block_outputs(lowered, lowered["outputs"], state)
    expected = {"op": "const", "width": 32, "value": hex(terminal)}
    assert prove_terms_equal(returned["control_ip"], expected, 3000) is ProofStatus.PROVED
