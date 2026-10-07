from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
import inertia.lowering.segmented_global_loads as module
from inertia.lowering.segmented_global_loads import (
    DirectGlobalSymbolRef8616,
    DwordGlobalZeroTestEvidence8616,
    SegmentedLoadIdentity8616,
    recover_dword_global_zero_test_evidence_8616,
)

from inertia.structuring.simple_loop_recovery import InsnSummary8616


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(addr=0x10060)
        self.cstyle_null_cmp = False
        self.max_str_len = None

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        return name


def _access(instruction_addr: int, offset: int) -> SegmentAccessFact:
    return SegmentAccessFact(
        block_addr=instruction_addr,
        instruction_addr=instruction_addr,
        kind=SegmentAccessKind.READ,
        address=IRAddress(
            space=MemSpace.DS,
            offset=offset,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        segment_register="ds",
        physical_source="ds",
        verdict=SegmentFactVerdict.PROVEN,
    )


def _indexed_word(codegen: _Codegen, index: int) -> CIndexedVariable:
    arch = codegen.project.arch
    base = CVariable(
        SimMemoryVariable(0x132, 2, name="g_0132", region=0x10060),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
        tags={
            module._NAMED_DIRECT_SCALAR_MATERIALIZED_TAG_8616: SegmentedLoadIdentity8616(
                space=MemSpace.DS,
                offset=0x132,
                width=2,
                region=0x10060,
            )
        },
    )
    return CIndexedVariable(
        base,
        CConstant(index, SimTypeShort(False).with_arch(arch), codegen=codegen),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )


def _direct_refs() -> dict[tuple[int, int], DirectGlobalSymbolRef8616]:
    return {
        (0x132, 2): DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2),
        (0x134, 2): DirectGlobalSymbolRef8616(0x134, "g_0132", 2, 2, 2),
        (0x132, 4): DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 4, 0),
    }


def test_dword_zero_test_recovery_preserves_source_instruction_addresses() -> None:
    evidence = recover_dword_global_zero_test_evidence_8616(
        [
            InsnSummary8616("mov", "reg", "ax", "direct_mem", 0x134, 2, 2, 0x10074),
            InsnSummary8616("or", "reg", "ax", "direct_mem", 0x132, 2, 2, 0x10077),
            InsnSummary8616("jne", "imm", 0x10090, "none", None, 2, 0, 0x1007B),
        ]
    )

    assert evidence == (
        DwordGlobalZeroTestEvidence8616(
            0x132,
            0x132,
            0x134,
            "ax",
            low_instruction_addr=0x10077,
            high_instruction_addr=0x10074,
        ),
    )


def test_dword_zero_test_replay_uses_exact_segment_provenance_after_ast_regeneration() -> None:
    codegen = _Codegen()
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x10060,
        accesses=(
            _access(0x10074, 0x134),
            _access(0x10077, 0x132),
            _access(0x10084, 0x134),
            _access(0x10087, 0x132),
        ),
    )
    evidence = (
        DwordGlobalZeroTestEvidence8616(
            0x132,
            0x132,
            0x134,
            "ax",
            low_instruction_addr=0x10077,
            high_instruction_addr=0x10074,
        ),
    )

    low = module._make_dword_scalar_indexed_subword_projection_expr_8616(
        codegen, _indexed_word(codegen, 0), _direct_refs(), evidence
    )
    high = module._make_dword_scalar_indexed_subword_projection_expr_8616(
        codegen, _indexed_word(codegen, 1), _direct_refs(), evidence
    )

    assert isinstance(low, CBinaryOp)
    assert low.op == "And"
    assert isinstance(high, CBinaryOp)
    assert high.op == "Shr"


def test_dword_zero_test_replay_refuses_addressless_regenerated_projection() -> None:
    codegen = _Codegen()
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x10060,
        accesses=(
            _access(0x10074, 0x134),
            _access(0x10077, 0x132),
            _access(0x10084, 0x134),
            _access(0x10087, 0x132),
        ),
    )

    projected = module._make_dword_scalar_indexed_subword_projection_expr_8616(
        codegen,
        _indexed_word(codegen, 0),
        _direct_refs(),
        (DwordGlobalZeroTestEvidence8616(0x132, 0x132, 0x134, "ax"),),
    )

    assert projected is None
