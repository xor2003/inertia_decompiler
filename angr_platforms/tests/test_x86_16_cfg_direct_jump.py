"""Native CFG discovery must preserve precise symbolic control execution."""
from __future__ import annotations

import copy
import io

import angr
import cle
import pytest
import pyvex
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import DEFAULT_RESOLVERS
from angr_platforms.X86_16.alias.register_reaching_source import RegisterReachingSourceVerdict8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_register_provenance import recover_register_source_before_instruction_8616
from angr_platforms.X86_16.frontend_cfg_direct_jobs import register_native_direct_job_adapter_8616
from angr_platforms.X86_16.frontend_cfg_direct_jump import (
    NativeDirectJumpResolver8616,
    register_native_direct_jump_resolver_8616,
)

from inertia_decompiler.project_loading import _build_project_from_bytes


def test_forward_jump_discovers_native_condition_block() -> None:
    """Discover the missing comparison without flattening execution VEX."""
    project = _build_project_from_bytes(
        bytes.fromhex("8a46082ae4eb0083f8017501c3c3"),
        base_addr=0x1000, entry_point=0x1000,
    )
    native = project.factory.block(0x1000, opt_level=0).vex
    assert isinstance(native.next, pyvex.expr.RdTmp)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    assert function.block_addrs_set == {0x1000, 0x1007, 0x100C, 0x100D}
    assert cfg.model.get_any_node(0x1007, anyaddr=True) is not None
    low = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1007, register="al",
    )
    high = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1007, register="ah",
    )
    assert low.verdict is high.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert low.source == ("bp", 8, 1)
    assert high.source == ("imm", 0)
    assert isinstance(project.factory.block(0x1000, opt_level=0).vex.next, pyvex.expr.RdTmp)


@pytest.mark.parametrize(("code", "target"), [("eb00c3", 0x1002), ("eb029090c3", 0x1004)])
def test_same_address_different_binary_uses_its_native_target(code: str, target: int) -> None:
    """Each project's bytes determine its discovery edge without global caches."""
    project = _build_project_from_bytes(bytes.fromhex(code), base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    block = project.factory.block(0x1000, size=2, opt_level=0).vex
    assert isinstance(block, pyvex.IRSB)
    resolver = NativeDirectJumpResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, block, "Ijk_Boring") == (True, [target])
    source_node = cfg.model.get_any_node(0x1000)
    target_node = cfg.model.get_any_node(target, anyaddr=True)
    assert source_node is not None and target_node is not None
    assert source_node == target_node or cfg.graph.has_edge(source_node, target_node)


@pytest.mark.parametrize("code", ["eb80", "ffe0"])
def test_selector_dependent_or_indirect_jump_remains_unresolved(code: str) -> None:
    """A mapped nominal wrap target is still not a selector-invariant target."""
    image = bytearray(b"\x90" * 0x500)
    image[0x200:0x202] = bytes.fromhex(code)
    project = _build_project_from_bytes(bytes(image), base_addr=0xE00, entry_point=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False, resolve_indirect_jumps=False)
    block = project.factory.block(0x1000, size=2, opt_level=0).vex
    assert isinstance(block, pyvex.IRSB)
    resolver = NativeDirectJumpResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, block, "Ijk_Boring") == (False, [])


def test_registration_is_idempotent_and_preserves_other_resolvers() -> None:
    """Repeated startup preserves existing third-party defaults and one adapter."""
    before = tuple(DEFAULT_RESOLVERS[Arch86_16.name][cle.Backend])
    register_native_direct_jump_resolver_8616()
    register_native_direct_jump_resolver_8616()
    after = tuple(DEFAULT_RESOLVERS[Arch86_16.name][cle.Backend])
    assert after == before
    assert after.count(NativeDirectJumpResolver8616) == 1


def test_direct_job_adapter_registration_is_idempotent() -> None:
    """Repeated bootstrap must retain one discovery adapter, not nest it."""
    before = CFGFast._create_jobs
    register_native_direct_job_adapter_8616()
    register_native_direct_job_adapter_8616()
    assert CFGFast._create_jobs is before


def test_adapter_ignores_flat32_architecture() -> None:
    """The platform registration must leave the flat32 comparator path alone."""
    project = angr.Project(
        io.BytesIO(bytes.fromhex("eb00c3")),
        main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    resolver = NativeDirectJumpResolver8616(project)
    block = project.factory.block(0x1000, opt_level=0).vex
    assert not resolver.filter(object(), 0x1000, 0x1000, block, "Ijk_Boring")


@pytest.mark.parametrize("corruption", ["next", "producer", "instruction_head"])
def test_supplied_discovery_ir_must_match_native_jump(corruption: str) -> None:
    """Fresh native evidence cannot authorize altered discovery control state."""
    project = _build_project_from_bytes(
        bytes.fromhex("e90d00c3") + bytes(12) + bytes.fromhex("c3"),
        base_addr=0x1000, entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    supplied = copy.deepcopy(project.factory.block(0x1000, size=3, opt_level=0).vex)
    resolver = NativeDirectJumpResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, supplied, "Ijk_Boring") == (True, [0x1010])
    assert isinstance(supplied.next, pyvex.expr.RdTmp)
    replacement = pyvex.expr.Const(pyvex.const.U32(0x1011))
    if corruption == "next":
        supplied.next = replacement
    elif corruption == "producer":
        producer = next(row for row in supplied.statements
                        if isinstance(row, pyvex.stmt.WrTmp) and row.tmp == supplied.next.tmp)
        producer.data = replacement
    else:
        mark = next(row for row in supplied.statements if isinstance(row, pyvex.stmt.IMark))
        mark.addr += 1
    assert resolver.resolve(cfg, 0x1000, 0x1000, supplied, "Ijk_Boring") == (False, [])
