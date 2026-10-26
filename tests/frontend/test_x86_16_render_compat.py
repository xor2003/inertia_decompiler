from __future__ import annotations

from copy import copy
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunction, CFunctionCall, CReturn, CStatements, CSwitchCase
from angr.knowledge_plugins.functions.function import Function, PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeShort
from angr.sim_variable import SimStackVariable, SimTemporaryVariable

from inertia.frontend.x86_16.render_compat import (
    install_structured_codegen_sort_compat_8616,
    repair_cfunctioncall_render_targets_8616,
    set_cfunctioncall_render_name_8616,
)


class _NoKbProject:
    kb = None


class _Codegen(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._idx = 0

    def next_idx(self, _name):
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _DetachedCallee(SimpleNamespace):
    """Stand-in for a copied native Function that lost its project."""


_DetachedCallee.__module__ = Function.__module__


def _detached_callee() -> _DetachedCallee:
    return _DetachedCallee(project=None, addr=0x1234, name="helper")


def _assert_dropped(call: CFunctionCall, repaired: int) -> None:
    assert repaired == 1
    assert call.callee_func is None
    assert call.callee_target == "helper"


def test_render_compat_disables_disambiguation_for_projectless_callee():
    codegen = _Codegen(project=_NoKbProject())
    call = CFunctionCall("helper", _detached_callee(), [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([call], codegen=codegen))

    _assert_dropped(call, repair_cfunctioncall_render_targets_8616(codegen))


def test_render_compat_repairs_return_value_call_targets():
    codegen = _Codegen(project=_NoKbProject())
    call = CFunctionCall("helper", _detached_callee(), [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([CReturn(call, codegen=codegen)], codegen=codegen))

    _assert_dropped(call, repair_cfunctioncall_render_targets_8616(codegen))


def test_render_compat_repairs_switch_case_call_targets():
    codegen = _Codegen(project=_NoKbProject())
    call = CFunctionCall("helper", _detached_callee(), [], codegen=codegen)
    case_body = CStatements([CReturn(call, codegen=codegen)], codegen=codegen)
    switch = CSwitchCase(SimpleNamespace(), [(69, case_body)], None, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([switch], codegen=codegen))

    _assert_dropped(call, repair_cfunctioncall_render_targets_8616(codegen))


def _detached_native_call() -> tuple[angr.Project, Function, Function, _Codegen, CFunctionCall]:
    """Keep a chosen declaration distinct from the real KB's default prototype."""
    project = angr.load_shellcode(b'\xc3', arch='x86', load_address=0x1000)
    canonical = project.kb.functions.function(addr=0x1000, create=True)
    canonical.prototype = SimTypeFunction([], SimTypeInt(False)).with_arch(project.arch)
    detached = copy(canonical)
    detached.name = 'helper'
    detached.prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(project.arch)
    detached.prototype_source = PrototypeSource.CCA_DECOMPILER
    detached.prototype_libname = 'selected ABI'
    codegen = _Codegen(project=project)
    call = CFunctionCall('helper', detached, [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([CReturn(call, codegen=codegen)], codegen=codegen))
    return project, canonical, detached, codegen, call


def test_render_target_reattachment_preserves_selected_prototype():
    """Project repair must not replace a call's chosen ABI with the KB default."""
    project, canonical, detached, codegen, call = _detached_native_call()
    chosen = detached.prototype

    assert repair_cfunctioncall_render_targets_8616(codegen) == 1
    assert call.callee_func.project is project
    assert call.callee_func.prototype is chosen and call.type is chosen.returnty
    assert call.callee_func.name == 'helper'
    assert call.callee_func.prototype_source is detached.prototype_source
    assert call.callee_func.prototype_libname == detached.prototype_libname
    assert call.callee_func.is_prototype_guessed == detached.is_prototype_guessed
    assert detached.project is None
    assert canonical.prototype.returnty.size == 32
    assert repair_cfunctioncall_render_targets_8616(codegen) == 0


def test_callsite_render_sanitization_preserves_abi_and_target():
    """The compatibility consumer must not erase a detached native declaration."""
    from inertia.postprocess.decompiler_postprocess_calls import _preserve_detached_callee_render_metadata_8616

    project, _canonical, detached, _codegen, call = _detached_native_call()
    assert _preserve_detached_callee_render_metadata_8616(call)
    assert call.callee_func is not None and call.callee_func.project is project
    assert call.callee_func.prototype is detached.prototype
    assert call.type is detached.prototype.returnty


def test_canonical_address_name_keeps_proven_call_declaration():
    """Selecting an address label must preserve the call's chosen result type."""
    from inertia.postprocess.decompiler_postprocess_calls import _bind_canonical_addr_target_8616

    project, canonical, detached, codegen, call = _detached_native_call()
    assert repair_cfunctioncall_render_targets_8616(codegen) == 1
    chosen = detached.prototype
    selected = call.callee_func
    previous_names = list(selected.previous_names)
    assert _bind_canonical_addr_target_8616(project, call, canonical, 0x1000, None)
    assert call.callee_func is not None
    assert call.callee_func.project is project and call.callee_func.prototype is chosen
    assert call.callee_func.name == 'sub_1000' and call.callee_target == 'sub_1000'
    assert call.type is chosen.returnty and detached.name == 'helper'
    assert selected.name == 'helper' and selected.previous_names == previous_names
    identity = call.callee_func
    assert not _bind_canonical_addr_target_8616(project, call, canonical, 0x1000, None)
    assert call.callee_func is identity


@pytest.mark.parametrize('foreign_project', [False, True])
def test_render_name_cannot_promote_an_unmatched_target(foreign_project):
    """A label supplies no authority for another address or another project."""
    project, _canonical, _detached, codegen, call = _detached_native_call()
    assert repair_cfunctioncall_render_targets_8616(codegen) == 1
    selected, target = call.callee_func, call.callee_target
    authority = angr.load_shellcode(b'\xc3', arch='x86', load_address=0x1000) if foreign_project else project
    address = 0x1000 if foreign_project else 0x1001
    assert set_cfunctioncall_render_name_8616(authority, call, address, 'sub_1000') is None
    assert call.callee_func is selected and call.callee_target is target
    assert call.callee_func.project is project


def test_unresolved_render_target_keeps_semantic_metadata():
    """An absent KB disables name disambiguation without inventing target proof."""
    _project, _canonical, _detached, codegen, call = _detached_native_call()
    codegen.project = _NoKbProject()
    assert repair_cfunctioncall_render_targets_8616(codegen) == 1
    assert call.callee_func is None
    assert call.callee_target == 'helper'


def test_render_target_lookup_preserves_unexpected_exception():
    """A broken native lookup must retain its cause instead of silently guessing."""
    _project, _canonical, _detached, codegen, _call = _detached_native_call()
    failure = ValueError('explicit KB failure')

    def lookup(*, addr, create):
        assert addr == 0x1000 and not create
        raise failure

    codegen.project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lookup)))
    with pytest.raises(ValueError) as caught:
        repair_cfunctioncall_render_targets_8616(codegen)
    assert caught.value is failure


def test_render_compat_sort_local_vars_accepts_none_and_string_idents():
    install_structured_codegen_sort_compat_8616()
    unnamed = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000)
    named = SimStackVariable(-2, 2, base="bp", name="local_2_alias", region=0x1000)
    unnamed.ident = None
    named.ident = "local_2_alias"

    assert CFunction.sort_local_vars((named, unnamed)) == [unnamed, named]


def test_render_compat_preserves_temporary_declarations():
    install_structured_codegen_sort_compat_8616()
    first, second = SimTemporaryVariable(0, 4), SimTemporaryVariable(1, 2)
    stack = SimStackVariable(-4, 4, base="bp", ident=None)
    assert CFunction.sort_local_vars((second, stack, first)) == [stack, first, second]
