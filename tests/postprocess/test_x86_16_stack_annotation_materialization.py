from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.postprocess.decompiler_postprocess import _apply_annotations_8616

from inertia.lowering.annotations import ANNOTATION_KEY


class _Functions:
    def __init__(self, func):
        self._func = func

    def function(self, addr, create=False):
        return self._func if addr == self._func.addr else None


class _Codegen(SimpleNamespace):
    def __init__(self):
        super().__init__()
        self._next = 0
        self.project = None
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_apply_annotations_matches_negative_normalized_cod_stack_offset():
    arch = archinfo.ArchX86()
    stack_var = SimStackVariable(-4, 4, base="bp", name="local_4", region=0x1000)
    codegen = _Codegen()
    project = SimpleNamespace(arch=arch)
    codegen.project = project
    cvar = structured_c.CVariable(stack_var, variable_type=SimTypeLong(False), codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={stack_var: cvar},
        unified_local_vars={},
        arg_list=[],
        statements=structured_c.CStatements([], codegen=codegen),
        functy=SimTypeFunction([], SimTypeLong(False)).with_arch(arch),
    )
    codegen.cfunc = cfunc
    func = SimpleNamespace(
        addr=0x1000,
        prototype=cfunc.functy,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {-6: "goal"},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            }
        },
    )
    project.kb = SimpleNamespace(functions=_Functions(func))

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert stack_var.name == "goal"
    assert getattr(cvar, "name", None) == "goal"


def test_apply_annotations_keeps_wide_name_off_interior_high_word():
    arch = archinfo.ArchX86()
    wide_var = SimStackVariable(-4, 4, base="bp", name="goal", region=0x1000)
    high_var = SimStackVariable(-2, 2, base="bp", name="goal", region=0x1000)
    codegen = _Codegen()
    project = SimpleNamespace(arch=arch)
    codegen.project = project
    wide_cvar = structured_c.CVariable(wide_var, variable_type=SimTypeLong(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={wide_var: wide_cvar, high_var: high_cvar},
        unified_local_vars={},
        arg_list=[],
        statements=structured_c.CStatements([], codegen=codegen),
        functy=SimTypeFunction([], SimTypeLong(False)).with_arch(arch),
    )
    codegen.cfunc = cfunc
    func = SimpleNamespace(
        addr=0x1000,
        prototype=cfunc.functy,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {-4: {"name": "goal", "type": "long"}},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            }
        },
    )
    project.kb = SimpleNamespace(functions=_Functions(func))

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert wide_var.name == "goal"
    assert high_var.name == "local_2"
    assert wide_cvar.name == "goal"
    assert high_cvar.name == "local_2"
