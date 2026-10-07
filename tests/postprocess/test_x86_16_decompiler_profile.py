import sys
from collections import UserDict
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

import inertia.postprocess.decompiler_postprocess as postprocess
from inertia.postprocess.decompiler_postprocess import (
    _apply_annotations_8616,
    _apply_stack_arg_cvar_type_8616,
    _classify_return_shape_8616,
    _normalize_arg_names_8616,
    _normalize_function_prototype_arg_names_8616,
    _return_value_is_unresolved_synthetic_carrier_8616,
)
from inertia.postprocess.decompiler_postprocess_stage import (
    DECOMPILER_POSTPROCESS_PASSES,
    _decompiler_postprocess_passes_for_function,
    _is_exposed_nonvoid_stack_arg_scalar_return_delta_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
)

from inertia.lowering.annotations import (
    ANNOTATION_KEY,
    _parse_c_prototype_8616,
    _source_decl_from_cod_source_lines,
    _source_decl_from_cod_source_lines_cached_8616,
)
from inertia.lowering.annotations import (
    _normalize_arg_names as _normalize_annotation_arg_names,
)


class _DummyFunction:
    def __init__(self, addr: int, *, call_sites=(), info=None):
        self.addr = addr
        self.info = info or {}
        self._call_sites = tuple(call_sites)

    def get_call_sites(self):
        return self._call_sites


def test_source_decl_from_cod_source_lines_is_cached_by_function_name():
    _source_decl_from_cod_source_lines_cached_8616.cache_clear()
    source_lines = (
        "int helper(int x);",
        "void HeapSort(void)",
        "{",
        "}",
    )

    assert _source_decl_from_cod_source_lines(source_lines, "HeapSort") is None
    first_info = _source_decl_from_cod_source_lines_cached_8616.cache_info()
    assert first_info.misses == 0
    assert _source_decl_from_cod_source_lines(source_lines, "HeapSort") is None
    second_info = _source_decl_from_cod_source_lines_cached_8616.cache_info()
    assert second_info.hits == first_info.hits


class _FakeInsn:
    def __init__(self, mnemonic: str, op_str: str):
        self.mnemonic = mnemonic
        self.op_str = op_str


class _FakeBlock:
    def __init__(self, insns):
        self.capstone = SimpleNamespace(insns=tuple(insns))


class _FakeFactory:
    def __init__(self, blocks):
        self._blocks = blocks

    def block(self, addr, opt_level=0):
        return self._blocks[addr]


class _FakeProject:
    def __init__(self, blocks):
        self.factory = _FakeFactory(blocks)


class _FakeFunctionManager:
    def __init__(self):
        self._funcs = {}

    def function(self, addr, create=False, **_kwargs):
        func = self._funcs.get(addr)
        if func is None and create:
            func = SimpleNamespace(addr=addr, name=f"sub_{addr:x}", info={})
            self._funcs[addr] = func
        return func


def test_tiny_function_with_only_call_sites_can_still_be_wrapper_like():
    function = _DummyFunction(0x1000, call_sites=(0x1010,), info={})

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)
    options = _decompile._preferred_decompiler_options(1, 24, wrapper_like=profile["wrapper_like"])

    assert profile["call_site_count"] == 1
    assert profile["wrapper_like"] is True
    assert options == [("structurer_cls", "Phoenix")]


def test_tiny_wrapper_like_profile_selects_cheaper_structurer():
    function = _DummyFunction(0x1000, call_sites=(), info={})

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)
    options = _decompile._preferred_decompiler_options(1, 24, wrapper_like=profile["wrapper_like"])

    assert profile["wrapper_like"] is True
    assert options == [("structurer_cls", "Phoenix")]


def test_single_block_helper_with_absolute_memory_traffic_is_not_wrapper_like():
    blocks = {
        0x1000: _FakeBlock(
            [
                _FakeInsn("push", "bp"),
                _FakeInsn("mov", "bp, sp"),
                _FakeInsn("mov", "byte ptr [0x7000], 0x48"),
                _FakeInsn("call", "0x101c"),
            ]
        )
    }
    function = _DummyFunction(0x1000, call_sites=(), info={})
    function.project = _FakeProject(blocks)
    function.block_addrs_set = {0x1000}

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)

    assert profile["wrapper_like"] is False
    assert profile["internal_call_count"] == 1


def test_single_block_helper_with_internal_call_is_not_wrapper_like():
    blocks = {
        0x1000: _FakeBlock(
            [
                _FakeInsn("push", "bp"),
                _FakeInsn("mov", "bp, sp"),
                _FakeInsn("call", "0x101c"),
                _FakeInsn("ret", ""),
            ]
        )
    }
    function = _DummyFunction(0x1000, call_sites=(), info={})
    function.project = _FakeProject(blocks)
    function.block_addrs_set = {0x1000}

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)

    assert profile["wrapper_like"] is False
    assert profile["internal_call_count"] == 1


def test_tiny_wrapper_like_postprocess_keeps_argument_normalization():
    function = _DummyFunction(
        0x1000,
        info={"x86_16_decompilation_profile": {"wrapper_like": True}},
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None)
        )
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr))

    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
    pass_names = tuple(spec.name for spec in pass_specs)

    assert pass_names[:6] == (
        "_apply_word_global_types_8616",
        "_apply_annotations_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_return_address_stack_arguments_8616",
        "_prune_unused_unnamed_memory_declarations_8616",
    )
    assert "_lower_stable_ss_stack_accesses_8616" in pass_names
    assert tuple(name for name in pass_names if "callsite" in name or "direct_calls" in name) == (
        "_attach_callsite_summaries_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
    )


def test_call_heavy_small_function_postprocess_keeps_full_pass_list():
    function = _DummyFunction(
        0x1000,
        info={"x86_16_decompilation_profile": {"wrapper_like": False}},
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None)
        )
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr))

    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
    pass_names = tuple(spec.name for spec in pass_specs)
    expected_names = tuple(spec.name for spec in DECOMPILER_POSTPROCESS_PASSES)

    default_disabled = {
        "_normalize_fact_backed_stack_accesses_8616",
        "_simplify_boolean_cites_8616",
        "_simplify_structured_expressions_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_recover_missing_direct_calls_final_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_normalize_recovered_call_target_names_8616",
        "_normalize_call_target_names_final_8616",
    }

    assert pass_names == tuple(name for name in expected_names if name not in default_disabled)
    assert "_apply_annotations_8616" in pass_names
    assert "_normalize_function_prototype_arg_names_8616" in pass_names
    assert "_materialize_callsite_stack_arguments_final_8616" not in pass_names


def test_call_heavy_small_function_profile_is_not_marked_wrapper_like():
    function = _DummyFunction(0x1000, call_sites=(0x1010,), info={})

    profile = _decompile._function_decompilation_profile(function, block_count=4, byte_count=48)
    options = _decompile._preferred_decompiler_options(4, 48, wrapper_like=profile["wrapper_like"])

    assert profile["wrapper_like"] is False
    assert options is None


def test_linear_region_inference_keeps_early_return_fallthrough_code():
    path = REPO_ROOT / "cod" / "f14" / "CARR.COD"
    entries = _decompile.extract_cod_function_entries(path, "_SetHook", "NEAR")
    selected_entries = _decompile.extract_small_two_arg_cod_logic_entries(entries)
    if selected_entries is None:
        selected_entries = _decompile.extract_simple_cod_logic_entries(entries)
    if selected_entries is None:
        logic_start = _decompile.infer_cod_logic_start(entries)
        proc_code, _ = _decompile.join_cod_entries_with_synthetic_globals(entries, start_offset=logic_start)
    else:
        proc_code, _ = _decompile.join_cod_entries_with_synthetic_globals(selected_entries)

    project = _decompile._build_project_from_bytes(proc_code, base_addr=0x1000, entry_point=0x1000)
    region = _decompile._infer_x86_16_linear_region(project, 0x1000, window=len(proc_code))

    assert region == (0x1000, 0x1033)


def test_normalize_arg_names_makes_duplicates_unique():
    assert _normalize_arg_names_8616(("s", "s", None), 3) == ["s", "s_2", "a2"]


def test_annotation_arg_names_are_normalized_before_assignment():
    assert _normalize_annotation_arg_names(["s", "s", None], 3) == ["s", "s_2", "a2"]


def test_normalize_function_prototype_arg_names_pass_updates_duplicates():
    from angr.sim_type import SimTypeShort

    class _DummyPrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = arg_names
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    prototype = _DummyPrototype([SimTypeShort(False), SimTypeShort(False)], SimTypeShort(False), arg_names=("s", "s"))
    func = SimpleNamespace(prototype=prototype)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, prototype=prototype))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )

    changed = _normalize_function_prototype_arg_names_8616(project, codegen)

    assert changed is True
    assert func.prototype.arg_names == ["s", "s_2"]
    assert codegen.cfunc.prototype.arg_names == ["s", "s_2"]


def test_parse_c_prototype_treats_unknown_source_types_as_opaque_words():
    name, prototype, _ = _parse_c_prototype_8616("void Swaps( BAR *bar1, BAR *bar2 );")

    assert name == "Swaps"
    assert len(prototype.args) == 2
    assert tuple(prototype.arg_names or ()) == ("bar1", "bar2")


def test_attach_cod_variable_names_deduplicates_stack_aliases():
    stack_a = SimStackVariable(-6, 2, base="bp", name="v0", region=0x1000)
    stack_b = SimStackVariable(-2, 2, base="bp", name="v1", region=0x1000)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            variables_in_use={
                stack_a: SimpleNamespace(unified_variable=SimpleNamespace(name="v0")),
                stack_b: SimpleNamespace(unified_variable=SimpleNamespace(name="v1")),
            }
        )
    )
    cod_metadata = SimpleNamespace(stack_aliases={-6: "err", -2: "err"})

    changed = _decompile._attach_cod_variable_names(codegen, cod_metadata)
    changed_again = _decompile._attach_cod_variable_names(codegen, cod_metadata)

    assert changed is False
    assert changed_again is False
    assert stack_a.name == "v0"
    assert stack_b.name == "v1"
    assert codegen.cfunc.variables_in_use[stack_a].unified_variable.name == "v0"
    assert codegen.cfunc.variables_in_use[stack_b].unified_variable.name == "v1"


def test_attach_cod_variable_names_uses_normalized_bp_displacements():
    arg_lhs = SimStackVariable(2, 2, base="bp", name="arg_4", region=0x1000)
    arg_rhs = SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000)
    local_tmp = SimStackVariable(-4, 2, base="bp", name="local_2", region=0x1000)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            variables_in_use={
                arg_lhs: SimpleNamespace(unified_variable=SimpleNamespace(name="arg_4")),
                arg_rhs: SimpleNamespace(unified_variable=SimpleNamespace(name="arg_6")),
                local_tmp: SimpleNamespace(unified_variable=SimpleNamespace(name="local_2")),
            }
        )
    )
    cod_metadata = SimpleNamespace(stack_aliases={4: "lhs", 6: "rhs", -2: "tmp"})

    changed = _decompile._attach_cod_variable_names(codegen, cod_metadata)

    assert changed is False
    assert arg_lhs.name == "arg_4"
    assert arg_rhs.name == "arg_6"
    assert local_tmp.name == "local_2"
    assert codegen.cfunc.variables_in_use[arg_lhs].unified_variable.name == "arg_4"
    assert codegen.cfunc.variables_in_use[arg_rhs].unified_variable.name == "arg_6"
    assert codegen.cfunc.variables_in_use[local_tmp].unified_variable.name == "local_2"


def test_attach_cod_variable_names_keeps_exact_source_backed_arg_offsets():
    value_var = SimStackVariable(4, 2, base="bp", name="value", region=0x1000)
    limit_var = SimStackVariable(6, 2, base="bp", name="limit", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    value_cvar = structured_c.CVariable(value_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    limit_cvar = structured_c.CVariable(limit_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            variables_in_use={
                value_var: value_cvar,
                limit_var: limit_cvar,
            },
            arg_list=[value_cvar, limit_cvar],
        )
    )
    cod_metadata = SimpleNamespace(stack_aliases={2: "value", 4: "limit"})

    changed = _decompile._attach_cod_variable_names(codegen, cod_metadata)

    assert changed is False
    assert value_var.name == "value"
    assert limit_var.name == "limit"
    assert value_cvar.name == "value"
    assert limit_cvar.name == "limit"


def test_attach_cod_variable_names_prefers_exact_negative_bp_displacements():
    switch_slot = SimStackVariable(-8, 2, base="bp", name="arg_6", region=0x1000)
    limit_slot = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x1000)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            variables_in_use={
                switch_slot: SimpleNamespace(unified_variable=SimpleNamespace(name="arg_6")),
                limit_slot: SimpleNamespace(unified_variable=SimpleNamespace(name="local_6")),
            }
        )
    )
    cod_metadata = SimpleNamespace(stack_aliases={-8: "iSwitch", -6: "iLimit"})

    changed = _decompile._attach_cod_variable_names(codegen, cod_metadata)

    assert changed is False
    assert switch_slot.name == "arg_6"
    assert limit_slot.name == "local_6"
    assert codegen.cfunc.variables_in_use[switch_slot].unified_variable.name == "arg_6"
    assert codegen.cfunc.variables_in_use[limit_slot].unified_variable.name == "local_6"


def test_attach_cod_variable_names_visits_stack_nodes_missing_from_variables_in_use():
    stack_var = SimStackVariable(-8, 2, base="bp", name="arg_6", region=0x1000)
    codegen = SimpleNamespace(next_idx=lambda _kind: 0, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    stack_node = structured_c.CVariable(stack_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=stack_node,
        variables_in_use={},
    )
    cod_metadata = SimpleNamespace(stack_aliases={-8: "iSwitch"})

    changed = _decompile._attach_cod_variable_names(codegen, cod_metadata)

    assert changed is False
    assert stack_var.name == "arg_6"
    assert codegen.cfunc.variables_in_use == {}


def test_attach_project_cod_source_annotations_is_inert():
    functions = _FakeFunctionManager()
    func = functions.function(0x1000, create=True)
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=functions),
        _inertia_cod_metadata_by_func_addr_8616={
            0x1000: SimpleNamespace(
                stack_aliases={4: "lhs", 6: "rhs", -2: "tmp"},
                source_lines=("void swap(int *lhs, int *rhs)", "{", "}"),
            )
        },
    )

    changed = postprocess._attach_project_cod_source_annotations_if_missing_8616(project, 0x1000, func)

    assert changed is False
    assert ANNOTATION_KEY not in func.info


def test_attach_project_cod_source_annotations_preserves_mutable_mapping_info_without_writing():
    functions = _FakeFunctionManager()
    func = functions.function(0x1000, create=True)
    func.info = UserDict()
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=functions),
        _inertia_cod_metadata_by_func_addr_8616={
            0x1000: SimpleNamespace(
                stack_aliases={4: "lhs"},
                source_lines=("void swap(int *lhs)", "{", "}"),
            )
        },
    )

    changed = postprocess._attach_project_cod_source_annotations_if_missing_8616(project, 0x1000, func)

    assert changed is False
    assert ANNOTATION_KEY not in func.info


def test_apply_annotations_deduplicates_stack_variable_names():
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    stack_a = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    stack_b = SimStackVariable(6, 2, base="bp", name="s", region=0x1000)
    ast_codegen = _FakeCodegen()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=structured_c.CStatements([], codegen=ast_codegen),
            variables_in_use={
                stack_a: structured_c.CVariable(
                    stack_a, unified_variable=SimpleNamespace(name="s"), codegen=ast_codegen
                ),
                stack_b: structured_c.CVariable(
                    stack_b, unified_variable=SimpleNamespace(name="s"), codegen=ast_codegen
                ),
            },
        )
    )
    func = SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {4: {"name": "s"}}}})
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        )
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert stack_a.name == "s"
    assert stack_b.name == "s_2"
    assert codegen.cfunc.variables_in_use[stack_a].unified_variable.name == "s"
    assert codegen.cfunc.variables_in_use[stack_b].unified_variable.name == "s_2"


def test_apply_annotations_names_projected_arguments_by_machine_bp_offset() -> None:
    """Keep adjacent arguments distinct when angr stores entry-SP offsets."""

    class _FakeCodegen:
        def __init__(self) -> None:
            self._idx = 0
            self.cstyle_null_cmp = False

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx

        def next_node_idx(self) -> int:
            return self.next_idx("")

        def next_ident(self, name: str) -> str:
            return name

    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [word_type, word_type],
        word_type,
        arg_names=("a", "b"),
    ).with_arch(arch)
    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=arch)
    left_variable = SimStackVariable(2, 2, base="bp", name="arg_4", region=0x1000)
    right_variable = SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000)
    left = structured_c.CVariable(left_variable, variable_type=word_type, codegen=codegen)
    right = structured_c.CVariable(right_variable, variable_type=word_type, codegen=codegen)
    body_left_variable = SimStackVariable(2, 2, base="bp", name="arg_4", region=0x1000)
    body_right_variable = SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000)
    body_left = structured_c.CVariable(
        body_left_variable,
        variable_type=word_type,
        codegen=codegen,
    )
    body_right = structured_c.CVariable(
        body_right_variable,
        variable_type=word_type,
        codegen=codegen,
    )
    left_map_variable = SimStackVariable(2, 2, base="bp", name="arg_4", region=0x1000)
    right_map_variable = SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000)
    condition = structured_c.CBinaryOp("CmpGT", body_right, body_left, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([condition], codegen=codegen),
        variables_in_use={left_map_variable: left, right_map_variable: right},
        unified_local_vars={},
        arg_list=[left, right],
        functy=prototype,
        prototype=prototype,
    )
    function = SimpleNamespace(
        prototype=prototype,
        info={
            "x86_16_annotations": {
                "prototype": prototype,
                "stack_vars": {
                    2: {"name": "a"},
                    4: {"name": "b"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function if addr == 0x1000 else None,
            )
        ),
    )
    codegen.project = project
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=left_variable,
        cvar=left,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=right_variable,
        cvar=right,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )
    assert record_stack_variable_coordinate_alias_8616(
        codegen,
        bp_offset=4,
        size=2,
        variable=body_left_variable,
    ) is not None
    assert record_stack_variable_coordinate_alias_8616(
        codegen,
        bp_offset=6,
        size=2,
        variable=body_right_variable,
    ) is not None

    assert postprocess._positive_stack_specs_are_normalized_for_codegen_8616(
        function.info["x86_16_annotations"]["stack_vars"],
        codegen,
    ) is True
    assert _apply_annotations_8616(project, codegen) is True
    assert left_variable.name == "a"
    assert right_variable.name == "b"
    assert condition.lhs.variable is right_variable
    assert condition.rhs.variable is left_variable


def test_apply_annotations_keeps_structurally_equal_codegen_prototype_unchanged():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    current_prototype = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=("value",),
        variadic=False,
    )
    metadata_prototype = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=("value",),
        variadic=False,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=structured_c.CStatements([], codegen=_FakeCodegen()),
            variables_in_use={},
            arg_list=[],
            functy=current_prototype,
        )
    )
    func = SimpleNamespace(
        prototype=metadata_prototype,
        info={"x86_16_annotations": {"stack_vars": {}}},
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        )
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.functy is current_prototype
    assert not hasattr(codegen, "_inertia_codegen_prototype_sync_count_8616")


def test_apply_stack_arg_cvar_type_ignores_structurally_equal_type():
    arch = Arch86_16()
    cvar = SimpleNamespace(variable_type=SimTypeShort(False).with_arch(arch))
    requested_type = SimTypeShort(False).with_arch(arch)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(variable_manager=None))

    changed = _apply_stack_arg_cvar_type_8616(codegen, cvar, requested_type)

    assert changed is False


def test_materialize_missing_register_local_declarations_recovers_unified_locals():
    register = SimRegisterVariable(0, 2, name="a1", region=0x1000)

    class _HashableCVar(SimpleNamespace):
        __hash__ = object.__hash__

    cvar = _HashableCVar(variable_type=SimTypeShort(False), unified_variable=SimpleNamespace(name="a1"))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=(),
            unified_local_vars={},
            variables_in_use={register: cvar},
        )
    )

    changed = _decompile._materialize_missing_register_local_declarations(codegen)

    assert changed is True
    assert register in codegen.cfunc.unified_local_vars
    assert len(codegen.cfunc.unified_local_vars[register]) == 1


def test_materialize_missing_register_local_declarations_keeps_distinct_register_names():
    raw_ax = SimRegisterVariable(0, 2, name="ax", region=0x1000)
    temp_ax = SimRegisterVariable(0, 2, name="v19", region=0x1000)

    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.cstyle_null_cmp = False
            self.project = SimpleNamespace(arch=Arch86_16())

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    cnode_codegen = _FakeCodegen()
    raw_cvar = structured_c.CVariable(raw_ax, variable_type=SimTypeShort(False), codegen=cnode_codegen)
    temp_cvar = structured_c.CVariable(temp_ax, variable_type=SimTypeShort(False), codegen=cnode_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=(),
            statements=structured_c.CStatements([raw_cvar], codegen=cnode_codegen),
            unified_local_vars={temp_ax: {(temp_cvar, SimTypeShort(False))}},
            variables_in_use={temp_ax: temp_cvar},
        )
    )

    changed = _decompile._materialize_missing_register_local_declarations(codegen)

    assert changed is True
    assert raw_cvar.unified_variable is temp_ax
    assert temp_ax in codegen.cfunc.unified_local_vars


def test_dedupe_codegen_variable_names_prefers_meaningful_name_and_uniquifies():
    stack_a = SimStackVariable(4, 2, base="bp", name="count", region=0x1000)
    stack_b = SimStackVariable(6, 2, base="bp", name="count", region=0x1000)
    cvar_a = SimpleNamespace(name="v1", unified_variable=SimpleNamespace(name="count"))
    cvar_b = SimpleNamespace(name="v2", unified_variable=SimpleNamespace(name="count"))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=(),
            unified_local_vars={},
            variables_in_use={stack_a: cvar_a, stack_b: cvar_b},
            sort_local_vars=lambda: None,
        )
    )

    changed = _decompile._dedupe_codegen_variable_names_8616(codegen)

    assert changed is True
    assert stack_a.name == "count"
    assert stack_b.name == "count_2"
    assert cvar_a.name == "count"
    assert cvar_b.name == "count_2"


def test_apply_annotations_resolves_direct_bp_stack_loads_to_annotated_slots(monkeypatch):
    class _FakeCodegen:
        def __init__(self, project):
            self._idx = 0
            self.project = project

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    project_stub = SimpleNamespace(arch=SimpleNamespace())
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    stack_cvar = structured_c.CVariable(
        stack_var, variable_type=SimTypeShort(False), codegen=_FakeCodegen(project_stub)
    )
    bp_stack_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CConstant(0, SimTypeShort(False), codegen=_FakeCodegen(project_stub)),
        codegen=_FakeCodegen(project_stub),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=structured_c.CStatements([bp_stack_load], codegen=_FakeCodegen(project_stub)),
            variables_in_use={stack_var: stack_cvar},
        )
    )
    func = SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {4: {"name": "s"}}}})
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        )
    )

    monkeypatch.setattr(
        postprocess,
        "_match_bp_stack_load_8616",
        lambda node, _project: 4 if node is bp_stack_load else None,
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements[0] is stack_cvar


def test_apply_annotations_materializes_stack_arguments_from_annotations():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    class _FakePrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = tuple(arg_names or ())
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=Arch86_16())
    prototype = _FakePrototype([], SimTypeShort(False))
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([], codegen=codegen),
        variables_in_use={},
        arg_list=[],
        functy=prototype,
    )
    func = SimpleNamespace(
        prototype=prototype,
        info={"x86_16_annotations": {"stack_vars": {4: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["segment"]
    assert isinstance(codegen.cfunc.arg_list[0], structured_c.CVariable)
    assert codegen.cfunc.arg_list[0].variable.offset == 4
    assert codegen.cfunc.functy.arg_names == ("segment",)


def test_apply_annotations_shrinks_overguessed_stack_arguments():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    class _FakePrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = tuple(arg_names or ())
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=Arch86_16())
    prototype = _FakePrototype([SimTypeShort(False), SimTypeShort(False)], SimTypeShort(False), arg_names=("a0", "a1"))
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([], codegen=codegen),
        variables_in_use={},
        arg_list=[],
        functy=prototype,
        prototype=prototype,
    )
    codegen.project = SimpleNamespace(arch=Arch86_16())
    func = SimpleNamespace(
        prototype=prototype,
        info={"x86_16_annotations": {"stack_vars": {4: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["segment"]
    assert codegen.cfunc.functy.arg_names == ("segment",)
    assert len(codegen.cfunc.functy.args) == 1


def test_return_shape_classify_ignores_cfg_proven_switch_loop_unreachable_tail_returns():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    class _FakePrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = tuple(arg_names or ())
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=Arch86_16())
    prototype = _FakePrototype([], SimTypeShort(False))
    selector = structured_c.CVariable("ax", codegen=codegen)
    switch = structured_c.CSwitchCase(
        selector,
        [(27, structured_c.CStatements([structured_c.CReturn(None, codegen=codegen)], codegen=codegen))],
        None,
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        structured_c.CStatements([switch], codegen=codegen),
        codegen=codegen,
    )
    tail = structured_c.CStatements(
        [
            structured_c.CReturn(structured_c.CVariable("vvar_127", codegen=codegen), codegen=codegen),
            structured_c.CReturn(selector, codegen=codegen),
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([loop, tail], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        variables_in_use={},
        arg_list=[],
        functy=prototype,
        prototype=prototype,
    )
    codegen._inertia_switch_loop_exit_return_materialized_8616 = True
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )

    changed = _classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)
    assert func.prototype.returnty.label == "void"
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeBottom)
    assert func.info["x86_16_return_shape"]["ignored_unreachable_returns"] == 2


def test_return_shape_classify_keeps_unobserved_default_scalar_synthetic_return():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=Arch86_16())
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(Arch86_16())
    synthetic_segment = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="v4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    synthetic_linear = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Mul",
            structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
            synthetic_segment,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    synthetic_stack_local_return = structured_c.CBinaryOp(
        "Sub",
        structured_c.CVariable(
            SimStackVariable(-2, 2, base="bp", name="local_2_2", region=0x1000),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        structured_c.CConstant(44, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assert _return_value_is_unresolved_synthetic_carrier_8616(synthetic_stack_local_return) is True
    top_level_stack_local_return = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assert _return_value_is_unresolved_synthetic_carrier_8616(top_level_stack_local_return) is True
    unnamed_stack_slot_return = structured_c.CBinaryOp(
        "Sub",
        structured_c.CVariable(
            SimStackVariable(-2, 4, base="bp", region=0x1000),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        structured_c.CConstant(44, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assert _return_value_is_unresolved_synthetic_carrier_8616(unnamed_stack_slot_return) is True
    indexed_stack_segment_return = structured_c.CBinaryOp(
        "Sub",
        structured_c.CIndexedVariable(
            structured_c.CUnaryOp(
                "Reference",
                structured_c.CVariable(
                    SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                structured_c.CVariable(
                    SimRegisterVariable(0, 2, name="ss"),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        structured_c.CConstant(44, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assert _return_value_is_unresolved_synthetic_carrier_8616(indexed_stack_segment_return) is True
    synthetic_return = structured_c.CReturn(
        structured_c.CBinaryOp(
            "Sub",
            synthetic_linear,
            structured_c.CConstant(44, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([synthetic_return], codegen=codegen),
        variables_in_use={},
        arg_list=[],
        functy=prototype,
        prototype=prototype,
    )
    func = SimpleNamespace(
        addr=0x1000,
        name="DrawBar",
        prototype=prototype,
        is_prototype_guessed=False,
        _inertia_return_compat_caller_uses_return_8616=False,
        info={},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )

    changed = _classify_return_shape_8616(project, codegen)

    assert changed is False
    assert synthetic_return.retval is not None
    assert isinstance(func.prototype.returnty, SimTypeShort)
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert "x86_16_return_shape" not in func.info


def test_validation_accepts_exposed_nonvoid_stack_arg_scalar_return():
    function = SimpleNamespace(
        prototype=SimTypeFunction((SimTypeShort(False),), SimTypeShort(False)),
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("Add(stack_slot:SS:BP+0x4:size2,const:1)",),
                "removed": ("none",),
            },
        },
    }

    assert _is_exposed_nonvoid_stack_arg_scalar_return_delta_8616(function, validation)


def test_validation_refuses_exposed_nonvoid_call_return_without_stack_arg_proof():
    function = SimpleNamespace(
        prototype=SimTypeFunction((SimTypeShort(False),), SimTypeShort(False)),
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("call:helper",),
                "removed": ("none",),
            },
        },
    }

    assert not _is_exposed_nonvoid_stack_arg_scalar_return_delta_8616(function, validation)


def test_simplify_structured_expressions_rewrites_far_pointer_stack_pairs_to_mk_fp():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=SimpleNamespace())
    codegen.cstyle_null_cmp = False
    offset_var = SimStackVariable(-0xA, 2, base="bp", name="ovlHeader_2", region=0x1000)
    segment_var = SimStackVariable(-0x8, 2, base="bp", name="ovlHeader", region=0x1000)
    slot_var = SimStackVariable(-0x6, 2, base="bp", name="slotArray_2", region=0x1000)
    segment_source = SimRegisterVariable(0x10, 2, name="ovlLoadSegment")
    offset_cvar = structured_c.CVariable(offset_var, variable_type=SimTypeShort(False), codegen=codegen)
    segment_cvar = structured_c.CVariable(segment_var, variable_type=SimTypeShort(False), codegen=codegen)
    slot_cvar = structured_c.CVariable(slot_var, variable_type=SimTypeShort(False), codegen=codegen)
    segment_source_cvar = structured_c.CVariable(segment_source, variable_type=SimTypeShort(False), codegen=codegen)
    stmts = structured_c.CStatements(
        [
            structured_c.CAssignment(
                offset_cvar, structured_c.CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen
            ),
            structured_c.CAssignment(segment_cvar, segment_source_cvar, codegen=codegen),
            structured_c.CAssignment(
                slot_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    offset_cvar,
                    structured_c.CConstant(36, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=stmts)

    changed = _decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[2].rhs
    assert isinstance(rhs, structured_c.CFunctionCall)
    assert rhs.callee_target == "MK_FP"
