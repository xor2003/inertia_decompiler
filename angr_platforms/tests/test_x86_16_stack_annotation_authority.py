"""Optional COD names must not supply function-parameter layout evidence."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import decompiler_postprocess
from angr_platforms.X86_16.annotations import (
    ANNOTATION_KEY,
    StackAnnotationPurpose8616,
    stack_layout_annotation_specs_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import (
    attach_cod_stack_alias_annotations_8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    positive_stack_specs_8616,
)


@pytest.mark.parametrize("first_bp", [4, 6])
def test_cod_names_do_not_supply_near_or_far_parameter_layout(first_bp: int) -> None:
    function = SimpleNamespace(addr=0x1000, prototype=None, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)),
    )
    aliases = {first_bp: "fn", first_bp + 4: "value"}

    assert attach_cod_stack_alias_annotations_8616(
        project, function.addr, SimpleNamespace(stack_aliases=aliases),
    )
    names = function.info[ANNOTATION_KEY]["stack_vars"]
    assert names[first_bp - 2]["name"] == "fn"
    assert names[first_bp + 2]["name"] == "value"
    assert positive_stack_specs_8616(function) == ()
    _annotations, _pointer_flags, specs, arguments = (
        decompiler_postprocess._collect_stack_promotion_inputs_8616(function)
    )
    assert specs == {}
    assert arguments == []
    assert not attach_cod_stack_alias_annotations_8616(
        project, function.addr, SimpleNamespace(stack_aliases=aliases),
    )


def test_explicit_stack_contract_keeps_its_existing_layout() -> None:
    function = SimpleNamespace(
        info={ANNOTATION_KEY: {"stack_vars": {4: {"name": "first"}, 6: {"name": "second"}}}},
    )
    assert positive_stack_specs_8616(function) == ((4, "first"), (6, "second"))


def test_only_explicit_layout_purpose_can_supply_geometry() -> None:
    explicit = {"name": "first", "purpose": StackAnnotationPurpose8616.EXPLICIT_LAYOUT}
    annotations = {"stack_vars": {
        4: explicit,
        6: {"name": "label", "purpose": StackAnnotationPurpose8616.NAME_ONLY},
        8: {"name": "unknown", "purpose": "future_unrecognized_purpose"},
    }}
    assert stack_layout_annotation_specs_8616(annotations) == {4: explicit}
