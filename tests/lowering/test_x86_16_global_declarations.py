from types import SimpleNamespace

from inertia.lowering.global_declarations import (
    NamedAggregateDeclarationCType8616,
    record_global_declaration_spec_8616,
)


def test_registered_named_aggregate_replaces_scalar_compatibility_view() -> None:
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(("unsigned short", "g_work", 1),),
    )

    record_global_declaration_spec_8616(
        codegen,
        ctype=NamedAggregateDeclarationCType8616(
            type_name="g_work_entry",
            inline_definition="struct g_work_entry { unsigned char field_0; unsigned char field_1; }",
            registered=True,
        ),
        name="g_work",
        array_len=16,
    )

    assert codegen._inertia_global_declaration_specs_8616 == (("g_work_entry", "g_work", 16),)
