"""Tests for typed deliberate near-return-frame discard lowering."""

from __future__ import annotations

import io
from itertools import count
from types import MappingProxyType, SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.rustylib.ailment import Tags
import inertia.frontend.x86_16.lift_86_16 as lift_86_16
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.control_stack_escape import (
    ControlStackEscapeFact8616,
    ControlStackEscapeKind8616,
    ControlStackEscapeRecord8616,
    materialize_control_stack_escape_8616,
)


@pytest.mark.parametrize("tag_factory", (dict, MappingProxyType, Tags))
def test_escape_materialization_preserves_mapping_tags_and_replay(tag_factory) -> None:
    """Consume mapping metadata without dropping other evidence or duplicating RET."""
    codegen = SimpleNamespace(next_ident=lambda name: name, next_node_idx=count().__next__)
    fact = ControlStackEscapeFact8616(
        0x1000, 0x1000, 0x1001, "ax", 2, 1,
        ControlStackEscapeKind8616.DISCARD_NEAR_RETURN_FRAME,
    )
    evidence = object()
    tags = {"ins_addr": 0x1001, "prior_evidence": evidence}
    statement = c.CReturn(object(), codegen=codegen, tags=tags)
    statement.tags = tag_factory(tags)
    root = c.CStatements([statement], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert materialize_control_stack_escape_8616(codegen, fact)
    assert statement.retval is None
    assert statement.tags["prior_evidence"] is evidence
    assert statement.tags["inertia_x86_16_control_stack_escape"] is fact
    assert not materialize_control_stack_escape_8616(codegen, fact)
    assert root.statements == [statement]
    assert codegen._inertia_control_stack_escape_record_8616.closes_evidence


@pytest.mark.parametrize(
    ("code", "required_effect"),
    (
        (bytes.fromhex("58 c3"), None),
        (bytes.fromhex("58 8b 36 22 85 89 9c 2d 13 c3"), "SEG_U8"),
    ),
)
def test_entry_pop_terminal_ret_is_typed_control_stack_escape(
    code: bytes,
    required_effect: str | None,
) -> None:
    """Do not expose a deliberately discarded return address as a C result."""
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(normalize=True)
    decompilation = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert decompilation.codegen is not None
    assert "*(inertia_ss" not in decompilation.codegen.text
    if required_effect is not None:
        assert required_effect in decompilation.codegen.text
    record = decompilation.codegen._inertia_control_stack_escape_record_8616
    assert isinstance(record, ControlStackEscapeRecord8616)
    assert record.closes_evidence
    assert record.fact.pop_addr == 0x1000
    assert record.fact.extra_unwind_depth == 1
