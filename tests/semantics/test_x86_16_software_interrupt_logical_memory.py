from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.semantics.software_interrupt_inputs import (
    SoftwareInterruptInputStats8616,
    build_software_interrupt_input_artifact_8616,
    software_interrupt_value_fingerprint_8616,
)


def _mouse_position_ir():
    code = bytes.fromhex(
        "b80400"  # mov ax, 4
        "8b4e04"  # mov cx, word ptr [bp+4]
        "d1e1"  # shl cx, 1
        "8b5606"  # mov dx, word ptr [bp+6]
        "cd33"  # int 33h
    )
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    return build_x86_16_ir_function_artifact(project, function)


def test_interrupt_inputs_consume_closed_byte_executed_word_reads() -> None:
    ir_artifact = _mouse_position_ir()

    artifact = build_software_interrupt_input_artifact_8616(ir_artifact)

    assert artifact.stats == SoftwareInterruptInputStats8616(1, 1, 1, 1, 0)
    assert len(artifact.facts) == 1
    assert tuple(
        software_interrupt_value_fingerprint_8616(value)
        for value in artifact.facts[0].argument_values
    ) == (
        "const:0x4:size2",
        "Shl(stack:SS:BP+0x4:size2,const:0x1:size1):size2",
        "stack:SS:BP+0x6:size2",
    )


def test_interrupt_inputs_refuse_byte_executed_words_without_logical_proof() -> None:
    ir_artifact = replace(_mouse_position_ir(), logical_memory=None)

    artifact = build_software_interrupt_input_artifact_8616(ir_artifact)

    assert artifact.facts == ()
    assert artifact.stats == SoftwareInterruptInputStats8616(1, 1, 1, 0, 1)
    assert artifact.refusals[0][2] == "cx,dx"
