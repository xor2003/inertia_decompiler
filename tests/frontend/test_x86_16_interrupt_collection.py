"""Focused tests for collecting decoded real-mode interrupt calls.

Layer: frontend analysis
Responsibility: prove that interrupt opcode forms become typed interrupt-call facts.
"""

from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.lowering.analysis_helpers import collect_interrupt_calls, render_interrupt_call


def test_collect_interrupt_calls_recognizes_single_byte_int3() -> None:
    """Map opcode CC's operand-free mnemonic to interrupt vector 3."""
    project = angr.load_shellcode(
        b"\xcc\xc3",
        arch=Arch86_16(),
        load_address=0x1000,
        simos="DOS",
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1000})

    calls = collect_interrupt_calls(function)

    assert len(calls) == 1
    assert calls[0].vector == 3
    assert calls[0].insn_addr == 0x1000


def test_collect_interrupt_calls_includes_transition_graph_endpoint_blocks() -> None:
    """Collect a terminating DOS service even when block_addrs_set omits its endpoint."""
    project = angr.load_shellcode(
        b"\xb4\x4c\xcd\x21",
        arch=Arch86_16(),
        load_address=0x1000,
        simos="DOS",
    )
    endpoint = SimpleNamespace(addr=0x1000, size=4)
    function = SimpleNamespace(
        project=project,
        block_addrs_set=set(),
        transition_graph=SimpleNamespace(nodes=(endpoint,)),
    )

    calls = collect_interrupt_calls(function)

    assert len(calls) == 1
    assert calls[0].insn_addr == 0x1002
    assert calls[0].ah == 0x4C


def test_collect_interrupt_calls_restores_pushed_register_across_zero_cleanup_calls() -> None:
    """A balanced PUSH/POP carries entry AX into the later DOS DS:DX argument."""
    code = (
        b"\x50"  # push ax
        b"\xe8\x0c\x00"  # call 1010h
        b"\xe8\x09\x00"  # call 1010h
        b"\x5a"  # pop dx
        b"\xb8\x00\x09"  # mov ax,0900h
        b"\xcd\x21"  # int 21h
        b"\xc3\x90\x90"  # ret; padding
        b"\xc3"  # 1010h: ret
    )
    original_project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        load_address=0x2000,
        simos="DOS",
    )
    project = angr.load_shellcode(
        code[:14],
        arch=Arch86_16(),
        load_address=0x1000,
        simos="DOS",
    )
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0x1000
    endpoints = (
        SimpleNamespace(addr=0x1000, size=4),
        SimpleNamespace(addr=0x1004, size=3),
        SimpleNamespace(addr=0x1007, size=7),
    )
    function = SimpleNamespace(
        project=project,
        block_addrs_set=set(),
        transition_graph=SimpleNamespace(nodes=endpoints),
    )

    calls = collect_interrupt_calls(function)

    assert len(calls) == 1
    assert calls[0].ah == 0x09
    assert calls[0].dx is None
    assert calls[0].dx_expr == "inertia_eax & 0xffff"
    assert render_interrupt_call(calls[0], "modern") == (
        "print_dos_string((const char *)(inertia_eax & 0xffff))"
    )


def test_collect_interrupt_calls_consumes_explicit_segment_for_near_encoded_far_call() -> None:
    """A proven RETF consumes contiguous PUSH CS without hiding the saved DX word."""
    code = (
        b"\x52"  # 1000h: push dx
        b"\x0e"  # push cs
        b"\xe8\x0b\x00"  # near-encoded call 1010h
        b"\x5a"  # pop dx
        b"\xb8\x00\x3d"  # mov ax,3d00h
        b"\xcd\x21"  # int 21h
        b"\xc3\x90\x90\x90\x90"  # ret; padding
        b"\xcb"  # 1010h: retf
    )
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        load_address=0x1000,
        simos="DOS",
    )
    endpoints = (
        SimpleNamespace(addr=0x1000, size=5),
        SimpleNamespace(addr=0x1005, size=7),
    )
    function = SimpleNamespace(
        project=project,
        block_addrs_set=set(),
        transition_graph=SimpleNamespace(nodes=endpoints),
    )

    calls = collect_interrupt_calls(function)

    assert len(calls) == 1
    assert calls[0].ah == 0x3D
    assert calls[0].dx is None
    assert calls[0].dx_expr == "inertia_edx & 0xffff"
    assert render_interrupt_call(calls[0], "modern") == (
        "open((const char *)(inertia_edx & 0xffff), 0)"
    )
