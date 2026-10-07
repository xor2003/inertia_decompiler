"""Alias proofs for partial-register writes before word argument pushes."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.alias.partial_register_address_break import (
    collect_partial_register_address_break_8616,
)


def _instructions(code: bytes) -> tuple[object, ...]:
    """Decode one synthetic 16-bit block through the production frontend."""
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
    return tuple(project.factory.block(0x1000, size=len(code)).capstone.insns)


def test_low_byte_immediate_breaks_word_address_provenance() -> None:
    """Keep physical AX unknown while proving it is not an unchanged address."""
    evidence = collect_partial_register_address_break_8616(
        _instructions(bytes.fromhex("b00250c3")),
        0x1002,
    )

    assert evidence is not None
    assert evidence.complete
    assert evidence.carrier_register == "ax"
    assert evidence.written_register == "al"
    assert evidence.immediate == 2


def test_full_word_definition_is_not_partial_address_break_evidence() -> None:
    """A full AX definition belongs to ordinary value-source recovery."""
    evidence = collect_partial_register_address_break_8616(
        _instructions(bytes.fromhex("b8020050c3")),
        0x1003,
    )

    assert evidence is None


def test_latest_full_word_write_supersedes_earlier_partial_write() -> None:
    """Refuse stale partial-write evidence after a complete carrier rewrite."""
    evidence = collect_partial_register_address_break_8616(
        _instructions(bytes.fromhex("b002b8030050c3")),
        0x1005,
    )

    assert evidence is None


def test_incomplete_dynamic_instruction_surface_refuses_evidence() -> None:
    """Mixed compatibility fixtures must fail closed instead of raising."""
    evidence = collect_partial_register_address_break_8616(
        (SimpleNamespace(),),
        0x1000,
    )

    assert evidence is None
