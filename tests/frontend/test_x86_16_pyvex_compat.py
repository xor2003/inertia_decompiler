from __future__ import annotations

import itertools

import inertia.frontend.x86_16.public_api  # noqa: F401
import pyvex.block
import pyvex.const as pyvex_const
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from pyvex.lifting.util import vex_helper

from inertia.cli.project_loading import _build_project_from_bytes


def test_pyvex_runtime_compatibility_is_applied() -> None:
    assert hasattr(pyvex_const.get_type_size, "cache_info")
    assert hasattr(pyvex_const.get_type_spec_size, "cache_info")
    assert vex_helper.Type.int_16 == vex_helper.Type.int_16


def test_arch_register_layout_is_stable_across_instances() -> None:
    first = Arch86_16()
    first_layout = {register.name: (register.vex_offset, register.size) for register in first.register_list}
    second = Arch86_16()
    second_layout = {register.name: (register.vex_offset, register.size) for register in second.register_list}

    assert second_layout == first_layout
    assert second.registers == first.registers
    ordered_spans = sorted((offset, offset + size, name) for name, (offset, size) in second_layout.items())
    assert all(left_end <= right_start for (_, left_end, _), (right_start, _, _) in itertools.pairwise(ordered_spans))


def test_pyvex_runtime_compatibility_avoids_eager_irsb_stringification(monkeypatch) -> None:
    original_str = pyvex.block.IRSB.__str__

    def _boom(self):
        raise AssertionError("IRSB.__str__ should not be called when debug logging is disabled")

    monkeypatch.setattr(pyvex.block.IRSB, "__str__", _boom)
    project = _build_project_from_bytes(b"\x55\x8b\xec\xb8\x01\x00\x5d\xc3", base_addr=0x1000, entry_point=0x1000)
    block = project.factory.block(0x1000, opt_level=0)
    irsb = block.vex_nostmt
    monkeypatch.setattr(pyvex.block.IRSB, "__str__", original_str)
    assert irsb is not None
