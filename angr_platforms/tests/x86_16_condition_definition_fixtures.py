"""Small decoded CFG fixtures for condition projection tests.

Layer: Tests.
Responsibility: supply real instruction effects to isolated C projection tests.
"""

from types import SimpleNamespace
from typing import Any

import capstone
import pytest
from angr_platforms.X86_16 import register_source_block_inventory as owner
from angr_platforms.X86_16.register_source_block_inventory import (
    RegisterSourceBlockEvidence8616,
    RegisterSourceBlockInventory8616,
)


def install_condition_definition_block(
    monkeypatch: pytest.MonkeyPatch,
    project: Any,
    *,
    address: int,
    data: bytes,
) -> None:
    """Provide one complete decoded block without invoking expensive CFG analysis."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instructions = tuple(
        SimpleNamespace(address=insn.address, mnemonic=insn.mnemonic, insn=insn)
        for insn in decoder.disasm(data, address)
    )
    block = RegisterSourceBlockEvidence8616(address, (), instructions)
    inventory = RegisterSourceBlockInventory8616(address, (block,), 1, 1, 1, 1, 0)
    function = SimpleNamespace(addr=address)
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda **_kw: function))
    monkeypatch.setattr(owner, "collect_register_source_block_inventory_8616", lambda _function: inventory)
