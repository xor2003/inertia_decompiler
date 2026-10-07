from __future__ import annotations

from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_jcc as decompiler_postprocess_jcc


def test_repeated_jcc_linear_scan_reuses_exact_frontend_decodes() -> None:
    calls: list[tuple[int, int | None, int]] = []
    instructions = {
        address: SimpleNamespace(address=address, size=1, mnemonic="nop")
        for address in range(0x1000, 0x1003)
    }

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        calls.append((address, num_inst, opt_level))
        return SimpleNamespace(capstone=SimpleNamespace(insns=(instructions[address],)))

    project = SimpleNamespace(
        factory=SimpleNamespace(block=decode_block),
        loader=SimpleNamespace(min_addr=0, main_object=SimpleNamespace(min_addr=0x1000)),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    first = decompiler_postprocess_jcc._linear_insns_before_addr_8616(project, codegen, 0x1003)
    second = decompiler_postprocess_jcc._linear_insns_before_addr_8616(project, codegen, 0x1003)

    assert first == second == tuple(instructions.values())
    assert calls == [
        (0x1000, 1, 0),
        (0x1001, 1, 0),
        (0x1002, 1, 0),
    ]
