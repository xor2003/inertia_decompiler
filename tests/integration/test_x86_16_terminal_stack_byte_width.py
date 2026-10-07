"""Regressions for terminal return recovery from byte stack storage."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
import inertia.postprocess.decompiler_postprocess_stage as postprocess_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.semantics.branch_target_return import (
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
)
from inertia.structuring.return_chains import TerminalAxScanResult8616


def test_terminal_al_stack_load_keeps_byte_storage_width(monkeypatch) -> None:
    """Widen the recovered expression without widening its stack variable."""
    project = SimpleNamespace(
        arch=Arch86_16(),
        factory=SimpleNamespace(block=lambda _addr, opt_level=0: None),
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        cfunc=SimpleNamespace(
            functy=SimpleNamespace(
                returnty=SimTypeShort(False).with_arch(project.arch),
            ),
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    byte_variable = SimStackVariable(-4, 1, base="bp", name="b", region=0x1000)
    byte_cvar = CVariable(
        byte_variable,
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    requests: list[tuple[int, int]] = []

    def terminal_stack_expr(
        _project: object,
        _codegen: object,
        displacement: int,
        size: int,
    ) -> CVariable:
        requests.append((displacement, size))
        return byte_cvar

    def terminal_scan(
        _block_addrs: object,
        _load_block: object,
        _branch_target: object,
        callbacks: object,
    ) -> TerminalAxScanResult8616:
        effect = TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.MOV_REG_STACK,
            dst_reg="al",
            mem_disp=-4,
            mem_size=1,
        )
        action = callbacks.process_instruction(object(), effect)
        assert action.classified is True
        return TerminalAxScanResult8616(
            expr=callbacks.combined_return_expr(),
            raw_insns=1,
            classified=1,
            terminal_value_block_count=1,
        )

    monkeypatch.setattr(postprocess_stage, "_terminal_stack_arg_expr_8616", terminal_stack_expr)
    monkeypatch.setattr(postprocess_stage, "_structuring_linear_terminal_ax_return_scan_8616", terminal_scan)
    function = SimpleNamespace(block_addrs_set={0x1000})

    result = postprocess_stage._linear_terminal_ax_return_expr_8616(
        project,
        codegen,
        function,
    )

    assert requests == [(-4, 1)]
    assert byte_variable.size == 1
    assert isinstance(result, CBinaryOp)
    assert result.op == "And"
