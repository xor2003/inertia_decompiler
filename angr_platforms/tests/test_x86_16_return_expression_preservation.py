"""Existing native return expressions are not missing-value placeholders."""

from angr_platforms.X86_16 import decompiler_return_compat as compat
from test_x86_16_smoketest import _project_from_bytes


def test_native_stack_return_is_not_replaced_by_c_inference(monkeypatch):
    # ENTER 2,0; MOV [BP-2],1; MOV AX,[BP-2]; LEAVE; RET.
    project = _project_from_bytes(bytes.fromhex("c8020000c746fe01008b46fec9c3"))
    inferred = []
    original = compat._infer_x86_16_c_return_value_from_ax_8616

    def observe(codegen):
        inferred.append(codegen)
        return original(codegen)

    monkeypatch.setattr(compat, "_infer_x86_16_c_return_value_from_ax_8616", observe)
    cfg = project.analyses.CFGFast(normalize=True)
    result = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert result.codegen is not None
    assert not inferred, "A present native return expression must survive compatibility rendering"
