"""Focused tests for typed REP port-I/O loop-carrier structuring."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.semantics.string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord
import inertia.structuring.string_io_loop_carriers as string_io_loop_carriers

from inertia.structuring.string_io_loop_carriers import materialize_string_io_loop_carriers_8616


class _Codegen(SimpleNamespace):
    """Minimal structured-codegen identity allocator."""

    _next_index = 0
    cstyle_null_cmp = False

    def next_node_idx(self) -> int:
        """Return one deterministic node identity."""
        self._next_index += 1
        return self._next_index

    def next_ident(self, name: str) -> str:
        """Return one deterministic display identity."""
        return name


def _reg(codegen: object, offset: int, size: int, ident: str) -> structured_c.CVariable:
    """Build one exact register SSA carrier."""
    return structured_c.CVariable(
        SimRegisterVariable(offset, size, ident=ident, region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_rep_outsb_rebinds_loop_carriers_and_source_index() -> None:
    """REP OUTSB uses mutable CX/DX/SI identities and DS:SI each iteration."""
    registers = {"cx": (4, 2), "dx": (8, 2), "si": (24, 2), "d": (52, 4)}
    codegen = _Codegen(project=SimpleNamespace(arch=SimpleNamespace(registers=registers)))
    cx = _reg(codegen, 4, 2, "cx_pre")
    dx = _reg(codegen, 8, 2, "dx_pre")
    si = _reg(codegen, 24, 2, "si_pre")
    direction = _reg(codegen, 52, 4, "d_pre")
    count_update = structured_c.CAssignment(
        _reg(codegen, 4, 2, "cx_loop"),
        structured_c.CBinaryOp(
            "Sub",
            _reg(codegen, 100, 2, "tmp_0"),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    port_copy = structured_c.CAssignment(_reg(codegen, 108, 2, "tmp_8"), _reg(codegen, 8, 2, "dx_loop"), codegen=codegen)
    source_call = structured_c.CFunctionCall(
        "SEG_U8",
        None,
        [
            _reg(codegen, 42, 2, "ds"),
            structured_c.CConstant(0x8202, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    io_call = structured_c.CFunctionCall("inertia_io_out8", None, [], codegen=codegen)
    loop = structured_c.CDoWhileLoop(
        _reg(codegen, 4, 2, "cx_condition"),
        structured_c.CStatements([count_update, port_copy, source_call, io_call], codegen=codegen),
        codegen=codegen,
    )
    preheader = [
        structured_c.CAssignment(cx, structured_c.CConstant(0x300, SimTypeShort(False), codegen=codegen), codegen=codegen),
        structured_c.CAssignment(dx, structured_c.CConstant(0x3C9, SimTypeShort(False), codegen=codegen), codegen=codegen),
        structured_c.CAssignment(si, structured_c.CConstant(0x8202, SimTypeShort(False), codegen=codegen), codegen=codegen),
        structured_c.CAssignment(direction, structured_c.CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                structured_c.CStatements(preheader, codegen=codegen),
                structured_c.CStatements([loop], codegen=codegen),
            ],
            codegen=codegen,
        )
    )
    codegen._inertia_string_instruction_artifact = StringInstructionArtifact(
        records=(
            StringInstructionRecord(
                index=0,
                family="outs",
                mnemonic="outsb",
                repeat_kind="rep",
                width=1,
                source_segment="ds",
                destination_segment=None,
                direction_mode="unknown",
                zero_seeded_accumulator=None,
                zf_sensitive=False,
                instruction_addr=0x110,
            ),
        )
    )

    assert materialize_string_io_loop_carriers_8616(codegen.project, codegen) is True
    assert isinstance(count_update.rhs, structured_c.CBinaryOp)
    assert count_update.rhs.lhs.variable.ident == "cx_pre"
    assert port_copy.rhs.variable.ident == "dx_pre"
    assert isinstance(source_call.args[1], structured_c.CVariable)
    assert source_call.args[1].variable.ident == "si_pre"


def _builder_spy(monkeypatch: pytest.MonkeyPatch) -> tuple[StringInstructionArtifact, list[object]]:
    """Replace the binary builder with a spy returning one typed artifact."""
    built = StringInstructionArtifact(records=())
    calls: list[object] = []

    def _builder(project: object, function: object) -> StringInstructionArtifact:
        calls.append(function)
        return built

    monkeypatch.setattr(
        string_io_loop_carriers,
        "build_x86_16_string_instruction_artifact",
        _builder,
    )
    return built, calls


def _function_project(function: object) -> SimpleNamespace:
    """Return a project whose kb resolves one binary function by address."""
    return SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create: function,
            )
        )
    )


def test_absent_artifact_uses_binary_function_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """A physically absent artifact falls back to the binary builder path."""
    built, calls = _builder_spy(monkeypatch)
    function = object()
    codegen = _Codegen(project=_function_project(function))
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=None)

    assert materialize_string_io_loop_carriers_8616(codegen.project, codegen) is False
    assert calls == [function]
    assert codegen._inertia_string_instruction_artifact is built


@pytest.mark.parametrize("malformed", [object(), "artifact", 0])
def test_malformed_artifact_uses_binary_function_evidence(
    monkeypatch: pytest.MonkeyPatch,
    malformed: object,
) -> None:
    """A present but wrong-typed attachment is rebuilt from binary evidence."""
    built, calls = _builder_spy(monkeypatch)
    function = object()
    codegen = _Codegen(project=_function_project(function))
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=None)
    codegen._inertia_string_instruction_artifact = malformed

    assert materialize_string_io_loop_carriers_8616(codegen.project, codegen) is False
    assert calls == [function]
    assert codegen._inertia_string_instruction_artifact is built


def test_absent_artifact_without_function_evidence_refuses() -> None:
    """Absent artifact plus missing function lookup produces no attachment."""
    codegen = _Codegen(project=SimpleNamespace(kb=SimpleNamespace(functions=None)))
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=None)

    assert materialize_string_io_loop_carriers_8616(codegen.project, codegen) is False
    assert not hasattr(codegen, "_inertia_string_instruction_artifact")
    stats = codegen._inertia_string_io_loop_carrier_stats_8616
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_absent_artifact_without_cfunc_returns_no_records() -> None:
    """Absent artifact plus no cfunc keeps the existing refuse path."""
    codegen = _Codegen(project=SimpleNamespace(kb=SimpleNamespace(functions=None)))
    codegen.cfunc = None

    assert materialize_string_io_loop_carriers_8616(codegen.project, codegen) is False
    assert not hasattr(codegen, "_inertia_string_instruction_artifact")


class _ExplodingArtifactCodegen(_Codegen):
    """Codegen whose optional artifact slot fails for a non-absence reason."""

    @property
    def _inertia_string_instruction_artifact(self) -> object:
        """Raise a failure that physical-absence handling must not swallow."""
        raise RuntimeError("attachment boundary failure")


def test_non_absence_artifact_failure_propagates() -> None:
    """A non-AttributeError boundary failure must not be treated as absence."""
    codegen = _ExplodingArtifactCodegen()
    codegen.cfunc = None

    with pytest.raises(RuntimeError, match="attachment boundary failure"):
        materialize_string_io_loop_carriers_8616(object(), codegen)
