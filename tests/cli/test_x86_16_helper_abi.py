from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall, CStatements
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
import inertia.semantics.helper_abi as helper_abi
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.helper_abi import (
    known_helper_is_variadic_8616,
    known_helper_logical_argument_widths_8616,
    known_helper_prototype_8616,
)
from archinfo import ArchX86

from inertia.lowering.analysis_helpers import (
    known_helper_signature_decl,
    preferred_known_helper_signature_decl,
)
from inertia.validation.validation_calls import validate_call_interfaces_8616


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _validated_call(
    name: str,
    *,
    binary_argument_count: int,
    materialized_argument_count: int,
):
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    callee = SimpleNamespace(
        addr=0x2000,
        name=name,
        prototype=SimTypeFunction([short_type, short_type], short_type).with_arch(
            codegen.project.arch
        ),
    )
    arguments = [
        CConstant(index, short_type, codegen=codegen)
        for index in range(materialized_argument_count)
    ]
    call = CFunctionCall(
        name,
        callee,
        arguments,
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=binary_argument_count,
        arg_widths=(2,) * binary_argument_count,
        stack_cleanup=2 * binary_argument_count,
        return_register="ax",
        return_used=True,
        logical_arg_widths=(2,) * binary_argument_count,
    )
    return validate_call_interfaces_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )


def test_helper_abi_catalog_preserves_declarations_widths_and_variadic_status() -> None:
    assert known_helper_signature_decl("_ERROR") == "int _ERROR(const char *fmt, ...);"
    assert preferred_known_helper_signature_decl("ERROR") == "int _ERROR(const char *fmt, ...);"
    assert known_helper_is_variadic_8616("DEBUG")
    assert known_helper_is_variadic_8616("_fprintf")
    assert not known_helper_is_variadic_8616("getvideoconfig")
    assert known_helper_logical_argument_widths_8616("_getvideoconfig") == (4,)
    assert known_helper_logical_argument_widths_8616("loadprog") is None


def test_helper_abi_catalog_projects_variadic_pointer_prototype() -> None:
    prototype = known_helper_prototype_8616("ERROR", Arch86_16())

    assert isinstance(prototype, SimTypeFunction)
    assert prototype.variadic
    assert len(prototype.args) == 1
    assert isinstance(prototype.args[0], SimTypePointer)
    assert isinstance(prototype.args[0].pts_to, SimTypeChar)


def test_helper_prototype_refuses_non_function_architecture_binding(monkeypatch) -> None:
    """A third-party binding must not replace a function contract with a scalar."""
    prototype = SimTypeFunction([], SimTypeShort())
    monkeypatch.setattr(helper_abi, "convert_cproto_to_py", lambda _text: ("ERROR", prototype, ""))
    monkeypatch.setattr(SimTypeFunction, "with_arch", lambda _self, _arch: SimTypeShort())
    assert known_helper_prototype_8616("ERROR", Arch86_16()) is None


def test_helper_prototype_refuses_non_function_parser_result(monkeypatch) -> None:
    monkeypatch.setattr(helper_abi, "convert_cproto_to_py", lambda _text: ("ERROR", SimTypeShort(), ""))
    assert known_helper_prototype_8616("ERROR", Arch86_16()) is None


def test_variadic_helper_validation_uses_binary_proven_arity() -> None:
    report = _validated_call("ERROR", binary_argument_count=4, materialized_argument_count=4)

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_variadic_helper_validation_refuses_unproven_extra_argument() -> None:
    report = _validated_call("ERROR", binary_argument_count=4, materialized_argument_count=5)

    assert not report.passed
    assert report.failure_count == 1
    assert "expected-argc=4:actual-argc=5" in report.issue_tokens()[0]


def test_fixed_helper_validation_remains_exact() -> None:
    report = _validated_call("setbkcolor", binary_argument_count=2, materialized_argument_count=2)

    assert not report.passed
    assert report.failure_count == 1
    assert "expected-argc=1:actual-argc=2" in report.issue_tokens()[0]
