from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CFunctionCall, CTypeCast, CVariable
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable
import inertia.postprocess.decompiler_postprocess_stage as decompiler_postprocess_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.stack_variable_display_names as stack_variable_display_names

from inertia.cli import cli_decompilation


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.show_casts = False
        self.cstyle_null_cmp = False
        self.display_vvar_ids = False
        self.const_formats = {}
        self.text = ""
        self._inertia_callsite_args_ast_materialized_8616 = True
        self.cfunc = _DummyCFunc(self)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name

    def render_text(self, cfunc):
        return cfunc.c_repr()

    def regenerate_text(self):
        self.text = self.cfunc.c_repr()


class _DummyCFunc:
    def __init__(self, codegen):
        self.addr = 0x1000
        self.codegen = codegen
        self.functy = None
        self.statements = None
        self.body = None

    def c_repr(self):
        if self.statements is None:
            return ""
        return "".join(str(text) for text, _obj in self.statements.c_repr_chunks(asexpr=True)) + ";"


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _call_with_unfolded_long_constant(codegen):
    long_type = SimTypeLong(False)
    frequency = CVariable(
        SimRegisterVariable(0, 2, name="frequency"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dividend = CBinaryOp(
        "Or",
        CTypeCast(None, long_type, _const(13532, codegen), codegen=codegen),
        CBinaryOp(
            "Shl",
            CTypeCast(None, long_type, _const(18, codegen), codegen=codegen),
            _const(16, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    return CFunctionCall(
        "aNldiv",
        None,
        [dividend, CTypeCast(None, long_type, frequency, codegen=codegen)],
        codegen=codegen,
    )


def test_regenerate_codegen_text_simplifies_replayed_callsite_arguments(monkeypatch):
    codegen = _DummyCodegen()
    replay_count = 0

    def fake_replay(_project, replay_codegen):
        nonlocal replay_count
        replay_count += 1
        if replay_count > 1:
            return False
        replay_codegen.cfunc.statements = _call_with_unfolded_long_constant(replay_codegen)
        replay_codegen.cfunc.body = replay_codegen.cfunc.statements
        return True

    monkeypatch.setattr(cli_decompilation, "replay_callsite_stack_arguments_after_regeneration_8616", fake_replay)

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 Beep")

    assert regenerated is True
    assert "aNldiv(1193180" in text
    assert "18 << 16" not in text


def test_regenerate_codegen_text_replays_call_arguments_after_broad_simplification(monkeypatch):
    stale_text = "void f(void) { consume(stale); }\n"
    correct_text = "void f(void) { consume(iDown); }\n"
    simplified_wrong_text = "void f(void) { consume(vvar_1215); }\n"

    class _TextCFunc:
        def __init__(self) -> None:
            self.text = stale_text
            self.functy = None

        def c_repr(self) -> str:
            return self.text

    codegen = SimpleNamespace(
        text=stale_text,
        cfunc=_TextCFunc(),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        _inertia_postprocess_changed=True,
        _inertia_callsite_args_ast_materialized_8616=True,
    )
    replay_count = 0
    events: list[str] = []
    render_name_events: list[str] = []

    def replay_call_arguments(_project: object, replay_codegen: object) -> bool:
        nonlocal replay_count
        assert replay_codegen is codegen
        replay_count += 1
        events.append("call")
        codegen.cfunc.text = correct_text
        return True

    def simplify_after_replay(simplify_codegen: object) -> bool:
        assert simplify_codegen is codegen
        events.append("simplify")
        codegen.cfunc.text = simplified_wrong_text
        return True

    def replay_stack_semantics(replay_codegen: object) -> bool:
        assert replay_codegen is codegen
        events.append("stack")
        return True

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(
        decompiler_postprocess_stage,
        "_normalize_stack_variable_identifiers_8616",
        lambda _codegen: render_name_events.append("normalize"),
    )
    monkeypatch.setattr(
        stack_variable_display_names,
        "reapply_stack_variable_projection_names_8616",
        lambda _codegen: render_name_events.append("reapply") or True,
    )
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        replay_call_arguments,
    )
    for name in (
            "_replay_named_segmented_global_lowering_after_regen_8616",
            "_replay_indexed_segmented_global_lowering_after_regen_8616",
            "_replay_stack_address_lowering_after_regen_8616",
            "_replay_runtime_segment_lowering_after_regen_8616",
            "_stabilize_regenerated_noncall_ast_8616",
    ):
        monkeypatch.setattr(cli_decompilation, name, lambda _codegen: False)
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        replay_stack_semantics,
    )
    monkeypatch.setattr(cli_decompilation, "_simplify_structured_expressions_8616", simplify_after_replay)

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert replay_count >= 2
    assert events[-2:] == ["stack", "call"]
    assert render_name_events[-2:] == ["normalize", "reapply"]
    assert text == correct_text


def test_render_restore_replays_call_arguments_without_pruning_stack_setup(monkeypatch):
    stale_text = "void f(void) { stack[-2] = 21; ScaleRotate(vvar_324); }\n"
    candidate_text = "void f(void) { ScaleRotate(21); }\n"
    restored_text = "void f(void) { stack[-2] = 21; ScaleRotate(21); }\n"

    class _TextCFunc:
        def __init__(self, text: str) -> None:
            self.text = text
            self.functy = None

        def c_repr(self) -> str:
            return self.text

    codegen = SimpleNamespace(
        text=stale_text,
        cfunc=_TextCFunc(stale_text),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        _inertia_postprocess_changed=True,
        _inertia_callsite_args_ast_materialized_8616=True,
    )
    events: list[str] = []

    def replay_calls(_project: object, replay_codegen: object) -> bool:
        replay_codegen.cfunc.text = candidate_text
        return True

    def replay_restored(
        _project: object,
        replay_codegen: object,
        *,
        preserve_setup: bool = False,
    ) -> bool:
        assert preserve_setup is True
        events.append("restore-call-arguments")
        replay_codegen.cfunc.text = restored_text
        return True

    decisions = iter(
        (
            cli_decompilation.RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
            cli_decompilation.RenderRefreshPreservationDecision8616.PRESERVE_REPLAY,
        )
    )

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_finalize_typed_call_interfaces_before_render_8616", lambda _codegen: False)
    monkeypatch.setattr(cli_decompilation, "_finalize_callsite_arguments_after_noncall_regen_8616", lambda _codegen: False)
    monkeypatch.setattr(cli_decompilation, "replay_callsite_stack_arguments_after_regeneration_8616", replay_calls)
    monkeypatch.setattr(cli_decompilation, "_replay_bound_callsite_argument_consumer_8616", replay_restored)
    monkeypatch.setattr(cli_decompilation, "_collect_render_refresh_tail_summary_8616", lambda _codegen: object())
    monkeypatch.setattr(cli_decompilation, "_render_refresh_replay_preserves_live_out_8616", lambda *_args: False)
    monkeypatch.setattr(
        cli_decompilation,
        "_render_refresh_lost_stack_writes_are_validated_materialization_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_render_refresh_lost_stack_writes_have_direct_stack_evidence_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_render_refresh_preservation_evidence_8616",
        lambda *_args: SimpleNamespace(
            decision=next(decisions),
            lost_stack_slots=("stack[-2]",),
        ),
    )
    for name in (
        "_replay_named_segmented_global_lowering_after_regen_8616",
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        "_replay_stack_address_lowering_after_regen_8616",
        "_replay_direct_stack_semantics_after_regen_8616",
        "_replay_runtime_segment_lowering_after_regen_8616",
        "_finalize_regenerated_noncall_ast_8616",
    ):
        monkeypatch.setattr(cli_decompilation, name, lambda _codegen: False)

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(
        codegen,
        context="0x1000 f",
    )

    assert regenerated is True
    assert text == restored_text
    assert codegen.cfunc.text == restored_text
    assert events == ["restore-call-arguments"]


def test_callsite_finalize_enforces_structuring_identity_after_call_replay(monkeypatch):
    codegen = SimpleNamespace(project=object())
    events: list[str] = []

    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        lambda _codegen: events.append("stack") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: events.append("calls") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_call_interfaces_before_render_8616",
        lambda _codegen: events.append("interfaces") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "finalize_shared_call_occurrences_8616",
        lambda _project, _codegen: events.append("occurrences") or False,
    )

    changed = cli_decompilation._finalize_callsite_arguments_after_noncall_regen_8616(codegen)

    assert changed is False
    assert events == ["stack", "calls", "interfaces", "occurrences"]


def test_regeneration_finalizes_types_after_stack_name_normalization(monkeypatch) -> None:
    """Cleanup cannot overwrite a proven return type immediately before C rendering."""
    events: list[str] = []
    cfunc = SimpleNamespace(functy=SimTypeFunction([], SimTypeChar(signed=True)))

    def c_repr() -> str:
        if cfunc.functy.returnty.signed is False:
            return "unsigned char f(void)\n"
        return "char f(void)\n"

    cfunc.c_repr = c_repr
    codegen = SimpleNamespace(
        text="char f(void)\n",
        cfunc=cfunc,
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        _inertia_force_codegen_regeneration_8616=True,
    )

    def normalize(_codegen: object) -> None:
        events.append("normalize")
        cfunc.functy = SimTypeFunction([], SimTypeChar(signed=True))

    def finalize(_codegen: object) -> bool:
        events.append("finalize")
        cfunc.functy = SimTypeFunction([], SimTypeChar(signed=False))
        return True

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "require_codegen_render_integrity_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompiler_postprocess_stage,
        "_normalize_stack_variable_identifiers_8616",
        normalize,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_call_interfaces_before_render_8616",
        finalize,
    )

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == "unsigned char f(void)\n"
    assert events[-2:] == ["normalize", "finalize"]


def test_typed_interface_finalize_replays_stack_widths_before_specialized_parameters(monkeypatch):
    codegen = SimpleNamespace(project=object(), cfunc=SimpleNamespace(functy=None))
    events: list[str] = []

    monkeypatch.setattr(
        cli_decompilation,
        "reapply_stack_aggregate_object_facts_8616",
        lambda _codegen: events.append("aggregates") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "reconcile_exact_stack_argument_prototype_8616",
        lambda _project, _codegen: events.append("stack-widths") or True,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "materialize_function_pointer_parameters_8616",
        lambda _project, _codegen: events.append("function-pointers") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "materialize_callsite_prototype_declarations_8616",
        lambda _project, _codegen: events.append("declarations"),
    )

    changed = cli_decompilation._finalize_typed_call_interfaces_before_render_8616(codegen)

    assert changed is True
    assert events == ["aggregates", "stack-widths", "function-pointers", "declarations"]
