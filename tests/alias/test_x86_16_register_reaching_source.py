from types import SimpleNamespace

from inertia.alias.register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceVerdict8616,
    resolve_register_reaching_source_8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616
from inertia.semantics.call_register_effects import (
    SyntheticCallRegisterEffectVerdict8616,
    classify_synthetic_call_register_effect_8616,
)
from inertia.semantics.callsite_register_provenance import (
    recover_callsite_register_source_8616,
    recover_register_source_before_instruction_8616,
)
from inertia.semantics.callsite_summary import summarize_x86_16_callsite
from inertia.cli.project_loading import _build_project_from_bytes


def _preserve(block: int, *predecessors: int) -> RegisterBlockTransfer8616:
    return RegisterBlockTransfer8616(
        block,
        predecessors,
        RegisterBlockTransferKind8616.PRESERVE,
    )


def test_register_reaching_source_crosses_preserving_cfg_paths() -> None:
    source = ("imm", 146)
    result = resolve_register_reaching_source_8616(
        (
            RegisterBlockTransfer8616(
                0x1000,
                (),
                RegisterBlockTransferKind8616.REPLACE,
                source,
            ),
            _preserve(0x1010, 0x1000),
            _preserve(0x1020, 0x1000),
            _preserve(0x1030, 0x1010, 0x1020),
        ),
        entry_addr=0x1000,
        sink_addr=0x1030,
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == source
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0


def test_synthetic_call_register_effect_closes_registered_abi_verdicts() -> None:
    project = _build_project_from_bytes(
        b"\xc3",
        base_addr=0x1000,
        entry_point=0x1000,
    )
    record_synthetic_call_stubs_8616(project, frozenset({0x1100}))

    preserved = classify_synthetic_call_register_effect_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1100,
        register="si",
    )
    clobbered = classify_synthetic_call_register_effect_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1100,
        register="ax",
    )
    refused = classify_synthetic_call_register_effect_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1101,
        register="si",
    )

    assert preserved.verdict is SyntheticCallRegisterEffectVerdict8616.PRESERVED
    assert clobbered.verdict is SyntheticCallRegisterEffectVerdict8616.CLOBBERED
    assert preserved.closes_evidence and clobbered.closes_evidence
    assert refused.verdict is SyntheticCallRegisterEffectVerdict8616.UNKNOWN_REFUSE
    assert refused.failure_count == 1


def test_register_reaching_source_refuses_conflicting_join() -> None:
    result = resolve_register_reaching_source_8616(
        (
            RegisterBlockTransfer8616(
                0x1000,
                (),
                RegisterBlockTransferKind8616.REPLACE,
                ("imm", 146),
            ),
            RegisterBlockTransfer8616(
                0x1010,
                (0x1000,),
                RegisterBlockTransferKind8616.REPLACE,
                ("imm", 147),
            ),
            _preserve(0x1020, 0x1000, 0x1010),
        ),
        entry_addr=0x1000,
        sink_addr=0x1020,
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None
    assert result.failure_count == 1


def test_register_reaching_source_refuses_killed_path() -> None:
    result = resolve_register_reaching_source_8616(
        (
            RegisterBlockTransfer8616(
                0x1000,
                (),
                RegisterBlockTransferKind8616.REPLACE,
                ("imm", 146),
            ),
            RegisterBlockTransfer8616(
                0x1010,
                (0x1000,),
                RegisterBlockTransferKind8616.KILL,
            ),
            _preserve(0x1020, 0x1010),
        ),
        entry_addr=0x1000,
        sink_addr=0x1020,
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.materialized_count == 0
    assert result.failure_count == 1


def test_register_reaching_source_refuses_memory_source_after_clobber() -> None:
    result = resolve_register_reaching_source_8616(
        (
            RegisterBlockTransfer8616(
                0x1000,
                (),
                RegisterBlockTransferKind8616.REPLACE,
                ("bp", -2),
            ),
            RegisterBlockTransfer8616(
                0x1010,
                (0x1000,),
                RegisterBlockTransferKind8616.PRESERVE,
                clobbers_memory_sources=True,
            ),
        ),
        entry_addr=0x1000,
        sink_addr=0x1010,
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None


def test_register_reaching_source_converges_through_stable_loop() -> None:
    source = ("imm", 146)
    result = resolve_register_reaching_source_8616(
        (
            RegisterBlockTransfer8616(
                0x1000,
                (),
                RegisterBlockTransferKind8616.REPLACE,
                source,
            ),
            _preserve(0x1010, 0x1000, 0x1020),
            _preserve(0x1020, 0x1010),
            _preserve(0x1030, 0x1010),
        ),
        entry_addr=0x1000,
        sink_addr=0x1030,
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == source


def test_callsite_register_source_crosses_binary_proven_leaf_call() -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    result = recover_callsite_register_source_8616(
        function,
        push_instruction_addr=0x1007,
        register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == ("imm", 146)


def test_reaching_source_resolves_each_call_target_once_per_query(monkeypatch) -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    calls: list[int] = []

    def resolve_target(_project: object, instruction: object) -> int:
        calls.append(instruction.address)
        return 0x1009

    monkeypatch.setattr(
        "inertia.semantics.callsite_register_provenance.resolve_direct_call_target_from_instruction_8616",
        resolve_target,
    )

    result = recover_register_source_before_instruction_8616(
        function,
        instruction_addr=0x1007,
        register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert calls == [0x1004]


def test_callsite_register_source_decodes_leaf_with_empty_cfg_function(monkeypatch) -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    discovered = cfg.kb.functions[0x1000]
    project_without_callee = SimpleNamespace(
        factory=project.factory,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: SimpleNamespace(block_addrs_set=set()),
            ),
        ),
    )
    function = SimpleNamespace(
        addr=discovered.addr,
        project=project_without_callee,
        graph=discovered.graph,
        block_addrs_set=discovered.block_addrs_set,
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_register_provenance.resolve_direct_call_target_from_instruction_8616",
        lambda _project, _instruction: 0x1009,
    )

    result = recover_callsite_register_source_8616(
        function,
        push_instruction_addr=0x1007,
        register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == ("imm", 146)


def test_callsite_register_source_refuses_out_of_image_leaf_target(monkeypatch) -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    monkeypatch.setattr(
        "inertia.semantics.callsite_register_provenance.resolve_direct_call_target_from_instruction_8616",
        lambda _project, _instruction: 0x2000,
    )

    result = recover_callsite_register_source_8616(
        function,
        push_instruction_addr=0x1007,
        register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None


def test_callsite_register_source_refuses_synthetic_leaf_body(monkeypatch) -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("b8 92 00 e8 02 00 50 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    record_synthetic_call_stubs_8616(project, frozenset({0x1008}))
    monkeypatch.setattr(
        "inertia.semantics.callsite_register_provenance.resolve_direct_call_target_from_instruction_8616",
        lambda _project, _instruction: 0x1008,
    )

    result = recover_callsite_register_source_8616(
        function,
        push_instruction_addr=0x1006,
        register="ax",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None


def test_callsite_register_source_uses_registered_abi_for_synthetic_nonvolatile_register() -> None:
    project = _build_project_from_bytes(
        bytes.fromhex(
            "56 be 92 00 e8 09 00 56 e8 06 00 83 c4 02 5e c3 c3 c3"
        ),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    record_synthetic_call_stubs_8616(project, frozenset({0x1010, 0x1011}))
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    result = recover_callsite_register_source_8616(
        function,
        push_instruction_addr=0x1007,
        register="si",
    )
    summary = summarize_x86_16_callsite(function, 0x1008)

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == ("imm", 146)
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0
    assert summary is not None
    assert summary.push_arg_sources == (("imm", 146),)


def test_callsite_register_source_refuses_undiscovered_leaf_register_write(monkeypatch) -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("56 be 92 00 e8 02 00 56 c3 be 93 00 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    discovered = cfg.kb.functions[0x1000]
    project_without_callee = SimpleNamespace(
        factory=project.factory,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda *, addr, create=False: None),
        ),
    )
    function = SimpleNamespace(
        addr=discovered.addr,
        project=project_without_callee,
        graph=discovered.graph,
        block_addrs_set=discovered.block_addrs_set,
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_register_provenance.resolve_direct_call_target_from_instruction_8616",
        lambda _project, _instruction: 0x1009,
    )

    result = recover_callsite_register_source_8616(
        function,
        push_instruction_addr=0x1007,
        register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None


def test_callsite_summary_uses_cfg_source_after_local_sibling_push_refusal() -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("56 be 92 00 b8 15 00 50 56 e8 04 00 83 c4 04 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    summary = summarize_x86_16_callsite(function, 0x1009)

    assert summary is not None
    assert summary.push_arg_sources == (("imm", 21), ("imm", 146))


def test_callsite_summary_uses_cfg_stack_snapshot_after_skipped_exit_branch() -> None:
    code = bytes.fromhex(
        "e8 2d 00 "
        "89 46 fe "
        "09 c0 "
        "75 03 "
        "e9 13 00 "
        "b9 15 00 "
        "51 "
        "50 "
        "e8 1c 00 "
        "83 c4 04 "
        "c3"
    ).ljust(0x30, b"\x90") + b"\xc3\xc3"
    project = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    record_synthetic_call_stubs_8616(project, frozenset({0x1030, 0x1031}))
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    summary = summarize_x86_16_callsite(function, 0x1012)

    assert summary is not None
    assert summary.push_arg_sources == (("imm", 21), ("bp", -2, 2))


def test_callsite_summary_preserves_return_value_through_self_or_and_branch() -> None:
    code = bytes.fromhex(
        "e8 1d 00 "
        "89 46 fe "
        "09 c0 "
        "74 09 "
        "6a 00 "
        "50 "
        "e8 11 00 "
        "83 c4 04 "
        "c3"
    ).ljust(0x20, b"\x90") + b"\xc3\xc3"
    project = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    record_synthetic_call_stubs_8616(project, frozenset({0x1020}))
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    summary = summarize_x86_16_callsite(function, 0x100D)

    assert summary is not None
    assert summary.push_arg_sources == (("imm", 0), ("bp", -2, 2))
