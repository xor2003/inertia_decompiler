from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event, Lock
from types import SimpleNamespace

from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)

import inertia.cli.cache as cache_module
import inertia.cli.cli_core as cli_core
from inertia.cli.lst_extract import LSTMetadata
from inertia.frontend.x86_16.cod_extract import CODProcMetadata
from inertia.cli.function_cache_context import function_decompilation_cache_key_8616
from inertia.cli.work_items import FunctionWorkItem, FunctionWorkResult


class _Graph:
    def __init__(self, edges, edge_data=None):
        self.nodes = (0x1000, 0x1010)
        self.edges = edges
        self.edge_data = edge_data or {}

    def get_edge_data(self, source, destination):
        return self.edge_data.get((source, destination))


def _item(*, edges=((0x1000, 0x1010),), edge_data=None, project=None):
    graph = _Graph(edges, edge_data=edge_data)
    function = SimpleNamespace(
        addr=0x1000,
        name="sub_1000",
        info={"x86_16_binary_exact_region": (0x1000, 0x1020)},
        block_addrs_set=frozenset({0x1000, 0x1010}),
        transition_graph=graph,
        project=project or SimpleNamespace(arch=SimpleNamespace()),
    )
    return FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)


def _key(tmp_path, item, *, cod_metadata=None, synthetic_globals=None, lst_metadata=None):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ-cache-context")
    return function_decompilation_cache_key_8616(
        item,
        binary_path=binary,
        api_style="pascal",
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        enable_structured_simplify=True,
        enable_postprocess=True,
    )


def test_function_cache_context_separates_recovered_cfg_shape(tmp_path):
    first = _key(tmp_path, _item(edges=((0x1000, 0x1010),)))
    second = _key(tmp_path, _item(edges=((0x1010, 0x1000),)))

    assert first is not None
    assert second is not None
    assert first != second


def test_function_cache_context_separates_cfg_edge_evidence(tmp_path):
    first = _key(
        tmp_path,
        _item(edge_data={(0x1000, 0x1010): {"type": "transition"}}),
    )
    second = _key(
        tmp_path,
        _item(edge_data={(0x1000, 0x1010): {"type": "call"}}),
    )

    assert first is not None
    assert second is not None
    assert first != second


def test_function_cache_context_separates_cod_and_synthetic_annotations(tmp_path):
    first_cod = CODProcMetadata(
        stack_aliases={-2: "first"},
        call_names=(),
        call_sources=(),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
    )
    second_cod = CODProcMetadata(
        stack_aliases={-2: "second"},
        call_names=(),
        call_sources=(),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
    )

    first = _key(tmp_path, _item(), cod_metadata=first_cod, synthetic_globals={0x2000: ("one", 2)})
    second = _key(tmp_path, _item(), cod_metadata=second_cod, synthetic_globals={0x2000: ("two", 2)})

    assert first is not None
    assert second is not None
    assert first != second


def test_function_cache_context_separates_typed_project_evidence(tmp_path):
    first_project = SimpleNamespace(arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset()))
    second_project = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset({0x1222}))
    )
    evidence = CallerReturnUseEvidence8616(
        target_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.USED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=1,
        unused_callsite_count=0,
        callsite_addrs=(0x1100,),
    )
    record_caller_return_use_evidence_8616(second_project, evidence.target_addr, evidence)

    first = _key(tmp_path, _item(project=first_project))
    second = _key(tmp_path, _item(project=second_project))

    assert first is not None
    assert second is not None
    assert first != second


def test_function_cache_context_separates_sidecar_metadata(tmp_path):
    first = _key(
        tmp_path,
        _item(),
        lst_metadata=LSTMetadata(data_labels={0x2000: "first"}, code_labels={}),
    )
    second = _key(
        tmp_path,
        _item(),
        lst_metadata=LSTMetadata(data_labels={0x2000: "second"}, code_labels={}),
    )

    assert first is not None
    assert second is not None
    assert first != second


def test_function_cache_context_refuses_malformed_project_evidence(tmp_path):
    project = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=(0x1222,))
    )

    assert _key(tmp_path, _item(project=project)) is None


def test_function_cache_context_refuses_unknown_cfg_nodes(tmp_path):
    item = _item()
    item.function.transition_graph = SimpleNamespace(nodes=(object(),), edges=())

    assert _key(tmp_path, item) is None


def test_function_cache_context_refuses_nondeterministic_runtime(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTHONHASHSEED", raising=False)
    assert _key(tmp_path, _item()) is None

    monkeypatch.setenv("PYTHONHASHSEED", "17")
    assert _key(tmp_path, _item()) is None


def _accepted_cache_record(
    *,
    diagnostic_output: str | None = None,
) -> dict[str, object]:
    payload = "void sub_1000(void)\n{\n    return;\n}\n"
    payload_hash = cli_core._sha256_text_8616(payload)
    return {
        "status": "ok",
        "payload": payload,
        "validated_c_hash": payload_hash,
        "gcc_checked_c_hash": payload_hash,
        "diagnostic_output": diagnostic_output,
    }


def test_typed_switch_cache_refuses_missing_diagnostic_provenance(monkeypatch):
    item = _item()
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", "1")
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(cli_core, "_load_cache_json", lambda *_args, **_kwargs: _accepted_cache_record())

    result, debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=None,
        timeout=20,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is None
    assert "missing_diagnostic_provenance" in debug


def test_typed_switch_cache_replays_matching_diagnostics(monkeypatch):
    item = _item()
    diagnostic = '[typed-switch-pre-codegen-seqnode] {"node_count": 1}\n'
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", "1")
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        cli_core,
        "_load_cache_json",
        lambda *_args, **_kwargs: _accepted_cache_record(diagnostic_output=diagnostic),
    )

    result, debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=None,
        timeout=20,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert debug == ""
    assert result is not None
    assert result.from_cache is True
    assert result.debug_output.endswith(diagnostic)


def test_function_work_cache_serializes_concurrent_producers(monkeypatch, tmp_path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    item = _item()
    cache_key = {"kind": "function_decompile", "function_addr": item.original_addr}
    expected = FunctionWorkResult(
        index=item.index,
        status="ok",
        payload="void sub_1000(void) { return; }",
        debug_output="",
        function=item.function,
        function_cfg=item.function_cfg,
    )
    state_lock = Lock()
    both_attempted = Event()
    state = {"attempts": 0, "producers": 0, "cached": None}

    @contextmanager
    def observed_cache_lock(namespace, key):
        with state_lock:
            state["attempts"] += 1
            if state["attempts"] == 2:
                both_attempted.set()
        with cache_module._cache_key_lock(namespace, key, timeout_seconds=2.0):
            yield

    def lookup(*_args, **_kwargs):
        with state_lock:
            cached = state["cached"]
        return cached, "", cache_key, False, ()

    def produce(*_args, **_kwargs):
        with state_lock:
            state["producers"] += 1
        assert both_attempted.wait(timeout=2.0)
        with state_lock:
            state["cached"] = expected
        return expected

    monkeypatch.setattr(cli_core, "_cache_key_lock", observed_cache_lock)
    monkeypatch.setattr(
        cli_core,
        "function_decompilation_cache_key_8616",
        lambda *_args, **_kwargs: cache_key,
    )
    monkeypatch.setattr(cli_core, "_function_work_cache_lookup", lookup)
    monkeypatch.setattr(cli_core, "_run_function_work_item_uncached", produce)

    def run():
        return cli_core._run_function_work_item(
            item,
            timeout=2,
            api_style="modern",
            binary_path=None,
            cod_metadata=None,
            synthetic_globals=None,
            lst_metadata=None,
            enable_structured_simplify=True,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(future.result(timeout=4.0) for future in (executor.submit(run), executor.submit(run)))

    assert results == (expected, expected)
    assert state["attempts"] == 2
    assert state["producers"] == 1
    assert not cache_module._cache_json_path("function_decompile", cache_key).with_suffix(".lock").exists()


def test_cache_json_load_refuses_corrupt_and_non_object_payload(monkeypatch, tmp_path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    key = {"kind": "function_decompile", "function_addr": 0x1000}
    cache_path = cache_module._cache_json_path("function_decompile", key)
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text("{broken", encoding="utf-8")

    assert cache_module._load_cache_json("function_decompile", key) is None

    cache_path.write_text("[]", encoding="utf-8")

    assert cache_module._load_cache_json("function_decompile", key) is None
