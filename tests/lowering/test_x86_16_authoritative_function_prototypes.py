from __future__ import annotations

from types import SimpleNamespace

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from inertia.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    capture_authoritative_function_prototype_8616,
    publish_authoritative_function_prototype_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY


def test_authoritative_prototype_survives_mutable_function_rebuild() -> None:
    explicit = SimTypeFunction(
        [SimTypePointer(SimTypeChar())],
        SimTypePointer(SimTypeChar()),
    )
    function = SimpleNamespace(
        addr=0x1000,
        prototype=explicit,
        prototype_source=PrototypeSource.USER,
        info={},
    )
    project = SimpleNamespace()

    captured = capture_authoritative_function_prototype_8616(project, function)
    function.prototype = SimTypeFunction([SimTypeShort(False)], explicit.returnty)

    assert captured is not None
    restored = authoritative_function_prototype_8616(
        project,
        function,
        argument_count=1,
    )
    assert restored == explicit
    assert restored is not explicit


def test_authoritative_prototype_refuses_changed_argument_census() -> None:
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction([SimTypeShort(False)], SimTypeShort(False)),
        prototype_source=PrototypeSource.USER,
        info={},
    )
    project = SimpleNamespace()

    capture_authoritative_function_prototype_8616(project, function)

    assert authoritative_function_prototype_8616(
        project,
        function,
        argument_count=2,
    ) is None


def test_unowned_cca_inference_is_not_an_authoritative_prototype() -> None:
    inferred = SimTypeFunction([SimTypeChar(False)], SimTypeChar(False))
    function = SimpleNamespace(
        addr=0x1000,
        prototype=inferred,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        info={},
    )
    project = SimpleNamespace()

    assert capture_authoritative_function_prototype_8616(project, function) is None
    assert (
        authoritative_function_prototype_8616(
            project,
            function,
            argument_count=1,
        )
        is None
    )


def test_typed_annotation_precedes_a_mutated_live_prototype() -> None:
    explicit = SimTypeFunction(
        [SimTypePointer(SimTypeChar())],
        SimTypePointer(SimTypeChar()),
    )
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction([SimTypeShort(False)], explicit.returnty),
        prototype_source=PrototypeSource.USER,
        info={ANNOTATION_KEY: {"prototype": explicit}},
    )
    project = SimpleNamespace()

    capture_authoritative_function_prototype_8616(project, function)

    restored = authoritative_function_prototype_8616(
        project,
        function,
        argument_count=1,
    )
    assert restored == explicit


def test_typed_annotation_replaces_an_earlier_inferred_snapshot() -> None:
    inferred = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False))
    explicit = SimTypeFunction(
        [SimTypePointer(SimTypeChar())],
        SimTypePointer(SimTypeChar()),
    )
    function = SimpleNamespace(
        addr=0x1000,
        prototype=inferred,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        info={},
    )
    project = SimpleNamespace()

    capture_authoritative_function_prototype_8616(project, function)
    function.prototype = inferred
    function.prototype_source = PrototypeSource.CCA_DECOMPILER
    function.info = {ANNOTATION_KEY: {"prototype": explicit}}
    capture_authoritative_function_prototype_8616(project, function)

    restored = authoritative_function_prototype_8616(
        project,
        function,
        argument_count=1,
    )
    assert restored == explicit


def test_owned_contract_publication_replaces_same_precedence_snapshot() -> None:
    stale = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False))
    recovered = SimTypeFunction(
        [SimTypePointer(SimTypeChar()), SimTypeShort(False)],
        SimTypeShort(False),
    )
    function = SimpleNamespace(
        addr=0x1000,
        prototype=stale,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        info={},
    )
    project = SimpleNamespace()
    capture_authoritative_function_prototype_8616(project, function)
    assert authoritative_function_prototype_8616(
        project,
        function,
        argument_count=1,
        minimum_source=PrototypeSource.SIGNATURES,
    ) is None

    publish_authoritative_function_prototype_8616(
        project,
        function.addr,
        recovered,
        source=PrototypeSource.CCA_DECOMPILER,
    )

    assert authoritative_function_prototype_8616(
        project,
        function,
        argument_count=2,
    ) == recovered


def test_owned_contract_publication_preserves_stronger_snapshot() -> None:
    explicit = SimTypeFunction(
        [SimTypePointer(SimTypeChar())],
        SimTypeShort(False),
    )
    weaker = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False))
    function = SimpleNamespace(
        addr=0x1000,
        prototype=explicit,
        prototype_source=PrototypeSource.USER,
        info={},
    )
    project = SimpleNamespace()
    capture_authoritative_function_prototype_8616(project, function)

    publish_authoritative_function_prototype_8616(
        project,
        function.addr,
        weaker,
        source=PrototypeSource.CCA_DECOMPILER,
    )

    assert authoritative_function_prototype_8616(
        project,
        function,
        argument_count=1,
    ) == explicit
