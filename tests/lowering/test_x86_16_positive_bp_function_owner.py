"""Keep argument evidence attached to its recovered function owner."""

import io
from types import SimpleNamespace

import angr
import pytest

import inertia.frontend.x86_16.public_api  # noqa: F401
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.positive_bp_arguments import _prepare_positive_bp_run_8616
from inertia.pipeline.errors import PipelineHardError


def _project() -> angr.Project:
    """Decode an ordinary near-frame word load without DOS execution."""
    return angr.Project(
        io.BytesIO(bytes.fromhex("558bec8b46045dc3")),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
                   "entry_point": 0x1000},
        auto_load_libs=False,
    )


@pytest.mark.parametrize("stale_default", [False, True])
def test_argument_reads_use_retained_analysis_function(stale_default):
    """An empty or same-address default KB cannot replace the recovery owner."""
    project = _project()
    analysis_kb = angr.KnowledgeBase(project)
    function = analysis_kb.functions.function(addr=0x1000, create=True)
    function._register_node(True, project.factory.block(0x1000, size=8).codenode)
    if stale_default:
        project.kb.functions.function(addr=0x1000, create=True)
    codegen = SimpleNamespace(
        project=project, _func=function,
        cfunc=SimpleNamespace(addr=0x1000, statements=None),
    )

    run = _prepare_positive_bp_run_8616(project, codegen)

    assert run is not None
    assert run.function is function
    assert run.word_access_offsets == frozenset({4})


def test_foreign_retained_function_is_rejected():
    """A same-address function from a foreign project cannot supply ABI facts."""
    project = _project()
    foreign = _project()
    function = foreign.kb.functions.function(addr=0x1000, create=True)
    codegen = SimpleNamespace(
        project=project, _func=function,
        cfunc=SimpleNamespace(addr=0x1000, statements=None),
    )

    with pytest.raises(PipelineHardError, match="different project"):
        _prepare_positive_bp_run_8616(project, codegen)
