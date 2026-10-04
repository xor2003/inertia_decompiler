"""Runtime-profile correlation must retain decorated Cython hot functions."""

import cProfile

import pytest

from scripts.report_cython_vex import report


def test_report_includes_decorated_runtime_hotspot(tmp_path):
    source = tmp_path / "lifter.py"
    source.write_text("def identity(fn):\n    return fn\n@identity\ndef hot():\n    return sum(range(100))\n")
    namespace = {}
    exec(compile(source.read_text(), str(source), "exec"), namespace)
    profiler = cProfile.Profile()
    profiler.runcall(namespace["hot"])
    profile = tmp_path / "lowering.prof"
    profiler.dump_stats(str(profile))
    annotation = tmp_path / "lifter.html"
    annotation.write_text('<pre class="cython line score-0">&#xA0;<span>4</span>: def hot():</pre><pre class="cython line score-7">+<span>5</span>: return sum(range(100))</pre>')
    result = report(source, annotation, profile)
    assert "| hot:4 | 1 |" in result
    assert "| 1 | 7 |" in result
    assert "not a\nmeasurement of compiled function speed" in result
    source.write_text("# Different source; the old profile cannot provide current evidence.\n")
    with pytest.raises(ValueError, match="No lifter functions matched"):
        report(source, annotation, profile)
