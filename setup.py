"""Layer: packaging.

Responsibility: build and seal the mandatory pure-mode Cython lifter in native wheels.
"""

from __future__ import annotations

import hashlib
import json
import sys
import sysconfig
from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py

SOURCE: Path = Path("inertia/frontend/x86_16/lift_86_16.py")
DIRECTIVES: dict[str, int | bool] = {
    "language_level": 3, "annotation_typing": False, "binding": True, "infer_types": False,
}


class SealedLifterBuild(build_ext):
    """Place the extension in the runtime-verified bundle and bind its exact bytes."""

    def get_ext_fullpath(self, ext_name: str) -> str:
        """Keep the canonical module name while storing its binary in the bundle."""
        path = Path(super().get_ext_fullpath(ext_name))
        return str(path.parent / "cython-vex" / path.name)

    def _get_inplace_equivalent(self, command: build_py, ext: Extension) -> tuple[str, str]:
        """Make editable copying and output mappings use the verified bundle layout."""
        inplace, regular = super()._get_inplace_equivalent(command, ext)
        destination = Path(inplace).parent / "cython-vex" / Path(inplace).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = Path(regular).parent / "cython-vex" / Path(regular).name
        return str(destination), str(source)

    def run(self) -> None:
        """Compile first, then publish the manifest required for backend activation."""
        source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        super().run()
        if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != source_hash:
            raise RuntimeError("Lifter source changed during wheel compilation")
        artifact = Path(self.get_ext_fullpath("inertia.frontend.x86_16.lift_86_16"))
        manifest = {
            "schema": 1,
            "cache_tag": sys.implementation.cache_tag,
            "soabi": sysconfig.get_config_var("SOABI"),
            "source_sha256": source_hash,
            "extension": artifact.name,
            "extension_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }
        (artifact.parent / "active.json").write_text(json.dumps(manifest, indent=2) + "\n")


setup(
    ext_modules=cythonize(
        [Extension("inertia.frontend.x86_16.lift_86_16", [str(SOURCE)], extra_compile_args=["-O2", "-g0"])],
        build_dir="build/cython-vex", compiler_directives=DIRECTIVES,
    ),
    cmdclass={"build_ext": SealedLifterBuild},
)
