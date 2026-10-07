# Ada Script in Inertia

Run from a checkout with Inertia dependencies and the `ada` extra:

```sh
.venv/bin/python -m pip install -e '.[ada]'
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m tools.ada_script /path/GAME.EXE \
  --work-dir .cache/ada/game --full --xrefs \
  --signature-catalog /path/runtime.pat
```

With a uv-managed environment, use
`uv pip install --python .venv/bin/python -e '.[ada]'` instead of pip.

The analyzer, backends, database, tests and upstream provenance live in this
package. The command is `inertia-ada` or `python -m tools.ada_script`; no external
checkout or import-path mutation is needed.
The integrated CLI supports IDC (`--idc-script`), runtime JSON (`--runtime`),
Capstone/Rizin backends, `--full`, `--classify`, `--xrefs`, and report `--output`.
Rizin is selected explicitly with `--backend rizin`; Capstone does not silently
fall back to another engine. Rizin itself must be available for that backend.
Use a fresh workdir: upstream MZ loading recreates `analysis.db` on each run.
When `--runtime` is provided, the merged CLI requires an integer
`Meta.DosboxLoadSeg` in the JSON trace and refuses missing metadata rather
than using the upstream fallback segment.

The shared PAT engine names library matches before analyzer context and operand
rendering. Without an explicit catalog, the same automatic library-only catalog
builder used by Inertia is selected. `--signature-catalog` accepts repeatable
PAT paths, and `--pat-backend` selects `python_regex`, `hyperscan`, or `auto`.
Use the existing signature catalog builder to convert OMF OBJ/LIB inputs.
`--no-signatures` or `INERTIA_DISABLE_SIGNATURES=1` disables naming.

Outputs: `GAME.asm`, `GAME.lst`, `analysis.db`, `analysis.md`, `signatures.json`
and a reusable `signature-cache/`. Relative `--output` paths are resolved under
the workdir. Signature evidence includes proposed names, catalog/module origin,
compiler labels and per-address disposition:

`--asm-code-encoding exact` is the default. It emits original instruction
bytes as `db` where the assembler would alter an encoding or reject the
mnemonic. `--asm-code-encoding mnemonic` displays decoded instructions instead
of those byte-preserving fallbacks. The mnemonic view is for inspection and
assembler experiments: it may fail to assemble, and an executable produced
from it is not expected to match the original bytes. The `.lst` and analysis
database retain the same instruction evidence in either mode.

| Status | Behavior |
| --- | --- |
| `named` | Replace auto labels, update matching function names and seed a candidate function entry when the matcher supplies one |
| `preserved_user_name` | Keep explicit IDC/user names and retain the proposed library identity separately |
| `ambiguous` | Conflicting catalogs propose different names; do not rename |
| `name_collision` | Another address already owns this name; do not rename |
| `data_conflict` | A declared data item covers the address; do not rename |

The shared matcher requires a unique body occurrence; repeated bodies do not
yield library identity. A module length is not imposed as a function extent.
The integration does not mark code semantically proved, erase library bodies,
infer C signatures, or exclude matched code from validation. Signature labels
are optional evidence. The source format is DOS MZ/USE16, including only the
instruction support supplied by the imported analyzer. PE, NE, LE and LX
payloads behind an MZ stub are refused before the analysis database is reset.

Focused gate:

```sh
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m pytest \
  tests/integration/test_ada_signature_integration.py \
  -n 2 --tb=short --durations=5 -q
```
