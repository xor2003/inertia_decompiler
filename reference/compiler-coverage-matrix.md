# Compiler Coverage Matrix

Frozen finite coverage plan for `reference/compiler-coverage-plan.md`.
Data file: `examples/compiler_coverage/coverage-matrix.json` (`coverage-matrix-1`).
This is planning data, not proof of completion. All sixteen first-batch round
trips have been attempted and timed out during decompilation; acceptance is 0/16.
Other round trips remain `not_attempted`, and emitted mechanisms remain
`unverified` unless a reviewed receipt is named.

## How to read it

- `sources[]` — the finite pilot set (36). `state`: `existing` (file read and
  hashed), `planned_not_implemented` (proposal only; path must not exist),
  `generated_retained` (Csmith seed 2, pinned SHA-256). `kind` separates
  `runtime_case`, `compile_probe`, `generated_case`; `oracle` records the
  declared success contract (`exit_code_255`, `exit_code_0`,
  `compile_time_assert`). `compile_run_evidence` is original-compiler
  compile/link/run receipt only — never decompiler roundtrip evidence.
- `cells[]` — required matrix entries. `axis` separates `source_feature`,
  `emitted_pattern`, `configuration`, `boundary`. `covers` lists the obligation
  IDs the cell owns (each admitted obligation belongs to exactly one cell).
  Every cell names a `witness` source, `profiles`, `desired_emitted` mechanism
  and a `corruption_control`.
- `profiles[]` — selected compiler/model configurations, IDs aligned with the
  adapter registry `examples/compiler_coverage/toolchains.json`.
  `msc51-small`, `msc51-large`, `bc31-small`, `bc31-large` are `verified`
  (registry + receipt `.cache/compiler-coverage/toolchain-probes-20261006/`);
  `*-opt` and `*-probe` remain `unverified`/`proposed_pending_probe`;
  `wtc11-*` are `phase_not_started`.
- `phases[]` — `ms_borland_corpus` (planning) then `watcom_11b_same_corpus`
  (`not_started`, applies to the same admitted corpus; not excluded).
- `deferred` — `later` (inventory, no witness this pilot), `excluded`
  (reasons recorded), `undecided` (target-defined, probe-bound where named).
- `negative_controls` — corruption must be detected as **deviation from the
  declared oracle** (255 pass / 1..N deliberate failure; Csmith 0), not a bare
  nonzero exit.

## Exact totals (recomputed by the private checker)

| Measure | Count |
| --- | --- |
| Sources | 36 = 35 existing + 0 planned + 1 generated |
| Runtime sources / compile probes | 32 / 4 |
| Cells | 40 (39 admitted, 1 undecided: `types.plain_char`) |
| Obligations | 202 = 138 covered / 48 later / 8 excluded / 8 undecided |
| MS+Borland case pairs | 78 (64 small + 8 large subset + 6 opt subset) |
| Watcom pairs | 40, all `not_started` |
| First batch | 16 = baseline 8 + directed 6 + csmith 2 |

## First batch (16 cases, acceptance 0/16)

`word_comparisons`=compare16.c, `array_pointer_writes`=pointer_memory.c,
`branches_loops`=simple_control.c, `call_composition`=function_pointers.c,
`struct_value_abi`/`bitfield_neighbors`/`multidim_alias`=
examples/compiler_coverage/*.c, `csmith_seed2`=pinned generator output.
Each × `msc51-small` + `bc31-small`.

## What remains

- Repair the first batch's semantic/decompilation blockers, then accept all
  sixteen round trips and corruption controls under the verified profiles.
- Target compilation and emitted-mechanism inspection for the ten newly
  implemented sources, including `library_call_boundary`; runtime signature
  resolution remains required for that case and Csmith.
- `emitted.switch_jump_table` requires observed table emission — a switch in
  source never counts.
- Optimization probes (`msc51-small-opt`, `bc31-small-opt`), the compile
  probes for char signedness/bitfield/aggregate layout, and the full Watcom
  11.0b same-corpus phase.

## Checks

Run `make compiler-coverage-matrix PYTHON=./.venv/bin/python` for the durable
consistency audit. The owner is
`tools/compiler_toolchain/compiler_coverage_matrix.py`; it checks identities,
source hashes, obligation partitions and denominators. Earned runtime statuses
require existing runner reports and verified toolchain registries; empty profile
sets and forged receipts refuse. Mechanism artifacts require reviewed
observations and hashes; the checker does not itself prove the mechanism.
Compile-probe acceptance needs its separate evidence contract and currently
refuses earned claims rather than treating a runtime receipt as layout proof.

Sixteen directed runtime sources and three layout/signedness probes now have host
oracle/control checks. These establish source readiness, not DOS layout,
emitted-pattern coverage or decompiler acceptance. First16 acceptance remains
0/16. The complete baseline attempted all sixteen cases: every original compiled
and ran correctly, while each decompilation reached its 120-second limit.
The existing runner was invoked independently for each pinned row, with two
external jobs and full accounting; no case was skipped after another timed out.
Source identity was unchanged before/after. Receipt:
`.cache/compiler-coverage/first16-independent-20261007/complete.json`.

### MS C 5.1 source-option blockers

Unchanged `array_init.c` and `bitfield_signed.c` were tested with explicit cleared
`CL`, under both `/AS /Od /W3` and the same options plus `/Za`. Automatic array
initializers fail with C2073 in both modes. Explicit signed bitfields compile
with C4014 (forced unsigned), then exit 2 instead of the required 255 in both
modes. `/Za` therefore does not discharge either obligation. This is evidence
for these tested configurations, not a claim about every possible option.
No fixture, selected profile, case denominator or required cell was changed.
Exact commands, hashes and original-only results:
`.cache/compiler-coverage/msc51-ansi-option-probe-20261007/results.json`.

### Target layout probes (2026-10-07)

Original-only small-model probes ran through the verified DOSBox profiles.
All six originals and six correct expectation controls built and exited 255;
six incorrect expectation controls failed on negative array sizes. These are
compiler/layout observations, not decompiler round trips or earned matrix cells.
Exact source/tool identities and logs:
`.cache/compiler-coverage/probe-refresh-20261007/probe-evidence.json`.

| Observation | MS C 5.1 | Borland C++ 3.1 |
| --- | --- | --- |
| Mixed struct size | 10 | 9 |
| Word / long / pointer offsets | 2 / 4 / 8 | 1 / 3 / 7 |
| Union size / enclosing offset | 4 / 2 | 4 / 1 |
| Enum size | 2 | 2 |
| Bitfield struct size / tag offset | 6 / 4 | 4 / 3 |
| Zero-width-split struct size / tag offset | 6 / 4 | 3 / 2 |
| Plain-int bitfield signed | no | yes |
| Plain char signed / CHAR_BIT | yes / 8 | yes / 8 |

MS C's header reports `CHAR_MIN=-127`, while Borland reports `-128`; these
are recorded header values, not a portable guarantee for out-of-range casts.
MS C warns that the plain bitfield must be unsigned. Explicit signed-bitfield
fixture behavior therefore still needs its own target check.

### Reproducing first16 DOS runtime corruption controls

The existing harness checks private copies of `compare16.c` and
`pointer_memory.c` plus return, branch and store mutations. This is runtime
oracle evidence only: four paired originals exit 255 and six mutants exit 1
across the two lanes. First16 roundtrip acceptance remains **0/16**.
The reviewed receipt is
`.cache/compiler-coverage/first16-dos-corruption-20261007/runtime-control-receipt.json`;
it also retains the earlier filename refusal and partial retry history.

From the repository root, prepare a fresh private directory. The assertions
pin the originals and require exactly one replacement per mutant. Short mutant
stems satisfy the existing DOS 8.3 staging contract; originals use the harness's
existing name mapping.

```bash
export CONTROL_ROOT="$PWD/.cache/compiler-coverage/first16-dos-corruption-rerun"
mkdir -p "$CONTROL_ROOT/sources" "$PWD/.cache/tmp"
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python - <<'PY'
import hashlib
import os
from pathlib import Path

dest = Path(os.environ['CONTROL_ROOT']) / 'sources'
pins = {
    'compare16': 'd2295f9cc9660b5040f0fccad0184dd079af2cdd626a09dc70fb8e5940cacc25',
    'pointer_memory': '570526e250e12a4a2bf17d81b7f720ac108813e92ec17864e419a7df6434f68e',
}
originals = {}
for name, digest in pins.items():
    data = Path(f'examples/msc6_constructs/{name}.c').read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    (dest / f'{name}.c').write_bytes(data)
    originals[name] = data
mutations = (
    ('retbad', 'compare16', b'return -1;', b'return 0;'),
    ('brbad', 'compare16',
     b'int cmp_i16(int a, int b)\n{\n    if (a < b) {',
     b'int cmp_i16(int a, int b)\n{\n    if (a > b) {'),
    ('stbad', 'pointer_memory', b'dst[i] = value;', b'dst[i] = 0;'),
)
for name, source, before, after in mutations:
    data = originals[source]
    assert data.count(before) == 1, name
    (dest / f'{name}.c').write_bytes(data.replace(before, after, 1))
PY
```

Run both lanes serially, with the pinned private registry and unchanged
120-second stage limit. `--skip-constructs` skips decompilation, while the same
`--only-constructs` selection still compiles and runs all five private sources.
Each harness invocation should exit 1 because its three negative controls fail
the expected-255 oracle; inspect receipts rather than treating that exit alone
as successful rejection.

```bash
for lane in msc51-small bc31-small; do
  mkdir -p "$CONTROL_ROOT/$lane"
  rtk proxy nice -n 10 env PYTHON_JIT=1 TMPDIR="$PWD/.cache/tmp" \
    .venv/bin/python -m tools.compiler_toolchain.build_msc6_examples \
    --kvikdos .cache/compiler-coverage/frozen-runner-20261006/kvikdos-869fe0cec87aa948c246919046e87828927a5b47a2dca8ee033f647c1a2597e1 \
    --compiler-profile "$lane" \
    --profile-evidence .cache/compiler-coverage/dosbox-parent-probes-20261006/toolchains-dosbox.json \
    --examples-dir "$CONTROL_ROOT/sources" \
    --only-constructs compare16,pointer_memory,retbad,brbad,stbad \
    --skip-constructs compare16,pointer_memory,retbad,brbad,stbad \
    --stage-timeout 120 --out-dir "$CONTROL_ROOT/$lane" \
    > "$CONTROL_ROOT/$lane/harness.log" 2>&1
  echo "$?" > "$CONTROL_ROOT/$lane/harness.exit"
done
```

Check each report and individual original receipt. A build failure or missing
guest exit is not a runtime rejection. Exit 1 identifies the unchanged first
oracle check: `cmp_i16(-2, 5) != -1` for return/branch, or `bytes[2] != 3` for
store. Retain the reports, logs, source/binary hashes and exact registry identity
with any new result.

```bash
rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['CONTROL_ROOT'])
expected = {'compare16': 255, 'pointer_memory': 255,
            'retbad': 1, 'brbad': 1, 'stbad': 1}
for lane in ('msc51-small', 'bc31-small'):
    rows = json.loads((root / lane / 'report.json').read_text())
    assert len(rows) == 5 and {r['name'] for r in rows} == set(expected)
    for row in rows:
        positive = expected[row['name']] == 255
        assert row['build_ok'] and row['decompile_skipped']
        assert row['run_exit_code'] == expected[row['name']]
        assert row['run_ok'] == positive
        receipt = Path(row['exe']).with_suffix('.original.json')
        evidence = json.loads(receipt.read_text())
        assert evidence['build_ok'] and evidence['expected_exit_code'] == 255
        assert evidence['run_exit_code'] == expected[row['name']]
        assert evidence['run_ok'] == positive
print('4 original passes; 6 runtime rejections; no roundtrip evidence')
PY
```
