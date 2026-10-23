# bitfield_score fixture

Durable, frozen test data backing the isolated symbolic proof for
`sub_1d12` (bitfield score case). This is a **generated artifact** of the
ordinary CLI output recompiled under the frozen BC31 profile. It does **not** replace the
fresh decompilation/recompilation acceptance loop; it only preserves the
exact byte ranges and generated payload the diagnostic consumed.

## Files

- `fixture.json` — provenance hashes plus exact MZ image code slices
  (`code_hex`) for the oracle, candidate, and runtime helper, each with its
  own `sha256`.
- `generated.c` — verbatim copy of the generated candidate source
  `.cache/score-fixture/fresh-generated/conditional/00001d12-sub_1d12.c`
  (payload SHA256 `4a0360e0…8bda897a`), kept for review. It requires the
  harness runtime (`inertia_ds`, EAX/ESI spill cells, `N_LXURSH@`) and is
  **not** standalone C — it cannot be compiled or executed in isolation.

## Provenance

| role      | file                                                            | sha256     |
|-----------|-----------------------------------------------------------------|------------|
| source    | `.cache/bitfield-route/original-dosbox/BITNBR.EXE`              | `d9b3548a…`|
| candidate | `.cache/score-fixture/fresh-dos/work/HARNESS.EXE`                | `d6a21a69…`|
| payload   | `…/conditional/00001d12-sub_1d12.c`                             | `4a0360e0…`|

Compiler profile: `BC31-small -Od -ms DOSBox`.

Slices are cut from the loaded image starting at `header_paragraphs * 16`
(MZ header offset 8), at module-relative offsets recorded as decimal
`entry` (hex in `entry_hex`). Each module has one MZ relocation whose
target does not overlap any slice (`relocation_overlaps: []`), so
`code_hex` is reloc-independent.

| slice     | module      | entry | size | sha256     |
|-----------|-------------|-------|------|------------|
| oracle    | BITNBR.EXE  | 754   | 49   | `05d2b186…`|
| candidate | HARNESS.EXE | 706   | 233  | `99c7f7d5…`|
| helper    | HARNESS.EXE | 1583  | 33   | `f16d2934…`|

The candidate includes one real helper call; the test proves its return target
and CS preservation while composing its actual body. The unchanged payload
was compiled and executed in DOSBox (402/402 native-derived concrete cases),
separately from this frozen symbolic regression.

## Proof premises (fixed, explicit)

The diagnostic proves **9 observations** under a fixed entry state —
not unconditional ABI or whole-case acceptance:

- Entry registers: `CS=0x100`, `DS=SS=0x277`, `SP=0xfff8`.
- Physical code image loaded at `0x1000` (CS `0x100` × 16).
- Stack frame contents: near return `0x15b` at `SS:0xfff8`, pointer
  `0x400` at `SS:0xfffa`.
- Private compiler stack footprint: `SS:0xffb8..0xfff7`.
- Candidate runtime cells: EAX/ESI spill words at `DS:0xa96`, `0xa98`,
  `0xaa6`, `0xaa8`; runtime DS word at `DS:0xd44..0xd45` fixed to `0x277`.

The 9 proved observations in the permanent regression: `ax`, `sp`,
`bp`, `si`, `di`, `esi_hi`, `runtime_si`, `runtime_esi_hi`,
`framed_memory`.

The permanent regression additionally proves that both roots preserve CS and
return to physical control address `0x115b` (CS `0x100`, IP `0x15b`). It uses
the composer's full-width `control_ip`, not its truncated `ip` projection.
Three instruction mutations must produce counterexamples: incorrect return
arithmetic, omitted input bit, and unexpected write to the input object.

Run from the repository root:

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python -m pytest tools/dosunit/tests/test_generated_bitfield_function.py -q --tb=short
```

No DOS compiler, KVM, or files under `.cache/` are needed for this frozen test.
Rebuilding the candidate from fresh decompiler output is a separate obligation.

## Limitations

- Scalar inputs and all other memory are symbolic; only the 9 listed
  observations are proved.
- Flags, the full ABI, and caller reachability are **not** discharged.
- Module-relative offsets, catalog entries, and source paths recorded
  here are provenance for this fixture only — they are not production
  address hacks and must not be read as general ownership or load
  contracts.

## Ordinary decompiler output checkpoint

A separate fresh CLI run without a declared-entry file emits this identical
payload into the accepted output directory and reports `validation=passed`
(exit 0, stable structuring/postprocess snapshots). The explicit load segment
is necessary to select the same function address:

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 \
  .venv/bin/python .cache/bc31-dosbox-unblock/run-current-profile-cli.py \
  .cache/bitfield-route/original-dosbox/BITNBR.EXE \
  --base-addr 0x1a2 --addr 0x1d12 --exact-region-end 0x1d43 --timeout 60 \
  --no-alternate-source-c --ignore-local-sidecar-hints \
  --output-c-dir .cache/score-entry-next/ordinary-generated
```

This command uses the existing local frozen compiler-context launcher and
original EXE; unlike the frozen pytest above it requires those local artifacts.
Evidence: `.cache/score-entry-next/ordinary.log`. CLI transformation validation
and the explicitly scoped original-vs-recompiled Z3 proof are distinct checks;
neither claims the entire program or compiler-coverage plan is accepted.
