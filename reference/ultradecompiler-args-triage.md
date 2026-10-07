# UltraDecompiler QuickC `args.c` Triage

## Fixture

- Fixture: `args`
- Source: `borrow/UltraDecompiler/QuickC/PROGRAMS/args.c`
- Runner: `/home/xor/kvikdos/kvikdos`
- Command:

```bash
./.venv/bin/python tools.compiler_toolchain.import_ultra_quickc_fixtures --only args --output-root /tmp/inertia_ultra_quickc_args_triage_omf_retry --decompile-timeout 30
```

## Current Status

- Fixture status: `passed`
- Expected status: `required`
- Compile: passed
- Link: passed
- Run: passed
- Decompile: passed
- Validation: passed
- Compiler evidence: passed
- Runtime stdout:

```text
[1] alpha
[2] beta
total: 2
```

The previous blocker was target selection: MAP-only discovery selected runtime
`_start`, which produced validation failure and timeout symptoms. That blocker
is resolved for this fixture by using QuickC OBJ OMF PUBDEF evidence.

## Target Selection Evidence

- Mode: `auto`
- Evidence source: `omf_public`
- OMF symbol: `_main`
- Selected target: `sub_10058`
- Selected address: `0x10058`
- OBJ path:
  `/tmp/inertia_ultra_quickc_args_triage_omf_retry/args/ARGS.OBJ`
- Reason: QuickC OBJ PUBDEF provides a CODE-segment user function candidate.

This is structured binary evidence from the object file, not rendered-C or
rendered-assembly text matching.

## Decompile Evidence

- Decompile status: `passed`
- Return code: `0`
- Generated C present: `true`
- Missing targets: none
- Validation status: `passed`

Observed generated C is still ugly around `argc`/`argv` and pointer flow, but
that is a readability/type-quality issue after semantic validation, not the
runner/tooling blocker that prevented promotion.

## Compiler Evidence

- Compiler family: `Microsoft QuickC family`
- Memory model: `small`
- Flags: `/Od`, `/AS`
- Runtime marker: `Microsoft Quick C 1.0`

## Layer Classification

Resolved blocker: runner/tooling target selection.

Why:

- Build and DOS run pass through `kvikdos`.
- Compiler evidence is structured and passes.
- OMF PUBDEF evidence identifies the user `_main` symbol.
- Decompiling the selected user function validates successfully.

Residual follow-up:

- If improving readability for `argc`/`argv`, investigate earliest semantic
  layers that prove pointer/argument flow: frontend, IR, alias, widening, and
  types before structuring or rewrite.
- Do not add postprocess argument repair for `argc`/`argv`.
- Do not use source names, fixture names, rendered C, or rendered assembly as
  semantic proof.
