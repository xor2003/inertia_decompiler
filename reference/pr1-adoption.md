# PR 1 Review And Adoption

Scope: selective adoption of https://github.com/xor2003/inertia_decompiler/pull/1,
not a blanket merge into the shared worktree. September 20, 2026.

## Catalog Budget

`--catalog-timeout` defaults to 60 seconds, independently of the function
`--timeout`. `INERTIA_CATALOG_TIMEOUT` supplies an environment default; the CLI
overrides it. Invalid/nonpositive budgets fail argument parsing. Recovery and
display-catalog cache identity consume the same budget. This is a per-recovery
phase budget, not a whole-run wall-clock deadline. A larger budget does not
prove all candidate entries are functions or guarantee complete recovery.
Unqueued candidate counts are reported on stderr when the direct inventory
exposes an incomplete selection.

## Instruction Test Review

The PR's five assembly specimens are useful bug reports, but their generated-C
assertions are not sufficient acceptance gates:

- ES:BX reader: a nonempty body or any `return` does not prove the memory read,
  AX value, or BX increment survived. An observable caller and execution oracle
  must check all three, including a nonzero selector and wrapping offset.
- BX-only update: nonempty output does not prove the new BX is visible to a
  caller. Establish the register ABI through a consumer, then check the value.
- Conditional-call join: the presence of `g_86DC` or its decimal address does
  not prove both definitions reach the join. Exercise both branch outcomes,
  distinguish the two memory values and check the callee's side effect.
- Push-immediate idiom: the provided callee loads DX and CX but never uses
  either. Requiring exactly three rendered arguments, especially a far-pointer
  interpretation, is not justified by that fixture. Make those inputs affect
  observable stores or the result before asserting their preservation.
- Shared tail jump: a numeric literal or function name anywhere in a body is
  not proof that its write executes. A single blob also does not reproduce the
  independently discovered target condition described in the PR.

Do not import these as strict xfails: timeouts, compile failures or unrelated
assertion failures would all satisfy xfail and obscure the actual defect. Keep
these reproducers as diagnostic proposals until their behavioral oracles and
caller contexts are made explicit. This review does not claim the five
decompiler gaps are fixed.

The PR's fatal-error containment change is rejected by explicit user policy:
unsupported-instruction ERROR/ASSERT paths must retain `SystemExit(1)` and a
visible stderr diagnostic. The existing real-lifter regression enforces that
behavior. They must not be converted to recoverable `LiftingException` failures.

Existing 80386 coverage includes a deduplicated hardware instruction corpus,
per-opcode/width decode-and-lift sampling, and hardware-state checks in
`test_x86_16_80386_verifier.py`. MOV, ADD, PUSH/POP, Jcc, CALL/JMP and RET corpus
files already exist. Do not add duplicate single-instruction tests for these
specimens. This is distinct from proving multi-instruction register ABI, phi
joins and generated-C behavior; no exhaustive semantic coverage is claimed.

## PKLITE

Use the native [Deark decoder](https://github.com/jsummers/deark), not the PR's
heuristic dual-emulation relocation inference. Build Deark using its Makefile,
then put `deark` on PATH or set `INERTIA_DEARK_PATH` to its executable. Inertia
invokes its `pklite` module in a private temporary directory with a 60-second
timeout and a 32-MiB output limit. It validates the MZ extent, entry and every
relocation before feeding the normal DOS loader. Relocations remain unapplied.
No game executable or third-party source is vendored.

Missing Deark, decoder failure, malformed output, or unsupported trailing
overlay data remain explicit packed-input refusals (CLI exit 7). Mere container
validation is not proof of original-versus-unpacked whole-program behavior.
The local VIKINGS executable and its archived copy are already unpacked, so
they were not used as positive PKLITE evidence. Native decoding of the local
CAD.EXE produced 431,640 load-image bytes and 34 relocations, preserving header
entry/stack/allocation fields and overlay number 6.

User-selected acceptance sample: `/home/xor/games/cadavr2/UP.EXE` successfully
decoded to 17,904 load-image bytes and 308 relocations, entry `0000:2CF2`, stack
`04FA:4000`. Inertia then loaded that image through DOSMZ at entry `0x12CF2`,
with PKLITE provenance retained. No further sample binaries are required for
this integration checkpoint. This is unpack/load evidence, not a claim that
all UP.EXE functions decompile correctly.

## Missing DOS Tools

Required recompilation gates remain required. Missing-tool errors now point to:

- https://github.com/xor2003/kvikdos; configure `INERTIA_KVIKDOS_PATH`.
- https://github.com/davidly/dos_compilers; configure `INERTIA_MSC51_ROOT` to
  the Microsoft C 5.1 directory. The tiny-example runner uses `--msc6-root`
  for Microsoft C 6 and `--kvikdos` for the emulator.

The PR's optional/off recompilation policy is not imported: the requested change
is installation guidance, not relaxation of required compiler checks.

## Verification Checkpoint

- Catalog/decoder/loader/recompilation selection: 89 passed in 46.39 seconds.
- Additional CLI discovery selection: 31 passed, 3 skipped in 27.48 seconds.
- Final focused cache/tool/decoder selection: 42 passed in 14.75 seconds.
- Restored fatal policy: all six existing debug tests pass. A separate process
  lifting `66 0F 00 C0` exits 1 with its stderr diagnostic, without executing
  the following statement. No new instruction-semantic tests were added.
- Scoped mypy passes when the owned cache-file-digest module is included in
  the checked surface; isolated skip-import checking reports its exports as
  Any. New focused modules pass Ruff. Legacy large owners retain complexity
  debt, and whole quality-fast/architecture checks are not green.
- The ordinary pipeline passed 268 contract checks, then was stopped during
  routine tests after the user restored fatal-instruction termination policy.
  It started on superseded code and is not final acceptance evidence. The
  partial log is retained at `.cache/pr1-pipeline.log`; no full-suite green
  claim is made. A fresh broad run remains required before broad acceptance.

Deark executable content participates in semantic cache identity, so replacing
it at the same path invalidates cached results. The reviewed native build
reports version 1.7.3-1. The tools were built under `/tmp` for verification;
install/configure Deark explicitly for regular use.
