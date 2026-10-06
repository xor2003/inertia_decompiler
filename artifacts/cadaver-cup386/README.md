# CUP386 DOS assembly recovery

The source is `/home/xor/games/cadaver/CUP386.EXE` (SHA-256
`892a1ce9f67622bd8802926b61de2e595457a96227e6069c3f3108dec0dddfc4`).
It is a 16-bit DOS MZ executable containing some 386 instructions; the `386`
in its name does not make it a flat 32-bit program. The input's image is
61,364 bytes, has no MZ relocations, and starts at `0EF5:000C`.

`CUP386.runtime.json` was collected by
`/home/xor/inertia_player/libdosbox/build/custom-instrument/dosbox` with
`CUP386.EXE` mounted from a writable copy. It records 160 executed code
addresses and 11,582 instruction executions on this startup path. It is
path-specific evidence, not a complete execution inventory. The captured
load segment is `0x01A2`.

The integrated `/home/xor/vextest/ada.py` consumed that trace with `--full
--xrefs --no-signatures`, producing `analysis.db`, `CUP386.lst`, and
`CUP386.asm`. Ada reported 32,224 disassembled instructions and 543 candidate
functions. `functions.json` lists their starts, ends, names and flags; 16
function entries were observed on the captured runtime path. Its reported
123.7% coverage reflects overlapping decodes, so
function boundaries and code/data separation need review. The IDA `.lst`
sidecar contains 331 `sub_* proc` definitions. The supplied `.idc` uses
syntax outside the integrated IDC grammar and was **not** applied. The CLI
now refuses this parser failure instead of silently proceeding with no IDC
names. No library PAT catalog was applied to this capture.

## Rebuild

Run `./build.sh [output-directory]` from any directory. It invokes UASM and
alink on the checked-in `CUP386.asm`. The measured assembly result was
**zero errors and zero warnings**; alink produced an MZ executable and
warned that the generated source does not declare a stack for its MZ header.

The linked result is a rebuildable executable, **not a byte-exact or
semantically verified reproduction**. Its load image is 61,362 bytes, two
bytes shorter than the original. The first image mismatch is at offset `4`;
the original entry is `0EF5:000C`, while alink writes `0EF5:000A`, and its
SS:SP is `0000:0000` instead of `0F17:0150`. Both binaries exited with DOS
status zero in one instrumented startup, but their traces differ: of 160
executed code addresses on each run, 110 addresses overlap. Correcting only
the linked MZ stack header did not change that divergence.

## Regenerate the Ada analysis

Run this from `/home/xor/vextest`, using a fresh writable work directory:

```sh
PYTHON_JIT=1 .venv/bin/python ada.py \
  /home/xor/games/cadaver/CUP386.EXE \
  --work-dir /home/xor/vextest/.cache/cup386/ada-recheck \
  --runtime /home/xor/vextest/artifacts/cadaver-cup386/CUP386.runtime.json \
  --full --xrefs --no-signatures
```

The `.asm` deliberately emits original bytes for ambiguous MOVSX/MOVZX
memory widths, unsized LGDT/LIDT operands, and two-operand FXCH notation.
That preserves the recovered instructions while keeping UASM acceptance
independent of a guessed operand size. Next steps for a faithful executable
are to review the overlapping code/data decodes against the IDA sidecars,
resolve linker layout and stack declaration, then compare image bytes and
runtime behavior again.

## Assembly readability

The runtime trace supplied 612 segment-register events, mostly repeated
values. The generator now emits `assume` only when the effective assembler
state changes, plus the directives needed at physical segment boundaries.
This reduced the output from 617 to 8 `assume` lines. All other assembly
lines are identical to the previous output, and the linked MZ SHA-256 is
unchanged (`4f1e628589dd76a7a6d1c3865d327298dfeef60397440114c18ff5bb2527a8c4`).

At `sub_1036D`, `db 80h,3Eh,3Eh,78h,31h` represents the decoded instruction
`cmp byte ptr ds:783Eh, 31h`. The original IDA listing confirms that
instruction, and the `CODE XREF` comment is a caller reference to the
function entry. This is executable code emitted byte-for-byte: UASM encodes
the readable absolute-memory form as `67 80 3D 3E 78 00 00 31` under the
required `.686p` CPU mode, instead of the original five bytes
`80 3E 3E 78 31`. The `db` spelling preserves the original address size.
It does not classify those bytes as data.

`CUP386.mnemonic.asm` is a second rendering of the same analysis with
`--asm-code-encoding mnemonic`. It shows the instruction at `sub_1036D` as
`cmp byte ptr ds:783Eh, 31h`. This view is deliberately not the rebuild
source: UASM reaches syntax errors on other formerly byte-preserved
instructions. Use `CUP386.asm` for the verified UASM/alink build. The
installed JWasm 2.11 ELF32 executable could not be tested in this sandbox
because it exits with `SIGSYS`, so its handling of this operand is unverified.
