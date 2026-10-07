# DOS game toolchain integration

Current integration: ada_script's tracked sources are preserved in
`tools/ada_script`, with its CLI and owned adapters in
`tools/ada_script`. Library naming uses the shared PAT matcher before rendering,
preserves explicit user names, and records conflicts/provenance. See
[usage and tests](../tools/ada_script/README.md). masm2c and libdosbox remain
independently buildable dependencies. The broader evidence-exchange plan below
is still incremental; source inclusion does not make every planned adapter complete.

## Responsibilities

| Component | Role | Outputs / boundary |
| --- | --- | --- |
| `ada_script` | Disassembly workspace, IDC annotations, runtime-evidence import, reassemblable output | Catalogs, symbols, relocations, ASM/LST; annotations and observations retain provenance |
| Inertia in `vextest` | Recover typed semantics and readable C from binary IR | C plus explicit validation results; semantic changes within Inertia belong to its owning layers |
| Ghidra and Reko alongside Inertia | Complementary analysis/decompilation of the same binary | Alternative pseudocode, annotations and hypotheses to reconcile against original bytes; agreement between tools is not a proof |
| `masm2c` | Translate MASM/IDA assembly into C++ with explicit machine-state operations | Native candidate plus runtime dependencies; useful for assembly-heavy or mixed games |
| `inertia_player/libdosbox` | Execute the original in a DOS hardware environment, record observations, dispatch/compare translated code in configured builds | Runtime JSON, memory dumps, execution evidence; game scenarios |
| `dosunit` | Function catalogs, oracle vectors, concrete comparison and SSA/Z3 validation | Separate tested/proved/conditional/refused results |
| Assembler + compiler + linker | Reassemble originals and build incremental C/ASM replacements | Linked DOS candidate, objects, map and build provenance |
| Local `mzretools` | Header/map inspection, instruction/layout and data comparison | Use `/home/xor/games/f19ru/F19/mzretools/build/`; structural evidence independent of semantic proof |

Use libdosbox for hardware-dependent game execution; use the dosunit execution
backend for suitable isolated functions. A native translated function needs a
harness exposing the same guest state and observables; it is not automatically
compatible with a DOS executable runner or the flat32 comparator.

## Recommended end-to-end order

1. Identify and hash the binary; record execution mode and runtime resources.
2. Run the original in libdosbox batch mode to collect initial runtime evidence.
3. Feed those observations to ada_script and Inertia, and use them to improve
   ASM/LST input and mappings for masm2c. Analyze the same binary with Ghidra
   and Reko where useful; reconcile conflicting hypotheses explicitly.
4. Reconstruct C/ASM or translate with masm2c, then build the candidate.
5. Check bytes/instructions and initialized data where applicable; run SSA/Z3
   semantic comparison on supported binary function pairs.
6. Run dosunit concrete oracle/candidate tests, including realizable Z3
   counterexamples and functions that refused symbolic comparison.
7. Run full game scenarios in libdosbox, expanding runtime coverage and feeding
   new evidence back into analysis.

Z3 comes before dosunit's concrete execution lane in this workflow. Both use
dosunit machinery, but answer different questions. "Binary equality" should
be reported precisely: byte identity, mapped instruction agreement, or modeled
semantic equivalence. Z3 addresses the last of these; it does not require
identical instruction sequences. Concrete tests remain useful after a proof
because they exercise the lifting, integration and environment assumptions.

### Batch collection is an initial analysis input

Collect executed instruction addresses/bytes, observed branch and call targets,
segment values, memory access widths and directions, pointer evidence, and load
metadata. These help locate code and characterize byte/word/dword accesses for
ada_script, Inertia and masm2c. Access width is evidence about a use, not by
itself a complete C type; code/data may overlap. Unexecuted regions remain
unknown. Different startup/menu/gameplay scenarios should retain separate
coverage and provenance before their evidence is combined.

The local [build/run wrapper](/home/xor/inertia_player/libdosbox/scripts/build_custom.sh)
documents the `instrument` build profile for collection without translated-game
dispatch, plus `--run`, `--run-timeout` and `--trace-exec`. This is an existing
bounded launch path, not a freshly verified batch collection run. Build profile
and runtime collection toggles are separate settings. A reusable batch runner
must record both, use isolated output directories, and confirm that the expected
JSON/dumps were written and match the binary/load metadata. Arrange orderly
dump/exit; a timeout alone does not guarantee flushed collection artifacts.
The current wrapper tolerates run failures with `|| true`, so its final success
status is insufficient evidence that execution or collection succeeded.

Aggregated runtime observations aid analysis; complete per-call states are
required for direct dosunit replay. Keep original execution as the oracle even
when libdosbox also supports dispatch into translated functions.

Ghidra/Reko collaboration is part of the intended workflow, not a claim of
implemented bidirectional adapters. Exchange binary-linked catalogs and typed
evidence with provenance; do not make Inertia semantics depend on parsing their
rendered pseudocode or on agreement among decompilers.

## Execution mode is separate from instruction width

| Actual target | Required model | Tool selection |
| --- | --- | --- |
| 8086/286 real-mode C, ASM or mixed game | Segmented memory, 16-bit default operands/addresses, near/far control flow | Real-mode Inertia/dosunit; ada_script and masm2c with target checks; libdosbox; mzdiff where supported |
| 386+ real-mode game using EAX, 32-bit arithmetic or address overrides | Still segmented real mode; decode each instruction's operand/address size; preserve upper register bits | Real-mode pipeline with verified 386 coverage; never select flat32 solely because EAX appears |
| Unreal-mode code or a program changing CPU mode | Segment-cache state, transitions and effective limits are explicit obligations | Runtime investigation and dedicated model support; refuse uncovered static claims |
| 32-bit protected-mode DOS extender game | Extender loader, selectors/descriptors, callbacks and DOS/BIOS interface | Separate protected-mode adapter; the PE32 comparator is not a generic extender loader |

Ordinary real mode defaults to 16-bit operand/address sizes; overrides permit
32-bit operations on supporting CPUs. This does not turn the program into a
flat PE32 program. See Intel SDM Volume 1 sections 3.3.5 and 3.6:
[Basic Architecture](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf).

## Two reconstruction paths, one validation system

For C-oriented reconstruction:

```text
original binary -> libdosbox batch observations + optional annotations
  -> Inertia, with complementary Ghidra/Reko analysis
  -> reconstructed C + retained ASM
  -> target compiler / assembler / linker
  -> byte/instruction checks + eligible SSA/Z3 proofs
  -> dosunit concrete tests
  -> complete game scenarios in libdosbox
```

For assembly-oriented translation or a native port:

```text
original binary -> libdosbox batch observations
  -> ada_script or existing disassembler analysis -> ASM/LST
  -> assembler/linker round trip and byte/relocation checks
  -> masm2c -> translated C++ -> native candidate
  -> eligible SSA/Z3 checks -> dosunit tests where a compatible harness exists
  -> libdosbox-backed runtime comparison and game scenarios
  -> replace selected routines with readable C, checking the same contracts
```

Existing assembly source can enter at ASM directly. A mixed game may use both
paths per function. Source language does not change the need to preserve flags,
register ABI, stack, memory and external effects. Handwritten ASM may have no
conventional C function boundary; use validated regions and explicit entry/exit
contracts instead of inventing signatures.

Before calling a reassembly byte-exact, compare the loaded image, relocation
entries, entry state and initialized data. Distinguish that from whole-file
identity. Retaining original bytes for awkward encodings can aid a round trip,
but does not prove those instructions were understood.

### Recovering an unpacked MZ from libdosbox dumps

`CUP386.EXE` is CyberWare Code Digger, a real-mode debugger with execution
breakpoints and an executable-creation path. The useful workflow is to pause at
the first instruction of the unpacked program in two runs, capture the *same*
relative CS:IP after moving the DOS load segment, then compare the images.
The 4 KiB reservation is just a way to move the load segment; it is not a
4 KiB dump-size limit. `libdosbox` emulates the original CPU and writes DE
dumps; CUP386's disassembly is evidence for the workflow, not the CPU oracle.

This tool belongs in `libdosbox/scripts/` alongside `make_exe_from_dumps.py`.
The [apply-ready libdosbox patch](../artifacts/libdosbox-mz-dump-pair.patch)
adds `scripts/mz_dump_pair.py`, its focused tests, and a `recover` command to
`scripts/memdump-workflow.sh`. Apply it from the libdosbox checkout; it was
checked with `git apply --check` there. Then run it on two or more current DE
dumps and their `.meta.json` files:

```bash
git apply /home/xor/vextest/artifacts/libdosbox-mz-dump-pair.patch
scripts/memdump-workflow.sh recover first.1 second.1 third.1 \
  --template PACKED.EXE -o UNPACKED.EXE
```

The tool requires the same image size and relative live CS:IP, accounts for
every changed byte as a non-overlapping 16-bit load-segment fixup, writes those
fixups into an MZ relocation table, and replays the loader against every dump.
An unexplained change or mismatched capture point is a refusal. A third load
segment can reject a coincidental two-dump relocation. The output is a
*candidate* unpacked MZ: matching memory dumps does not independently prove
that a changed word is a true relocation, that the pause was at original code,
or that DOS startup behavior was restored. The full captured image is retained;
large uninitialized tails and overlay-loaded blocks still need separate review.
The current `libdosbox` Ctrl+0 hotkey is manual. Automatic original-entry
detection and batch-triggered capture are not implemented by this tool.

## What current source inspection established

Inspection date: 2026-09-26. Only vextest was indexed in the graph service;
external repositories were inspected directly. These are bounded findings,
not complete capability audits or fresh game execution results.

* The local [mzretools checkout](/home/xor/games/f19ru/F19/mzretools/README.md)
  has `version.txt` set to `1.0.20` and built files named `mzdiff`, `mzhdr`,
  `mzmap`, `mzdup`, `mzptr`, `mzsig`, `addrtool` and `psptool`. Its README still
  documents MZ/8086 scope; presence of those executables does not establish
  386 or protected-mode support. They were not executed in this assessment.

* [ADA CLI](../tools/ada_script/cli.py) uses an MZ parser, IDC application,
  optional `--runtime` JSON, Capstone/Rizin analysis, then ASM/LST output.
  The README's Unicorn-centric/dataclass description is stale relative to
  this CLI and the SQLite [database](/home/xor/ada_script/database.py).
* [MZParser](/home/xor/ada_script/mz_parser.py) uses linear analysis addresses
  based at `0x10000`, guesses a default DS from relocations, and recreates
  `analysis.db` in the working directory. The adapter must isolate output paths,
  preserve raw relocations, and label guessed DS as a hypothesis.
* [Runtime import](/home/xor/ada_script/runtime_info.py) already consumes
  libdosbox observations, but falls back to load segment `0x1A2`. Require actual
  load metadata at the shared boundary; do not silently relocate evidence using
  that fallback. Observed accesses are neither complete types nor proof that an
  address is exclusively data.
* [ASM output](/home/xor/ada_script/output_generator.py) selects a CPU directive
  and emits USE16 segments. This supersedes the AGENTS.md advice to always emit
  `.286`. Decode/encode round trips must cover 386 prefixes before claiming
  mixed-width support. The current analyzer starts with `CS_MODE_16`; that is
  compatible with prefixed instructions, not proof of full 386 semantic coverage.
* [masm2c README](/home/xor/masm2c/README.md) describes MASM/IDA input, C++ output,
  an internal SDL runtime and a libdosbox target. Its documented scope includes
  386 instructions with FPU limitations; those claims were not retested here.
* [asm.h](/home/xor/masm2c/asm.h) has a `M2CDEBUG == -1` decompilation mode that
  drops PF/AF and simplifies call/return machinery. Keep this mode out of
  correctness acceptance unless equivalence of those omissions is separately
  established. Use the faithful runtime configuration for execution evidence.
* [custom.cpp](/home/xor/inertia_player/libdosbox/src/custom/custom.cpp) contains
  runtime collection, comparison and translated-call dispatch, the latter
  gated by `DOSBOX_CUSTOM_ENABLE_GAME_DISPATCH`. Confirm build/runtime profiles;
  the presence of a hook alone does not show that a particular run used it.
* [dosunit importer](../tools/dosunit/libdosbox_import.py) already consumes
  runtime priorities/access ranges and `CallSnapshots`. It explicitly refuses
  direct replay when only aggregate observations are available. Extend this
  boundary rather than adding another competing replay interpretation.

The live-memory contract remains mandatory: `m2c::m` is the translated-program
view of live DOSBox guest memory. An independent zero buffer is not a valid
replacement. Access instrumentation metadata and guest memory are distinct.

## What to integrate from ada_script

Next evidence-exchange deliverable: an adapter producing existing dosunit
function catalogs plus a versioned evidence sidecar. It should read a copied
analysis database, not mutate the user's database. Import names/bounds as
catalog evidence; keep semantic recovery in Inertia's owning layers.

Keep these responsibilities separate:

| Reuse/integrate | Keep out of semantic authority |
| --- | --- |
| IDC annotations, symbol names, comments, catalog export | Treating annotations as proven argument types or memory aliases |
| Raw MZ relocations and original bytes | Importing guessed DS/layout as fact |
| ASM/LST exporter for round-trip/masm2c workflows | Recovering semantics by parsing rendered assembly strings |
| Runtime observation transport with provenance | Assuming unobserved code is dead or one observed target is exhaustive |
| Read-only SQLite adapter | Replacing Inertia IR/alias storage identity with a linear-address database |

A shared record needs binary hash, module/overlay identity, original bytes,
address representation, CPU mode, operand/address widths, evidence origin and
scope. Keep file offset, module offset, analysis VA and runtime segment:offset
distinct. Record load metadata for conversion. For overlays or self-modifying
code, include code generation/bytes identity; the same CS:IP need not denote
the same instructions over time.

Reuse current catalogs/mappings/vector formats where sufficient. The sidecar
adds evidence rather than introducing a second semantic IR. Hypothesis,
observation and proof must be different typed categories.

## Integration sequence and acceptance

1. Pin component revisions and local modifications in a project manifest;
   record runtime profiles and build options. Use isolated per-game workdirs
   and establish a batch libdosbox collection artifact for each fixture.
2. Add read-only ada_script catalog/evidence export and import tests: address
   round trips at different load segments, explicit missing-metadata refusals,
   preserved relocations, conflicting annotations and mixed-width decoding.
3. Establish assembler/linker round trips for one C-built and one ASM-built
   fixture, including a 386 USE16 case. Check bytes and relocation semantics.
4. Run eligible SSA/Z3 comparisons first, then connect those same fixtures to
   dosunit oracle replay and masm2c/libdosbox comparison. Require deliberate
   mutations to fail and unsupported cases to
   remain visible. Do not substitute a translated candidate for the original
   machine-code oracle.
5. Admit a bounded real-game scenario: loading, input, a gameplay transition,
   video, sound and exit as applicable. Track exactly what ran; a title screen
   is not evidence for the rest of the game.
6. Only then move selected ada_script modules into this repository, preserving
   standalone CLI behavior and tests. Check attribution/dependencies as part
   of the actual import. Keep masm2c and libdosbox versioned externally unless
   a concrete maintenance need justifies relocating them.

ada_script was subsequently integrated as an auditable source snapshot plus
owned adapters; no external files were changed. Both masm2c and libdosbox had
local modifications when inspected. The six-step acceptance plan describes
remaining cross-tool/runtime integration rather than a completed game rebuild.
