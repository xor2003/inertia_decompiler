# Compiler Flag Detection Dataset Plan

## Purpose

Build an evidence-based, function-level dataset for detecting Microsoft C
compiler options from 16-bit DOS machine code. The detector should report only
flags whose effects are observable in the available function or module. It
must not infer an exact command line when multiple flag combinations generate
the same code.

This plan is based on measurements of:

- `/home/xor/nndecomp/artifacts/dataset/cod_combo_strict_10x.jsonl`
- `/home/xor/vextest/deep/output_*.COD`
- the flag-profile and matching tools in `tools/compiler_toolchain/build_msc51_flag_profiles.py`
  and `tools/compiler_id/report.py`
- the build and dataset tools under `/home/xor/nndecomp/scripts/`

## Current Corpus Measurements

The strict 10x dataset contains:

- 3,187 rows
- 188 distinct source-functions
- 40 source files that produced usable rows, out of 76 attempted files
- 47 flag combinations
- only the `msc61`/Microsoft C 6ax compiler label
- 8 to 268 nonblank assembly lines per function
- median 16 lines, 90th percentile 44 lines
- 42.9% of cross-flag function pairs with identical normalized assembly

All current rows contain `/Gs` and `/Oa`. Those flags cannot be learned from
this dataset because there is no negative class. `/Zi` changed zero of 967
controlled function pairs.

Measured single-flag body influence in the strict dataset:

| Flag | Controlled pairs | Changed bodies | Change rate |
| --- | ---: | ---: | ---: |
| `/Ol` | 782 | 565 | 72.3% |
| `/Oi` | 739 | 320 | 43.3% |
| `/Or` | 668 | 54 | 8.1% |
| `/On` | 18 | 1 | 5.6% |
| `/Zi` | 967 | 0 | 0.0% |

Measured optimization-mode replacement influence:

| Replacement | Controlled pairs | Changed bodies | Change rate |
| --- | ---: | ---: | ---: |
| `/Od` vs `/Os` | 276 | 195 | 70.7% |
| `/Od` vs `/Ot` | 356 | 55 | 15.4% |
| `/Od` vs `/Ox` | 251 | 128 | 51.0% |
| `/Os` vs `/Ot` | 397 | 300 | 75.6% |
| `/Os` vs `/Ox` | 200 | 160 | 80.0% |
| `/Ot` vs `/Ox` | 318 | 152 | 47.8% |

Code length alone is not a sufficient feature. Many changed bodies retained
the same instruction count and byte length.

The 126-file controlled COD matrix contains one large, deliberately diverse
test function per flag combination. It is useful for confirming that a flag
can affect code, but it must not be treated as 126 independent source samples.
The function ranges from 290 to 397 machine-code bytes. In available exact
single-flag pairs, `/Gs`, `/Oa`, `/Od`, `/Ol`, `/On`, `/Or`, `/Os`, and `/Ot`
changed that function, while `/Oi` and `/Zi` changed only 4.3% of their pairs.
These results are trigger-dependent and cannot establish general prevalence.

## Labels

### Primary function-level labels

- optimization mode: `/Od`, `/Os`, or `/Ot`
- `/Ol`, for functions containing relevant loops
- `/Oi`, for functions containing intrinsic-eligible operations
- `/Gs`, for functions whose stack frame would otherwise trigger a probe
- `/Oa`, for pointer- and alias-sensitive functions

### Conditional secondary labels

- `/Or`, for multi-return or return-heavy functions
- `/Op`, for floating-point functions
- `/On`, only after adding suitable unsafe-loop candidates
- `/Ox`, retained as the original command-line macro but expanded into a
  compiler-version-specific effective flag set for training

Microsoft C 5.1 and Microsoft C 6ax require separate `/Ox` expansion tables.
Command-line order must also be preserved because canonicalizing options as an
unordered set can erase precedence between conflicting optimization options.

### Module-level or excluded labels

- Detect `/Zi` from debug and object records at module level, not from function
  bodies.
- Exclude linker-only options from the function classifier.
- Do not turn an unchanged function pair into false positive/negative evidence
  about flag presence. Mark the flag `UNOBSERVABLE` for that function.

## Function Selection

Use decoded instruction count and machine-code byte count as separate fields.
Recommended instruction-count handling:

| Instructions | Use |
| ---: | --- |
| `< 8` | Exclude ordinary thunks and stubs. |
| `8-11` | Retain for prologue, stack-probe, and abstention calibration only. |
| `12-19` | Include in normal training. |
| `20-63` | Preferred training population. |
| `64+` | Include with capped sampling weight. |

Stratify sampling and metrics across `8-11`, `12-19`, `20-31`, `32-63`, and
`64+`. Do not use one global 96-byte cutoff. Flag observability depends more on
semantic triggers than on size alone.

Add explicit eligibility tags:

- loop-bearing for `/Ol` and `/On`
- intrinsic-call candidates for `/Oi`
- pointer/alias candidates for `/Oa`
- large local frames or observed probes for `/Gs`
- floating-point operations for `/Op`
- multiple returns for `/Or`

## Corpus and Flag Matrix

The available successful build reports contain 321 unique source files:

- 187 C files
- 134 C++ files
- 195 under `bcex`
- 105 under `msex`
- 21 under `tcex`

Build compatible sources separately with Microsoft C 5.1 and Microsoft C
6ax. Use a balanced paired matrix rather than an exhaustive Cartesian product:

```text
/Od
/Ot
/Os
/Ot with and without /Ol
/Ot with and without /Oi
/Ot with and without /Oa
/Ot with and without /Or
/Ot with and without /Gs
floating-point functions: /Ot with and without /Op
unsafe-loop functions: /Ol with and without /On
/Ox as a macro/validation case
```

Compile the complete selected matrix before selecting variants. Extract and
deduplicate at function level, not translation-unit level. Balance each flag
by observable changed pairs, unchanged/unobservable pairs, function-size bin,
semantic eligibility, compiler version, project, and C versus C++.

## Dataset Record

Each function variant should contain at least:

```text
compiler_version
memory_model
ordered_compiler_argv
effective_flag_set
source_project
source_file
function_group_id
function_raw_hash
function_normalized_hash
machine_code_bytes
relocation_mask
decoded_instructions
instruction_count
byte_count
basic_block_count
stack_frame_size
call_count
loop_count
has_fp
has_intrinsic_candidate
has_alias_candidate
has_stack_probe
observable_flags
unobservable_flags
```

The current `raw_hash` and `norm_hash` in the strict dataset are
translation-unit hashes repeated for every function. Add function-level hashes
before training a function detector.

For supervised learning, also materialize paired contrast records containing
two variants of the same source-function that differ in exactly one effective
flag. The label must say whether the body changed and whether that flag is
observable for the pair.

## Features

Include:

- relocation-masked function bytes
- opcode and operand-class n-grams
- register, memory, immediate, and branch operand shapes
- CFG and basic-block shape
- prologue, epilogue, stack-frame, and stack-probe features
- loop, call, floating-point, and memory-access counts
- compiler runtime-helper family, without source-specific symbol leakage
- function size as a bucket and numeric feature

Do not include:

- raw addresses
- source or function names
- whole-OBJ byte n-grams in the function classifier
- debug sections for function-body flags
- bytes from neighboring functions

Whole-object byte features can learn `/Zi`, OMF layout, source symbols, or
unrelated functions. If module-level detection is desired, train a separate
module classifier with explicit module-level labels.

## Current Builder Issues

1. `build_flag_matrix_dedup.py` selects only `/Gs` because its code-generation
   loop iterates `MSC_GROUPS['codegen']` rather than both the empty and `/Gs`
   choices. This explains why `/Gs` is fixed in the generated corpus.
2. `build_combo_dataset.py` stops after the first N unique translation-unit
   variants. Since combinations are sorted, this biases the surviving rows
   toward the earliest flag prefixes; the strict 10x corpus consequently has
   `/Gs /Oa` in every row.
3. Deduplication occurs before function extraction and uses translation-unit
   hashes. A flag may change one function and leave every other function
   unchanged, producing duplicated or contradictory function rows.
4. Flag strings are canonicalized as unordered sets. Preserve the ordered argv
   and derive a separate effective-state representation.
5. The current profile builder mixes symbol tokens, assembly tokens, and
   whole-OBJ/EXE byte n-grams. Function and module evidence must be separated.

## Splitting and Evaluation

Keep every compiler/flag variant of a source-function in the same partition.
Split by complete project, not individual source file. Also group normalized C
and assembly clones before assigning partitions.

Maintain three evaluations:

1. held-out functions from known projects
2. held-out projects
3. held-out compiler version or cross-version transfer

Report per-flag precision, recall, F1, PR-AUC, calibration, and coverage versus
abstention risk. Report exact flag-set accuracy only as a secondary metric,
because exact command-line recovery is impossible for flags that did not
change the observed function.

## Acceptance Criteria

Before using a regenerated corpus for training:

- no modeled flag is present or absent in 100% of rows
- each primary flag has at least 500 observable changed contrast pairs across
  at least 50 projects and all main size bins
- unchanged pairs are labeled `UNOBSERVABLE`, not ordinary negatives
- no source-function, project, normalized clone, or flag variant crosses splits
- C and C++ distributions are reported separately
- MSC 5.1 and MSC 6ax distributions and effective flag expansions are reported
  separately
- a simple non-neural baseline beats the majority and size-only baselines on
  held-out projects before a more complex model is trained
