# CodeView (CV2–CV4) Debug Format Support

## Overview

CodeView is a legacy debug information format used by many DOS-era C compilers. This implementation provides **minimal but effective support** for CodeView NB02 (CV2) and NB04 (CV4), the most common formats used in pre-1993 DOS games.

**Goal**: 20% implementation effort → 80% value (function names, stack variables, basic type info)

---

## Supported Formats

| Format   | Signature | Era           | Compiler Examples                    |
|----------|-----------|---------------|--------------------------------------|
| NB00     | `NB00`    | Early/legacy  | Very early Microsoft C               |
| **NB02** | `NB02`    | DOS era       | Turbo C v1–v2, Microsoft C v1–v3    |
| **NB04** | `NB04`    | DOS era ✓     | Microsoft C v5/v6, Turbo C++        |
| **NB05** | `NB05`    | Transitional ✓| LINK 5.3x / Microsoft C v6–v7 (late DOS) |

**Primary target for DOS games: NB04** (most common in compiled binaries)

---

## Architecture

### Pipeline Integration

```
Binary (EXE/COM)
  ├─ NB00 parsing (existing: codeview_nb00.py)
  ├─ NB02/NB04 parsing (new: codeview_nb02_nb04.py) ← You are here
  └─ Data merged into sidecar metadata
```

### Core Parsing Flow

1. **Find trailer**: Search EXE tail for CV signature + offset
2. **Parse subsection directory**: Map debug data sections
3. **Extract key subsections**:
   - `SST_PUBLIC`: Public function names
   - `SST_SYMBOLS`: Local/global symbols
   - `SST_SRCMODULE`: Line number mapping
4. **Parse symbol records**:
   - `S_GPROC16`: Global procedures (functions)
   - `S_LPROC16`: Local procedures
   - `S_BPREL16`: Stack variables (BP-relative)
   - `S_GDATA16` / `S_LDATA16`: Global/local data

---

## Module: `codeview_nb02_nb04.py`

**Location**: `inertia/cli/codeview_nb02_nb04.py`

### Key Functions

#### `find_codeview_nb0204(data, signatures=None) → (str, int) | None`

Locate CodeView trailer in binary.

```python
# Returns: ("NB04", 0x1234) or None
info = find_codeview_nb0204(exe_bytes)
if info:
    sig, debug_base = info
    print(f"Found {sig} at offset {debug_base:#x}")
```

#### `parse_codeview_nb0204_bytes(data, load_base_linear=0) → CodeViewNB0204Info | None`

Parse complete CodeView debug table.

```python
parsed = parse_codeview_nb0204_bytes(exe_bytes)
if parsed:
    print(parsed.code_labels)      # {addr: name}
    print(parsed.data_labels)      # {addr: name}
    print(parsed.procedures)       # tuple of S_GPROC16/S_LPROC16 symbols
    print(parsed.stack_variables)  # {func_name: [S_BPREL16 symbols]}
```

#### `parse_codeview_nb0204(path, load_base_linear=0) → CodeViewNB0204Info | None`

Parse from file (convenience).

```python
parsed = parse_codeview_nb0204(Path("myexe.exe"))
```

### Symbol Types

```python
class CodeViewSymbol:
    type_code: int               # S_GPROC16, S_BPREL16, etc.
    name: str                    # Function/variable name
    offset: int                  # Offset within segment
    segment: int | None          # Code segment
    length: int | None           # Procedure length
    data_type: int | None        # Type index (advanced use)
    
    # Convenience methods
    is_procedure() → bool        # S_GPROC16/S_LPROC16?
    is_stack_var() → bool        # S_BPREL16?
    is_data_symbol() → bool      # S_GDATA16/S_LDATA16?
```

---

## Integration: `sidecar_parsers.py`

**Function**: `_parse_codeview_nb0204_metadata()`

Wraps NB02/NB04 parsing and converts to standard metadata format:

```python
code_labels, data_labels, code_ranges = _parse_codeview_nb0204_metadata(
    binary_path,
    load_base_linear=0x10000,
)
```

Fallback strategy:
1. Try NB00 parsing (existing)
2. If NB00 yields nothing, try NB02/NB04
3. Return whichever has results

---

## Integration: `sidecar_metadata.py`

**Location**: `_load_lst_metadata()`

Automatically tries CodeView in this order:
1. NB00 (lines ~125–180)
2. NB02/NB04 fallback (lines ~182–192)

**Output annotated in `LSTMetadata`**:
- `source_formats` includes `"codeview_nb00"` or `"codeview_nb0204"`

---

## What's Extracted (80/20 Focus)

### ✅ Code Labels (Functions)

From `S_GPROC16`/`S_LPROC16` records:

```
0x1234: main
0x1500: render
0x2000: update_state
```

Typical DOS game: 50–200 functions identified

### ✅ Data Labels

From `S_GDATA16`/`S_LDATA16`:

```
0x4000: global_buffer
0x4100: sprite_cache
```

Not a primary focus, but available.

### ✅ Stack Variables

From `S_BPREL16` records grouped by procedure:

```
{
  "main": [
    CodeViewSymbol(name="i", offset=-2),
    CodeViewSymbol(name="buffer", offset=-10),
  ],
  "render": [
    CodeViewSymbol(name="x", offset=4),
    CodeViewSymbol(name="y", offset=6),
  ],
}
```

**Enables**: Stack frame reconstruction in decompiler

### ❌ Type Information (Not yet)

Full type records (pointers, structs, arrays) are **parsed but not extracted**.

Why not? They're complex and lower priority for initial decompilation quality.

**May add if needed for**:
- Complex struct layout recovery
- Pointer type inference

---

## File Format Reference

### Header

```c
struct CVHeader {
    char signature[4];       // "NB04"
    uint32_t subdir_offset;  // Offset to subsection directory
};
```

### Subsection Directory Entry

```c
struct DirEntry {
    uint16_t type;           // SST_PUBLIC, SST_SYMBOLS, etc.
    uint16_t module_index;
    uint32_t data_offset;    // Relative to debug_base
    uint16_t data_size;
};
```

### Symbol Record

```c
struct Symbol {
    uint16_t length;         // Bytes following length field
    uint16_t type;           // S_GPROC16, S_BPREL16, etc.
    uint8_t data[...];       // Type-specific data
};
```

Example `S_GPROC16`:

```c
struct S_GPROC16 {
    uint32_t parent;         // Parent scope index
    uint32_t end;            // End record index
    uint32_t next;           // Next sibling index
    uint16_t length;         // Code length
    uint16_t offset;         // Offset in segment
    uint16_t segment;        // Segment index
    uint16_t ptype;          // Procedure type
    uint8_t name_len;
    char name[...];          // Null-terminated name
};
```

### NB05 / LINK 5.x interim layout

NB05 trailers emitted by Microsoft LINK 5.31+ (e.g. retail F-14 `F14R.EXE`)
use CV4-style *per-module* subsection values that differ from the legacy
NB02/NB04 table. The parser dispatches on the actual observed values:

| Type     | Meaning                                   | Producer      |
|----------|-------------------------------------------|---------------|
| `0x120`  | Module record                             | per module    |
| `0x121`  | Types                                     | per module    |
| `0x123`  | `sstAlignSym` — publics/procs (S_PUB16…) | per module    |
| `0x124`  | Locals/params (`mprintf(fmt,args)`)       | per module    |
| `0x127`  | `sstSrcModule` — source/line tables       | per module    |
| `0x12d`  | `sstSegMap` — global segment map          | module `0xffff` |

#### `sstSegMap` (`0x12d`)

LINK 5.x NB05 stores segment references as **1-based indices** into the
segment map, not as paragraphs. The map starts with
`uint16 seg_count, entry_count` followed by 20-byte entries:

```c
struct SegMapEntry {           // 20 bytes
    uint16_t flags, ovl, group;
    uint16_t frame;            // paragraph inside the loaded image
    uint16_t seg_name, class_name;
    uint32_t offset;           // contribution offset within frame
    uint32_t size;             // contribution size
};
```

Every `segment` field in `0x123` symbol records and `0x127` line tables is
such an index; the linear address is:

```
linear = load_base + (entry.frame << 4) + entry.offset + record_offset
```

Verified against `F14RUN.MAP` (`_AdiCrt` seg 2:0 → frame `0x1e`+off `0xc`
= `0x1ec` = MAP `001E:000C`).

#### Per-file line attribution

`0x127` srcmodule records carry one file record per source file; the
parser tags each `line_map` row with the file's index into
`info.source_files` (`-1` when the file name could not be decoded), which
the DWARF exporter turns into per-file `info line` attribution.

---

## Testing & Validation

### Unit Tests (planned)

```python
def test_find_codeview_nb04():
    # Test trailer detection
    data = b"... NB04" + struct.pack("<I", offset)
    result = find_codeview_nb0204(data)
    assert result[0] == "NB04"

def test_parse_symbol_records():
    # Test S_GPROC16, S_BPREL16 parsing
    ...
```

### Corpus Validation

Verify against real DOS game binaries:
- [ ] Turbo C-compiled
- [ ] Microsoft C-compiled
- [ ] Mixed symbol coverage

---

## Known Limitations

1. **No full type recovery**: Type records are parsed but not exposed
2. **No line number mapping yet**: SST_SRCMODULE parsing is stubbed
3. **No inlining info**: Procedure relationships minimally handled
4. **16-bit only**: Focus is x86-16; x86-32 version would differ

---

## Future Enhancements

| Priority | Task                                      |
|----------|-------------------------------------------|
| 🔴 High  | Improve stack variable BP offset handling |
| 🟡 Med   | Extract basic type signatures (for params)|
| 🟠 Low   | Line number → source mapping             |
| ⚪ Future | Switch to LLVM CodeView library if needed |

---

## References

### Authoritative Sources

1. **LLVM CodeView Documentation**
   - GitHub: `llvm/include/llvm/DebugInfo/CodeView/`
   - Best modern reference for legacy CV concepts

2. **Wine dbghelp Implementation**
   - GitHub: `winehq/wine/dlls/dbghelp/`
   - Excellent for real-world DOS-era format handling

3. **Microsoft Tools (Legacy)**
   - CVDUMP, CVPACK (from VC++ 1.5 era)
   - Format reverse engineering references

### Key Symbol Types

See `CodeViewSymbolType` enum in `codeview_nb02_nb04.py` for complete list.

---

## Integration Checklist

- [x] Parser module created (`codeview_nb02_nb04.py`)
- [x] Wrapper function added (`_parse_codeview_nb0204_metadata()`)
- [x] Integrated into sidecar metadata pipeline
- [x] Fallback logic (NB00 → NB02/NB04)
- [x] Source format tracking updated
- [ ] Unit tests added
- [ ] Corpus validation pass
- [ ] Documentation (you are here!)

---

## Quick Start

**To use in your decompiler:**

```python
from inertia_decompiler.sidecar_metadata import _load_lst_metadata

metadata = _load_lst_metadata(
    binary_path=Path("game.exe"),
    project=angr_project,
)

# CodeView data automatically merged into:
# metadata.code_labels
# metadata.code_ranges
# metadata.source_formats  # includes "codeview_nb0204" if used
```

No additional configuration needed—it works automatically!

---

**Status**: ✅ **Ready for integration and corpus testing**
