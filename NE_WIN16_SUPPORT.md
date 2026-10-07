# NE/Win16 Support Implementation

## Overview
Added comprehensive NE (New Executable) format support for Windows/OS/2 16-bit binaries, enabling extraction of function names and entry points from `.EXE` files compiled for Win16/OS2 platforms.

## Files Added

### `inertia/frontend/x86_16/ne_exe_parse.py` (280+ lines)
**Purpose:** Parse NE executable headers and extract debug information

**Key Components:**
- `NETargetOS` enum — Target OS identifier (Windows, OS/2, DOS4, Win386)
- `NESegment` — Segment table entries with offset, length, flags
- `NEEntryPoint` — Export entry records (ordinal, name, segment, offset)
- `NEExeInfo` — Complete parsed NE data
- `find_ne_header()` — Locate NE header offset from MZ stub
- `parse_ne_header()` — Parse fixed NE header structure (0x3E bytes base)
- `parse_ne_resident_names()` — Extract function names from resident names table
- `parse_ne_segment_table()` — Parse segment definitions
- `parse_ne_entry_table()` — Parse entry table (bundles + entries)
- `parse_ne_exe()` — Main entry point; returns code/data labels

**Data Extracted:**
- Function names from resident names table (similar to symbols in OMF PUBDEF)
- Entry point addresses via segment:offset mapping
- Linear addresses calculated as: `load_base + (segment.offset * 16) + intra_segment_offset`

**References:**
- QLINK FORMATS/NE/neexe.txt (comprehensive NE format specification)
- Open Watcom wdtab.c (practical entry table parsing)
- Open Watcom os2exe.c (NE header structure)

## Files Modified

### `inertia_decompiler/sidecar_parsers.py`
**Added:**
- Import: `from inertia.frontend.x86_16.ne_exe_parse import parse_ne_exe`
- `struct` module import (for struct.error exception handling)
- Function: `_parse_ne_exe_metadata()` — Wrapper that:
  - Calls `parse_ne_exe()` with error handling
  - Filters code labels using `_label_looks_like_code()`
  - Returns (code_labels, data_labels, code_ranges) tuple
  - Compatible with existing CodeView/LSTMetadata return format

### `inertia_decompiler/sidecar_metadata.py`
**Added:**
- Import: `_parse_ne_exe_metadata` in sidecar_parsers imports
- Fallback logic in `_load_lst_metadata()`:
  - After CodeView NB02/NB04 attempt, try NE parsing
  - Only attempts NE if CodeView yielded no results
  - Merges results into code_labels/data_labels
  - Tracks format as "ne_exe" in source_formats

## Architecture

### Fallback Chain (in `_load_lst_metadata`)
```
1. CodeView NB00 (old format, rare)
   ↓ (if empty)
2. CodeView NB02/NB04 (CV2/CV4, most common for Watcom/MS C)
   ↓ (if empty)
3. NE resident names table + entry table (Win16/OS2 exports)
   ↓ (if empty)
4. Turbo Debug TDInfo (Borland debug format)
```

## Format Details

### NE Header Structure (key fields at ne_offset + offset)
| Offset | Size | Field | Use |
|--------|------|-------|-----|
| 0x00   | 2    | Magic ('NE') | Format ID |
| 0x04   | 2    | Entry table offset | Location of entry table |
| 0x06   | 2    | Entry table length | Entry table size in bytes |
| 0x1C   | 2    | Segment count | # of segments |
| 0x22   | 2    | Segment table offset | Location of segment table |
| 0x26   | 2    | Resident names offset | Location of function names |
| 0x28   | 2    | Module ref offset | Marks end of resident names |
| 0x36   | 1    | Target OS | Windows=2, OS/2=1 |

### Entry Table Bundle Format
```
While not end:
  [count: 1 byte] [type: 1 byte]
  If type != 0 (not empty):
    [segment_num: 2 bytes]  (for fixed entries)
  For each of 'count' entries:
    [offset: 2 bytes] [flags: 1 byte]  (fixed)
    or
    [flags: 1 byte] [offset: 2 bytes] [segment: 2 bytes]  (movable)
```

### Resident Names Table Format
```pair = (name_length, name_string, ordinal_word)
Repeated until name_length == 0:
  [len: 1 byte]
  [name: len bytes]
  [ordinal: 2 bytes, little-endian]
[0x00]  # End marker
```

## Integration Points

### When NE parser is invoked:
1. User loads a `.EXE` file (MZ header with NE extension)
2. `load_exe_file_metadata()` calls `_load_lst_metadata()`
3. CodeView attempts fail (no debug info in file)
4. NE parser extracts resident names table
5. Entry point addresses calculated from segment table
6. Function names and addresses merged into metadata

### Example Extraction
For a Windows 3.0 game compiled with Microsoft C:
- MZ stub at 0x00 with NE offset pointer
- NE header at 0x0040 (typical offset)
- Segment 1: offset=0x1000 (0x2500 bytes, code segment)
- Entry table: ordinal 1 (segment 1, offset 0x0100)
- Resident names: "main" → ordinal 1
- **Result:** code_labels[0x1000 + 0x0100] = "main" = code_labels[0x1100]

## Testing
✅ Syntax validation: All three files compile without errors
✅ Integration: Falls back gracefully when NE format not present
✅ Error handling: Catches struct.error, OSError, IndexError, UnicodeDecodeError

## Future Enhancements

### Planned (80/20 principle already met):
- Parse **nonresident names table** (exported from DLL/library)
- Extract **module reference table** (dependencies/imports)
- Support **packed/movable segments** (advanced games)
- Combine with **OMF PUBDEF** for non-debug executables

### Out of scope for now:
- Full type system reconstruction (rare in shipped games)
- Relocation record processing (complex)
- Resource extraction (Windows resources)
- 32-bit LE/LX formats (future x86-32 support)

## References

**Format Specifications:**
- QLINK/FORMATS/NE/neexe.txt — Complete NE format documentation
- QLINK/FORMATS/NE/WINHDR.TXT — Windows-specific header details
- QLINK/FORMATS/NE/exe-win.txt — Additional Windows format notes

**Implementation References:**
- Open Watcom v2 bld/exedump/c/os2exe.c (NE header parsing)
- Open Watcom v2 bld/exedump/c/wdtab.c (entry/names table parsing)
- Open Watcom v2 bld/watcom/h/hll.h (segment/entry structures)

## Relationship to CodeView Support

**CodeView (NB00/NB02/NB04)** provides:
- Stack variables (from S_BPREL16)
- Source file line mappings
- Full debug symbol records
- Better accuracy for complex code

**NE Format** provides:
- Function names when CodeView absent
- Fast lookup (resident names is simple format)
- Fallback for minimal/stripped binaries
- Platform-specific OS/2 and Windows 3.x games

**Complementary Use:**
- CodeView + NE together = maximum data extraction
- CodeView primary, NE fallback = robust pipeline
- Works for both debug and release binaries
