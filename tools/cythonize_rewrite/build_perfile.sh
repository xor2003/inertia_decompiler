#!/bin/bash
# Layer: Tooling/cythonize.
# Responsibility: per-file cython+gcc build of every inertia/*.py into an
# in-place extension module. Bypasses cythonize's dependency graph, which
# wrongly excludes all modules in a package whose __init__ uses PEP-810
# lazy imports. Failures keep their .py (interpreted fallback). Resumable:
# existing .so files newer than their .py are skipped.
# Usage: tools/cythonize_rewrite/build_perfile.sh [jobs]
set -u
cd "$(dirname "$0")/../.." || exit 1
JOBS="${1:-8}"
CYTHON=.venv/bin/cython
PYINC="$(.venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["include"])')"
SUFX="$(.venv/bin/python -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')"
CFLAGS="${CYTHON_CFLAGS:--O2}"
LOG=.cache/cython-bench/perfile-errors.log
: > "$LOG"
export PYINC SUFX CFLAGS CYTHON LOG
# Modules invoked via `python -m` must stay interpreted: a compiled extension
# has no code object to run as __main__.
MAIN_MODULES='serial_clean_worker_cli.py debug_dos.py gdb_symbol_export.py lift_86_16.py'
export MAIN_MODULES

build_one() {
    f="$1"
    case " $MAIN_MODULES " in
        *" $(basename "$f") "*) return 0 ;;
    esac
    base="${f%.py}"
    so="${base}${SUFX}"
    [ -f "$so" ] && [ "$so" -nt "$f" ] && return 0
    stem="$(echo "$base" | tr '/.' '__')"
    c="build/cython-perfile/${stem}.c"
    # regenerate when missing or older than the source; write to a temp and
    # mv so concurrent workers never see a partially-written .c.  A timeout
    # bounds infer_types pathologies (observed >1h on a 300-line module):
    # such files keep their interpreted .py fallback.
    if [ ! -f "$c" ] || [ "$f" -nt "$c" ]; then
        if ! err=$(timeout "${CYTHON_TIMEOUT:-900}" "$CYTHON" -3 -o "$c.tmp.$$" "$f" 2>&1); then
            # retry without infer_types: file-level directives override -X,
            # so compile a same-named copy with the directive stripped.
            # A typed .so still beats the interpreted .py fallback.
            tmpd="build/cython-perfile/noinfer.$$"
            mkdir -p "$tmpd"
            grep -v 'infer_types' "$f" > "$tmpd/$(basename "$f")"
            if err2=$(timeout "${CYTHON_TIMEOUT:-900}" "$CYTHON" -3 -X infer_types=False -o "$c.tmp.$$" "$tmpd/$(basename "$f")" 2>&1); then
                echo "=== CYTHON-NOINFER $f" >>"$LOG"
                mv -f "$c.tmp.$$" "$c"
            else
                rm -f "$so" "$c.tmp.$$"
                echo "=== CYTHON $f" >>"$LOG"; echo "$err" >>"$LOG"; echo "$err2" >>"$LOG"
                rm -rf "$tmpd"; return 1
            fi
            rm -rf "$tmpd"
        else
            mv -f "$c.tmp.$$" "$c"
        fi
    fi
    # huge generated C files (10MB+) take minutes under any -O; drop to -O0
    local fc=$CFLAGS
    if [ -f "$c" ] && [ "$(stat -c%s "$c")" -gt 3000000 ]; then
        fc="-O0"
    fi
    if ! err=$(gcc -shared -fPIC $fc -w -I"$PYINC" "$c" -o "$so" 2>&1); then
        echo "=== GCC $f" >>"$LOG"; echo "$err" >>"$LOG"; rm -f "$so"; return 1
    fi
    strip --strip-unneeded "$so" 2>/dev/null || true
    rm -f "$c" "$c.dep"
    return 0
}
export -f build_one

mkdir -p build/cython-perfile
find inertia -name '*.py' -print0 | xargs -0 -P "$JOBS" -I{} bash -c 'build_one "$@"' _ {}
echo "so_count=$(find inertia -name "*${SUFX}" | wc -l)"
