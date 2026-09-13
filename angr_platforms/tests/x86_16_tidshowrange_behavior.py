"""Layer: Tests.

Responsibility: execute the COD-evidenced TID range display call contract.
Coordinates and table values are fixture oracles, never production recovery.
"""

import subprocess
from pathlib import Path

_PRELUDE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
unsigned short Rp1, Rp2, Tscale;
uint32_t inertia_eax, inertia_ebx, inertia_ecx, inertia_edx;
uint32_t inertia_esi, inertia_edi, inertia_ebp, inertia_esp;
uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
uint8_t inertia_memory[1 << 20];
void RectFill(unsigned short, short, short, short, short, short);
char *itoa(short, char *, short);
short pstrlen(unsigned short, char *);
void RpPrint(unsigned short, short, short, char *);
void RectCopy(unsigned short, short, short, short, short, unsigned short, short, short);
unsigned short MapInEMSSprite(short, short);
void ScaleRotate(unsigned short, short, short, short, short, unsigned short, short, short, short, short, short, short);
"""

_RUNTIME = r"""
static unsigned int event_index;
static unsigned short mapped_segment;
static short text_width;
static char *text_buffer;
static const short ranges[5] = {200, 100, 50, 25, 10};
static const short positions[5][6] = {
    {87, 145, 20, 13, 187, 183},
    {42, 145, 16, 18, 186, 182},
    {7, 145, 9, 17, 187, 182},
    {23, 145, 16, 18, 185, 182},
    {63, 145, 18, 13, 183, 184}
};
static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "Tscale=%u segment=%u width=%d event=%u: %s\n",
                Tscale, mapped_segment, text_width, event_index, message);
        exit(1);
    }
}
static void event(unsigned int kind) {
    static const unsigned int sequence[] = {0, 1, 2, 3, 4, 5, 6, 6, 4};
    check(event_index < 9 && sequence[event_index] == kind, "wrong call order/count");
    ++event_index;
}
void RectFill(unsigned short rp, short x, short y, short w, short h, short color) {
    event(0);
    check(rp == Rp2 && x == 146 && y == 21 && w == 29 && h == 9 && color == 0,
          "wrong RectFill arguments");
}
char *itoa(short value, char *buffer, short radix) {
    event(1);
    check(value == ranges[Tscale] && buffer != NULL && radix == 10, "wrong itoa arguments");
    text_buffer = buffer;
    snprintf(buffer, 10, "%d", value);
    return buffer;
}
short pstrlen(unsigned short rp, char *text) {
    event(2);
    check(rp == Rp2 && text == text_buffer, "lost itoa result pointer");
    return text_width;
}
void RpPrint(unsigned short rp, short x, short y, char *text) {
    char expected[10];
    event(3);
    snprintf(expected, sizeof(expected), "%d", ranges[Tscale]);
    check(rp == Rp2 && x == 160 - text_width / 2 && y == 23, "wrong text position");
    check(text == text_buffer && strcmp(text, expected) == 0, "wrong text buffer/content");
}
void RectCopy(unsigned short src, short x, short y, short w, short h,
              unsigned short dst, short dx, short dy) {
    int first = event_index == 4;
    event(4);
    check(src == Rp2 && dst == Rp1, "wrong RectCopy surfaces");
    if (first)
        check(x == 146 && y == 21 && w == 29 && h == 9 && dx == 146 && dy == 21,
              "wrong text copy rectangle");
    else
        check(x == 164 && y == 164 && w == 46 && h == 31 && dx == 164 && dy == 164,
              "wrong sprite copy rectangle");
}
unsigned short MapInEMSSprite(short group, short index) {
    event(5);
    check(group == 2 && index == 0, "wrong sprite mapping arguments");
    return mapped_segment;
}
void ScaleRotate(unsigned short segment, short sx, short sy, short w, short h,
                 unsigned short rp, short dx, short dy, short scale, short angle, short a, short b) {
    int first = event_index == 6;
    event(6);
    check(mapped_segment && segment == mapped_segment && rp == Rp2, "wrong sprite mapping");
    check(scale == 256 && angle == 0 && a == 0 && b == 0, "wrong sprite transform");
    if (first)
        check(sx == 25 && sy == 175 && w == 46 && h == 31 && dx == 187 && dy == 179,
              "wrong common sprite arguments");
    else {
        const short *p = positions[Tscale];
        check(sx == p[0] && sy == p[1] && w == p[2] && h == p[3] && dx == p[4] && dy == p[5],
              "wrong per-case sprite arguments");
    }
}
int main(void) {
    const unsigned short segments[] = {0, 1, 32768, 65535};
    const short widths[] = {-32768, -3, -1, 0, 1, 2, 3, 17, 32767};
    for (unsigned int t = 0; t < 5; ++t)
    for (unsigned int m = 0; m < sizeof(segments) / sizeof(segments[0]); ++m)
    for (unsigned int w = 0; w < sizeof(widths) / sizeof(widths[0]); ++w) {
        Tscale = t; Rp1 = 0x1234; Rp2 = 0x5678;
        mapped_segment = segments[m]; text_width = widths[w];
        event_index = 0; text_buffer = NULL;
        _TIDShowRange();
        check(event_index == (mapped_segment ? 9u : 6u), "missing display calls");
        check(Tscale == t && Rp1 == 0x1234 && Rp2 == 0x5678, "changed input globals");
    }
    return 0;
}
"""


def assert_tidshowrange_behavior(generated_c: str, tmp_path: Path) -> None:
    """Check unchanged generated C across all five cases and 180 input combinations."""
    executable = tmp_path / "tidshowrange-behavior"
    compiled = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined",
         "-x", "c", "-", "-o", str(executable)],
        input=_PRELUDE + generated_c + _RUNTIME, capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, f"TIDShowRange compilation failed: {compiled.stderr}"
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=5)
    assert executed.returncode == 0, f"TIDShowRange behavior failed: {executed.stderr}"
