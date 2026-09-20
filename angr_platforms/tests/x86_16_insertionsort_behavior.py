"""Execute unchanged InsertionSort C against an independent state/call oracle.

Layer: Tests.
Responsibility: verify signed-byte sorting, complete object copies, observable
call timing and arguments, wrapping counters, and preserved register state.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

_HARNESS = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
enum { CAPACITY = 10, MAX_EVENTS = 2 * (CAPACITY * CAPACITY + CAPACITY) };
typedef struct { char field_0, field_1; } g_08F0_entry;
g_08F0_entry g_0B4C[CAPACITY];
unsigned short g_0BA2, g_0BA4, g_0BAA;
static unsigned case_index, event_count, next_event;
static g_08F0_entry expected[CAPACITY];
static uint16_t expected_compares, expected_swaps;
struct Event {
    unsigned kind, row;
    uint16_t compares, swaps;
    g_08F0_entry state[CAPACITY];
};
static struct Event events[MAX_EVENTS];
#define require(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "case=%u line=%d invariant=%s\n", case_index, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

static void expect_call(unsigned kind, unsigned row)
{
    require(event_count < MAX_EVENTS);
    struct Event *event = &events[event_count++];
    event->kind = kind;
    event->row = row;
    event->compares = expected_compares;
    event->swaps = expected_swaps;
    memcpy(event->state, expected, sizeof(expected));
}

static void observe_call(unsigned kind, unsigned row)
{
    require(next_event < event_count);
    const struct Event *event = &events[next_event++];
    require(event->kind == kind && event->row == row);
    require(g_0BAA == event->compares && g_0BA4 == event->swaps);
    require(memcmp(g_0B4C, event->state, sizeof(g_0B4C)) == 0);
}

void sub_106c8(unsigned short row) { observe_call(0, row); }
void sub_10498(unsigned short row) { observe_call(1, row); }
void sub_10808(void);

static void reference_sort(unsigned count)
{
    for (unsigned row = 0; row < count; ++row) {
        g_08F0_entry item = expected[row];
        unsigned position = row;
        while (position > 0) {
            ++expected_compares;
            if ((signed char)expected[position - 1].field_0 <= (signed char)item.field_0)
                break;
            ++expected_swaps;
            expected[position] = expected[position - 1];
            expect_call(0, position);
            expect_call(1, position);
            --position;
        }
        expected[position] = item;
        expect_call(0, position);
        expect_call(1, position);
    }
}

static void run_case(const unsigned char *values, unsigned count)
{
    require(count < CAPACITY);
    for (unsigned i = 0; i < CAPACITY; ++i) {
        g_0B4C[i].field_0 = i < count ? values[i] : 0x55;
        g_0B4C[i].field_1 = (unsigned char)(0xA7 + i * 29);
    }
    memcpy(expected, g_0B4C, sizeof(expected));
    expected_compares = g_0BAA = 65533;
    expected_swaps = g_0BA4 = 65531;
    event_count = next_event = 0;
    g_0BA2 = count;
    inertia_esi = 0x12345678UL;
    inertia_edi = 0x87654321UL;
    reference_sort(count);
    sub_10808();
    require(next_event == event_count);
    require(g_0BA2 == count);
    require(g_0BAA == expected_compares && g_0BA4 == expected_swaps);
    require(memcmp(g_0B4C, expected, sizeof(expected)) == 0);
    require(inertia_esi == 0x12345678UL && inertia_edi == 0x87654321UL);
    ++case_index;
}

int main(void)
{
    unsigned char pair[2];
    for (unsigned first = 0; first < 256; ++first) {
        for (unsigned second = 0; second < 256; ++second) {
            pair[0] = first;
            pair[1] = second;
            run_case(pair, 2);
        }
    }
    static const unsigned char cases[][8] = {
        {128, 127, 0, 255, 1, 129, 126, 42},
        {0, 0, 0, 0, 0, 0, 0, 0},
        {127, 126, 42, 1, 0, 255, 129, 128},
        {128, 129, 255, 0, 1, 42, 126, 127},
        {255, 0, 255, 0, 127, 128, 127, 128}
    };
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c)
        for (unsigned count = 0; count <= sizeof(cases[0]); ++count)
            run_case(cases[c], count);
    return 0;
}
'''


def assert_insertionsort_behavior(function_c: str, tmp_path: Path) -> None:
    """Compile the unchanged generated function and compare state at each call."""
    source = tmp_path / "insertion_oracle.c"
    executable = tmp_path / "insertion_oracle"
    runtime = coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616()
    source.write_text(runtime + _HARNESS + "\n" + function_c, encoding="utf-8")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Werror", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=20,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False, timeout=10,
    )
    assert executed.returncode == 0, f"violated the insertion oracle: {executed.stderr}"
