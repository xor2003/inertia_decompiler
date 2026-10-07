/* Layer: Tooling/gates.
 * Responsibility: provide the generated-C runtime ABI and observed external
 * effects for SORTD execution tests, without replacing decompiled bodies.
 */
#include <stdint.h>
#include <string.h>

uint8_t inertia_memory[65536];
uint16_t inertia_cs;
uint16_t inertia_ds;
uint16_t inertia_es;
uint16_t inertia_ss;
#ifndef INERTIA_COHERENT_GP_RUNTIME_H
/* Legacy artifacts use scalar storage; coherent builds supply the shared ABI. */
unsigned long inertia_eax;
unsigned long inertia_ebx;
unsigned long inertia_ecx;
unsigned long inertia_edx;
unsigned long inertia_esi;
unsigned long inertia_edi;
unsigned long inertia_esp;
unsigned long inertia_ebp;
#endif

unsigned long fake_clock;
int clock_calls;
unsigned short output_ports[8];
unsigned short output_values[8];
int output_calls;
unsigned short cursor_rows[8];
unsigned short cursor_columns[8];
int cursor_calls;
int text_calls;
int color_calls;
unsigned short last_color;
unsigned short colors[8];
unsigned short last_divisor;

/* Check both timer bytes from the same quotient, not merely the port order. */
int beep_timer_programming_matches(unsigned short frequency)
{
    unsigned long quotient;
    if (!frequency || output_calls != 5 || last_divisor != frequency)
        return 0;
    quotient = 1193180UL / frequency;
    return output_ports[0] == 67 && output_values[0] == 182
        && output_ports[1] == 66 && output_values[1] == (quotient & 255)
        && output_ports[2] == 66 && output_values[2] == ((quotient >> 8) & 255)
        && output_ports[3] == 97 && output_values[3] == 0x33
        && output_ports[4] == 97 && output_values[4] == 0x30;
}

int background_calls;
char *g_0136[2] = {"menu one", "menu two"};
int key_calls;
int display_cursor_calls;
int config_calls;
static int key_index;
static const unsigned short keys[] = {84, 62, 60, 27};

int sub_113d4(char *destination, unsigned short value, unsigned short count)
{
    memset(destination, (unsigned char)value, count);
    return 0;
}

int sub_128e4(unsigned short row, unsigned short column)
{
    if (cursor_calls < 8) {
        cursor_rows[cursor_calls] = row;
        cursor_columns[cursor_calls] = column;
    }
    cursor_calls++;
    return 0;
}

int sub_12756(char *text, unsigned short segment)
{
    (void)text;
    if (segment != inertia_ss)
        return -1;
    text_calls++;
    return 0;
}

int sub_12b24(unsigned short color)
{
    if (color_calls < 8)
        colors[color_calls] = color;
    color_calls++;
    last_color = color;
    return 0;
}

int sub_12b3e(unsigned short color, unsigned short pattern)
{
    (void)color;
    (void)pattern;
    background_calls++;
    return 0;
}

int sub_1123a(char *destination, void *source)
{
    (void)source;
    destination[0] = 'x';
    destination[1] = '\0';
    return 0;
}

unsigned short sub_11292(void)
{
    key_calls++;
    if (key_index < (int)(sizeof(keys) / sizeof(keys[0])))
        return keys[key_index++];
    return 27;
}

unsigned short sub_11278(unsigned short value)
{
    return value;
}

int sub_12bc0(unsigned short visible)
{
    (void)visible;
    display_cursor_calls++;
    return 0;
}

unsigned short sub_1132c(void *address)
{
    (void)address;
    return 0;
}

int sub_11402(unsigned short seed)
{
    (void)seed;
    return 0;
}

int sub_12ac8(void *configuration, unsigned short segment)
{
    uint16_t color_mode = 1;

    (void)segment;
    config_calls++;
    memcpy((uint8_t *)configuration + 18, &color_mode, sizeof(color_mode));
    return 0;
}

unsigned short sub_11414(void)
{
    return 0;
}

int sub_112ba(char *destination, ...)
{
    destination[0] = '\0';
    return 0;
}

unsigned long sub_1137e(void)
{
    clock_calls++;
    return fake_clock++;
}

int sub_1131e(unsigned short port, unsigned short value)
{
    if (output_calls < 8) {
        output_ports[output_calls] = port;
        output_values[output_calls] = value;
    }
    output_calls++;
    return 0;
}

unsigned short sub_11310(unsigned short port)
{
    return port == 97 ? 0x30 : 0;
}

unsigned long sub_1143a(
    unsigned short low,
    unsigned short high,
    unsigned short divisor,
    unsigned short divisor_high)
{
    unsigned long dividend = ((unsigned long)high << 16) | low;
    unsigned long wide_divisor = ((unsigned long)divisor_high << 16) | divisor;

    last_divisor = divisor;
    return wide_divisor ? dividend / wide_divisor : 0;
}

int32_t aNldiv(int32_t dividend, int32_t divisor)
{
    last_divisor = (unsigned short)divisor;
    return divisor ? dividend / divisor : 0;
}

void reset_runtime_observation(void)
{
    fake_clock = 0;
    clock_calls = 0;
    output_calls = 0;
    cursor_calls = 0;
    text_calls = 0;
    color_calls = 0;
    last_color = 0;
    last_divisor = 0;
    background_calls = 0;
    key_calls = 0;
    display_cursor_calls = 0;
    config_calls = 0;
    key_index = 0;
    inertia_eax = 0;
    inertia_ebx = 0;
    inertia_ecx = 0;
    inertia_edx = 0;
    inertia_esi = 0;
    inertia_edi = 0;
    inertia_esp = 0;
    inertia_ebp = 0;
    memset(colors, 0, sizeof(colors));
    memset(output_ports, 0, sizeof(output_ports));
    memset(output_values, 0, sizeof(output_values));
    memset(cursor_rows, 0, sizeof(cursor_rows));
    memset(cursor_columns, 0, sizeof(cursor_columns));
}
