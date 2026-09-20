#include <stdint.h>
#include <string.h>

extern uint8_t inertia_memory[65536];
extern uint16_t inertia_ss;
extern unsigned long fake_clock;
extern int clock_calls;
extern unsigned short output_ports[8];
extern unsigned short output_values[8];
extern int output_calls;
extern unsigned short cursor_rows[8];
extern unsigned short cursor_columns[8];
extern int cursor_calls;
extern int text_calls;
extern int color_calls;
extern unsigned short last_color;
extern unsigned short colors[8];
extern unsigned short last_divisor;
int beep_timer_programming_matches(unsigned short frequency);
extern int background_calls;
extern int key_calls;
extern int display_cursor_calls;
extern int config_calls;
void reset_runtime_observation(void);

short sub_10060(void);
short sub_102e0(void);
short sub_10560(void);
unsigned short sub_10768(unsigned short first, unsigned short second);

short sub_101f0(
    unsigned short top,
    unsigned short left,
    unsigned short width,
    short height);

void sub_10498(unsigned short row);

short sub_106c8(unsigned short row);
short sub_10678(void);

int sub_10794(unsigned short first, unsigned short second)
{
    uint16_t temporary;

    temporary = *(uint16_t *)&inertia_memory[first];
    *(uint16_t *)&inertia_memory[first] = *(uint16_t *)&inertia_memory[second];
    *(uint16_t *)&inertia_memory[second] = temporary;
    return 0;
}

void sub_107b8(unsigned short *left, unsigned short *right);
void sub_10808(void);
void sub_108d0(void);
void sub_10970(void);
void sub_109e8(unsigned short maximum);
void sub_10a88(short maximum);
void sub_10b50(void);
void sub_10c18(void);
void sub_10ce0(short low, short high);
void sub_10e70(unsigned short frequency, short duration);
unsigned short sub_10f38(long wait);

int sub_10a61(unsigned short maximum)
{
    sub_10a88((short)maximum);
    return 0;
}

static void set_rows(int a, int b, int c, int d, int e)
{
    static const int colors[5] = {1, 2, 3, 4, 5};
    const int lengths[5] = {a, b, c, d, e};
    int index;

    memset(inertia_memory, 0, sizeof(inertia_memory));
    *(uint16_t *)&inertia_memory[0x0BA2] = 5;
    for (index = 0; index < 5; ++index) {
        inertia_memory[0x0B4C + index * 2] = (uint8_t)lengths[index];
        inertia_memory[0x0B4D + index * 2] = (uint8_t)colors[index];
    }
}

static int lengths_equal(int a, int b, int c, int d, int e)
{
    const int expected[5] = {a, b, c, d, e};
    int index;

    for (index = 0; index < 5; ++index) {
        if (inertia_memory[0x0B4C + index * 2] != expected[index])
            return 0;
    }
    return 1;
}

static int sorted(void)
{
    int index;

    for (index = 1; index < 5; ++index) {
        if (inertia_memory[0x0B4C + (index - 1) * 2] >
            inertia_memory[0x0B4C + index * 2])
            return 0;
    }
    return 1;
}

int main(void)
{
    set_rows(5, 3, 4, 1, 2);
    sub_107b8(
        (unsigned short *)&inertia_memory[0x0B4C],
        (unsigned short *)&inertia_memory[0x0B4E]);
    if (!lengths_equal(3, 5, 4, 1, 2))
        return 1;

    set_rows(3, 1, 2, 4, 5);
    sub_109e8(3);
    if (!lengths_equal(4, 3, 2, 1, 5))
        return 2;

    set_rows(1, 5, 4, 3, 2);
    sub_10a88(4);
    if (!lengths_equal(5, 4, 2, 3, 1))
        return 3;

    set_rows(4, 2, 5, 3, 1);
    sub_10808();
    if (!sorted())
        return 4;

    set_rows(4, 1, 5, 3, 2);
    sub_108d0();
    if (!sorted())
        return 5;

    set_rows(5, 1, 4, 2, 3);
    sub_10970();
    if (!sorted())
        return 6;

    set_rows(5, 4, 3, 2, 1);
    sub_10b50();
    if (!sorted())
        return 7;

    set_rows(5, 3, 4, 1, 2);
    sub_10c18();
    if (!sorted())
        return 8;

    set_rows(2, 5, 1, 4, 3);
    sub_10ce0(0, 4);
    if (!sorted())
        return 9;

    reset_runtime_observation();
    sub_101f0(1, 2, 5, 3);
    if (cursor_calls != 4 || text_calls != 4)
        return 10;
    if (cursor_rows[0] != 1 || cursor_rows[1] != 2 ||
        cursor_rows[2] != 3 || cursor_rows[3] != 4)
        return 11;
    if (cursor_columns[0] != 2 || cursor_columns[1] != 2 ||
        cursor_columns[2] != 2 || cursor_columns[3] != 2)
        return 12;

    reset_runtime_observation();
    set_rows(5, 3, 4, 1, 2);
    sub_106c8(2);
    if (cursor_calls != 1 || text_calls != 1 || color_calls != 1)
        return 13;
    if (cursor_rows[0] != 3 || cursor_columns[0] != 0 || last_color != 3)
        return 14;

    reset_runtime_observation();
    set_rows(5, 3, 4, 1, 2);
    sub_10768(1, 2);
    if (!lengths_equal(5, 3, 4, 1, 2))
        return 15;
    if (cursor_calls != 3 || text_calls != 3 || color_calls != 3)
        return 16;
    if (cursor_rows[0] != 2 || cursor_rows[1] != 3 ||
        colors[0] != 2 || colors[1] != 3)
        return 17;
    if (last_color != 15 || clock_calls != 3)
        return 18;

    reset_runtime_observation();
    set_rows(5, 3, 4, 1, 2);
    {
        uint32_t pause = 42;
        memcpy(&inertia_memory[0x0132], &pause, sizeof(pause));
    }
    sub_10498(3);
    if (cursor_calls != 1 || text_calls != 1 || color_calls != 1)
        return 19;
    if (last_color != 15 || clock_calls != 45 || output_calls != 0)
        return 20;

    reset_runtime_observation();
    {
        uint16_t sound = 1;
        uint32_t pause = 75;
        memcpy(&inertia_memory[0x0B46], &sound, sizeof(sound));
        memcpy(&inertia_memory[0x0132], &pause, sizeof(pause));
    }
    sub_10498(3);
    if (output_calls != 5 || last_divisor != 180 || clock_calls != 80)
        return 21;

    reset_runtime_observation();
    sub_10f38(17);
    if (clock_calls != 19 || fake_clock != 19)
        return 22;

    reset_runtime_observation();
    sub_10e70(0, 30);
    if (clock_calls != 32 || output_calls != 0)
        return 23;

    reset_runtime_observation();
    sub_10e70(120, 30);
    if (clock_calls != 77 || output_calls != 5)
        return 24;
    if (output_ports[0] != 67 || output_values[0] != 182)
        return 25;
    if (!beep_timer_programming_matches(120))
        return 26;
    if (output_ports[3] != 97 || output_values[3] != 0x33)
        return 27;
    if (output_ports[4] != 97 || output_values[4] != 0x30)
        return 28;

    set_rows(5, 3, 4, 1, 2);
    memcpy(&inertia_memory[0x08F0], &inertia_memory[0x0B4C], 10);
    memset(&inertia_memory[0x0B4C], 0, 10);
    reset_runtime_observation();
    sub_10678();
    if (!lengths_equal(5, 3, 4, 1, 2))
        return 29;
    if (cursor_calls != 5 || text_calls != 5 || color_calls != 5)
        return 30;
    if (clock_calls != 1 || cursor_rows[4] != 5 || colors[4] != 5)
        return 31;

    memset(inertia_memory, 0, sizeof(inertia_memory));
    {
        uint16_t menu_count = 2;
        uint16_t sound = 1;
        uint32_t pause = 30;
        memcpy(&inertia_memory[0x0160], &menu_count, sizeof(menu_count));
        memcpy(&inertia_memory[0x0B46], &sound, sizeof(sound));
        memcpy(&inertia_memory[0x0132], &pause, sizeof(pause));
    }
    reset_runtime_observation();
    sub_10060();
    if (color_calls != 1 || last_color != 15 || background_calls != 1)
        return 32;
    if (cursor_calls != 9 || text_calls != 9)
        return 33;

    memset(inertia_memory, 0, sizeof(inertia_memory));
    {
        uint16_t menu_count = 2;
        uint32_t pause = 30;
        memcpy(&inertia_memory[0x0160], &menu_count, sizeof(menu_count));
        memcpy(&inertia_memory[0x0132], &pause, sizeof(pause));
    }
    reset_runtime_observation();
    sub_102e0();
    {
        uint16_t sound;
        uint32_t pause;
        memcpy(&sound, &inertia_memory[0x0B46], sizeof(sound));
        memcpy(&pause, &inertia_memory[0x0132], sizeof(pause));
        if (key_calls != 4 || display_cursor_calls != 8)
            return 34;
        if (sound != 1 || pause != 30)
            return 35;
    }

    memset(inertia_memory, 0, sizeof(inertia_memory));
    {
        uint16_t row_count = 5;
        memcpy(&inertia_memory[0x0BA2], &row_count, sizeof(row_count));
    }
    reset_runtime_observation();
    sub_10560();
    {
        uint16_t sound;
        uint32_t pause;
        int seen[6] = {0};
        int index;
        memcpy(&sound, &inertia_memory[0x0B46], sizeof(sound));
        memcpy(&pause, &inertia_memory[0x0132], sizeof(pause));
        if (sound != 1 || pause != 30 || config_calls != 1)
            return 36;
        for (index = 0; index < 5; ++index) {
            unsigned int length = inertia_memory[0x08F0 + index * 2];
            if (length < 1 || length > 5 || inertia_memory[0x08F1 + index * 2] != 7)
                return 37;
            seen[length]++;
        }
        for (index = 1; index <= 5; ++index)
            if (seen[index] != 1)
                return 38;
        if (memcmp(&inertia_memory[0x08F0], &inertia_memory[0x0B4C], 10) != 0)
            return 39;
        if (cursor_calls != 5 || text_calls != 5 || color_calls != 5)
            return 40;
    }

    return 0;
}
