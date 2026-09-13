static int g_counter = 3;
static unsigned char g_table[4] = { 1, 2, 3, 4 };

static int bump_static(void)
{
    static int seen = 10;

    seen += 2;
    return seen;
}

int sum_globals(void)
{
    int i;
    int total;

    total = g_counter;
    for (i = 0; i < 4; ++i) {
        total += g_table[i];
    }
    return total;
}

int main(void)
{
    int total;

    total = sum_globals();
    if (total != 13) {
        return 1;
    }
    if (bump_static() != 12) {
        return 2;
    }
    if (bump_static() != 14) {
        return 3;
    }
    /* Exercise pre-store values on both sides of a byte carry. */
    g_counter = 242;
    if (sum_globals() != 252) {
        return 4;
    }
    g_counter = 246;
    if (sum_globals() != 256) {
        return 5;
    }
    return 255;
}
