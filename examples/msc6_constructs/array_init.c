/*
 * Contract: initializers across element widths and storage classes: byte,
 * word and long element arrays; partial, explicit-zero, string and
 * single-element initializers; over global, local and static-local storage.
 * Checks read the stored elements back, including the zero-filled tails of
 * partial and string initializers; layout and padding are never an oracle.
 * Returns 255 on success; 1..N identify the failing check.
 */
static unsigned char g_bytes[6] = { 200, 30, 5 };
unsigned short g_words[4] = { 1111, 2222, 3333, 4444 };
static long g_longs[3] = { 50000L, -60000L, 70000L };
static char g_text[8] = "dose";
unsigned char g_blank[3] = { 0, 0, 0 };
static int g_one[1] = { 41 };

int byte_sum(const unsigned char *p, int count)
{
    int i;
    int total;

    total = 0;
    for (i = 0; i < count; ++i) {
        total += p[i];
    }
    return total;
}

long long_sum(const long *p, int count)
{
    int i;
    long total;

    total = 0L;
    for (i = 0; i < count; ++i) {
        total += p[i];
    }
    return total;
}

int text_len(const char *s)
{
    int n;

    n = 0;
    while (s[n] != 0) {
        ++n;
    }
    return n;
}

int main(void)
{
    volatile int seed = 6;
    unsigned char l_bytes[5] = { 1, 2 };
    int l_words[3] = { 7, 8, 9 };
    static unsigned char s_bytes[4] = { 9, 8, 7 };
    char l_name[5] = "ab";
    long l_longs[2] = { -1L, 2L };
    int l_zero[4] = { 0 };

    /* Global partial initializer: stored head, zero-filled tail. */
    if (byte_sum(g_bytes, seed) != 235) {
        return 1;
    }
    if (g_bytes[3] != 0 || g_bytes[5] != 0) {
        return 2;
    }
    /* Global word array, full initializer. */
    if (g_words[0] + g_words[1] + g_words[2] + g_words[3] != 11110) {
        return 3;
    }
    /* Global long array keeps 32-bit signed values. */
    if (long_sum(g_longs, 3) != 60000L) {
        return 4;
    }
    /* Global string initializer: text plus zero-filled tail. */
    if (text_len(g_text) != 4 || g_text[4] != 0 || g_text[7] != 0) {
        return 5;
    }
    /* Explicit zero initializer and single-element array. */
    if (byte_sum(g_blank, 3) != 0 || g_one[0] != 41) {
        return 6;
    }
    /* Local partial initializer zero-fills the remainder. */
    if (byte_sum(l_bytes, 5) != 3 || l_bytes[4] != 0) {
        return 7;
    }
    if (l_words[0] + l_words[1] + l_words[2] != 24) {
        return 8;
    }
    /* Static-local partial initializer keeps its stored tail zero. */
    if (byte_sum(s_bytes, 4) != 24 || s_bytes[3] != 0) {
        return 9;
    }
    /* Local string initializer. */
    if (text_len(l_name) != 2 || l_name[2] != 0 || l_name[4] != 0) {
        return 10;
    }
    /* Local long array and single-value zero initializer. */
    if (long_sum(l_longs, 2) != 1L) {
        return 11;
    }
    if (l_zero[0] != 0 || l_zero[1] != 0 || l_zero[2] != 0 || l_zero[3] != 0) {
        return 12;
    }
    return 255;
}
