/*
 * Contract: && and || chains whose later operands are calls with observable
 * global side effects, nested call composition, and if/else selection on the
 * composed result.  Each probe appends its id to g_sequence and increments
 * g_calls, so the checks prove both short-circuit suppression (a suppressed
 * call never appends) and left-to-right evaluation order (appended ids appear
 * in operand order).  Existing sources only have pure-load conditions.
 * Returns 255 on success; 1..N identify the failing check.
 */
static int g_sequence;
static int g_calls;

static void note_call(int id)
{
    g_sequence = g_sequence * 10 + id;
    ++g_calls;
}

int probe_small(int x)
{
    note_call(1);
    return x < 5;
}

int probe_big(int x)
{
    note_call(2);
    return x > 15;
}

int bump(int x)
{
    return x + 4;
}

int main(void)
{
    volatile int seed_a = 3;
    volatile int seed_b = 7;
    volatile int seed_c = 30;
    int a;
    int b;
    int c;
    int hits;

    a = seed_a;
    b = seed_b;
    c = seed_c;

    /* && with a false first operand: second call must be suppressed. */
    g_sequence = 0;
    g_calls = 0;
    if (probe_big(a) && probe_small(a)) {
        hits = 1;
    } else {
        hits = 2;
    }
    if (hits != 2) {
        return 1;
    }
    if (g_calls != 1 || g_sequence != 2) {
        return 2;
    }

    /* || with a true first operand: second call must be suppressed. */
    g_sequence = 0;
    g_calls = 0;
    if (probe_small(a) || probe_big(a)) {
        hits = 1;
    } else {
        hits = 2;
    }
    if (hits != 1) {
        return 3;
    }
    if (g_calls != 1 || g_sequence != 1) {
        return 4;
    }

    /* Composed call as first operand; both probes run in operand order. */
    g_sequence = 0;
    g_calls = 0;
    if (probe_big(bump(b)) || probe_small(b)) {
        hits = 1;
    } else {
        hits = 2;
    }
    if (hits != 2) {
        return 5;
    }
    if (g_calls != 2 || g_sequence != 21) {
        return 6;
    }

    /* && chain: middle operand false suppresses the third call. */
    g_sequence = 0;
    g_calls = 0;
    if (probe_big(c) && probe_small(c) && probe_small(bump(c))) {
        hits = 1;
    } else {
        hits = 2;
    }
    if (hits != 2) {
        return 7;
    }
    if (g_calls != 2 || g_sequence != 21) {
        return 8;
    }

    /* Nested if/else on composed call results, both calls execute. */
    g_sequence = 0;
    g_calls = 0;
    if (probe_small(a)) {
        if (probe_big(bump(c))) {
            hits = 1;
        } else {
            hits = 3;
        }
    } else {
        hits = 2;
    }
    if (hits != 1) {
        return 9;
    }
    if (g_calls != 2 || g_sequence != 12) {
        return 10;
    }

    return 255;
}
