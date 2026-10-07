/*
 * Contract: depth-bounded recursion whose frame entries, base-case hits and
 * depth-limit exits are observed through globals.  descend_sum recurses with
 * n - 2 until n <= 0 (base case) or depth reaches limit (fallback), so the
 * checks prove recursive frames, base-case selection and the limit branch.
 * Frame depth stays at most six and every input is deterministic.
 * Returns 255 on success; 1..N identify the failing check.
 */
static int g_frames;
static int g_base_hits;
static int g_limit_hits;

int descend_sum(int n, int depth, int limit)
{
    ++g_frames;
    if (n <= 0) {
        ++g_base_hits;
        return 0;
    }
    if (depth >= limit) {
        ++g_limit_hits;
        return -1;
    }
    return n + descend_sum(n - 2, depth + 1, limit);
}

int tally_descend(int n, int limit)
{
    g_frames = 0;
    g_base_hits = 0;
    g_limit_hits = 0;
    return descend_sum(n, 0, limit);
}

int main(void)
{
    volatile int seed_n = 9;
    volatile int seed_limit = 6;
    int n;
    int total;

    n = seed_n;

    /* Base case reached: frames 0..5, one base hit, no limit hit. */
    total = tally_descend(n, seed_limit);
    if (total != 25) {
        return 1;
    }
    if (g_frames != 6 || g_base_hits != 1 || g_limit_hits != 0) {
        return 2;
    }

    /* Depth limit reached first: limit fallback contributes -1. */
    total = tally_descend(n, 3);
    if (total != 20) {
        return 3;
    }
    if (g_frames != 4 || g_base_hits != 0 || g_limit_hits != 1) {
        return 4;
    }

    /* Boundary: n == 0 hits the base case in the first frame. */
    total = tally_descend(0, seed_limit);
    if (total != 0) {
        return 5;
    }
    if (g_frames != 1 || g_base_hits != 1 || g_limit_hits != 0) {
        return 6;
    }

    /* Boundary: negative n also selects the base case immediately. */
    total = tally_descend(-4, 2);
    if (total != 0) {
        return 7;
    }
    if (g_frames != 1 || g_base_hits != 1 || g_limit_hits != 0) {
        return 8;
    }

    return 255;
}
