/* Explicit signed-int bitfield probe.
 * Width-1 and intermediate-width signed fields with in-range values
 * only; reads must show sign extension. Allocation-unit packing is not
 * assumed: only declared field values and member preservation are
 * checked, never the underlying storage word. Layout belongs to the
 * per-compiler bitfield layout probe.
 */
struct SignedBits {
    signed int one : 1;
    signed int mid : 5;
    signed int wide : 9;
    int ordinary;
};

int one_read(int v)
{
    struct SignedBits s;

    s.one = v;
    return s.one;
}

int mid_read(int v)
{
    struct SignedBits s;

    s.mid = v;
    return s.mid;
}

int wide_read(int v)
{
    struct SignedBits s;

    s.wide = v;
    return s.wide;
}

int bump_mid(int v, int d)
{
    struct SignedBits s;

    s.mid = v;
    s.mid += d;
    return s.mid;
}

int neighbor_probe(void)
{
    struct SignedBits s;

    s.one = -1;
    s.mid = 0;
    s.wide = -200;
    s.ordinary = 77;
    s.mid = 7;
    if (s.one != -1) {
        return -1;
    }
    if (s.wide != -200) {
        return -2;
    }
    if (s.ordinary != 77) {
        return -3;
    }
    if (s.mid != 7) {
        return -4;
    }
    s.mid--;
    if (s.mid != 6) {
        return -5;
    }
    s.mid++;
    if (s.mid != 7) {
        return -6;
    }
    if (s.one != -1 || s.wide != -200 || s.ordinary != 77) {
        return -7;
    }
    return 0;
}

int main(void)
{
    if (one_read(0) != 0) {
        return 1;
    }
    if (one_read(-1) != -1) {
        return 2;
    }
    if (mid_read(-2) != -2) {
        return 3;
    }
    if (mid_read(7) != 7) {
        return 4;
    }
    if (mid_read(-16) != -16) {
        return 5;
    }
    if (mid_read(15) != 15) {
        return 6;
    }
    if (wide_read(-200) != -200) {
        return 7;
    }
    if (wide_read(255) != 255) {
        return 8;
    }
    if (wide_read(-256) != -256) {
        return 9;
    }
    if (bump_mid(14, 1) != 15) {
        return 10;
    }
    if (bump_mid(-15, -1) != -16) {
        return 11;
    }
    if (bump_mid(0, -1) != -1) {
        return 12;
    }
    if (neighbor_probe() != 0) {
        return 13;
    }
    return 255;
}
