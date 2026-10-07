long select_max(long a, long b)
{
    if (a >= b) {
        return a;
    }
    return b;
}

int compare_signed(long a, long b)
{
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    if (a == b) {
        return 0;
    }
    return 2;
}

int compare_unsigned(unsigned long a, unsigned long b)
{
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    if (a == b) {
        return 0;
    }
    return 2;
}

long clamp_window(long value, long low, long high)
{
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

int rel_signed32(long a, long b)
{
    int mask;

    mask = 0;
    if (a < b) {
        mask |= 1;
    }
    if (a <= b) {
        mask |= 2;
    }
    if (a > b) {
        mask |= 4;
    }
    if (a >= b) {
        mask |= 8;
    }
    if (a == b) {
        mask |= 16;
    }
    if (a != b) {
        mask |= 32;
    }
    return mask;
}

int rel_unsigned32(unsigned long a, unsigned long b)
{
    int mask;

    mask = 0;
    if (a < b) {
        mask |= 1;
    }
    if (a <= b) {
        mask |= 2;
    }
    if (a > b) {
        mask |= 4;
    }
    if (a >= b) {
        mask |= 8;
    }
    if (a == b) {
        mask |= 16;
    }
    if (a != b) {
        mask |= 32;
    }
    return mask;
}

int main(void)
{
    long a;
    long b;
    unsigned long ua;
    unsigned long ub;
    long clipped;

    a = 100000L;
    b = -2000L;
    ua = 300000UL;
    ub = 300001UL;
    clipped = clamp_window(a, -100L, 50000L);
    if (select_max(a, b) != a) {
        return 1;
    }
    if (compare_signed(a, b) != 1) {
        return 2;
    }
    if (compare_signed(b, a) != -1) {
        return 3;
    }
    if (compare_signed(a, a) != 0) {
        return 4;
    }
    if (compare_unsigned(ua, ub) != -1) {
        return 5;
    }
    if (compare_unsigned(ub, ua) != 1) {
        return 6;
    }
    if (compare_unsigned(ua, ua) != 0) {
        return 7;
    }
    if (rel_signed32(b, a) != (1 | 2 | 32)) {
        return 8;
    }
    if (rel_signed32(a, b) != (4 | 8 | 32)) {
        return 9;
    }
    if (rel_signed32(a, a) != (2 | 8 | 16)) {
        return 10;
    }
    if (rel_unsigned32(ua, ub) != (1 | 2 | 32)) {
        return 11;
    }
    if (rel_unsigned32(ub, ua) != (4 | 8 | 32)) {
        return 12;
    }
    if (rel_unsigned32(ua, ua) != (2 | 8 | 16)) {
        return 13;
    }
    if (clipped != 50000L) {
        return 14;
    }
    return 255;
}
