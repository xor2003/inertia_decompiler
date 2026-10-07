/* Signed/unsigned char boundary probe.
 * Exercises the 127/128/255 edges, explicit truncation casts and
 * promotion into int arithmetic and comparisons. int is 16-bit and
 * char is 8-bit on every target profile. Every int-to-signed-char cast
 * stays in range (-128..127): out-of-range signed conversion is
 * implementation-defined and is not used as an oracle. Unsigned
 * narrowing is defined (mod 256) in C89 on every compiler, so the
 * unsigned truncation inputs 256, -1, 384 and 511 are fixed
 * expectations. The signed cases double as extension controls: a
 * widened -1 must come back as -1 (sign extension), while an unsigned
 * 255 must come back as 255 (zero extension).
 */
int widen_sc(int v)
{
    signed char c;

    c = (signed char)v;
    return c;
}

int widen_uc(int v)
{
    unsigned char c;

    c = (unsigned char)v;
    return c;
}

int add_sc(int av, int b)
{
    signed char a;

    a = (signed char)av;
    return a + b;
}

int add_uc(int av, int b)
{
    unsigned char a;

    a = (unsigned char)av;
    return a + b;
}

int sc_lt_uc(int av, int bv)
{
    signed char a;
    unsigned char b;

    a = (signed char)av;
    b = (unsigned char)bv;
    return a < b;
}

int main(void)
{
    if (widen_sc(-128) != -128) {
        return 1;
    }
    if (widen_sc(-1) != -1) {
        return 2;
    }
    if (widen_sc(0) != 0) {
        return 3;
    }
    if (widen_sc(127) != 127) {
        return 4;
    }
    if (widen_uc(127) != 127) {
        return 5;
    }
    if (widen_uc(128) != 128) {
        return 6;
    }
    if (widen_uc(255) != 255) {
        return 7;
    }
    if (widen_uc(256) != 0) {
        return 8;
    }
    if (widen_uc(-1) != 255) {
        return 9;
    }
    if (widen_uc(384) != 128) {
        return 10;
    }
    if (widen_uc(511) != 255) {
        return 11;
    }
    if (add_sc(127, 1) != 128) {
        return 12;
    }
    if (add_sc(-128, -1) != -129) {
        return 13;
    }
    if (add_uc(255, 1) != 256) {
        return 14;
    }
    if (add_uc(128, 128) != 256) {
        return 15;
    }
    if (sc_lt_uc(-1, 255) != 1) {
        return 16;
    }
    if (sc_lt_uc(127, 128) != 1) {
        return 17;
    }
    if (sc_lt_uc(100, 50) != 0) {
        return 18;
    }
    if (sc_lt_uc(5, 5) != 0) {
        return 19;
    }
    return 255;
}
