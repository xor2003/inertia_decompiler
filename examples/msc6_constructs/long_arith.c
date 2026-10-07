/* Signed/unsigned long multiply, divide and modulo on in-range values.
 * On 16-bit targets these plausibly emit compiler helper calls or inline
 * multiword sequences; the emitted mechanism is recorded per compiler.
 * All results stay inside the 32-bit range so the host 64-bit unsigned
 * long matches the DOS oracle without masking. The negative-operand
 * division check uses only the C89 invariant (a/b)*b + a%b == a, which
 * holds regardless of implementation-defined rounding direction.
 */
long mul_l(long a, long b)
{
    return a * b;
}

unsigned long mul_ul(unsigned long a, unsigned long b)
{
    return a * b;
}

long div_l(long a, long b)
{
    return a / b;
}

long mod_l(long a, long b)
{
    return a % b;
}

unsigned long div_ul(unsigned long a, unsigned long b)
{
    return a / b;
}

unsigned long rem_ul(unsigned long a, unsigned long b)
{
    return a % b;
}

int main(void)
{
    long a;
    long b;

    if (mul_l(30000L, 40000L) != 1200000000L) {
        return 1;
    }
    if (mul_l(-30000L, 40000L) != -1200000000L) {
        return 2;
    }
    if (mul_l(-7L, -8L) != 56L) {
        return 3;
    }
    if (mul_ul(65535UL, 65535UL) != 4294836225UL) {
        return 4;
    }
    if (mul_ul(100000UL, 40000UL) != 4000000000UL) {
        return 5;
    }
    if (div_l(2100000000L, 7L) != 300000000L) {
        return 6;
    }
    if (mod_l(123456789L, 1000L) != 789L) {
        return 7;
    }
    if (div_ul(4000000000UL, 40000UL) != 100000UL) {
        return 8;
    }
    if (rem_ul(4294967295UL, 65536UL) != 65535UL) {
        return 9;
    }
    a = -123456789L;
    b = 1000L;
    if (div_l(a, b) * b + mod_l(a, b) != a) {
        return 10;
    }
    if (div_l(-2100000000L, 7L) != -300000000L) {
        return 11;
    }
    return 255;
}
