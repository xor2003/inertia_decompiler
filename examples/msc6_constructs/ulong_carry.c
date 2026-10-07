/* Unsigned long carry/borrow probe across the 65535 low-word boundary.
 * Desired emitted mechanism is adc/sbb carry propagation on the 16-bit
 * targets. unsigned long is 32-bit there and 64-bit on the host, so
 * results are masked to 32 bits to keep the oracle identical. Signed
 * long use stays in-range; no signed overflow.
 */
unsigned long add_u32(unsigned long a, unsigned long b)
{
    return (a + b) & 0xFFFFFFFFUL;
}

unsigned long sub_u32(unsigned long a, unsigned long b)
{
    return (a - b) & 0xFFFFFFFFUL;
}

long add_i32(long a, long b)
{
    return a + b;
}

long sub_i32(long a, long b)
{
    return a - b;
}

int main(void)
{
    if (add_u32(0x0000FFFFUL, 1UL) != 0x00010000UL) {
        return 1;
    }
    if (add_u32(0x0000FFFFUL, 0x0000FFFFUL) != 0x0001FFFEUL) {
        return 2;
    }
    if (add_u32(0xFFFFFFFFUL, 1UL) != 0UL) {
        return 3;
    }
    if (add_u32(0x80000000UL, 0x80000000UL) != 0UL) {
        return 4;
    }
    if (add_u32(0x12345678UL, 0xEDCBA988UL) != 0UL) {
        return 5;
    }
    if (add_u32(add_u32(0x0000FFFFUL, 1UL), 0x0000FFFFUL) != 0x0001FFFFUL) {
        return 6;
    }
    if (sub_u32(0x00010000UL, 1UL) != 0x0000FFFFUL) {
        return 7;
    }
    if (sub_u32(0UL, 1UL) != 0xFFFFFFFFUL) {
        return 8;
    }
    if (sub_u32(0x10000000UL, 0x00000001UL) != 0x0FFFFFFFUL) {
        return 9;
    }
    if (sub_u32(0x00010000UL, 0x00010000UL) != 0UL) {
        return 10;
    }
    if (add_u32(0x0000FFFFUL, 1UL) >> 16 != 1UL) {
        return 11;
    }
    if (add_i32(-2000000000L, 2000000000L) != 0L) {
        return 12;
    }
    if (add_i32(2000000000L, 100000000L) != 2100000000L) {
        return 13;
    }
    if (sub_i32(100000L, 200000L) != -100000L) {
        return 14;
    }
    if (sub_i32(-2147483647L - 1L, -1L) != -2147483647L) {
        return 15;
    }
    return 255;
}
