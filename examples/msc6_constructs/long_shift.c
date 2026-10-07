/* Unsigned long shift probe.
 * Counts stay below the 32-bit width and cover the 15/16/17 multiword
 * boundary. Only unsigned right shifts are used; signed shifts are
 * avoided where implementation-defined. Counts pass through a volatile
 * source so the shift stays a runtime operation for emission evidence.
 * Results are masked to 32 bits so the host 64-bit unsigned long oracle
 * matches the 16-bit targets.
 */
unsigned long shl32(unsigned long v, int c)
{
    return (v << c) & 0xFFFFFFFFUL;
}

unsigned long shr32(unsigned long v, int c)
{
    return v >> c;
}

int main(void)
{
    volatile int vc;

    vc = 1;
    if (shl32(1UL, vc) != 2UL) {
        return 1;
    }
    vc = 15;
    if (shl32(1UL, vc) != 0x8000UL) {
        return 2;
    }
    vc = 16;
    if (shl32(1UL, vc) != 0x10000UL) {
        return 3;
    }
    vc = 17;
    if (shl32(1UL, vc) != 0x20000UL) {
        return 4;
    }
    vc = 31;
    if (shl32(1UL, vc) != 0x80000000UL) {
        return 5;
    }
    vc = 16;
    if (shl32(0xFFFFUL, vc) != 0xFFFF0000UL) {
        return 6;
    }
    vc = 17;
    if (shl32(0xFFFFUL, vc) != 0xFFFE0000UL) {
        return 7;
    }
    vc = 31;
    if (shr32(0x80000000UL, vc) != 1UL) {
        return 8;
    }
    vc = 16;
    if (shr32(0x80000000UL, vc) != 0x8000UL) {
        return 9;
    }
    vc = 17;
    if (shr32(0x80000000UL, vc) != 0x4000UL) {
        return 10;
    }
    vc = 16;
    if (shr32(0xFFFF0000UL, vc) != 0xFFFFUL) {
        return 11;
    }
    vc = 15;
    if (shr32(0xFFFF0000UL, vc) != 0x1FFFEUL) {
        return 12;
    }
    vc = 1;
    if (shr32(0xFFFFFFFFUL, vc) != 0x7FFFFFFFUL) {
        return 13;
    }
    return 255;
}
