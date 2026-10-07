/* Union member-width probe.
 * Byte/short/long members plus a byte-array member, and a union nested
 * in a struct. unsigned short is 16 bits on every target and on the
 * host, so the word member keeps one width everywhere. Every access is
 * same-member store/load: a value is written to one member and read
 * back through that same member. Reading an inactive member is never
 * used as an oracle — zero-initializing one member does not authorize
 * reading another — so this file assumes nothing about endianness,
 * padding, layout or overlay order. volatile union storage keeps the
 * store and the readback as real memory operations instead of being
 * folded away. All observations are named field/member accesses.
 */
union Wide {
    unsigned char byte;
    unsigned short word;
    unsigned long dword;
    unsigned char bytes[4];
};

struct Rec {
    int tag;
    union Wide u;
};

unsigned char round_byte(unsigned char v)
{
    volatile union Wide u;

    u.byte = v;
    return u.byte;
}

unsigned int round_word(unsigned int v)
{
    volatile union Wide u;

    u.word = (unsigned short)v;
    return u.word;
}

unsigned long round_dword(unsigned long v)
{
    volatile union Wide u;

    u.dword = v;
    return u.dword;
}

unsigned char bytes_at(unsigned char a, unsigned char b,
                       unsigned char c, unsigned char d, int i)
{
    volatile union Wide u;

    u.bytes[0] = a;
    u.bytes[1] = b;
    u.bytes[2] = c;
    u.bytes[3] = d;
    return u.bytes[i];
}

int nested_probe(void)
{
    volatile struct Rec r;

    r.tag = 77;
    r.u.byte = 0x34;
    if (r.tag != 77) {
        return -1;
    }
    if (r.u.byte != 0x34) {
        return -2;
    }
    r.tag = -5;
    if (r.u.byte != 0x34) {
        return -3;
    }
    if (r.tag != -5) {
        return -4;
    }
    r.u.word = 0x1234;
    if (r.u.word != 0x1234) {
        return -5;
    }
    if (r.tag != -5) {
        return -6;
    }
    r.u.dword = 0x12345678UL;
    if (r.u.dword != 0x12345678UL) {
        return -7;
    }
    if (r.tag != -5) {
        return -8;
    }
    r.u.bytes[0] = 0xAA;
    r.u.bytes[3] = 0x55;
    if (r.u.bytes[0] != 0xAA || r.u.bytes[3] != 0x55) {
        return -9;
    }
    if (r.tag != -5) {
        return -10;
    }
    return 0;
}

int main(void)
{
    if (round_byte(0) != 0) {
        return 1;
    }
    if (round_byte(0xFF) != 0xFF) {
        return 2;
    }
    if (round_byte(0x5A) != 0x5A) {
        return 3;
    }
    if (round_word(0) != 0) {
        return 4;
    }
    if (round_word(0x1234) != 0x1234) {
        return 5;
    }
    if (round_word(0xFFFFU) != 0xFFFFU) {
        return 6;
    }
    if (round_dword(0xCAFEBABEUL) != 0xCAFEBABEUL) {
        return 7;
    }
    if (round_dword(0UL) != 0UL) {
        return 8;
    }
    if (round_dword(0x00FF0000UL) != 0x00FF0000UL) {
        return 9;
    }
    if (bytes_at(0x12, 0x34, 0x56, 0x78, 0) != 0x12) {
        return 10;
    }
    if (bytes_at(0x12, 0x34, 0x56, 0x78, 3) != 0x78) {
        return 11;
    }
    if (bytes_at(0xFF, 0x00, 0xAA, 0x55, 2) != 0xAA) {
        return 12;
    }
    if (nested_probe() != 0) {
        return 13;
    }
    return 255;
}
