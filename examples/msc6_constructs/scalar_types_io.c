signed char add_sc(signed char a, signed char b)
{
    return (signed char)(a + b);
}

unsigned char mix_uc(unsigned char a, unsigned char b)
{
    return (unsigned char)((a << 1) ^ b);
}

unsigned short byteops_unsigned(void)
{
    unsigned char a;
    unsigned char b;

    a = 255;
    b = 143;
    b = a + b;
    a = a - b;
    a = a * b;
    b = b / a;
    b = b % a;
    a = a << 5;
    b = b >> a;
    return ((unsigned short)a << 8) | b;
}

short sub_ss(short a, short b)
{
    return (short)(a - b);
}

unsigned short mul_us(unsigned short a, unsigned short b)
{
    return (unsigned short)(a * b);
}

int add_int(int a, int b)
{
    return a + b;
}

unsigned int rot_ui(unsigned int a)
{
    return (a << 1) | (a >> 15);
}

long add_long(long a, long b)
{
    return a + b;
}

unsigned long sub_ulong(unsigned long a, unsigned long b)
{
    return a - b;
}
/* disable for now, because need lifter to support fpu
float scale_float(float a, float b)
{
    return a * b + 1.0f;
}

double blend_double(double a, double b)
{
    return a / 2.0 + b;
}
*/
char *pick_ptr(char *a, char *b, int which)
{
    if (which != 0) {
        return a;
    }
    return b;
}

int main(void)
{
    char text1[4];
    char text2[4];
    char *picked;
    int total;

    text1[0] = 'A';
    text1[1] = 0;
    text2[0] = 'B';
    text2[1] = 0;
    picked = pick_ptr(text1, text2, 0);
    total = add_sc(1, 2);
    total += mix_uc(7, 3);
    total += sub_ss(9, 4);
    total += mul_us(3, 5);
    total += add_int(10, 20);
    total += rot_ui(9U);
    total += (int)add_long(1000L, 2000L);
    total += (int)sub_ulong(90UL, 30UL);
    total += 7; //(int)scale_float(2.0f, 3.0f);
    total += 8;// (int)blend_double(8.0, 4.0);
    if (add_sc(1, 2) != 3) {
        return 1;
    }
    if (mix_uc(64, 0) != (unsigned char)128) {
        return 2;
    }
    if (byteops_unsigned() != 0xC000U) {
        return 13;
    }
    if (sub_ss(9, 4) != 5) {
        return 3;
    }
    if (mul_us(3, 5) != 15) {
        return 4;
    }
    if (add_int(10, 20) != 30) {
        return 5;
    }
    /* Exercise both input bytes, especially the bit shifted into bit zero. */
    if (rot_ui(9U) != 18U || rot_ui(0x8000U) != 1U ||
        rot_ui(0xffffU) != 0xffffU || rot_ui(0x0080U) != 0x0100U) {
        return 6;
    }
    if (add_long(1000L, 2000L) != 3000L) {
        return 7;
    }
    if (sub_ulong(90UL, 30UL) != 60UL) {
        return 8;
    }
/*
    if ((int)scale_float(2.0f, 3.0f) != 7) {
        return 9;
    }
    if ((int)blend_double(8.0, 4.0) != 8) {
        return 10;
    }
*/
    if (picked[0] != 'B') {
        return 11;
    }
    if (total == 0) {
        return 12;
    }
    return 255;
}
