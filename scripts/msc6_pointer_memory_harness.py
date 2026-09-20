"""Behavioral observations for rebuilt tiny MS C pointer functions.

Layer: Test infrastructure.
Responsibility: retain the original pointer fixture's checks without importing
compiler/decompiler machinery into lightweight oracle regression tests.
"""

POINTER_MEMORY_HARNESS_MAIN: str = """
int main(void)
{
    unsigned char bytes[8];
    unsigned short words[4];
    int a;
    int b;

    fill_bytes(bytes, 3, 8);
    words[0] = 10;
    words[1] = 20;
    words[2] = 30;
    words[3] = 40;
    a = 5;
    b = 9;
    swap_ptrs(&a, &b);
    if (bytes[2] != 3) {
        return 1;
    }
    if (sum_words(words, 4) != 100) {
        return 2;
    }
    if (a != 9 || b != 5) {
        return 3;
    }
    swap_ptrs(&a, &a);
    if (a != 9 || b != 5) {
        return 4;
    }
    fill_bytes(bytes + 1, 7, 6);
    if (bytes[0] != 3 || bytes[7] != 3 || bytes[1] != 7 || bytes[6] != 7) {
        return 5;
    }
    fill_bytes(bytes + 2, 9, 0);
    if (bytes[2] != 7) {
        return 6;
    }
    if (sum_words(words + 1, 2) != 50 || sum_words(words, 0) != 0) {
        return 7;
    }
    offset_copy(words + 1, words, 3);
    if (words[0] != 10 || words[1] != 11 || words[2] != 12 || words[3] != 13) {
        return 8;
    }
    offset_copy(words, words + 1, 3);
    if (words[0] != 12 || words[1] != 13 || words[2] != 14 || words[3] != 13) {
        return 9;
    }
    return 255;
}
"""
