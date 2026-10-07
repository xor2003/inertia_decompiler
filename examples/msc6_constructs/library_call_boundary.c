/* Library call boundary probe.
 * strlen/memset/memcpy/memcmp are called with runtime values so the
 * call arguments, results and visible effects are observable. Acceptance
 * of the decompiler side stays blocked until binary-signature matching
 * can exclude the linked runtime bodies; this source only fixes the
 * runtime contract the boundary must preserve.
 */
#include <string.h>

int probe_copy(const char *src)
{
    char dst[16];
    unsigned int n;

    memset(dst, 0x5A, sizeof dst);
    n = strlen(src);
    if (n + 1u > sizeof dst) {
        return -1;
    }
    memcpy(dst, src, n + 1u);
    if (memcmp(dst, src, n + 1u) != 0) {
        return -2;
    }
    if (dst[n] != '\0') {
        return -3;
    }
    return (int)n;
}

int fill_tail(char *dst, unsigned int cap)
{
    memset(dst, 0, cap);
    dst[0] = 'a';
    dst[1] = 'b';
    dst[2] = 'c';
    return (int)strlen(dst);
}

int main(void)
{
    char buf[8];
    int n;

    if (probe_copy("boundary") != 8) {
        return 1;
    }
    if (probe_copy("x") != 1) {
        return 2;
    }
    if (probe_copy("0123456789abcdef") != -1) {
        return 3;
    }
    if (memcmp("abc", "abd", 3) >= 0) {
        return 4;
    }
    if (memcmp("abd", "abc", 3) <= 0) {
        return 5;
    }
    n = fill_tail(buf, sizeof buf);
    if (n != 3) {
        return 6;
    }
    if (memcmp(buf, "abc", 3) != 0) {
        return 7;
    }
    if (buf[4] != 0 || buf[7] != 0) {
        return 8;
    }
    return 255;
}
