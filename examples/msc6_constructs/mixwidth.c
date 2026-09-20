/* Mixed int/long comparison probe inspired by nndecomp/msex/f14/src/TEST.C.
 * Parameters keep the comparison in an independently decompilable function.
 * MS C uses 16-bit int and 32-bit long; no out-of-range signed casts are needed.
 */
int compare_mixed(long wide, int narrow)
{
    if (wide < narrow) {
        return -1;
    }
    if (wide > narrow) {
        return 1;
    }
    return 0;
}

int main(void)
{
    if (compare_mixed(30000L, -28536) != 1) {
        return 1;
    }
    if (compare_mixed(-30000L, 28536) != -1) {
        return 2;
    }
    if (compare_mixed(-32768L, (-32767 - 1)) != 0) {
        return 3;
    }
    if (compare_mixed(32768L, 32767) != 1) {
        return 4;
    }
    if (compare_mixed(-32769L, (-32767 - 1)) != -1) {
        return 5;
    }
    if (compare_mixed(2147483647L, -1) != 1) {
        return 6;
    }
    if (compare_mixed((-2147483647L - 1L), 1) != -1) {
        return 7;
    }
    if (compare_mixed(0L, 0) != 0) {
        return 8;
    }
    return 255;
}
