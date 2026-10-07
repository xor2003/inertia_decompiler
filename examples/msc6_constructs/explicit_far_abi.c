/* Explicit far/near ABI probe.
 * On DOS compilers (MS C 5.1, Borland 3.1, Watcom 11) ABI_FAR/ABI_NEAR
 * map to the compiler's far/near tokens, so this file exercises real
 * seg:offset data transport, far calls and far function pointers under
 * both small and large models. The near-to-far cast below relies on the
 * compilers' documented conversion that supplies the data segment for a
 * near data address. The non-DOS host fallback maps both macros to
 * nothing, which keeps the host gcc oracle meaningful for control flow
 * and values only; it does not claim near-only coverage of the DOS ABI.
 */
#if defined(__TURBOC__) || defined(__WATCOMC__) || defined(MSDOS) || \
    defined(__MSDOS__) || defined(__DOS__) || defined(_MSC_VER)
#define ABI_FAR far
#define ABI_NEAR near
#else
#define ABI_FAR
#define ABI_NEAR
#endif

static int ABI_NEAR near_pair[2];
static int ABI_FAR far_cell;

int through_far_ptr(int ABI_FAR *p, int v)
{
    *p = v;
    return *p;
}

int ABI_FAR add_far(int a, int b)
{
    return a + b;
}

int ABI_NEAR add_near(int a, int b)
{
    return a + b;
}

typedef int (ABI_FAR *far_fn_t)(int, int);

int main(void)
{
    int ABI_FAR *fp;
    volatile far_fn_t fn;

    near_pair[0] = 41;
    near_pair[1] = 42;
    far_cell = 0;
    fp = (int ABI_FAR *)&near_pair[0];
    if (through_far_ptr(fp, 97) != 97) {
        return 1;
    }
    if (near_pair[0] != 97) {
        return 2;
    }
    fp[1] = 5;
    if (near_pair[1] != 5) {
        return 3;
    }
    fp = &far_cell;
    if (through_far_ptr(fp, 55) != 55) {
        return 4;
    }
    if (far_cell != 55) {
        return 5;
    }
    fn = add_far;
    if (fn(30, 12) != 42) {
        return 6;
    }
    if (add_far(7, 8) != 15) {
        return 7;
    }
    if (add_near(20, 1) != 21) {
        return 8;
    }
    if (fn(-9, 9) != 0) {
        return 9;
    }
    return 255;
}
