/* Toolchain probe for the compiler-coverage plan.
 *
 * Proves at runtime that the toolchain emits 16-bit int / 32-bit long,
 * the expected data and function pointer widths for the selected memory
 * model, integer wrap/carry behaviour, and an indirect call. Exit code
 * follows the handwritten-case convention: 255 on success, a small
 * positive failure count otherwise (Csmith-generated programs use 0).
 *
 * Compile with -DEXPECTED_DATA_PTR=<2|4> -DEXPECTED_FUNC_PTR=<2|4>.
 * C89 only; no compiler-specific keywords.
 */
#include <stdio.h>

#ifndef EXPECTED_DATA_PTR
#error "probe requires -DEXPECTED_DATA_PTR=<bytes>"
#endif
#ifndef EXPECTED_FUNC_PTR
#error "probe requires -DEXPECTED_FUNC_PTR=<bytes>"
#endif

/* Compile-time width checks: a negative array bound must be rejected. */
typedef char probe_int_is_word[(sizeof(int) == 2) ? 1 : -1];
typedef char probe_long_is_dword[(sizeof(long) == 4) ? 1 : -1];
typedef char probe_data_ptr_model[(sizeof(void *) == EXPECTED_DATA_PTR) ? 1 : -1];
typedef char probe_func_ptr_model[(sizeof(int (*)(int)) == EXPECTED_FUNC_PTR) ? 1 : -1];

static int add_seven(int value)
{
    return value + 7;
}

int main(void)
{
    unsigned int ui = 65535u;
    unsigned long ul = 65535ul;
    int (*fn)(int) = add_seven;
    int failures = 0;

    ui = ui + 1u;   /* wraps to 0 only if int is 16 bits */
    ul = ul + 1ul;  /* reaches 65536 only if long is 32 bits */

    if (sizeof(int) != 2u) failures++;
    if (sizeof(long) != 4u) failures++;
    if (sizeof(void *) != EXPECTED_DATA_PTR) failures++;
    if (sizeof(int (*)(int)) != EXPECTED_FUNC_PTR) failures++;
    if (ui != 0u) failures++;
    if (ul != 65536ul) failures++;
    if ((0x12345678ul & 0xFFFFul) != 0x5678ul) failures++;
    if ((0x12345678ul >> 16) != 0x1234ul) failures++;
    if (-32767 - 1 > 32767) failures++;
    if (fn(35) != 42) failures++;

    printf("probe int=%u long=%u data_ptr=%u func_ptr=%u ui=%u ul=%lu fn=%d\n",
           (unsigned int)sizeof(int), (unsigned int)sizeof(long),
           (unsigned int)sizeof(void *), (unsigned int)sizeof(int (*)(int)),
           ui, ul, fn(35));
    printf("probe result=%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? failures : 255;
}
