/* Target-defined facts, not a portable signedness assumption. Record stdout
 * separately for each compiler/configuration. EXPECT_* enables a compile-time
 * check against a previously observed fact, including deliberate wrong facts.
 */
#include <limits.h>
#include <stdio.h>

#ifdef EXPECT_CHAR_BITS
typedef char expected_char_bits[(CHAR_BIT == EXPECT_CHAR_BITS) ? 1 : -1];
#endif
#ifdef EXPECT_PLAIN_CHAR_SIGNED
typedef char expected_plain_char_sign[((CHAR_MIN < 0) ==
    EXPECT_PLAIN_CHAR_SIGNED) ? 1 : -1];
#endif

int main(void)
{
    printf("char_bits=%d char_min=%d char_max=%d plain_signed=%d\n",
        CHAR_BIT, CHAR_MIN, CHAR_MAX, (char)-1 < 0);
    if (((char)-1 < 0) != (CHAR_MIN < 0)) {
        return 1;
    }
    return 255;
}
