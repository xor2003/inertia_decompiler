/* Observe per-compiler layout; never compare padding bytes or assume another
 * compiler's packing. EXPECT_* checks frozen observations at compile time.
 */
#include <stddef.h>
#include <stdio.h>

/* MS C 5.1's stddef.h does not provide offsetof. Observe member addresses
 * within the live object instead of inventing a null-pointer implementation.
 * sizeof assertions remain compile-time checks on every selected compiler.
 */
#define FIELD_OFFSET(object, member) ((unsigned long)( \
    (unsigned char *)&(object).member - (unsigned char *)&(object)))

enum LayoutTag { LAYOUT_NEGATIVE = -1, LAYOUT_SPARSE = 300 };

struct MixedLayout {
    unsigned char byte;
    int word;
    long dword;
    int *pointer;
};

union LayoutUnion {
    unsigned char byte;
    int word;
    long dword;
};

struct UnionAlignment {
    unsigned char prefix;
    union LayoutUnion value;
};

#ifdef EXPECT_MIXED_BYTES
typedef char expected_mixed_bytes[(sizeof(struct MixedLayout) ==
    EXPECT_MIXED_BYTES) ? 1 : -1];
#endif
#if defined(EXPECT_WORD_OFFSET) && defined(offsetof)
typedef char expected_word_offset[(offsetof(struct MixedLayout, word) ==
    EXPECT_WORD_OFFSET) ? 1 : -1];
#endif
#ifdef EXPECT_UNION_BYTES
typedef char expected_union_bytes[(sizeof(union LayoutUnion) ==
    EXPECT_UNION_BYTES) ? 1 : -1];
#endif
#ifdef EXPECT_ENUM_BYTES
typedef char expected_enum_bytes[(sizeof(enum LayoutTag) ==
    EXPECT_ENUM_BYTES) ? 1 : -1];
#endif

int main(void)
{
    struct MixedLayout mixed;
    struct UnionAlignment aligned;

#if defined(EXPECT_WORD_OFFSET) && !defined(offsetof)
    if (FIELD_OFFSET(mixed, word) != EXPECT_WORD_OFFSET) {
        return 1;
    }
#endif
    printf("mixed_bytes=%lu byte_offset=%lu word_offset=%lu "
        "dword_offset=%lu pointer_offset=%lu union_bytes=%lu "
        "union_offset=%lu enum_bytes=%lu\n",
        (unsigned long)sizeof(struct MixedLayout),
        FIELD_OFFSET(mixed, byte),
        FIELD_OFFSET(mixed, word),
        FIELD_OFFSET(mixed, dword),
        FIELD_OFFSET(mixed, pointer),
        (unsigned long)sizeof(union LayoutUnion),
        FIELD_OFFSET(aligned, value),
        (unsigned long)sizeof(enum LayoutTag));
    return 255;
}
