/* Observe target-defined bitfield storage, allocation boundaries and plain
 * int signedness. Raw bytes are diagnostic layout evidence for this compiler,
 * not portable checksums or a padding-byte equivalence oracle.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Live same-object byte offsets also work when MS C 5.1 lacks offsetof. */
#define FIELD_OFFSET(object, member) ((unsigned long)( \
    (unsigned char *)&(object).member - (unsigned char *)&(object)))

struct BitLayout {
    unsigned int first : 15;
    unsigned int second : 2;
    int plain : 2;
    unsigned char tag;
};

struct SplitLayout {
    unsigned int first : 1;
    unsigned int : 0;
    unsigned int second : 1;
    unsigned char tag;
};

#ifdef EXPECT_BITS_BYTES
typedef char expected_bits_bytes[(sizeof(struct BitLayout) ==
    EXPECT_BITS_BYTES) ? 1 : -1];
#endif
#if defined(EXPECT_BITS_TAG_OFFSET) && defined(offsetof)
typedef char expected_bits_tag_offset[(offsetof(struct BitLayout, tag) ==
    EXPECT_BITS_TAG_OFFSET) ? 1 : -1];
#endif
#if defined(EXPECT_SPLIT_TAG_OFFSET) && defined(offsetof)
typedef char expected_split_tag_offset[(offsetof(struct SplitLayout, tag) ==
    EXPECT_SPLIT_TAG_OFFSET) ? 1 : -1];
#endif

int main(void)
{
    struct BitLayout bits;
    struct SplitLayout split;
    const unsigned char *bytes;
    unsigned int i;

    memset(&bits, 0, sizeof(bits));
    memset(&split, 0, sizeof(split));
    bits.first = 0x1234U;
    bits.second = 2U;
    bits.plain = -1;
    bits.tag = 0x5aU;
    split.first = 1U;
    split.second = 1U;
    split.tag = 0x5aU;
#if defined(EXPECT_BITS_TAG_OFFSET) && !defined(offsetof)
    if (FIELD_OFFSET(bits, tag) != EXPECT_BITS_TAG_OFFSET) {
        return 2;
    }
#endif
#if defined(EXPECT_SPLIT_TAG_OFFSET) && !defined(offsetof)
    if (FIELD_OFFSET(split, tag) != EXPECT_SPLIT_TAG_OFFSET) {
        return 3;
    }
#endif
    printf("bits_bytes=%lu bits_tag_offset=%lu plain_signed=%d "
        "split_bytes=%lu split_tag_offset=%lu\n",
        (unsigned long)sizeof(bits),
        FIELD_OFFSET(bits, tag), bits.plain < 0,
        (unsigned long)sizeof(split),
        FIELD_OFFSET(split, tag));
    bytes = (const unsigned char *)&bits;
    printf("bits_storage=");
    for (i = 0; i < sizeof(bits); ++i) {
        printf("%02X", (unsigned int)bytes[i]);
    }
    printf("\nsplit_storage=");
    bytes = (const unsigned char *)&split;
    for (i = 0; i < sizeof(split); ++i) {
        printf("%02X", (unsigned int)bytes[i]);
    }
    printf("\n");
    if (bits.first != 0x1234U || bits.second != 2U || bits.tag != 0x5aU ||
        split.first != 1U || split.second != 1U || split.tag != 0x5aU) {
        return 1;
    }
    return 255;
}
