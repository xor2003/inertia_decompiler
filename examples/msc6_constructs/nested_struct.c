/*
 * Contract: a struct holding a nested struct, an array member and a pointer
 * member.  Fields are written through a struct pointer, read back through the
 * object, and modified through taken field addresses (&item.inner.code,
 * &item.values[i]).  Checks verify stored member values and pointer-member
 * indirection only; padding and layout are never an oracle.
 * Returns 255 on success; 1..N identify the failing check.
 */
struct Inner {
    int code;
    unsigned char tag;
};

struct Outer {
    struct Inner inner;
    int values[4];
    int *tail;
};

void outer_fill(struct Outer *dst, int base, int *tail)
{
    int i;

    dst->inner.code = base + 1;
    dst->inner.tag = (unsigned char)(base + 2);
    for (i = 0; i < 4; ++i) {
        dst->values[i] = base + i * 3;
    }
    dst->tail = tail;
}

int outer_total(const struct Outer *src)
{
    int i;
    int total;

    total = src->inner.code + src->inner.tag;
    for (i = 0; i < 4; ++i) {
        total += src->values[i];
    }
    if (src->tail != 0) {
        total += *src->tail;
    }
    return total;
}

int main(void)
{
    volatile int seed = 10;
    struct Outer item;
    struct Outer plain;
    int slot;
    int *field;
    int *cell;

    slot = seed + 40;
    outer_fill(&item, seed, &slot);
    outer_fill(&plain, 2, (int *)0);

    /* Writes through taken field addresses land in the named members. */
    field = &item.inner.code;
    *field += 5;
    cell = &item.values[2];
    *cell = 40;
    *item.tail = 60;

    if (item.inner.code != 16 || item.inner.tag != 12) {
        return 1;
    }
    if (item.values[0] != 10 || item.values[1] != 13 ||
        item.values[2] != 40 || item.values[3] != 19) {
        return 2;
    }
    if (slot != 60 || *item.tail != 60) {
        return 3;
    }
    if (outer_total(&item) != 170) {
        return 4;
    }
    /* Null pointer member: compared, never dereferenced. */
    if (outer_total(&plain) != 33) {
        return 5;
    }
    if (plain.tail != 0 || plain.values[3] != 11) {
        return 6;
    }
    return 255;
}
