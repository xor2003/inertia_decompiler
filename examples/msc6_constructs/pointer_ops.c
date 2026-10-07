/*
 * Contract: pointer ++/-- and scaled arithmetic confined to one array,
 * same-array pointer differences, pointer-to-pointer indirection, null
 * comparison without dereference, array iteration purely by pointer, and a
 * void* round trip of object pointers only.  Checks verify pointed-to values
 * and measured distances inside the array, never raw addresses.
 * Returns 255 on success; 1..N identify the failing check.
 */
int index_of(const int *base, const int *end, int target)
{
    const int *p;

    p = base;
    while (p < end) {
        if (*p == target) {
            return (int)(p - base);
        }
        ++p;
    }
    return -1;
}

void feed_slot(int **slot, int *backup)
{
    if (*slot == 0) {
        *slot = backup;
        return;
    }
    **slot += 1;
    --(*slot);
}

int read_shifted(const void *raw, int index)
{
    const int *view;

    view = (const int *)raw;
    return *(view + index);
}

int main(void)
{
    volatile int seed = 4;
    int arr[6];
    int backup;
    int *p;
    int *q;
    void *generic;
    int i;

    for (i = 0; i < 6; ++i) {
        arr[i] = seed + i * 2;
    }
    backup = 77;

    /* Pointer iteration and same-array difference via index_of. */
    if (index_of(arr, arr + 6, 10) != 3) {
        return 1;
    }
    /* Boundary: absent target and empty range both yield -1. */
    if (index_of(arr, arr + 6, 99) != -1 || index_of(arr, arr, 4) != -1) {
        return 2;
    }

    /* Scaled arithmetic, increment and decrement inside the array. */
    p = arr + 4;
    if (*p != 12) {
        return 3;
    }
    ++p;
    if (*p != 14) {
        return 4;
    }
    --p;
    p -= 2;
    if (*p != 8) {
        return 5;
    }
    p += 1;
    if (*p != 10) {
        return 6;
    }
    q = arr + 5;
    if ((int)(q - p) != 2) {
        return 7;
    }

    /* Pointer-to-pointer: non-null slot bumps pointee, then steps back. */
    p = arr + 2;
    feed_slot(&p, &backup);
    if (arr[2] != 9 || *p != 6 || (int)((arr + 6) - p) != 5) {
        return 8;
    }
    /* Null slot is redirected to the backup without dereference. */
    q = 0;
    feed_slot(&q, &backup);
    if (*q != 77 || q != &backup) {
        return 9;
    }

    /* void* round trip of an object pointer keeps the same element. */
    generic = (void *)arr;
    if (read_shifted(generic, 3) != 10) {
        return 10;
    }
    if ((int *)generic != arr) {
        return 11;
    }
    return 255;
}
