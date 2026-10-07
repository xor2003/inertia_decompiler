/* Directed probe: two-dimensional array handled through a pointer-to-row
 * parameter with variable row/column indexing. grid_add_const is exercised
 * on the same array (aliased dst/src store and readback) and on disjoint
 * arrays; checks require untouched rows in both arrays to survive.
 * All indices stay in bounds.
 */
#define GRID_ROWS 3
#define GRID_COLS 4

int grid_at(int (*grid)[GRID_COLS], int row, int col)
{
    return grid[row][col];
}

void grid_add_const(int (*dst)[GRID_COLS], int (*src)[GRID_COLS],
                    int row, int delta)
{
    int col;

    for (col = 0; col < GRID_COLS; ++col) {
        dst[row][col] = src[row][col] + delta;
    }
}

int main(void)
{
    int a[GRID_ROWS][GRID_COLS];
    int b[GRID_ROWS][GRID_COLS];
    volatile int base_seed = 40;
    volatile int row_seed = 1;
    volatile int col_seed = 2;
    volatile int delta_seed = 5;
    int row;
    int col;

    for (row = 0; row < GRID_ROWS; ++row) {
        for (col = 0; col < GRID_COLS; ++col) {
            a[row][col] = base_seed + row * 10 + col;
            b[row][col] = 200 + row * 10 + col;
        }
    }

    if (grid_at(a, row_seed, col_seed) != 52) {
        return 1;
    }
    if (grid_at(a, 0, 0) != 40 || grid_at(a, 2, 3) != 63) {
        return 2;
    }
    grid_add_const(a, a, row_seed, delta_seed);
    if (grid_at(a, 1, 0) != 55 || grid_at(a, 1, 3) != 58) {
        return 3;
    }
    if (grid_at(a, row_seed, col_seed) != 57) {
        return 4;
    }
    if (grid_at(a, 0, 2) != 42 || grid_at(a, 2, 0) != 60) {
        return 5;
    }
    grid_add_const(b, a, row_seed, delta_seed);
    if (grid_at(b, 1, 0) != 60 || grid_at(b, 1, 3) != 63) {
        return 6;
    }
    if (grid_at(b, 0, 0) != 200 || grid_at(b, 2, 3) != 223) {
        return 7;
    }
    if (grid_at(a, row_seed, col_seed) != 57) {
        return 8;
    }
    return 255;
}
