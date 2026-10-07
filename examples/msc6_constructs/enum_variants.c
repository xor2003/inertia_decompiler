/*
 * Contract: enums with explicit, mixed explicit/implicit, negative and sparse
 * values used as parameters, return values, struct members and switch
 * selectors, plus explicit integer conversion in both directions.  Checks
 * verify the numeric values and their transport through a struct; enum size
 * and layout are recorded elsewhere and are not an oracle here.
 * Returns 255 on success; 1..N identify the failing check.
 */
enum Shade {
    SHADE_DIM = 2,
    SHADE_MID,
    SHADE_GLOW = 17,
    SHADE_MAX
};

typedef enum {
    OP_DROP = -4,
    OP_KEEP = 0,
    OP_STEP = 6,
    OP_JUMP = 40
} Op;

enum Mode {
    MODE_HOLD = 1,
    MODE_RUN = 50,
    MODE_OFF = 900
};

struct Order {
    enum Shade shade;
    Op op;
    int qty;
};

enum Shade next_shade(enum Shade s)
{
    switch (s) {
    case SHADE_DIM:
        return SHADE_MID;
    case SHADE_MID:
        return SHADE_GLOW;
    case SHADE_GLOW:
        return SHADE_MAX;
    default:
        return SHADE_DIM;
    }
}

int apply_op(Op op, int a, int b)
{
    switch (op) {
    case OP_DROP:
        return a - b;
    case OP_KEEP:
        return a;
    case OP_STEP:
        return a + b;
    case OP_JUMP:
        return a * 2 + b;
    default:
        return -1;
    }
}

enum Mode mode_for_qty(int qty)
{
    if (qty < 0) {
        return MODE_OFF;
    }
    if (qty == 0) {
        return MODE_HOLD;
    }
    return MODE_RUN;
}

int main(void)
{
    volatile int seed_a = 9;
    volatile int seed_b = 4;
    struct Order order;
    int a;
    int b;

    a = seed_a;
    b = seed_b;

    /* Mixed explicit/implicit values. */
    if ((int)SHADE_MID != 3 || (int)SHADE_MAX != 18) {
        return 1;
    }
    /* Negative and sparse explicit values. */
    if ((int)OP_DROP != -4 || (int)OP_STEP != 6 || (int)OP_JUMP != 40) {
        return 2;
    }
    /* Enum parameters select switch arms. */
    if (apply_op(OP_DROP, a, b) != 5) {
        return 3;
    }
    if (apply_op(OP_STEP, a, b) != 13) {
        return 4;
    }
    if (apply_op(OP_JUMP, a, b) != 22) {
        return 5;
    }
    /* Integer -> enum conversion reaches the same switch arm. */
    if (apply_op((Op)6, 2, 3) != 5) {
        return 6;
    }
    /* Enum return transported through comparison and next_shade default. */
    if (next_shade(SHADE_GLOW) != SHADE_MAX) {
        return 7;
    }
    if (next_shade((enum Shade)77) != SHADE_DIM) {
        return 8;
    }
    /* Enum members stored in a struct keep their values. */
    order.shade = SHADE_MID;
    order.op = OP_JUMP;
    order.qty = 3;
    if (apply_op(order.op, order.qty, 1) != 7) {
        return 9;
    }
    if (next_shade(order.shade) != SHADE_GLOW) {
        return 10;
    }
    order.op = OP_DROP;
    if ((int)order.op != -4) {
        return 11;
    }
    /* Sparse enum used as an if/else-selected return value. */
    if (mode_for_qty(-1) != MODE_OFF || mode_for_qty(0) != MODE_HOLD) {
        return 12;
    }
    if ((int)mode_for_qty(b) != 50) {
        return 13;
    }
    return 255;
}
