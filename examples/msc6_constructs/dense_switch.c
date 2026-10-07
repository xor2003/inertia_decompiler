/* Dense consecutive switch probe.
 * Cases 0..11 return distinct nontrivial constants so any misrouted arm
 * is observable. The selector passes through a volatile source so the
 * dispatch stays a runtime decision; whether the compiler emits an
 * indirect jump table or a compare chain is emission evidence recorded
 * per profile, not assumed here.
 */
int dispatch(int x)
{
    switch (x) {
    case 0:
        return 37;
    case 1:
        return 102;
    case 2:
        return 219;
    case 3:
        return 301;
    case 4:
        return 457;
    case 5:
        return 523;
    case 6:
        return 619;
    case 7:
        return 734;
    case 8:
        return 811;
    case 9:
        return 937;
    case 10:
        return 1054;
    case 11:
        return 1199;
    default:
        return -1;
    }
}

int main(void)
{
    static const int expected[12] = {
        37, 102, 219, 301, 457, 523, 619, 734, 811, 937, 1054, 1199
    };
    volatile int sel;
    int i;

    for (i = 0; i < 12; ++i) {
        sel = i;
        if (dispatch(sel) != expected[i]) {
            return i + 1;
        }
    }
    sel = 12;
    if (dispatch(sel) != -1) {
        return 13;
    }
    sel = -3;
    if (dispatch(sel) != -1) {
        return 14;
    }
    return 255;
}
