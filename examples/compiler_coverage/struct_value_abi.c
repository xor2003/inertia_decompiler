/* Directed probe: mixed-width struct passed and returned by value.
 * shift_mixrec mutates its parameter copy, so an unchanged caller object
 * proves by-value argument transport; moved = shifted covers struct copy.
 * Checks compare named fields only; padding and sizeof are not observed.
 */
struct MixRec {
    unsigned char tag;
    int count;
    long total;
};

struct MixRec shift_mixrec(struct MixRec in, int delta)
{
    in.tag = (unsigned char)(in.tag + 1U);
    in.count = in.count + delta;
    in.total = in.total + (long)delta * 4L;
    return in;
}

int mixrec_score(struct MixRec rec)
{
    int folded;

    folded = (int)(rec.total & 0xFFL);
    return folded + rec.count - (int)rec.tag;
}

int main(void)
{
    volatile unsigned int tag_seed = 0x5AU;
    volatile int count_seed = 300;
    volatile long total_seed = 70000L;
    volatile int delta_seed = 9;
    struct MixRec orig;
    struct MixRec shifted;
    struct MixRec moved;

    orig.tag = (unsigned char)tag_seed;
    orig.count = count_seed;
    orig.total = total_seed;

    shifted = shift_mixrec(orig, delta_seed);
    moved = shifted;

    if (shifted.tag != 0x5BU || shifted.count != 309 || shifted.total != 70036L) {
        return 1;
    }
    if (moved.tag != shifted.tag || moved.count != shifted.count ||
        moved.total != shifted.total) {
        return 2;
    }
    if (orig.tag != 0x5AU || orig.count != 300 || orig.total != 70000L) {
        return 3;
    }
    if (mixrec_score(shifted) != 366) {
        return 4;
    }
    if (mixrec_score(orig) != 322) {
        return 5;
    }
    return 255;
}
