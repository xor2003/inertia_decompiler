/* Directed probe: adjacent unsigned-int bitfields plus an ordinary member.
 * flags_add_level and flags_disarm rewrite one field each; checks require
 * every neighbor field and the ordinary member to survive. All assigned
 * values stay in range; field reads, never raw storage words, are compared,
 * so no packing/layout assumption is made across compilers.
 */
struct FlagBits {
    unsigned int mode : 3;
    unsigned int level : 5;
    unsigned int armed : 1;
    unsigned int tag;
};

void flags_add_level(struct FlagBits *flags, unsigned int delta)
{
    flags->level = flags->level + delta;
}

void flags_disarm(struct FlagBits *flags)
{
    flags->armed = 0U;
}

unsigned int flags_score(const struct FlagBits *flags)
{
    return flags->mode + flags->level * 8U + flags->armed * 256U + flags->tag;
}

int main(void)
{
    volatile unsigned int mode_seed = 5U;
    volatile unsigned int level_seed = 9U;
    volatile unsigned int armed_seed = 1U;
    volatile unsigned int tag_seed = 0x234U;
    volatile unsigned int step_seed = 7U;
    struct FlagBits flags;

    flags.mode = mode_seed;
    flags.level = level_seed;
    flags.armed = armed_seed;
    flags.tag = tag_seed;

    if (flags_score(&flags) != 897U) {
        return 1;
    }
    flags_add_level(&flags, step_seed);
    if (flags.level != 16U) {
        return 2;
    }
    if (flags.mode != 5U || flags.armed != 1U || flags.tag != 0x234U) {
        return 3;
    }
    flags_disarm(&flags);
    if (flags.armed != 0U) {
        return 4;
    }
    if (flags.mode != 5U || flags.level != 16U || flags.tag != 0x234U) {
        return 5;
    }
    flags.mode = flags.mode + 1U;
    if (flags_score(&flags) != 698U) {
        return 6;
    }
    return 255;
}
