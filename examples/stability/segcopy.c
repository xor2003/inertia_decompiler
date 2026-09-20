/* MS C 5/6 diagnostic: unknown selector and offset must remain a far read.
 * Use --examples-dir examples/stability with build_msc6_examples.py.
 * This is not a passing routine fixture until the complete round trip passes.
 */
#include <dos.h>

unsigned read_far(unsigned selector, unsigned offset)
{
    return *(unsigned far *)(((unsigned long)selector << 16) | offset);
}

int main(void)
{
    unsigned words[2];
    unsigned far *pointer;

    words[0] = 0x1234;
    words[1] = 0xabcd;
    pointer = words;
    if (read_far(FP_SEG(pointer), FP_OFF(pointer)) != 0x1234) {
        return 1;
    }
    ++pointer;
    if (read_far(FP_SEG(pointer), FP_OFF(pointer)) != 0xabcd) {
        return 2;
    }
    return 255;
}
