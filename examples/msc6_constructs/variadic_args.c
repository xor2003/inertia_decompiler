/* Bounded variadic callee probe using stdarg.h.
 * Arguments are tag/value pairs terminated by a zero tag: tag 1 carries
 * an int, tag 2 carries a long. Mixed widths exercise the callee's
 * argument walk and the caller's cleanup of a variable push list; this
 * is not a printf port.
 */
#include <stdarg.h>

long collect(int first, ...)
{
    va_list ap;
    long total;
    int tag;

    total = 0L;
    tag = first;
    va_start(ap, first);
    while (tag != 0) {
        if (tag == 1) {
            total += va_arg(ap, int);
        } else if (tag == 2) {
            total += va_arg(ap, long);
        } else {
            va_end(ap);
            return -1L;
        }
        tag = va_arg(ap, int);
    }
    va_end(ap);
    return total;
}

long pair_total(void)
{
    return collect(1, 10, 1, 20, 0);
}

int main(void)
{
    if (collect(1, 5, 2, 30000L, 0) != 30005L) {
        return 1;
    }
    if (collect(2, -40000L, 1, 7, 0) != -39993L) {
        return 2;
    }
    if (collect(0) != 0L) {
        return 3;
    }
    if (collect(1, -1, 1, -1, 0) != -2L) {
        return 4;
    }
    if (collect(2, 100000L, 2, 200000L, 1, -3, 0) != 299997L) {
        return 5;
    }
    if (pair_total() != 30L) {
        return 6;
    }
    if (collect(9, 1, 0) != -1L) {
        return 7;
    }
    return 255;
}
