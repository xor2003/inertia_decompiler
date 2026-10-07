/* Checksum output contract for 16-bit Microsoft C and DOS. */
#ifndef CSMITH_MSC_PLATFORM_H
#define CSMITH_MSC_PLATFORM_H

#include <stdio.h>

static void platform_main_begin(void) { }

static void platform_main_end(uint32_t crc, int flag)
{
    (void)flag;
#ifndef NOT_PRINT_CHECKSUM
    printf("checksum = %lX\n", crc);
#endif
}

#endif
