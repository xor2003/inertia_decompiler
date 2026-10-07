/* Exact-width types and limits for the 16-bit Microsoft C data model. */
#ifndef CSMITH_MSC_STDINT_H
#define CSMITH_MSC_STDINT_H

#include <limits.h>

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed int int16_t;
typedef unsigned int uint16_t;
typedef signed long int32_t;
typedef unsigned long uint32_t;

#define INT8_MIN (-127 - 1)
#define INT8_MAX 127
#define UINT8_MAX 255U
#define INT16_MIN (-32767 - 1)
#define INT16_MAX 32767
#define UINT16_MAX 65535U
#define INT32_MIN (-2147483647L - 1L)
#define INT32_MAX 2147483647L
#define UINT32_MAX (~(uint32_t)0)

#endif
