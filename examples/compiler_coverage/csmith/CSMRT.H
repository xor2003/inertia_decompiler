/* 8.3-name Csmith runtime entry point for 16-bit Microsoft C. */
#ifndef CSMITH_MSC_RUNTIME_H
#define CSMITH_MSC_RUNTIME_H

#include "MSSTDINT.H"
#include <assert.h>

#ifndef DEPUTY
#define COUNT(n)
#define TC
#define SAFE
#endif

#define UNDEFINED(value) (value)
#define LOG_INDEX
#define LOG_EXEC
#define STATIC static

#include "MSCPLAT.H"

#define FUNC_NAME(x) (safe_##x)
#include "SAFEMATH.H"
#undef FUNC_NAME

#define INT_BIT (sizeof(int) * CHAR_BIT)
#define _CSMITH_BITFIELD(x) (((x) > INT_BIT) ? ((x) % INT_BIT) : (x))

#endif
