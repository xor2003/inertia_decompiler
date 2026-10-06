#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef long clock_t;
typedef long time_t;

clock_t clock(void);
int rand(void);
void srand(unsigned int seed);
time_t time(time_t *out);
char *strcpy(char *dst, const char *src);
unsigned short dos_int21_flags(void);
void inertia_io_out8(uint16_t port, uint8_t value);
void inertia_io_out16(uint16_t port, uint16_t value);
void inertia_io_out32(uint16_t port, uint32_t value);
int32_t aNldiv(int32_t dividend, int32_t divisor);

extern uint8_t inertia_memory[];
extern uint16_t inertia_cs;
extern uint16_t inertia_ds;
extern uint16_t inertia_es;
extern uint16_t inertia_ss;

#ifndef far
#define far
#endif

#define SEG_LINEAR(seg, off) ((((uint32_t)(uintptr_t)(seg)) << 4) + ((uint16_t)(uintptr_t)(off)))
#define MK_FP(seg, off)      (&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_PTR(seg, off)    ((char *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U8(seg, off)     (*(uint8_t  *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U16(seg, off)    (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U32(seg, off)    (*(uint32_t *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define MEM_U8(ptr)          (*(uint8_t  *)(ptr))
#define MEM_U16(ptr)         (*(uint16_t *)(ptr))
#define MEM_U32(ptr)         (*(uint32_t *)(ptr))
#define PTR_U16(ptr)       ((uint16_t)(uintptr_t)(ptr))
#define PTR_U32(ptr)       ((uint32_t)(uintptr_t)(ptr))

int demo(int x) { if (x) return 1; }