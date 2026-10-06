#include <DOS.H>

typedef signed char    int8_t;
typedef signed short   int16_t;
typedef signed long    int32_t;
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long  uint32_t;
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
long aNldiv(long dividend, long divisor);
extern uint16_t inertia_cs;
extern uint16_t inertia_ds;
extern uint16_t inertia_es;
extern uint16_t inertia_ss;

#ifndef MK_FP
#define MK_FP(seg, off) ((uint8_t far *)((((unsigned long)(unsigned short)(seg)) << 16) | (unsigned short)(off)))
#endif

#define SEG_PTR(seg, off)  MK_FP((seg), (off))
#define SEG_U8(seg, off)   (*(uint8_t  far *)MK_FP((seg), (off)))
#define SEG_U16(seg, off)  (*(uint16_t far *)MK_FP((seg), (off)))
#define SEG_U32(seg, off)  (*(uint32_t far *)MK_FP((seg), (off)))
#define MEM_U8(ptr)        (*(uint8_t  *)(ptr))
#define MEM_U16(ptr)       (*(uint16_t *)(ptr))
#define MEM_U32(ptr)       (*(uint32_t *)(ptr))
#define PTR_U16(ptr)       ((uint16_t)(ptr))
#define PTR_U32(ptr)       ((uint32_t)(ptr))

int demo(void) { return 0; }
