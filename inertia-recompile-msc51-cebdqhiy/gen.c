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
#define NEAR_OFFSET(seg, ptr) ((uint16_t)(ptr))
#define NEAR_PTR(seg, off) ((void near *)(uint16_t)(off))
#define NEAR_BYTE_ADD(src_seg, dst_seg, ptr, bytes) NEAR_PTR((dst_seg), (uint16_t)(NEAR_OFFSET((src_seg), (ptr)) + (uint16_t)(bytes)))

#ifndef INERTIA_COHERENT_GP_RUNTIME_H
#define INERTIA_COHERENT_GP_RUNTIME_H
#include <limits.h>
#if CHAR_BIT != 8
#error Inertia GP runtime requires 8-bit bytes
#endif
#if USHRT_MAX != 0xffffU
#error Inertia GP runtime requires a 16-bit unsigned short
#endif
#if UINT_MAX == 0xffffffffUL
typedef unsigned int inertia_gp_dword;
#elif ULONG_MAX == 0xffffffffUL
typedef unsigned long inertia_gp_dword;
#else
#error Inertia GP runtime requires a 32-bit unsigned integer type
#endif
typedef union inertia_gp_lane {
    inertia_gp_dword full;
    struct {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        unsigned short high, low;
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_M_I86) || defined(M_I86)
        unsigned short low, high;
#else
#error Inertia GP runtime needs a known target byte order
#endif
    } word;
} inertia_gp_lane;
typedef char inertia_gp_lane_must_be_four_bytes[(sizeof(inertia_gp_lane) == 4) ? 1 : -1];

extern inertia_gp_lane inertia_gp_eax;
#define inertia_eax (inertia_gp_eax.full)
#define inertia_ax (inertia_gp_eax.word.low)
extern inertia_gp_lane inertia_gp_ebx;
#define inertia_ebx (inertia_gp_ebx.full)
#define inertia_bx (inertia_gp_ebx.word.low)
extern inertia_gp_lane inertia_gp_ecx;
#define inertia_ecx (inertia_gp_ecx.full)
#define inertia_cx (inertia_gp_ecx.word.low)
extern inertia_gp_lane inertia_gp_edx;
#define inertia_edx (inertia_gp_edx.full)
#define inertia_dx (inertia_gp_edx.word.low)
extern inertia_gp_lane inertia_gp_esi;
#define inertia_esi (inertia_gp_esi.full)
#define inertia_si (inertia_gp_esi.word.low)
extern inertia_gp_lane inertia_gp_edi;
#define inertia_edi (inertia_gp_edi.full)
#define inertia_di (inertia_gp_edi.word.low)
extern inertia_gp_lane inertia_gp_esp;
#define inertia_esp (inertia_gp_esp.full)
#define inertia_sp (inertia_gp_esp.word.low)
extern inertia_gp_lane inertia_gp_ebp;
#define inertia_ebp (inertia_gp_ebp.full)
#define inertia_bp (inertia_gp_ebp.word.low)
#endif


unsigned short * sub_100f1(void* arg_4, unsigned short arg_6)
{
    unsigned char local_4;  /* [bp-0x6] */
    unsigned char local_3;  /* [bp-0x5] */
    unsigned char local_2;  /* [bp-0x4] */
    unsigned char local_1;  /* [bp-0x3] */

    local_2 = inertia_edi & 0xffff;
    local_1 = (inertia_edi & 0xffff) >> 8;
    local_4 = inertia_esi & 0xffff;
    local_3 = (inertia_esi & 0xffff) >> 8;
    inertia_si = local_4 | (local_3 << 8);
    inertia_di = local_2 | (local_1 << 8);
    return (arg_6 << 1) + arg_4;
}