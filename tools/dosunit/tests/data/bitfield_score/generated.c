#ifndef INERTIA_COHERENT_GP_RUNTIME_H
#define INERTIA_COHERENT_GP_RUNTIME_H
#include <limits.h>
#if CHAR_BIT != 8
#error Inertia GP runtime requires 8-bit bytes
#endif
#if USHRT_MAX != 0xffffU
#error Inertia GP runtime requires a 16-bit unsigned short
#endif
#if UINT_MAX == USHRT_MAX
typedef unsigned long inertia_gp_dword;
#else
typedef unsigned int inertia_gp_dword;
#endif
typedef char inertia_gp_dword_must_be_four_bytes[(sizeof(inertia_gp_dword) == 4) ? 1 : -1];
typedef union inertia_gp_lane {
    inertia_gp_dword full;
    struct {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        unsigned short high, low;
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_M_I86) || defined(M_I86) || (defined(__TURBOC__) && defined(__MSDOS__))
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


    extern unsigned short xff;
    extern unsigned short inertia_ds;
unsigned short sub_1d12(unsigned char *arg_4)
{

    unsigned short dx;  // dx
    unsigned short dx_2;  // dx
    unsigned short gp_saved_ax_1d26;  // [bp-0x6]
    unsigned short gp_saved_si_1d15;  // [bp-0x4]
    unsigned short tmp_0;  // tmp #0
    unsigned short tmp_1;  // tmp #1
    unsigned short tmp_2;  // tmp #2
    gp_saved_si_1d15 = inertia_esi & 0xffff;
    tmp_0 = PTR_U16(arg_4);
    inertia_si = tmp_0;
    inertia_eax = (inertia_eax & 0xffff0000) | (arg_4[0] & 0xff);
    tmp_1 = (((inertia_eax & 0xffff) >> 3) & 31) << 3;
    inertia_ax = tmp_1;
    gp_saved_ax_1d26 = inertia_eax & 0xffff;
    tmp_2 = (tmp_1 & 0xff00) | (arg_4[0] & 0xff);
    inertia_ax = tmp_2;
    dx = gp_saved_ax_1d26;
    dx_2 = (gp_saved_ax_1d26 & 0xff00) | (SEG_U8((uint32_t)inertia_ds, 1 + tmp_0) & 0xff);
    inertia_esi = (inertia_esi & 0xffff0000) | (gp_saved_si_1d15 & 0xffff);
    return (tmp_2 & 7) + dx + ((dx_2 & 1) << 8) + SEG_U16((uint32_t)inertia_ds, 2 + tmp_0);
}