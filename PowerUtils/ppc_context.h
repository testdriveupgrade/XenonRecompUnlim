#pragma once
#include <cstdint>
#include <cstdlib>

#ifdef __clang__
#define __restrict __restrict__
#define _byteswap_ushort __builtin_bswap16
#define _byteswap_ulong __builtin_bswap32
#define _byteswap_uint64 __builtin_bswap64
#endif

#define PPC_LOAD_U16(x) _byteswap_ushort(*(uint16_t*)(base + (x)))
#define PPC_LOAD_U32(x) _byteswap_ulong(*(uint32_t*)(base + (x)))
#define PPC_LOAD_U64(x) _byteswap_uint64(*(uint64_t*)(base + (x)))

#define PPC_STORE_U16(x, y) *(uint16_t*)(base + (x)) = _byteswap_ushort(y)
#define PPC_STORE_U32(x, y) *(uint32_t*)(base + (x)) = _byteswap_ulong(y)
#define PPC_STORE_U64(x, y) *(uint64_t*)(base + (x)) = _byteswap_uint64(y)

struct PPCRegister
{
    union
    {
        int8_t s8;
        uint8_t u8;
        int16_t s16;
        uint16_t u16;
        int32_t s32;
        uint32_t u32;
        int64_t s64;
        uint64_t u64;
        float f32;
        double f64;
    };
};

typedef float float128[4];

struct PPCContext
{
    uint64_t lr;
    uint64_t ctr;

    union
    {
        struct
        {
            uint32_t cr0;
            uint32_t cr1;
            uint32_t cr2;
            uint32_t cr3;
            uint32_t cr4;
            uint32_t cr5;
            uint32_t cr6;
            uint32_t cr7;
        };
        uint32_t cr[8];
    };

    union
    {
        struct
        {
            PPCRegister r0;
            PPCRegister r1;
            PPCRegister r2;
            PPCRegister r3;
            PPCRegister r4;
            PPCRegister r5;
            PPCRegister r6;
            PPCRegister r7;
            PPCRegister r8;
            PPCRegister r9;
            PPCRegister r10;
            PPCRegister r11;
            PPCRegister r12;
            PPCRegister r13;
            PPCRegister r14;
            PPCRegister r15;
            PPCRegister r16;
            PPCRegister r17;
            PPCRegister r18;
            PPCRegister r19;
            PPCRegister r20;
            PPCRegister r21;
            PPCRegister r22;
            PPCRegister r23;
            PPCRegister r24;
            PPCRegister r25;
            PPCRegister r26;
            PPCRegister r27;
            PPCRegister r28;
            PPCRegister r29;
            PPCRegister r30;
            PPCRegister r31;
        };
        PPCRegister r[32];
    };

    union
    {
        struct
        {
            PPCRegister f0;
            PPCRegister f1;
            PPCRegister f2;
            PPCRegister f3;
            PPCRegister f4;
            PPCRegister f5;
            PPCRegister f6;
            PPCRegister f7;
            PPCRegister f8;
            PPCRegister f9;
            PPCRegister f10;
            PPCRegister f11;
            PPCRegister f12;
            PPCRegister f13;
            PPCRegister f14;
            PPCRegister f15;
            PPCRegister f16;
            PPCRegister f17;
            PPCRegister f18;
            PPCRegister f19;
            PPCRegister f20;
            PPCRegister f21;
            PPCRegister f22;
            PPCRegister f23;
            PPCRegister f24;
            PPCRegister f25;
            PPCRegister f26;
            PPCRegister f27;
            PPCRegister f28;
            PPCRegister f29;
            PPCRegister f30;
            PPCRegister f31;
        };
        PPCRegister f[32];
    };

    union
    {
        struct
        {
            float128 v0;
            float128 v1;
            float128 v2;
            float128 v3;
            float128 v4;
            float128 v5;
            float128 v6;
            float128 v7;
            float128 v8;
            float128 v9;
            float128 v10;
            float128 v11;
            float128 v12;
            float128 v13;
            float128 v14;
            float128 v15;
            float128 v16;
            float128 v17;
            float128 v18;
            float128 v19;
            float128 v20;
            float128 v21;
            float128 v22;
            float128 v23;
            float128 v24;
            float128 v25;
            float128 v26;
            float128 v27;
            float128 v28;
            float128 v29;
            float128 v30;
            float128 v31;
            float128 v32;
            float128 v33;
            float128 v34;
            float128 v35;
            float128 v36;
            float128 v37;
            float128 v38;
            float128 v39;
            float128 v40;
            float128 v41;
            float128 v42;
            float128 v43;
            float128 v44;
            float128 v45;
            float128 v46;
            float128 v47;
            float128 v48;
            float128 v49;
            float128 v50;
            float128 v51;
            float128 v52;
            float128 v53;
            float128 v54;
            float128 v55;
            float128 v56;
            float128 v57;
            float128 v58;
            float128 v59;
            float128 v60;
            float128 v61;
            float128 v62;
            float128 v63;
            float128 v64;
            float128 v65;
            float128 v66;
            float128 v67;
            float128 v68;
            float128 v69;
            float128 v70;
            float128 v71;
            float128 v72;
            float128 v73;
            float128 v74;
            float128 v75;
            float128 v76;
            float128 v77;
            float128 v78;
            float128 v79;
            float128 v80;
            float128 v81;
            float128 v82;
            float128 v83;
            float128 v84;
            float128 v85;
            float128 v86;
            float128 v87;
            float128 v88;
            float128 v89;
            float128 v90;
            float128 v91;
            float128 v92;
            float128 v93;
            float128 v94;
            float128 v95;
            float128 v96;
            float128 v97;
            float128 v98;
            float128 v99;
            float128 v100;
            float128 v101;
            float128 v102;
            float128 v103;
            float128 v104;
            float128 v105;
            float128 v106;
            float128 v107;
            float128 v108;
            float128 v109;
            float128 v110;
            float128 v111;
            float128 v112;
            float128 v113;
            float128 v114;
            float128 v115;
            float128 v116;
            float128 v117;
            float128 v118;
            float128 v119;
            float128 v120;
            float128 v121;
            float128 v122;
            float128 v123;
            float128 v124;
            float128 v125;
            float128 v126;
            float128 v127;
        };
        float128 v[128];
    };
};
