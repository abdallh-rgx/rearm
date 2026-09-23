// A32 VFP corpus
vldr s0, [r0]
vldr s1, [r0, #4]
vldr d2, [r1, #8]
vstr s0, [r0]
vstr d0, [r1, #-8]
vldm r0, {s0-s3}
vldm r0, {d0-d3}
vldmia r0!, {s8-s15}
vldmdb r0!, {d0-d3}
vstm r0, {s0-s3}
vstmia r0!, {d0-d5}
vstmdb r0!, {s2-s9}
vadd.f32 s0, s1, s2
vadd.f64 d0, d1, d2
vsub.f32 s0, s1, s2
vsub.f64 d0, d1, d2
vmul.f32 s0, s1, s2
vmul.f64 d0, d1, d2
vnmul.f32 s0, s1, s2
vdiv.f32 s0, s1, s2
vdiv.f64 d0, d1, d2
vmla.f32 s0, s1, s2
vmla.f64 d0, d1, d2
vmls.f32 s0, s1, s2
vnmla.f32 s0, s1, s2
vnmls.f32 s0, s1, s2
vnmla.f64 d0, d1, d2
vnmls.f64 d0, d1, d2
vabs.f32 s0, s1
vabs.f64 d0, d1
vneg.f32 s0, s1
vneg.f64 d0, d1
vsqrt.f32 s0, s1
vsqrt.f64 d0, d1
vcmp.f32 s0, s1
vcmp.f64 d0, d1
vcmpe.f32 s0, s1
vcmp.f32 s0, #0.0
vcmpe.f32 s0, #0.0
vcmp.f64 d0, #0.0
vmov s0, s1
vmov d0, d1
vmov.f32 s0, #1.0
vmov.f32 s1, #0.5
vmov.f64 d0, #2.0
vmov r0, s1
vmov s1, r0
vmov r0, r1, d2
vmov d2, r0, r1
vmov.32 r0, d1[0]
vmov.32 d1[0], r0
vmov.32 r0, d1[1]
vmrs r0, fpscr
vmrs apsr_nzcv, fpscr
vmsr fpscr, r0
vcvt.f32.s32 s0, s1
vcvt.f32.u32 s0, s1
vcvt.s32.f32 s0, s1
vcvt.u32.f32 s0, s1
vcvt.f64.s32 d0, s1
vcvt.s32.f64 s0, d1
vcvt.f64.u32 d0, s1
vcvt.u32.f64 s0, d1
vcvtr.s32.f32 s0, s1
vcvtr.u32.f32 s0, s1
vcvt.f32.f64 s0, d1
vcvt.f64.f32 d0, s1
vcvt.f32.s16 s0, s0, #4
vcvt.f32.u16 s0, s0, #12
vcvt.s16.f32 s0, s0, #4
vcvt.u16.f32 s0, s0, #3
vcvt.f64.s16 d0, d0, #7
vcvt.s16.f64 d1, d1, #2
vcvt.f32.s32 s30, s31
vcvt.f64.f32 d15, s30
vsqrt.f32 s31, s30
