// A32 NEON corpus — shifts, moves, conversions, memory, permutation
vshl.i8 d0, d1, #3
vshl.i16 d0, d1, #7
vshl.i32 q0, q1, #5
vshl.i64 d0, d1, #13
vshr.s8 d0, d1, #3
vshr.u8 d0, d1, #5
vshr.s16 q0, q1, #9
vshr.u16 d0, d1, #12
vshr.s32 d0, d1, #17
vshr.u32 q0, q1, #25
vshr.s64 d0, d1, #40
vshr.u64 d0, d1, #63
vrshr.s8 d0, d1, #3
vrshr.u8 d0, d1, #5
vrshr.s16 q0, q1, #9
vrshr.u32 d0, d1, #25
vsra.s8 d0, d1, #3
vsra.u16 d0, d1, #12
vrsra.s32 q0, q1, #17
vrsra.u8 d0, d1, #5
vsri.8 d0, d1, #3
vsri.16 q0, q1, #9
vsli.32 d0, d1, #17
vsli.64 q0, q1, #40
vshll.s8 q0, d1, #3
vshll.u8 q0, d1, #5
vshll.s16 q0, d1, #9
vshll.u16 q0, d1, #12
vshll.s32 q0, d1, #17
vshll.u32 q0, d1, #25
vshrn.i16 d0, q1, #3
vshrn.i32 d0, q1, #9
vshrn.i64 d0, q1, #17
vrshrn.i16 d0, q1, #3
vrshrn.i32 d0, q1, #9
vrshrn.i64 d0, q1, #17
vshl.s8 d0, d1, d2
vshl.s16 q0, q1, q2
vshl.u8 d0, d1, d2
vshl.s64 d0, d1, d2
vqshl.s8 d0, d1, d2
vqshl.u16 q0, q1, q2
vqshl.u8 d0, d1, d2
vqrshl.s32 q0, q1, q2
vqrshl.u8 d0, d1, d2
vqshl.s8 d0, d1, #3
vqshl.u16 d0, d1, #5
vqshlu.s16 q0, q1, #7
vqshlu.s32 d0, d1, #9
vqshrn.s16 d0, q1, #3
vqshrn.s32 d0, q1, #9
vqshrn.u16 d0, q1, #3
vqshrun.s16 d0, q1, #3
vqshrun.s32 d0, q1, #9
vqrshrn.s16 d0, q1, #3
vqrshrn.u32 d0, q1, #9
vqrshrun.s16 d0, q1, #3
vqrshrun.s32 d0, q1, #9
vsri.64 q0, q1, #40
vsli.16 d0, d1, #12
vand d0, d1, d2
vand q0, q1, q2
vorr d0, d1, d2
vorr q0, q1, q2
veor d0, d1, d2
veor q0, q1, q2
vbic d0, d1, d2
vbic q0, q1, q2
vorn d0, d1, d2
vorn q0, q1, q2
vbsl q0, q1, q2
vbsl d0, d1, d2
vbit d0, d1, d2
vbit q0, q1, q2
vbif d0, d1, d2
vbif q0, q1, q2
vmvn d0, d1
vmvn q0, q1
vmov.i8 d0, #1
vmov.i8 q0, #0xff
vmov.i16 d0, #1
vmov.i16 d0, #0x100
vmov.i16 q0, #0x80
vmov.i32 d0, #1
vmov.i32 d0, #0x100
vmov.i32 d0, #0x10000
vmov.i32 d0, #0x1000000
vmov.i32 q0, #0xff
vmov.i32 q0, #0x7f
vmov.i64 q0, #0xff000000ff000000
vmov.i64 d0, #0xff00ff00ff00ff00
vmov.i64 q1, #0xff
vmov.i64 d1, #0xffff
vmov.i64 d2, #0xffffffff
vmov.f32 d0, #1.0
vmov.f32 d0, #0.5
vmov.f32 d0, #2.0
vmov.f32 d0, #4.0
vmov.f32 d0, #0.125
vmov.f32 d0, #-1.0
vmov.f32 q0, #1.0
vmov.f32 q0, #0.5
vmov.f32 q0, #-2.0
vmvn.i32 q0, #0xff
vmvn.i32 d0, #0x10000
vdup.8 d0, r1
vdup.16 d0, r1
vdup.32 d0, r1
vdup.8 q0, r1
vdup.16 q0, r1
vdup.32 q0, r1
vdup.8 d0, d1[0]
vdup.8 d0, d1[1]
vdup.16 d0, d1[2]
vdup.16 q0, d1[3]
vdup.32 d0, d1[0]
vdup.32 d0, d1[1]
vdup.32 q0, d1[1]
vdup.32 q0, d2[1]
vmov r0, r1, d2
vmov r2, r3, d4
vmov d2, r0, r1
vmov.32 r0, d1[0]
vmov.32 r0, d1[1]
vmov.32 d1[0], r0
vmov.32 d1[1], r0
vmov.u16 r0, d1[3]
vmov.16 d1[3], r0
vmov.u8 r0, d1[7]
vmov.8 d1[7], r0
vmov.32 r2, d3[1]
vmov.u16 r2, d3[3]
vmov.u8 r2, d3[7]
vmov.u8 r0, d1[7]
vmov.u16 r0, d1[3]
vmov.s8 r0, d1[7]
vmov.s16 r0, d1[3]
vmov.s32 r0, d1[1]
vmov.u32 r0, d1[1]
vmov.u8 r0, d1[0]
vmov.s16 r0, d1[1]
vcvt.s32.f32 q0, q1, #4
vcvt.u32.f32 q0, q1, #4
vcvt.s32.f32 q0, q1
vcvt.u32.f32 q0, q1
vcvt.f32.s32 q0, q1, #4
vcvt.f32.u32 q0, q1, #4
vcvt.f32.s32 q0, q1
vcvt.f32.u32 q0, q1
vcvt.f16.f32 d0, q1
vcvt.f32.f16 q0, d1
vrecpe.u32 d0, d1
vrecpe.u32 q0, q1
vrecps.f32 d0, d1, d2
vrintn.f32 d0, d1
vrintn.f32 q0, q1
vrintp.f32 d0, d1
vrintm.f32 d0, d1
vrintz.f32 d0, d1
vrinta.f32 d0, d1
vrintx.f32 q0, q1
vrintz.f64 d0, d1
vrintn.f64 d0, d1
vsqrt.f64 d0, d1
vabs.f32 s0, s1
vneg.f32 s0, s1
vqmovn.s16 d0, q1
vqmovn.s32 d0, q1
vqmovn.s64 d0, q1
vqmovn.u16 d0, q1
vqmovn.u32 d0, q1
vqmovun.s16 d0, q1
vqmovun.s32 d0, q1
vmovn.i16 d0, q1
vmovn.i32 d0, q1
vmovl.s8 q0, d1
vmovl.s16 q0, d1
vmovl.s32 q0, d1
vmovl.u8 q0, d1
vmovl.u16 q0, d1
vmovl.u32 q0, d1
vtrn.8 d0, d1
vtrn.16 q0, q1
vtrn.32 d0, d1
vtrn.8 q0, q1
vuzp.8 d0, d1
vuzp.16 q0, q1
vuzp.32 d0, d1
vuzp.8 q0, q1
vzip.8 d0, d1
vzip.16 q0, q1
vzip.32 d0, d1
vzip.8 q0, q1
vext.8 d0, d1, d2, #3
vext.16 d0, d1, d2, #2
vext.32 q0, q1, q2, #1
vext.64 q0, q1, q2, #1
vext.8 q0, q1, q2, #5
vtbl.8 d0, {d1}, d2
vtbl.8 d0, {d1, d2}, d3
vtbl.8 d0, {d1, d2, d3}, d4
vtbl.8 d0, {d1, d2, d3, d4}, d5
vtbx.8 d0, {d1}, d2
vtbx.8 d0, {d1, d2, d3}, d4
vtst.8 d0, d1, d2
vtst.16 q0, q1, q2
vtst.32 d0, d1, d2
vld1.8 {d0}, [r0]
vld1.16 {d0}, [r0]
vld1.32 {d0}, [r0]
vld1.64 {d0}, [r0]
vld1.8 {d0, d1}, [r0]
vld1.32 {d0, d1}, [r0]
vld1.64 {d0, d1}, [r0]
vld1.64 {d0, d1, d2, d3}, [r0:128]
vld1.64 {q0}, [r0]
vld1.64 {q0, q1}, [r0:256]
vld1.8 {d0}, [r0:64]
vld1.8 {d0, d1}, [r0:64]
vld1.8 {d0, d1, d2}, [r0:64]
vld1.32 {d0, d1, d2, d3}, [r0:128]
vld1.8 {d0}, [r0], r1
vld1.32 {d0, d1}, [r0], r1
vld1.64 {d0, d1, d2, d3}, [r0], r1
vld1.8 {d0}, [r0]!
vld1.64 {q0, q1}, [r0]!
vld2.8 {d0, d1}, [r0]
vld2.16 {d0, d1}, [r0]
vld2.32 {d0, d1}, [r0]
vld2.8 {d0, d1, d2, d3}, [r0]
vld2.32 {d0, d1, d2, d3}, [r0:64]
vld2.16 {q0, q1}, [r0:128]
vld2.8 {d0, d1}, [r0], r1
vld2.8 {d0, d1}, [r0]!
vld3.8 {d0, d1, d2}, [r0]
vld3.32 {d0, d1, d2}, [r0]
vld3.16 {d0, d1, d2}, [r0]
vld3.8 {d0, d1, d2}, [r0]!
vld4.8 {d0, d1, d2, d3}, [r0]
vld4.16 {d0, d1, d2, d3}, [r0]
vld4.32 {d0, d1, d2, d3}, [r0]
vld4.8 {d0, d1, d2, d3}, [r0:256]
vld4.32 {d0, d1, d2, d3}, [r0]
vld4.8 {d0, d1, d2, d3}, [r0], r1
vld4.32 {d0, d1, d2, d3}, [r0]!
vld1.8 {d0[2]}, [r0]
vld1.16 {d1[3]}, [r0]
vld1.32 {d2[1]}, [r0]
vld1.64 {d0}, [r0]
vld2.8 {d0[1], d1[1]}, [r0]
vld2.16 {d0[2], d1[2]}, [r0]
vld2.32 {d0[1], d1[1]}, [r0]
vld3.8 {d0[1], d1[1], d2[1]}, [r0]
vld3.32 {d0[0], d1[0], d2[0]}, [r0]
vld4.8 {d0[1], d1[1], d2[1], d3[1]}, [r0]
vld4.16 {d0[3], d1[3], d2[3], d3[3]}, [r0]
vld4.32 {d0[0], d1[0], d2[0], d3[0]}, [r0]
vld1.8 {d0[1]}, [r0]!
vld1.32 {d1[0]}, [r0], r2
vld1.16 {d0[3]}, [r0]!
vld1.8 {d0[]}, [r0]
vld1.32 {d0[]}, [r0]
vld2.8 {d0[], d1[]}, [r0]
vld2.32 {d0[], d1[]}, [r0]
vld4.16 {d0[], d1[], d2[], d3[]}, [r0]
vst1.8 {d0}, [r0]
vst1.16 {d0}, [r0]
vst1.32 {d0}, [r0]
vst1.64 {d0}, [r0]
vst1.8 {d0, d1}, [r0]
vst1.32 {d0, d1}, [r0]
vst1.64 {d0, d1}, [r0]
vst1.64 {d0, d1, d2, d3}, [r0:128]
vst1.64 {q0}, [r0]
vst1.64 {q0, q1}, [r0:256]
vst1.8 {d0}, [r0], r1
vst1.32 {d0, d1}, [r0], r1
vst1.8 {d0}, [r0]!
vst1.64 {d0, d1, d2, d3}, [r0]!
vst2.8 {d0, d1}, [r0]
vst2.16 {d0, d1}, [r0]
vst2.32 {d0, d1}, [r0]
vst2.8 {d0, d1, d2, d3}, [r0]
vst2.32 {d0, d1, d2, d3}, [r0:64]
vst2.16 {q0, q1}, [r0:128]
vst2.8 {d0, d1}, [r0], r1
vst2.8 {d0, d1}, [r0]!
vst3.8 {d0, d1, d2}, [r0]
vst3.32 {d0, d1, d2}, [r0]
vst3.8 {d0, d1, d2}, [r0]!
vst4.8 {d0, d1, d2, d3}, [r0]
vst4.16 {d0, d1, d2, d3}, [r0]
vst4.32 {d0, d1, d2, d3}, [r0]
vst4.8 {d0, d1, d2, d3}, [r0:256]
vst4.32 {d0, d1, d2, d3}, [r0]
vst4.8 {d0, d1, d2, d3}, [r0], r1
vst4.32 {d0, d1, d2, d3}, [r0]!
vst1.8 {d0[2]}, [r0]
vst1.16 {d1[3]}, [r0]
vst1.32 {d2[1]}, [r0]
vst2.8 {d0[1], d1[1]}, [r0]
vst2.16 {d0[2], d1[2]}, [r0]
vst2.32 {d0[1], d1[1]}, [r0]
vst3.8 {d0[1], d1[1], d2[1]}, [r0]
vst3.32 {d0[0], d1[0], d2[0]}, [r0]
vst4.8 {d0[1], d1[1], d2[1], d3[1]}, [r0]
vst4.16 {d0[3], d1[3], d2[3], d3[3]}, [r0]
vst4.32 {d0[0], d1[0], d2[0], d3[0]}, [r0]
vst1.8 {d0[1]}, [r0]!
vst1.32 {d1[0]}, [r0], r2
vswp d0, d1
vswp q0, q1
