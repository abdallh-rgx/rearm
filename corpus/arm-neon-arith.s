// A32 NEON corpus — arithmetic
vadd.i8 d0, d1, d2
vadd.i16 d0, d1, d2
vadd.i32 d0, d1, d2
vadd.i64 d0, d1, d2
vadd.i8 q0, q1, q2
vadd.i16 q0, q1, q2
vadd.i32 q0, q1, q2
vadd.i64 q0, q1, q2
vadd.f32 d0, d1, d2
vadd.f32 q0, q1, q2
vadd.f64 d0, d1, d2
vsub.i8 d0, d1, d2
vsub.i32 q0, q1, q2
vsub.f32 d0, d1, d2
vsub.f32 q0, q1, q2
vsub.f64 d0, d1, d2
vmul.i8 d0, d1, d2
vmul.i16 q0, q1, q2
vmul.i32 d0, d1, d2
vmul.f32 d0, d1, d2
vmul.f32 q0, q1, q2
vmul.p8 d0, d1, d2
vmul.i16 d0, d1, d2[2]
vmul.i32 q0, q1, d2[1]
vmul.f32 d0, d1, d2[0]
vmul.f32 q0, q1, d2[1]
vmla.i8 d0, d1, d2
vmla.i16 q0, q1, q2
vmla.i32 d0, d1, d2
vmla.f32 d0, d1, d2
vmla.f32 q0, q1, q2
vmls.i16 d0, d1, d2
vmls.f32 q0, q1, q2
vmlal.s8 q0, d1, d2
vmlal.s16 q0, d1, d2
vmlal.s32 q0, d1, d2
vmlal.u8 q0, d1, d2
vmlal.u16 q0, d1, d2
vmlal.u32 q0, d1, d2
vmlsl.s8 q0, d1, d2
vmlsl.s16 q0, d1, d2
vmlsl.s32 q0, d1, d2
vmlsl.u16 q0, d1, d2
vqdmlal.s16 q0, d1, d2
vqdmlal.s32 q0, d1, d2
vqdmlsl.s16 q0, d1, d2
vqdmlsl.s32 q0, d1, d2
vqdmulh.s16 d0, d1, d2
vqdmulh.s32 q0, q1, q2
vqrdmulh.s16 d0, d1, d2
vqrdmulh.s32 q0, q1, q2
vmull.s8 q0, d1, d2
vmull.s16 q0, d1, d2
vmull.s32 q0, d1, d2
vmull.u8 q0, d1, d2
vmull.u16 q0, d1, d2
vmull.u32 q0, d1, d2
vmull.p8 q0, d1, d2
vqdmull.s16 q0, d1, d2
vqdmull.s32 q0, d1, d2
vmull.s16 q0, d1, d2[3]
vqdmull.s32 q0, d1, d2[1]
vfma.f32 d0, d1, d2
vfma.f32 q0, q1, q2
vfms.f32 d0, d1, d2
vfms.f32 q0, q1, q2
vaddw.s8 q0, q1, d2
vaddw.s16 q0, q1, d2
vaddw.s32 q0, q1, d2
vaddw.u8 q0, q1, d2
vaddw.u16 q0, q1, d2
vaddw.u32 q0, q1, d2
vaddl.s8 q0, d1, d2
vaddl.s16 q0, d1, d2
vaddl.s32 q0, d1, d2
vaddl.u8 q0, d1, d2
vaddl.u16 q0, d1, d2
vaddl.u32 q0, d1, d2
vaddhn.i16 d0, q1, q2
vaddhn.i32 d0, q1, q2
vaddhn.i64 d0, q1, q2
vraddhn.i16 d0, q1, q2
vraddhn.i32 d0, q1, q2
vraddhn.i64 d0, q1, q2
vsubw.s16 q0, q1, d2
vsubw.u32 q0, q1, d2
vsubl.s8 q0, d1, d2
vsubl.s16 q0, d1, d2
vsubl.s32 q0, d1, d2
vsubl.u16 q0, d1, d2
vsubl.u32 q0, d1, d2
vsubhn.i16 d0, q1, q2
vsubhn.i32 d0, q1, q2
vsubhn.i64 d0, q1, q2
vrsubhn.i16 d0, q1, q2
vrsubhn.i32 d0, q1, q2
vrsubhn.i64 d0, q1, q2
vhadd.s8 d0, d1, d2
vhadd.s16 q0, q1, q2
vhadd.s32 d0, d1, d2
vhadd.u8 d0, d1, d2
vhadd.u32 q0, q1, q2
vrhadd.s8 d0, d1, d2
vrhadd.s16 q0, q1, q2
vrhadd.u32 d0, d1, d2
vhsub.s8 d0, d1, d2
vhsub.s16 q0, q1, q2
vhsub.s32 d0, d1, d2
vhsub.u8 q0, q1, q2
vabs.s8 d0, d1
vabs.s16 q0, q1
vabs.s32 d0, d1
vabs.f32 d0, d1
vabs.f32 q0, q1
vneg.s8 d0, d1
vneg.s16 q0, q1
vneg.s32 d0, d1
vneg.f32 d0, d1
vneg.f32 q0, q1
vmax.s8 d0, d1, d2
vmax.s16 q0, q1, q2
vmax.s32 d0, d1, d2
vmax.u8 d0, d1, d2
vmax.u16 q0, q1, q2
vmax.u32 d0, d1, d2
vmax.f32 d0, d1, d2
vmax.f32 q0, q1, q2
vmin.s8 d0, d1, d2
vmin.s16 q0, q1, q2
vmin.u32 d0, d1, d2
vmin.f32 d0, d1, d2
vmin.f32 q0, q1, q2
vpmax.s8 d0, d1, d2
vpmax.s16 d0, d1, d2
vpmax.u8 d0, d1, d2
vpmax.u32 d0, d1, d2
vpmax.f32 d0, d1, d2
vpmin.s8 d0, d1, d2
vpmin.s16 d0, d1, d2
vpmin.u8 d0, d1, d2
vpmin.f32 d0, d1, d2
vpadd.i8 d0, d1, d2
vpadd.i16 d0, d1, d2
vpadd.i32 d0, d1, d2
vpadd.f32 d0, d1, d2
vpaddl.s8 d0, d1
vpaddl.s16 d0, d1
vpaddl.s32 q0, q1
vpaddl.u8 q0, q1
vpaddl.u16 q0, q1
vpadal.s8 d0, d1
vpadal.s16 q0, q1
vpadal.s32 q0, q1
vpadal.u8 d0, d1
vpadal.u16 d0, d1
vcgt.s8 d0, d1, d2
vcgt.s16 q0, q1, q2
vcgt.s32 d0, d1, d2
vcgt.u8 q0, q1, q2
vcgt.f32 d0, d1, d2
vcgt.f32 q0, q1, q2
vcge.s8 d0, d1, d2
vcge.s16 q0, q1, q2
vcge.u32 d0, d1, d2
vcge.f32 d0, d1, d2
vceq.i8 d0, d1, d2
vceq.i16 q0, q1, q2
vceq.i32 d0, d1, d2
vceq.f32 q0, q1, q2
vclt.s8 d0, d1, d2
vclt.s16 q0, q1, q2
vclt.f32 d0, d1, d2
vcle.s16 d0, d1, d2
vcle.u32 q0, q1, q2
vclz.i8 d0, d1
vclz.i16 q0, q1
vclz.i32 d0, d1
vcls.s8 d0, d1
vcls.s16 q0, q1
vcls.s32 d0, d1
vcnt.8 d0, d1
vcnt.8 q0, q1
vrecpe.u32 d0, d1
vrecpe.f32 q0, q1
vrecps.f32 d0, d1, d2
vrecps.f32 q0, q1, q2
vrsqrte.u32 d0, d1
vrsqrte.f32 q0, q1
vrsqrts.f32 d0, d1, d2
vrsqrts.f32 q0, q1, q2
vqadd.s8 d0, d1, d2
vqadd.s16 q0, q1, q2
vqadd.s32 d0, d1, d2
vqadd.s64 d0, d1, d2
vqadd.u8 q0, q1, q2
vqadd.u16 d0, d1, d2
vqadd.u32 q0, q1, q2
vqsub.s8 d0, d1, d2
vqsub.s16 q0, q1, q2
vqsub.s32 q0, q1, q2
vqsub.s64 d0, d1, d2
vqsub.u8 d0, d1, d2
vqsub.u32 q0, q1, q2
vqabs.s8 d0, d1
vqabs.s16 q0, q1
vqabs.s32 d0, d1
vqneg.s8 d0, d1
vqneg.s16 q0, q1
vqneg.s32 d0, d1
vmaxnm.f32 d0, d1, d2
vmaxnm.f32 q0, q1, q2
vminnm.f32 d0, d1, d2
vminnm.f32 q0, q1, q2
vmaxnm.f64 d0, d1, d2
vminnm.f64 d0, d1, d2
