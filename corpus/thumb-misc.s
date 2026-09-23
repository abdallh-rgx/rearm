// T32 corpus — 16-bit + 32-bit Thumb-2
adds r0, r1, r2
adds r0, r1
subs r0, r1, r2
subs r0, r1, #3
adds r0, #7
subs r0, #7
movs r0, #255
ands r0, r1
eors r0, r1
lsls r0, r1, #2
lsrs r0, r1, #3
asrs r0, r1, #4
adcs r0, r1
sbcs r0, r1
rors r0, r1
tst r0, r1
rsbs r0, r1, #0
cmp r0, r1
cmp r0, #42
cmn r0, r1
movs r1, r8
mov r8, r0
mov.w r0, r1, lsl #3
mov.w r0, r1, lsr #7
mov.w r0, r1, asr #9
mov.w r0, r1, ror #11
movw r0, #0x5678
movt r0, #0x1234
movw r0, #0x5678
mvn r0, r1
mvns r0, r1
add.w r0, r1, r2
add.w r0, r1, r2, lsl #3
add.w r0, r1, r2, lsr #7
add.w r0, r1, r2, asr #9
add.w r0, r1, r2, ror #11
add.w r0, r1, r2, rrx
adds.w r0, r1, r2
adds.w r0, r1, r2, lsl #31
add.w r0, r1, r2
adds.w r0, r1, r2
sub.w r0, r1, r2
subs.w r0, r1, r2
subs.w r0, r1, #16
sbc.w r0, r1, r2
rsb.w r0, r1, #255
and.w r0, r1, r2
ands.w r0, r1, r2, lsl #1
bic.w r0, r1, r2
bics.w r0, r1, r2, lsr #4
eor.w r0, r1, r2
orrs.w r0, r1, r2, asr #3
orr.w r0, r1, r2
orn.w r0, r1, r2
add.w r0, sp, #128
add.w r0, sp, #64
sub.w sp, #96
add sp, #128
sub sp, #96
add r0, sp, #0
mul r0, r1, r2
mul r0, r1, r2
mla r0, r1, r2, r3
mls r0, r1, r2, r3
smull r1, r2, r3, r4
umull r1, r2, r3, r4
smlal r1, r2, r3, r4
umlal r1, r2, r3, r4
sdiv r0, r1, r2
udiv r0, r1, r2
ldr r0, [r1]
ldr r0, [r1, #8]
ldr r0, [r1, #-8]
ldr.w r0, [r1, #1020]
ldr r0, [r1, #4]!
ldr r0, [r1], #4
ldr r0, [r1, r2]
ldr r0, [r1, r2, lsl #2]
ldrb r0, [r1, #3]
ldrh r0, [r1, #6]
ldrsb r0, [r1, #5]
ldrsh r0, [r1, #5]
str r0, [r1, #4]
str r0, [r1, #4]!
str r0, [r1], #4
str r0, [r1, r2, lsl #1]
strb r0, [r1, #3]
strh r0, [r1, #6]
ldrd r2, r3, [r1, #8]
strd r2, r3, [r1, #8]
ldm r0, {r1, r2}
ldm.w r0, {r1-r3, r7, r9}
ldmia r0, {r1, r2}
ldmdb r0, {r1, r2}
ldmia r0!, {r1, r2}
stm r0, {r1, r2}
stmia r0, {r1, r2}
stmdb r0!, {r1, r2}
push {r4, r5, lr}
pop {r4, r5, pc}
push.w {r4-r11}
pop.w {r4-r11}
cbz r0, 8
cbnz r0, 8
cbz r5, 16
it eq
addeq r0, r1, r2
ite eq
addeq r0, r1, r2
subne r0, r1, r2
ittt hi
addhi r0, r1, r2
addhi r3, r4, r5
addhi r6, r7, r8
tbb [r0, r1]
tbh [r0, r1, lsl #1]
ldr r0, [pc, #16]
b 8
b 1024
b 16
beq 8
bne 256
blt 32
bl 1024
bx lr
bx r2
blx r3
tst.w r0, r1, lsl #4
cmp.w r0, #77
cmn.w r0, r1, ror #2
rev r0, r1
rev16 r0, r1
revsh r0, r1
clz r0, r1
rbit r0, r1
sbfx r0, r1, #3, #7
ubfx r0, r1, #3, #7
bfc r0, #3, #7
bfi r0, r1, #3, #7
sxtb r0, r1
sxtb.w r0, r1, ror #8
sxth r2, r3
uxtb r0, r1
uxtb.w r0, r1, ror #16
uxth r2, r3
sxtab r0, r1, r2
uxtah r0, r1, r2
qadd r0, r1, r2
qsub r0, r1, r2
qdadd r0, r1, r2
qdsub r0, r1, r2
sadd16 r0, r1, r2
sasx r0, r1, r2
uadd8 r0, r1, r2
usub16 r0, r1, r2
sel r0, r1, r2
pkhbt r0, r1, r2
pkhtb r0, r1, r2
ssat r0, #7, r1
usat r0, #7, r1
ldrex r0, [r1]
strex r2, r0, [r1]
ldrexb r0, [r1]
strexb r2, r0, [r1]
ldrexh r0, [r1]
strexh r2, r0, [r1]
nop
nop.w
yield
wfe
sev
dmb sy
dsb sy
isb sy
bkpt #12
svc #0
mrs r0, apsr
mrs r0, cpsr
msr apsr_nzcvq, r0
pld [r0]
pli [r0]
smlad r0, r1, r2, r3
smuad r0, r1, r2
usad8 r0, r1, r2
crc32b r0, r1, r2
crc32cb r0, r1, r2
vadd.f32 s0, s1, s2
vsub.f32 s0, s1, s2
vmul.f32 s0, s1, s2
vdiv.f32 s0, s1, s2
vabs.f32 s0, s1
vneg.f32 s0, s1
vsqrt.f32 s0, s1
vcvt.f32.s32 s0, s1
vcvt.s32.f32 s0, s1
vmov s0, r1
vmov r0, s1
vmov.f32 s0, #1.0
vcmp.f32 s0, s1
vldr s0, [r0]
vstr s0, [r0]
vldm r0, {s0-s3}
vstm r0, {s0-s3}
vadd.i8 d0, d1, d2
vadd.i32 q0, q1, q2
vadd.f32 q0, q1, q2
vmul.f32 d0, d1, d2
vsub.i16 q0, q1, q2
vand q0, q1, q2
veor d0, d1, d2
vmov.i32 q0, #0xff
vdup.32 d0, r1
vld1.32 {d0, d1}, [r0]
vst1.32 {d0, d1}, [r0]
vzip.8 d0, d1
vuzp.16 q0, q1
vtrn.32 d0, d1
vext.8 d0, d1, d2, #3
vqadd.s16 q0, q1, q2
vqsub.u8 d0, d1, d2
vceq.i32 d0, d1, d2
vcgt.s8 q0, q1, q2
vshl.i32 q0, q1, #5
vshr.s16 d0, d1, #9
vmax.f32 q0, q1, q2
vmin.f32 d0, d1, d2
vpadd.i16 d0, d1, d2
vmov r0, r1, d2
vmov.32 r0, d1[1]
