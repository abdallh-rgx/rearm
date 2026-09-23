// A64 corpus — what the translator emits
mov x0, x1
mov w0, w1
movz x0, #0x1234
movz w0, #0x1234, lsl #16
movk x0, #0x5678, lsl #16
movn x2, #5
movn w3, #0x100, lsl #16
add x0, x1, x2
add w0, w1, w2
adds x0, x1, x2
adds w0, w1, w2
sub x0, x1, x2
subs x0, x1, x2
subs wzr, w1, w2
add x0, x1, x2, lsl #3
add x0, x1, x2, lsr #7
add x0, x1, x2, asr #9
add x0, x1, x2, uxtx #3
add x0, x1, x2, lsl #63
add w0, w1, w2, lsr #31
add x0, x1, #4095
add x0, x1, #-4096
sub x0, x1, #1
adds x0, x1, #0
subs x0, x1, x2, lsl #2
negs w0, w1
ngc x0, x1
adc x0, x1, x2
adcs x0, x1, x2
sbcs x0, x1, x2
sbc x0, x1, x2
and x0, x1, x2
and w0, w1, w2
ands x0, x1, x2
ands xzr, x1, x2
eor x0, x1, x2
orr x0, x1, x2
orr x0, xzr, x1
bic x0, x1, x2
bics x0, x1, x2
eon x0, x1, x2
and x0, x1, #0xff
and x0, x1, #0xff00000000
orr w0, w1, #0x7
eor x0, x1, #0xffff
tst x1, #0xf
tst x1, x2, lsl #3
mul x0, x1, x2
mul w0, w1, w2
mneg x0, x1, x2
madd x0, x1, x2, x3
msub x0, x1, x2, x3
smull x0, w1, w2
umull x0, w1, w2
smulh x1, x2, x3
umulh x1, x2, x3
smaddl x0, w1, w2, x3
smsubl x0, w1, w2, x3
umaddl x0, w1, w2, x3
umsubl x0, w1, w2, x3
sdiv x0, x1, x2
udiv x0, x1, x2
sdiv w0, w1, w2
udiv w0, w1, w2
cinc x0, x1, eq
cinv x0, x1, ne
cneg x0, x1, lt
csel x0, x1, x2, eq
csinc x0, x1, x2, mi
csinv x0, x1, x2, pl
csneg x0, x1, x2, vs
cset x0, eq
csetm x0, ne
cset w0, lt
cmp x0, x1
cmn x0, x1
cmp x0, #5
cmn x0, x2, lsl #3
ccmp x0, x1, #0, eq
ccmn x0, x1, #3, ne
ldr x0, [x1]
ldr w0, [x1]
ldr x0, [x1, #8]
ldr x0, [x1, #-256]
ldr x0, [x1, x2]
ldr x0, [x1, x2, lsl #3]
ldur x0, [x1, #-8]
ldrb w0, [x1, #3]
ldrh w0, [x1, #6]
ldrsb x0, [x1]
ldrsh w0, [x1]
ldrsw x0, [x1, #4]
ldurb w0, [x1]
ldurh w0, [x1]
str x0, [x1]
str x0, [x1, #8]!
str x0, [x1], #8
stp x29, x30, [sp, #-16]!
ldp x29, x30, [sp], #16
stp x0, x1, [x1, #16]
ldp x0, x1, [x5, #-16]!
ldpsw x0, x1, [x1]
ldxr w0, [x1]
ldxr x0, [x1]
ldxrb w0, [x1]
ldxrh w0, [x1]
ldxp x0, x1, [x2]
stxr w3, w0, [x1]
stxr w3, x0, [x1]
stxrb w3, w0, [x1]
stxrh w3, w0, [x1]
stxp w3, x0, x1, [x2]
ldaxr w0, [x1]
stlxr w3, w0, [x1]
ldar w0, [x1]
stlr w0, [x1]
ldarb w0, [x1]
stlrb w0, [x1]
b 16
b 1024
b.eq 8
b.ne 256
b.lt -32
b.hi 128
b.ge 64
b.le 32
bl 1024
blr x0
br x1
ret
ret x30
ret x10
cbz x0, 8
cbnz w0, 16
tbz w0, #3, 8
tbnz x0, #5, 16
bfi x0, x1, #3, #7
bfm x0, x1, #3, #7
sbfx x0, x1, #3, #7
ubfx x0, x1, #3, #7
sbfm x0, x1, #3, #7
ubfm x0, x1, #3, #7
sxtb w0, w1
sxtb x0, w1
sxth w0, w1
sxth x0, w1
sxtw x0, w1
uxtb w0, w1
uxth w0, w1
asr x0, x1, #7
lsr x0, x1, #7
lsl x0, x1, #7
asr w0, w1, #15
ror x0, x1, #7
ror w0, w1, #17
extr x0, x1, x2, #7
extr w0, w1, w2, #17
rev x0, x1
rev w0, w1
rev16 x0, x1
rev32 x0, x1
clz x0, x1
clz w0, w1
cls x0, x1
cls w0, w1
rbit x0, x1
rbit w0, w1
sxtl v0.4s, v1.4h
nop
yield
wfe
wfi
sev
sevl
dmb sy
dsb sy
isb
msr daif, x0
msr daifset, #3
mrs x0, daif
msr nzcv, x0
mrs x1, nzcv
svc #0
hvc #0
smc #0
brk #12
msr spsel, #0
add v0.4s, v1.4s, v2.4s
add v0.8h, v1.8h, v2.8h
add v0.16b, v1.16b, v2.16b
sub v0.4s, v1.4s, v2.4s
mul v0.4s, v1.4s, v2.4s
mul v0.8h, v1.8h, v2.8h
and v0.16b, v1.16b, v2.16b
orr v0.16b, v1.16b, v2.16b
eor v0.16b, v1.16b, v2.16b
bic v0.8b, v1.8b, v2.8b
not v0.8b, v1.8b
movi v0.4s, #1
movi v0.4s, #1, lsl #8
movi v0.2d, #0xff
movi v0.16b, #31
movi d0, #0xff
mov v0.16b, v1.16b
mov v0.8b, v1.8b
fmov v0.4s, #1.0
fmov s0, w0
fmov w0, s0
fmov d0, x0
fmov x0, d0
fmov s0, s1
fmov d0, d1
fadd s0, s1, s2
fadd d0, d1, d2
fsub s0, s1, s2
fmul s0, s1, s2
fdiv s0, s1, s2
fsqrt s0, s1
fneg s0, s1
fabs s0, s1
fmadd s0, s1, s2, s3
fmsub s0, s1, s2, s3
fadd v0.4s, v1.4s, v2.4s
fmul v0.2d, v1.2d, v2.2d
fmax s0, s1, s2
fmin d0, d1, d2
fmaxnm s0, s1, s2
fminnm s0, s1, s2
fcmp s0, s1
fcmp s0, #0.0
fcmpe d0, d1
fcsel s0, s1, s2, eq
scvtf s0, w0
scvtf d0, x0
ucvtf s0, w0
ucvtf d0, x0
fcvt d0, s1
fcvt s0, d1
fcvtzs w0, s1
fcvtzu w0, s1
fcvtzs x0, d1
fcvtas w0, s1
fcvtns x0, s1
fcvtps w0, s1
fcvtms w0, s1
fcvtzs w0, s1, #4
scvtf s0, w1, #4
fmov x0, d0
fmov v0.d[1], x0
mov v0.s[0], w1
mov v0.h[3], w1
mov v0.b[7], w1
umov w0, v0.s[1]
umov w0, v0.h[3]
umov w0, v0.b[7]
smov w0, v0.h[3]
ins v0.s[1], w1
ins v0.b[2], v1.b[3]
dup v0.4s, w1
dup v0.8h, w1
dup v0.16b, w1
dup v0.2s, v1.s[1]
dup v0.4h, v1.h[2]
ldr q0, [x0]
str q0, [x0]
ldr d0, [x0]
str d0, [x0]
ldr s0, [x0, #4]
str s0, [x0, #4]
ld1 {v0.16b}, [x0]
ld1 {v0.4s, v1.4s}, [x0]
ld2 {v0.8b, v1.8b}, [x0]
ld3 {v0.16b, v1.16b, v2.16b}, [x0]
ld4 {v0.8h, v1.8h, v2.8h, v3.8h}, [x0]
st1 {v0.16b}, [x0]
st2 {v0.8b, v1.8b}, [x0]
st4 {v0.8h, v1.8h, v2.8h, v3.8h}, [x0]
sqadd v0.16b, v1.16b, v2.16b
sqsub v0.8h, v1.8h, v2.8h
uqadd v0.4s, v1.4s, v2.4s
uqsub v0.16b, v1.16b, v2.16b
sqdmulh v0.8h, v1.8h, v2.8h
sqrshrn v0.8b, v1.8h, #3
shl v0.4s, v1.4s, #3
sshr v0.8h, v1.8h, #5
ushr v0.16b, v1.16b, #7
uzp1 v0.8h, v1.8h, v2.8h
uzp2 v0.8h, v1.8h, v2.8h
zip1 v0.4s, v1.4s, v2.4s
zip2 v0.4s, v1.4s, v2.4s
trn1 v0.16b, v1.16b, v2.16b
trn2 v0.16b, v1.16b, v2.16b
ext v0.16b, v1.16b, v2.16b, #3
cmeq v0.4s, v1.4s, v2.4s
cmgt v0.8h, v1.8h, v2.8h
cmge v0.16b, v1.16b, v2.16b
cmhi v0.4s, v1.4s, v2.4s
cmhs v0.8h, v1.8h, v2.8h
cmtst v0.16b, v1.16b, v2.16b
fcmeq v0.4s, v1.4s, v2.4s
fcmgt v0.4s, v1.4s, v2.4s
fcmge v0.4s, v1.4s, v2.4s
smax v0.4s, v1.4s, v2.4s
smin v0.8h, v1.8h, v2.8h
umax v0.16b, v1.16b, v2.16b
umin v0.4s, v1.4s, v2.4s
smaxv b0, v0.16b
sminv h0, v0.8h
umaxv b0, v0.16b
uminv s0, v0.4s
addp v0.4s, v1.4s, v2.4s
addv b0, v0.16b
addv h0, v0.8h
addv s0, v0.4s
abs v0.8h, v1.8h
neg v0.4s, v1.4s
sqabs v0.16b, v1.16b
sqneg v0.16b, v1.16b
clz v0.4s, v1.4s
cls v0.4s, v1.4s
cnt v0.16b, v1.16b
cmeq v0.4s, v1.4s, #0
cmgt v0.8h, v1.8h, #0
cmge v0.16b, v1.16b, #0
sqshl v0.8h, v1.8h, #3
uqshl v0.4s, v1.4s, #5
sxtl v0.8h, v1.8b
uxtl v0.8h, v1.8b
sqxtn v0.8b, v1.8h
sqxtun v0.8b, v1.8h
ushll v0.8h, v1.8b, #3
sshll v0.4s, v1.4h, #3
ushll v0.4s, v1.4h, #7
shrn v0.8b, v1.8h, #3
rshrn v0.8b, v1.8h, #3
addhn v0.8b, v1.8h, v2.8h
raddhn v0.8b, v1.8h, v2.8h
subhn v0.8b, v1.8h, v2.8h
rsubhn v0.8b, v1.8h, v2.8h
saddl v0.4s, v1.4h, v2.4h
saddl2 v0.4s, v1.8h, v2.8h
uaddl v0.4s, v1.4h, v2.4h
ssubl v0.4s, v1.4h, v2.4h
usubl v0.4s, v1.4h, v2.4h
saddw v0.4s, v1.4s, v2.4h
uaddw v0.4s, v1.4s, v2.4h
ssubw v0.4s, v1.4s, v2.4h
smull v0.4s, v1.4h, v2.4h
umull v0.4s, v1.4h, v2.4h
smull2 v0.4s, v1.8h, v2.8h
sqdmull v0.4s, v1.4h, v2.4h
sqdmlal v0.4s, v1.4h, v2.4h
sqdmlsl v0.4s, v1.4h, v2.4h
pmull v0.8h, v1.8b, v2.8b
mla v0.4s, v1.4s, v2.4s
mls v0.4s, v1.4s, v2.4s
frintn v0.4s, v1.4s
frintp v0.4s, v1.4s
frintm v0.4s, v1.4s
frintz v0.4s, v1.4s
frinta v0.4s, v1.4s
frintx v0.4s, v1.4s
frinti v0.4s, v1.4s
fcvtns v0.4s, v1.4s
fcvtzs v0.4s, v1.4s
scvtf v0.4s, v1.4s
ucvtf v0.4s, v1.4s
tbl v0.16b, {v1.16b, v2.16b}, v3.16b
tbx v0.16b, {v1.16b}, v2.16b
sshr v0.2s, v1.2s, #3
add v0.2s, v1.2s, v2.2s
ld1r {v0.4s}, [x0]
ld2r {v0.4s, v1.4s}, [x0]
ld4r {v0.8b, v1.8b, v2.8b, v3.8b}, [x0]
