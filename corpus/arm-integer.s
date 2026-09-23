// A32 integer core — differential corpus
add r0, r1, r2
add r0, r1, r2, lsl #3
add r0, r1, r2, lsr #7
add r0, r1, r2, asr #9
add r0, r1, r2, ror #11
add r0, r1, r2, rrx
adds r0, r1, r2
adds r0, r1, r2, lsl #31
adc r3, r4, r5
adcs r3, r4, r5, asr #2
sub r0, r1, r2
subs r0, r1, #16
sbc r2, r3, r4
sbcs r2, r3, r4, ror #8
rsb r0, r1, #255
rsbs r0, r1, r2, lsl #5
rsc r1, r2, #0x1000
and r0, r1, r2
ands r0, r1, r2, lsl #1
bic r0, r1, r2
bics r0, r1, r2, lsr #4
eor r5, r6, r7
eors r5, r6, r7, asr #3
orr r8, r9, r10
orrs r8, r9, r10, ror #6
mov r0, r1
mov r0, r1, lsl #2
movs r0, r1
movs r0, r1, lsr #31
mov r0, #0x120
movs r0, #255
mvn r2, r3
mvns r2, #0x40
add r0, r1, r2, lsl r7
sub r0, r1, r2, lsr r7
add r0, r1, r2, asr r3
orr r0, r1, r2, ror r4
tst r0, r1
tst r0, r1, lsl #4
tst r0, #3
teq r1, r2, asr #8
cmp r0, r1
cmp r0, #77
cmp r0, r1, lsr #12
cmn r0, r1
cmn r0, r1, ror #2
add r0, pc, #8
sub r0, pc, #4
mov r0, pc
mul r0, r1, r2
muls r0, r1, r2
mla r3, r4, r5, r6
mlas r3, r4, r5, r6
mls r3, r4, r5, r6
smull r1, r2, r3, r4
umull r1, r2, r3, r4
smlal r1, r2, r3, r4
umlal r1, r2, r3, r4
smulls r1, r2, r3, r4
smulbb r0, r1, r2
smulbt r0, r1, r2
smultb r0, r1, r2
smultt r0, r1, r2
smlabb r0, r1, r2, r3
smlabt r0, r1, r2, r3
smlatb r0, r1, r2, r3
smlatt r0, r1, r2, r3
smulwb r0, r1, r2
smulwt r0, r1, r2
smlawb r0, r1, r2, r3
smlawt r0, r1, r2, r3
smuad r0, r1, r2
smuadx r0, r1, r2
smusd r0, r1, r2
smusdx r0, r1, r2
smlad r0, r1, r2, r3
smladx r0, r1, r2, r3
smlsd r0, r1, r2, r3
smlsdx r0, r1, r2, r3
smlald r2, r3, r4, r5
smlaldx r2, r3, r4, r5
smlsld r2, r3, r4, r5
smlsldx r2, r3, r4, r5
sadd16 r0, r1, r2
sadd8 r0, r1, r2
sasx r0, r1, r2
ssax r0, r1, r2
ssub16 r0, r1, r2
ssub8 r0, r1, r2
qadd16 r0, r1, r2
qadd8 r0, r1, r2
qasx r0, r1, r2
qsax r0, r1, r2
qsub16 r0, r1, r2
qsub8 r0, r1, r2
shadd16 r0, r1, r2
shadd8 r0, r1, r2
shasx r0, r1, r2
shsax r0, r1, r2
shsub16 r0, r1, r2
shsub8 r0, r1, r2
uadd16 r0, r1, r2
uadd8 r0, r1, r2
uasx r0, r1, r2
usax r0, r1, r2
usub16 r0, r1, r2
usub8 r0, r1, r2
uqadd16 r0, r1, r2
uqadd8 r0, r1, r2
uqasx r0, r1, r2
uqsax r0, r1, r2
uqsub16 r0, r1, r2
uqsub8 r0, r1, r2
uhadd16 r0, r1, r2
uhadd8 r0, r1, r2
uhasx r0, r1, r2
uhsax r0, r1, r2
uhsub16 r0, r1, r2
uhsub8 r0, r1, r2
pkhbt r0, r1, r2
pkhbt r0, r1, r2, lsl #5
pkhtb r0, r1, r2
pkhtb r0, r1, r2, asr #9
sel r0, r1, r2
usad8 r0, r1, r2
usada8 r0, r1, r2, r3
ssat r0, #7, r1
ssat r0, #7, r1, lsl #4
ssat r0, #31, r1, asr #3
usat r0, #7, r1
usat r0, #7, r1, lsl #4
usat r0, #31, r1, asr #3
ssat16 r0, #7, r1
usat16 r0, #7, r1
qadd r0, r1, r2
qsub r0, r1, r2
qdadd r0, r1, r2
qdsub r0, r1, r2
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
sxtb r0, r1, ror #8
sxth r2, r3
sxtb16 r2, r3
uxtb r0, r1
uxtb r0, r1, ror #16
uxth r2, r3
uxtb16 r2, r3
sxtab r0, r1, r2
sxtab r0, r1, r2, ror #8
sxtah r0, r1, r2
sxtab16 r0, r1, r2
uxtab r0, r1, r2
uxtah r0, r1, r2
uxtab16 r0, r1, r2
sdiv r0, r1, r2
udiv r0, r1, r2
ldr r0, [r1]
ldr r0, [r1, #8]
ldr r0, [r1, #-8]
ldr r0, [r1, #8]!
ldr r0, [r1], #8
ldr r0, [r1], #-8
ldr r0, [r1, r2]
ldr r0, [r1, r2, lsl #2]
ldr r0, [r1, -r2]
str r0, [r1, #4]
str r0, [r1, #4]!
str r0, [r1], #4
str r0, [r1, r2, lsl #1]
ldrb r0, [r1, #3]
strb r0, [r1, #3]
ldrh r0, [r1, #6]
strh r0, [r1, #6]
ldrh r0, [r1, r2]
ldrsb r0, [r1, #5]
ldrsh r0, [r1, #5]
ldrsb r0, [r1, r2]
ldrsh r0, [r1, r2]
ldrd r2, r3, [r1, #8]
strd r2, r3, [r1, #8]
ldrd r2, r3, [r1], #8
ldm r0, {r1, r2}
ldm r0, {r1-r3, r7, r9}
ldmia r0, {r1, r2}
ldmdb r0, {r1, r2}
ldmib r0, {r1, r2}
ldmda r0, {r1, r2}
ldmia r0!, {r1, r2}
stm r0, {r1, r2}
stmia r0, {r1, r2}
stmdb r0!, {r1, r2}
stmib r0, {r1, r2}
stmda r0, {r1, r2}
push {r4-r11}
pop {r4-r11}
ldm r0, {r1, r2, pc}
ldrex r0, [r1]
ldrex r0, [r1]
strexb r1, r0, [r2]
ldrexh r0, [r1]
strexh r1, r0, [r2]
ldrexb r0, [r1]
ldrd r2, r3, [r1, #0]
ldrexd r2, r3, [r1]
strexd r6, r2, r3, [r1]
b #16
bne #8
beq #12
blt #-4
bgt #8
ble #16
bhi #4
bls #8
bge #-12
bl #32
blx #16
bx lr
bx r2
blx r3
svc #0
svc #0x123456
nop
nop.w
yield
wfe
wfi
sev
dmb sy
dsb sy
isb sy
dmb ish
dsb nsh
mrs r0, apsr
mrs r0, cpsr
mrs r0, spsr
msr apsr_nzcvq, r0
msr apsr_g, r0
msr apsr_nzcvqg, r0
msr cpsr_c, r0
msr cpsr_xc, r0
msr cpsr_c, #0x13
msr spsr_fsxc, r0
bkpt #12
pld [r0]
pld [r0, #4]
pld [r1, r2]
pli [r2, #16]
pli [r2, r3, lsl #2]
setend be
setend le
b #4
bne #4
beq #4
ldr r0, [pc, #8]
add r0, pc, #0
