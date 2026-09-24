.thumb
.syntax unified
// ===== DP shifted register (EAxx space) =====
and.w r0, r1, r2
and.w r0, r1, r2, lsl #3
ands.w r0, r1, r2, lsr #7
and.w r0, r1, r2, asr #31
and.w r0, r1, r2, ror #8
eor.w r0, r1, r2
eors.w r0, r1, r2, lsl #12
sub.w r0, r1, r2, lsr #1
subs.w r0, r1, r2, asr #24
rsb.w r0, r1, r2, ror #16
rsbs.w r0, r1, r2
add.w r0, r1, r2, lsl #2
adds.w r0, r1, r2, lsr #5
adc.w r0, r1, r2, lsl #9
adcs.w r0, r1, r2
sbc.w r0, r1, r2, lsr #11
sbcs.w r0, r1, r2, asr #4
orr.w r0, r1, r2, ror #3
orrs.w r0, r1, r2, lsl #31
orn.w r0, r1, r2
orns.w r0, r1, r2, lsl #6
bic.w r0, r1, r2
bics.w r0, r1, r2, asr #19
// shifts by register (EA4F)
lsl.w r0, r1, r2
lsr.w r0, r1, r2
asr.w r0, r1, r2
ror.w r0, r1, r2
// MOV reg with shift (EA4F Rd)
mov.w r0, r1, lsl #5
mov.w r0, r1, lsr #13
mov.w r0, r1, asr #2
mov.w r0, r1, ror #27
mvn.w r0, r1, lsl #17
mvns.w r0, r1, lsr #3
rrx r0, r1
// TST/TEQ/CMP/CMN reg
tst.w r0, r1
tst.w r0, r1, lsl #8
teq.w r0, r1, lsr #9
cmp.w r0, r1, asr #7
cmp.w r0, r1, ror #1
cmn.w r0, r1, lsl #30
// ===== DP modified immediate (F04x/F05x) =====
and.w r0, r1, #0xff
and.w r0, r1, #0x100
and.w r0, r1, #0x1200
and.w r0, r1, #0x123000
ands.w r0, r1, #0x01010101
and.w r0, r1, #0x80808080
ands.w r0, r1, #0x9fc
eor.w r0, r1, #0xab0000
eors.w r0, r1, #0x2
sub.w r0, r1, #0x10101010
subs.w r0, r1, #0x81818181
rsb.w r0, r1, #0x55555555
rsbs.w r0, r1, #0x7f800000
add.w r0, r1, #0xc0000000
adds.w r0, r1, #0xf7ffffff
adc.w r0, r1, #0xff000000
adcs.w r0, r1, #0x1fe001fe
sbc.w r0, r1, #0x33000000
sbcs.w r0, r1, #0x1200
orr.w r0, r1, #0x99
orrs.w r0, r1, #0x77777777
orn.w r0, r1, #0x40
orns.w r0, r1, #0x7f8
bic.w r0, r1, #0x50
bics.w r0, r1, #0xdeadbe00
mov.w r0, #0xff
mov.w r0, #0x123400
movs.w r0, #0x81000000
mvn.w r0, #0xff000000
mvns.w r0, #0x42
tst.w r0, #1
teq.w r0, #0x77777777
cmp.w r0, #0x40
cmn.w r0, #0x33000000
// ===== ADD/SUB imm12 / SP =====
add.w r0, r1, #4095
add.w r0, r1, #0xff
add.w r0, r1, #-4095
add.w r0, r1, #-1
add.w r0, r1, #-255
adds.w r0, r1, #0x101
adds.w r0, r1, #-0x101
sub.w r0, r1, #0x7f
subs.w r0, r1, #0x1000
addw r0, r1, #4095
addw r0, r1, #0
subw r0, r1, #4095
subw r0, r1, #1
add.w r0, sp, #0x200
add.w r0, sp, #-0x200
add.w sp, sp, #0x50
add.w sp, sp, #-0x50
sub.w sp, sp, #0x120
add.w r0, r1, #0x1000
add.w r0, r1, #-0x1000
// ===== ADR =====
adr.w r0, here
here:
	adr.w r1, here2
	.space 256
here2:
	// ===== MOVW/MOVT =====
	movw r0, #0x1234
	movw r1, #0xfedc
	movw r2, #0x0056
	movw r3, #0x8001
	movw r4, #0x0f0f
	movw r5, #0xf0f0
	movt r0, #0x5678
	movt r1, #0xabcd
	movt r2, #0x0000
	movt r3, #0xffff
	movt r4, #0x0a0a
	movt r5, #0x5000
	// ===== saturation =====
	ssat r0, #5, r1
	ssat r0, #15, r1, asr #7
	ssat r0, #32, r1, lsl #3
	usat r0, #9, r1
	usat r0, #31, r1, lsl #3
	ssat16 r0, #7, r1
	ssat16 r0, #16, r2
	usat16 r0, #11, r1
	usat16 r0, #15, r3
	// ===== extends with rotation =====
	sxtb.w r0, r1
	sxtb.w r0, r1, ror #8
	sxtb.w r0, r1, ror #16
	sxtb.w r0, r1, ror #24
	sxth.w r0, r1
	sxth.w r0, r1, ror #8
	sxtb16 r0, r1
	sxtb16 r0, r1, ror #8
	sxtb16 r0, r1, ror #16
	sxtb16 r0, r1, ror #24
	uxtb.w r0, r1
	uxtb.w r0, r1, ror #8
	uxth.w r0, r1
	uxth.w r0, r1, ror #16
	uxtb16 r0, r1
	uxtb16 r0, r1, ror #8
	sxtab r0, r1, r2
	sxtab r0, r1, r2, ror #8
	sxtah r0, r1, r2
	sxtah r0, r1, r2, ror #24
	sxtab16 r0, r1, r2
	sxtab16 r0, r1, r2, ror #16
	uxtab r0, r1, r2
	uxtab r0, r1, r2, ror #8
	uxtah r0, r1, r2
	uxtah r0, r1, r2, ror #8
	uxtab16 r0, r1, r2
	uxtab16 r0, r1, r2, ror #8
	// ===== reversal =====
	rev.w r0, r1
	rev16.w r0, r1
	revsh.w r0, r1
	rbit r0, r1
	// ===== parallel (DSP) =====
	sadd16 r0, r1, r2
	sadd8 r0, r1, r2
	sasx r0, r1, r2
	ssub16 r0, r1, r2
	ssub8 r0, r1, r2
	ssax r0, r1, r2
	qadd16 r0, r1, r2
	qadd8 r0, r1, r2
	qasx r0, r1, r2
	qsub16 r0, r1, r2
	qsub8 r0, r1, r2
	qsax r0, r1, r2
	shadd16 r0, r1, r2
	shadd8 r0, r1, r2
	shasx r0, r1, r2
	shsub16 r0, r1, r2
	shsub8 r0, r1, r2
	shsax r0, r1, r2
	uadd16 r0, r1, r2
	uadd8 r0, r1, r2
	uasx r0, r1, r2
	usub16 r0, r1, r2
	usub8 r0, r1, r2
	usax r0, r1, r2
	uqadd16 r0, r1, r2
	uqadd8 r0, r1, r2
	uqasx r0, r1, r2
	uqsub16 r0, r1, r2
	uqsub8 r0, r1, r2
	uqsax r0, r1, r2
	uhadd16 r0, r1, r2
	uhadd8 r0, r1, r2
	uhasx r0, r1, r2
	uhsub16 r0, r1, r2
	uhsub8 r0, r1, r2
	uhsax r0, r1, r2
	// ===== misc 2-source =====
	sel r0, r1, r2
	clz r0, r1
	pkhbt r0, r1, r2
	pkhbt r0, r1, r2, lsl #5
	pkhtb r0, r1, r2
	pkhtb r0, r1, r2, asr #9
	qadd r0, r1, r2
	qsub r0, r1, r2
	qdadd r0, r1, r2
	qdsub r0, r1, r2
	crc32b r0, r1, r2
	crc32h r0, r1, r2
	crc32w r0, r1, r2
	crc32cb r0, r1, r2
	crc32ch r0, r1, r2
	crc32cw r0, r1, r2
	// ===== bitfield =====
	sbfx.w r0, r1, #3, #17
	ubfx.w r0, r1, #8, #8
	bfc.w r0, #5, #10
	bfi.w r0, r1, #2, #21
	// ===== status/system =====
	mrs r0, apsr
	mrs r0, cpsr
	mrs r0, spsr
	msr cpsr_f, r0
	msr apsr_nzcvq, r0
	msr apsr_g, r0
	msr cpsr_fs, r0
	msr spsr_c, r0
	// barriers + hints.w
	dmb sy
	dmb nsh
	dmb oshst
	dsb ish
	dsb nshst
	dsb sy
	isb sy
	isb
	nop.w
	yield.w
	wfe.w
	wfi.w
	sev.w
	// udf.w
	udf.w #0x1234
	udf.w #0xabcd
	// cps
	cpsie i
	cpsid f
	cpsie if
