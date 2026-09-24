.thumb
.syntax unified
// T32 branch corpus. No .w suffixes: llvm picks 16-bit when in range; wide
// forms are forced by .space distances beyond the 16-bit ranges (Bcond ±256,
// B ±2046). BL/BLX are always 32-bit.
t0:
	b t0
	b t1
	b t2
	b t3
	beq t0
	bne t1
	bcs t2
	bcc t3
	bmi t0
	bpl t1
	bvs t2
	bvc t3
	bhi t0
	bls t1
	bge t2
	blt t3
	bgt t0
	ble t1
	b t3
t1:
	.space 256
	beq t0
	bne t2
	bl t0
	bl t2
	bl t3
	bl t1
	blx arm0
	b t0
	b t2
t2:
	.space 2048
	bcc t0
	bcs t3
	b t0
	b t3
	bl t3
	bl t0
	blx arm1
	b t1
	bgt t3
t3:
	.space 4096
	b t0
	b t1
	b t2
	b t3
	beq t1
	bl t1
	bl t2
	blx arm0
	bls t2
	bpl t0
	bl t0
	blx arm1
	.space 512
	b t1
	bl t1
	bl t3
	blx arm0
	b t2

.align 2
.arm
arm0:
	nop
arm1:
	nop
