.thumb
.syntax unified
// T3 Bcc.W + T4 B.W + T1 BL + T2 BLX at assorted distances (bit coverage).
t0:
	b.w t0
	b.w t1
	b.w t2
	b.w t3
	b.w t0
	beq.w t0
	bne.w t1
	bcs.w t2
	bcc.w t3
	bmi.w t0
	bpl.w t1
	bvs.w t2
	bvc.w t3
	bhi.w t0
	bls.w t1
	bge.w t2
	blt.w t3
	bgt.w t0
	ble.w t1
	b.w t3
t1:
	.space 64
	beq.w t0
	bne.w t2
	bl t0
	bl t2
	bl t3
	bl t1
	blx arm0
	b.w t0
	b.w t2
t2:
	.space 1024
	bcc.w t0
	bcs.w t3
	b.w t0
	b.w t3
	bl t3
	bl t0
	blx arm1
	b.w t1
	bgt.w t3
t3:
	.space 4096
	b.w t0
	b.w t1
	b.w t2
	b.w t3
	beq.w t1
	bl t1
	bl t2
	blx arm0
	bls.w t2
	bpl.w t0
	bl t0
	blx arm1
	.space 512
	b.w t1
	bl t1
	bl t3
	blx arm0
	b.w t2

.align 2
.arm
arm0:
	nop
arm1:
	nop
