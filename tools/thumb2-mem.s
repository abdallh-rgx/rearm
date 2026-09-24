.thumb
.syntax unified
// ===== single ldst imm12 / imm8 modes (F8xx) =====
ldr.w r0, [r1]
ldr.w r0, [r1, #0]
ldr.w r0, [r1, #4]
ldr.w r0, [r1, #4095]
ldr.w r0, [r1, #-4]
ldr.w r0, [r1, #-255]
ldr.w r0, [r1, #255]
str.w r0, [r1, #4095]
str.w r0, [r1, #-4095]
str.w r0, [r1, #-1]
ldr.w r0, [r1, #16]!
ldr.w r0, [r1, #-16]!
str.w r0, [r1, #32]!
str.w r0, [r1, #-32]!
ldr.w r0, [r1], #16
ldr.w r0, [r1], #-16
str.w r0, [r1], #24
str.w r0, [r1], #-24
ldrb.w r0, [r1, #255]
ldrb.w r0, [r1, #-255]
strb.w r0, [r1, #31]
strb.w r0, [r1, #-31]
ldrh.w r0, [r1, #63]
ldrh.w r0, [r1, #-63]
strh.w r0, [r1, #1020]
strh.w r0, [r1, #-1020]
ldrsb.w r0, [r1, #31]
ldrsb.w r0, [r1, #-31]
ldrsh.w r0, [r1, #63]
ldrsh.w r0, [r1, #-63]
ldr.w r0, [r1], #4
// unprivileged (T-mode)
ldrt r0, [r1, #4]
strt r0, [r1, #8]
ldrbt r0, [r1, #12]
strbt r0, [r1, #16]
ldrht r0, [r1, #20]
strht r0, [r1, #24]
// register offset
ldr.w r0, [r1, r2]
ldr.w r0, [r1, r2, lsl #2]
ldr.w r0, [r1, r2, lsl #1]
ldrb.w r0, [r1, r2, lsl #1]
ldrh.w r0, [r1, r2]
str.w r0, [r1, r2, lsl #3]
strb.w r0, [r1, r2]
strh.w r0, [r1, r2, lsl #1]
ldrsb.w r0, [r1, r2]
ldrsh.w r0, [r1, r2, lsl #1]
// SP/PC relative
ldr.w r0, [sp, #1020]
ldr.w r0, [pc, #4095]
ldr.w r0, [pc, #-4095]
// ===== LDRD/STRD (E9xx) =====
ldrd r0, r1, [r2]
ldrd r0, r1, [r2, #16]
ldrd r0, r1, [r2, #-1020]
ldrd r0, r1, [r2, #24]!
ldrd r0, r1, [r2, #-24]!
ldrd r0, r1, [r2], #8
ldrd r0, r1, [r2], #-8
strd r0, r1, [r2]
strd r0, r1, [r2, #1020]
strd r0, r1, [r2, #-16]
strd r0, r1, [r2, #32]!
strd r0, r1, [r2, #-32]!
strd r0, r1, [r2], #12
strd r0, r1, [r2], #-12
// ===== LDM/STM (E8xx/E9xx) =====
ldm.w r0, {r1}
ldm.w r0, {r1, r2, r3}
ldm.w r0, {r1-r5, r7}
ldm.w r0!, {r1, r2}
ldmia r0!, {r1, r2, r3}
ldmdb r0, {r1, r2}
ldmdb r0!, {r1, r2}
ldm.w r0, {r1, r2, pc}
stm.w r0, {r1, r2}
stm.w r0!, {r1, r2}
stmia r0!, {r1-r4}
stmdb r0, {r1, r2}
stmdb r0!, {r1, r3, r5}
stm.w r0, {r0, r1}
ldm.w r0!, {r1, r2, pc}
// ===== TBB/TBH =====
tbb [r0, r1]
tbh [r0, r1, lsl #1]
tbb [r1, r2]
tbh [r2, r3, lsl #1]
// ===== exclusives =====
ldrex r0, [r1]
ldrex r0, [r1, #64]
ldrex r0, [r1, #1020]
ldrexb r0, [r1]
ldrexh r0, [r1]
ldrexd r0, r1, [r2]
strex r1, r0, [r2]
strex r1, r0, [r2, #128]
strex r1, r0, [r2, #1020]
strexb r1, r0, [r2]
strexh r1, r0, [r2]
strexd r1, r0, r3, [r2]
// ===== preload =====
pld [r0]
pld [r0, #1024]
pld [r0, #-1024]
pld [r0, r1]
pld [r0, r1, lsl #2]
pldw [r0]
pldw [r0, #256]
pldw [r0, r1, lsl #1]
pli [r0]
pli [r0, #-512]
pli [r0, r1]
