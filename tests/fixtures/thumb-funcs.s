@ rearm-elf test fixture: Thumb-2 function shapes (IT, ADR, literal, BL, CBZ)
.syntax unified
.thumb
.section .text.my_add, "ax"
.global my_add
.type my_add, %function
my_add:
  adds r0, r0, r1
  bx lr

.section .text.my_max, "ax"
.global my_max
.type my_max, %function
my_max:
  cmp r0, r1
  ite hi
  movhi r0, r0
  movls r0, r1
  bx lr

.section .text.my_abs, "ax"
.global my_abs
.type my_abs, %function
my_abs:
  cmp r0, #0
  bge 1f
  rsbs r0, r0, #0
1:
  cbz r2, 2f
  adds r2, r2, #1
2:
  bx lr

.section .text.literal_user, "ax"
.global literal_user
.type literal_user, %function
literal_user:
  ldr r3, .Ltable
  adds r0, r0, r3
  adr r1, my_add
  bl my_helper
  bx lr
  .align 2
.Ltable:
  .word 0x12345678

.section .text.my_helper, "ax"
.global my_helper
.type my_helper, %function
my_helper:
  movs r0, #7
  bx lr
