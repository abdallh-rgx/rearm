// rearm runtime v2.1 — payload-resident thunk + adapters + return glue.
// See payload.rs for the header layout and memory model.
//
// RETURN CONVENTION (v2.1.1):
//   Guest entry (trampoline or call_guest) pushes a 256-byte frame on the
//   REAL stack: [F+0]=x29 [F+8]=x30 [F+16..88]=x19..x28 [F+96..]=args, and
//   stores F at [x13+16] of the fake guest frame ([x13]=glue, [x13+8]=real
//   return address). The guest returns via bx lr / pop {..,pc} with the
//   PC value = the glue's low address → thunk miss → br x15 → glue, which
//   restores the caller's callee-saved state from F and pops it. This keeps
//   AAPCS64 intact across the guest (the guest owns x0-x15,x20,x21,x28).

    .text
    .globl rearm_return_glue
    .type rearm_return_glue, %function
rearm_return_glue:
    // x13 = the guest entry-time ARM stack (balanced by the returning guest)
    ldr  x16, [x13, #16]          // F — real-stack frame base
    ldr  x17, [x13, #8]           // real return address (caller's x30)
    ldp  x27, x28, [x16, #80]
    ldp  x25, x26, [x16, #64]
    ldp  x23, x24, [x16, #48]
    ldp  x21, x22, [x16, #32]
    ldp  x19, x20, [x16, #16]
    ldp  x29, x30, [x16]
    add  sp, x16, #256             // pop the trampoline/call_guest frame
    br   x17
    .size rearm_return_glue, . - rearm_return_glue

    .globl rearm_thunk
    .type rearm_thunk, %function
rearm_thunk:
    // invariant: x28 must point at the payload header ("REAR" + count>0)
    movz w19, #0x4552
    movk w19, #0x5241, lsl 16
    ldr  w17, [x28]
    cmp  w17, w19
    b.ne badhdr1
    ldr  w17, [x28, #12]
    cbz  w17, badhdr2
    lsr  x17, x15, #32
    cbnz x17, .Lforeign
    stp  x9, x10, [sp, #-16]!
    ldr  w9,  [x28, #8]           // map_off
    ldr  w17, [x28, #12]          // map_count
    add  x16, x28, x9
    add  x16, x16, #4             // &pairs[0]
    sub  w10, w17, #1             // hi
    mov  w9, #0                    // lo
.Lbs:
    cmp  x9, x10
    b.hi miss
    add  w17, w9, x10
    lsr  w17, w17, #1             // mid
    add  x18, x16, w17, uxtw #3
    ldr  w19, [x18]               // pair.src
    cmp  w15, w19
    b.lo bsleft
    b.hi bsright
    ldr  w17, [x18, #4]           // pair.off
    add  x15, x28, w17, uxtw
    ldp  x9, x10, [sp], #16
    ret
bsleft:
    sub  w10, w17, #1
    b    .Lbs
bsright:
    add  w9, w17, #1
    b    .Lbs
miss:
    ldp  x9, x10, [sp], #16
    ret
.Lforeign:
    mov  x16, x15                  // target
    mov  w15, #1                   // flag: return via x14 (ARM LR)
    b    rearm_foreign_adapter
badhdr1:
    movz x16, #0x0000
    movk x16, #0x0101, lsl 16
    str  x28, [x16]
    brk  #0xBEE1
badhdr2:
    movz x16, #0x0000
    movk x16, #0x0101, lsl 16
    str  x28, [x16]
    brk  #0xBEE2
    .size rearm_thunk, . - rearm_thunk

    .globl rearm_plt_adapter
    .type rearm_plt_adapter, %function
rearm_plt_adapter:
    ldr  w17, [x28, #24]          // got64_off
    add  x17, x17, x15, lsl #3
    ldr  x16, [x28, x17]          // GOT64[idx] = target
rearm_foreign_adapter:
    mov  x17, sp                  // old sp
    sub  x15, x13, #176           // frame below the ARM stack
    bic  x15, x15, #0xf           // 16-align
    mov  sp, x15
    stp  x29, x30, [sp]
    stp  x17, x16, [sp, #16]      // old sp, target
    stp  x4, x5, [sp, #32]
    stp  x6, x7, [sp, #48]
    stp  x8, x9, [sp, #64]
    stp  x10, x11, [sp, #80]
    stp  x12, x13, [sp, #96]
    stp  x14, x15, [sp, #112]     // ARM LR + flag
    stp  x20, x21, [sp, #128]     // APSR.Q / APSR.GE
    stp  x22, x23, [sp, #144]
    ldr  w4, [x13]                // stack args 5..8
    ldr  w5, [x13, #4]
    ldr  w6, [x13, #8]
    ldr  w7, [x13, #12]
    ldr  x16, [sp, #24]           // target
    blr  x16
    lsr  x1, x0, #32              // 64-bit return: r1 = hi32(x0)
    ldp  x29, x30, [sp]
    ldr  x17, [sp, #16]
    ldr  x16, [sp, #24]
    ldp  x4, x5, [sp, #32]
    ldp  x6, x7, [sp, #48]
    ldp  x8, x9, [sp, #64]
    ldp  x10, x11, [sp, #80]
    ldp  x12, x13, [sp, #96]
    ldp  x14, x15, [sp, #112]
    ldp  x20, x21, [sp, #128]
    ldp  x22, x23, [sp, #144]
    mov  sp, x17
    cbz  w15, 1f
    br   x14                       // foreign: return to the ARM LR
1:  ret                            // PLT: return to the translated caller
    .size rearm_plt_adapter, . - rearm_plt_adapter
