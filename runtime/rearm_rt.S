// rearm runtime v2.1 — payload-resident thunk + adapters + return glue.
//
// Lives at the start of every translated payload (after the 64-byte header),
// fully position independent: addressed through x28 (= payload base, set by
// the .so trampolines) and the payload header at [x28].
//
// Memory model ("low world"): EVERYTHING the guest can name — translated
// code, the source image (shadow), per-thread ARM stacks, heap, bridge
// stubs — lives below 4 GB as plain 32-bit addresses, exactly like a real
// ARM32 machine. Foreign A64 addresses (libc, ART) are the only values with
// upper bits set; they never flow through 32-bit guest slots (bridge stubs
// handle foreign function pointers stored in guest data).
//
// Payload header (offsets in bytes from the payload base):
//    0: magic "REARM1\0\0"
//    8: u32 map_off       12: u32 map_count
//   16: u32 reloc_off     20: u32 reloc_count
//   24: u32 got64_off     28: u32 n_imports
//   32: u32 init          (rebased guest addr of DT_INIT, 0 = none)
//   36: u32 init_array    (rebased guest addr, 0 = none)
//   40: u32 init_array_sz (byte count)
//   44: u32 shadow_off    (payload-internal offset of the shadow blob)
//   48: u32 shadow_len    (bytes; covers memsz incl. .bss)
//   52: u32 payload_size  (total blob bytes)
//   56: u32 glue_off      (= offset of rearm_return_glue)
//   60: u32 window        (guest-image window base W, absolute low)

    .globl rearm_return_glue
    .type rearm_return_glue, %function
rearm_return_glue:
    ldr  x16, [x13, #8]
    br   x16
    .size rearm_return_glue, . - rearm_return_glue

    .text
    .globl rearm_thunk
    .type rearm_thunk, %function
// x15 in: target address (guest: upper32==0; foreign: upper32!=0).
// x15 out: branchable runtime address.
// Preserves everything except x15 and the x16..x19 scratches.
rearm_thunk:
    // invariant: x28 must point at the payload header ("REAR" + count)
    ldr  w17, [x28]
    cmp  w17, #0x52414552
    b.ne 199f
    ldr  w17, [x28, #12]
    cbz  w17, 199f
    lsr  x17, x15, #32
    cbnz x17, .Lforeign           // foreign A64 address: calling adapter
    stp  x9, x10, [sp, #-16]!
    ldr  w9,  [x28, #8]           // map_off
    ldr  w17, [x28, #12]          // map_count
    add  x16, x28, x9
    add  x16, x16, #4             // &pairs[0]
    sub  w10, w17, #1             // hi
    mov  w9, #0                    // lo
.Lbs:
    cmp  x9, x10
    b.hi .Lmiss
    add  w17, w9, w10
    lsr  w17, w17, #1             // mid
    add  x18, x16, x17, lsl #3    // &pair[mid]
    ldr  w19, [x18]               // pair.src (rebased guest addr)
    cmp  w15, w19
    b.lo .Lbs_left
    b.hi .Lbs_right
    ldr  w17, [x18, #4]           // pair.off (payload offset)
    add  x15, x28, w17, uxtw      // x15 = payload_base + off
    ldp  x9, x10, [sp], #16
    ret
.Lbs_left:
    sub  w10, w17, #1
    b    .Lbs
.Lbs_right:
    add  w9, w17, #1
    b    .Lbs
.Lmiss:
    // Not translated code: keep the guest address (data / undiscovered).
    ldp  x9, x10, [sp], #16
    ret
.Lforeign:
    mov  x16, x15                  // target
    mov  w15, #1                   // flag: return via x14 (ARM LR)
    b    rearm_foreign_adapter
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
