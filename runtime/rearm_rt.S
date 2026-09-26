// rearm runtime — payload-resident thunk + PLT/foreign adapters (v2).
//
// This blob is embedded at the START of every translated payload (right after
// the 64-byte payload header) and is fully position independent: it addresses
// everything through x28 (= payload base, set by the .so trampolines) and the
// payload header at [x28]. NO external relocations, no adrp patches needed.
//
// Payload header (offsets in bytes from the payload base):
//    0: magic "REARM1\0\0"
//    8: u32 map_off        12: u32 map_count
//   16: u32 reloc_off      20: u32 reloc_count
//   24: u64 shadow_base    (runtime; 4GB-aligned mapping of the source image)
//   32: u32 got64_off      36: u32 n_imports
//   40: u32 init           (source-space DT_INIT, 0 = none)
//   44: u32 init_array     (source-space DT_INIT_ARRAY, 0 = none)
//   48: u32 init_array_sz  (source-space DT_INIT_ARRAYSZ)
//   52: u32 shadow_off     (payload-internal offset of the shadow blob)
//   56: u32 payload_size   60: u32 flags
//
// Memory model ("low world"): the source image (shadow) is mapped at a
// 4GB-aligned address S, so any 32-bit source pointer p has runtime form
// (S + p) whose low32 == p. Pointer classes at runtime (upper 32 bits):
//   0            raw 32-bit source value
//   S>>32        shadow address (data / literal pools / jump tables)
//   B>>32        payload address (translated code, x28-based)
//   anything else  foreign A64 address (libc, trampolines, mmap results)

    .text
    .globl rearm_thunk
    .type rearm_thunk, %function
// x15 in: address in any class.  x15 out: mapped runtime address.
// Preserves everything except x15 and the x16..x19 scratches.
rearm_thunk:
    stp  x9, x10, [sp, #-16]!
    lsr  x17, x15, #32
    asr  x16, x28, #32              // B_hi
    cmp  x17, x16
    b.eq .Ldone                      // payload address: keep as-is
    add  x18, x16, #1
    cmp  x17, x18
    b.eq .Lmap                       // shadow address: w15 == src
    cbnz x17, .Lforeign              // foreign: adapter path
                                       // else: raw 32-bit source value
.Lmap:
    ldr  w9,  [x28, #8]              // map_off
    ldr  w17, [x28, #12]             // map_count
    add  x16, x28, x9                // &count
    add  x16, x16, #4                // &pairs[0]
    sub  w10, w17, #1                // hi = count-1
    mov  w9, #0                      // lo = 0
.Lbs:
    cmp  x9, x10
    b.hi .Lmiss
    add  w17, w9, w10
    lsr  w17, w17, #1                // mid
    add  x18, x16, x17, lsl #3       // &pair[mid]
    ldr  w19, [x18]                  // pair.src
    cmp  w15, w19
    b.lo .Lbs_left
    b.hi .Lbs_right
    ldr  w17, [x18, #4]              // pair.off
    add  x15, x28, w17, uxtw         // x15 = B + off
    ldp  x9, x10, [sp], #16
    ret
.Lbs_left:
    sub  w10, w17, #1
    b    .Lbs
.Lbs_right:
    add  w9, w17, #1
    b    .Lbs
.Lmiss:
    lsr  x18, x15, #32
    ldp  x9, x10, [sp], #16
    cbnz x18, .Lret0                 // shadow input: already correct
    ldr  x16, [x28, #24]             // S
    add  x15, x16, w15, uxtw         // raw input: S + src
.Lret0:
    ret
.Ldone:
    ldp  x9, x10, [sp], #16
    ret
.Lforeign:
    ldp  x9, x10, [sp], #16         // undo the spill: adapter owns the frame
    mov  x16, x15                    // target
    mov  w15, #1                     // flag: return via x14 (ARM LR)
    b    rearm_foreign_adapter
    .size rearm_thunk, . - rearm_thunk

// ==================== PLT / foreign adapter ====================
// Entry A (PLT stub):   w15 = import index; return to x30.
// Entry B (thunk):       x16 = target, w15 = 1; return to x14 (ARM LR).
// Saves every ARM-live register, marshals stack args 5-8 (ARM [x13]) into
// x4-x7 (A64 arg regs), calls the target, restores, splits 64-bit returns.
    .globl rearm_plt_adapter
    .type rearm_plt_adapter, %function
rearm_plt_adapter:
    ldr  w17, [x28, #32]             // got64_off
    add  x17, x17, x15, lsl #3
    ldr  x16, [x28, x17]             // GOT64[idx] = target
rearm_foreign_adapter:
    mov  x17, sp                     // old sp
    sub  x15, x13, #176              // frame below the ARM stack
    bic  x15, x15, #0xf              // 16-align
    mov  sp, x15
    stp  x29, x30, [sp]
    stp  x17, x16, [sp, #16]         // old sp, target
    stp  x4, x5, [sp, #32]
    stp  x6, x7, [sp, #48]
    stp  x8, x9, [sp, #64]
    stp  x10, x11, [sp, #80]
    stp  x12, x13, [sp, #96]
    stp  x14, x15, [sp, #112]         // ARM LR + flag
    stp  x20, x21, [sp, #128]         // APSR.Q / APSR.GE
    stp  x22, x23, [sp, #144]
    ldr  w4, [x13]                    // stack args 5..8
    ldr  w5, [x13, #4]
    ldr  w6, [x13, #8]
    ldr  w7, [x13, #12]
    ldr  x16, [sp, #24]               // target
    blr  x16
    lsr  x1, x0, #32                  // 64-bit return: r1 = hi32(x0)
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
    br   x14                          // foreign: return to the ARM LR
1:  ret                               // PLT: return to the translated caller
    .size rearm_plt_adapter, . - rearm_plt_adapter
