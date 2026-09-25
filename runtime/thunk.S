// rearm payload thunk — source-address → payload-address mapper.
//
// Input:  w15 = source-space address (original 32-bit vaddr).
// Output: w15 = runtime address (payload base + mapped offset).
//
// The payload code map (sorted u32 (src, payload_off) pairs) lives at
// __REARM_MAP__ (payload offset, patched at build time); misses fall back to
// the shadow image at __REARM_SHADOW__ + src (data identity).
//
// Register contract: preserves EVERYTHING except w15 (in/out) and the
// translator scratches x16/x17/x18/x19 (dead at every call site — the thunk
// is only called from self-contained materialization sequences). x9/x10
// (A32 callee-saved r9/r10) are spilled to the stack. x28 = payload base.
//
// Assembled with: llvm-mc --triple=aarch64-linux-gnu --filetype=obj
// The .o's relocations against __REARM_MAP__/__REARM_SHADOW__ are applied
// by the payload builder (adrp imm21 + add imm12 patching).

    .text
    .globl rearm_thunk
    .type rearm_thunk, %function
rearm_thunk:
    adrp x16, __REARM_MAP__
    add  x16, x16, :lo12:__REARM_MAP__
    ldr  w17, [x16], #4            // w17 = count, x16 = pairs
    stp  x9, x10, [sp, #-16]!
    mov  w9, #0                    // lo
    sub  w10, w17, #1              // hi
.Lsearch:
    cmp  x9, x10
    b.hi .Lmiss                    // lo > hi → data path
    add  w17, w9, w10
    lsr  w17, w17, #1              // mid
    add  x17, x16, x17, lsl #3     // &pair[mid]
    ldr  w18, [x17]                // pair.src
    ldr  w19, [x17, #4]            // pair.dst
    cmp  w15, w18
    b.lo .Lleft                    // target < src
    b.hi .Lright                    // target > src
    // hit: payload offset → runtime address
    add  x15, x28, w19, uxtw
    ldp  x9, x10, [sp], #16
    ret
.Lleft:
    sub  w10, w17, #1              // hi = mid-1
    b    .Lsearch
.Lright:
    add  w9, w17, #1               // lo = mid+1
    b    .Lsearch
.Lmiss:
    adrp x16, __REARM_SHADOW__
    add  x16, x16, :lo12:__REARM_SHADOW__
    add  x15, x16, w15, uxtw       // shadow base + src
    ldp  x9, x10, [sp], #16
    ret
    .size rearm_thunk, . - rearm_thunk
