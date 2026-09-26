// Synthetic ARM32 (A32) shared-library fixture for `rearm so64`.
//
// Pure hand-written test code — no third-party material. Exercises:
//   * ldrex/strex word loop          (atomic_add32)
//   * ldrexd/strexd pair loop        (atomic_xchg64)
//   * compare-and-swap loop          (atomic_cas32)
//   * byte/halfword exclusives       (atomic_inc8 / atomic_inc16)
//   * a libc import through the PLT  (copy8 -> memcpy) — exercises the
//     loader's dlsym/GOT64 import path, the same path that pulls in the
//     outlined-atomics helpers (fetch_add/swap in loader.rs).
//
// Rebuild (see tests/soemit_atomics.rs for the consumer):
//   llvm-mc --triple=armv7-linux-gnueabi --filetype=obj \
//       -o atomics-fixture.o atomics-fixture.S
//   ld.lld -shared --soname atomics-fixture.so \
//       -o atomics-fixture.so atomics-fixture.o

    .syntax unified
    .arch  armv7-a
    .arm
    .text

// int32_t atomic_add32(volatile int32_t *p, int32_t v) — returns the NEW value
    .globl atomic_add32
    .type  atomic_add32, %function
atomic_add32:
1:  ldrex  r3, [r0]
    add    r3, r3, r1
    strex  r2, r3, [r0]
    cmp    r2, #0
    bne    1b
    mov    r0, r3
    bx     lr

// void atomic_xchg64(void *p, uint64_t desired) — returns old via (r0,r1)
    .globl atomic_xchg64
    .type  atomic_xchg64, %function
atomic_xchg64:
    push   {r4, r5, r6, lr}
1:  ldrexd r4, r5, [r0]
    strexd r6, r2, r3, [r0]
    cmp    r6, #0
    bne    1b
    mov    r0, r4
    mov    r1, r5
    pop    {r4, r5, r6, pc}

// int32_t atomic_cas32(volatile int32_t *p, int32_t expected, int32_t desired)
    .globl atomic_cas32
    .type  atomic_cas32, %function
atomic_cas32:
1:  ldrex  r3, [r0]
    cmp    r3, r1
    bne    2f
    strex  r4, r2, [r0]
    cmp    r4, #0
    bne    1b
2:  mov    r0, r3
    bx     lr

// uint8_t atomic_inc8(volatile uint8_t *p) — returns the new value
    .globl atomic_inc8
    .type  atomic_inc8, %function
atomic_inc8:
1:  ldrexb r3, [r0]
    add    r3, r3, #1
    strexb r2, r3, [r0]
    cmp    r2, #0
    bne    1b
    mov    r0, r3
    bx     lr

// uint16_t atomic_inc16(volatile uint16_t *p) — returns the new value
    .globl atomic_inc16
    .type  atomic_inc16, %function
atomic_inc16:
1:  ldrexh r3, [r0]
    add    r3, r3, #1
    strexh r2, r3, [r0]
    cmp    r2, #0
    bne    1b
    mov    r0, r3
    bx     lr

// void copy8(void *dst, const void *src) — libc import via PLT
    .globl copy8
    .type  copy8, %function
copy8:
    push   {r4, lr}
    mov    r2, #8
    bl     memcpy
    pop    {r4, pc}
