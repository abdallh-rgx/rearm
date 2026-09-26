// rearm runtime — outlined-atomics helpers (aarch64, ARMv8.0+ LL/SC).
//
// WHY: the embedded Rust loader (runtime/loader.o) uses core::sync::atomic
// (fetch_add / swap / compare_exchange). rustc targets plain armv8-a, so LLVM
// lowers those to calls into the compiler-rt outlined-atomics family:
//
//   iM __aarch64_casM_ORDER (iM expected, iM desired, iM *ptr) -> old
//   iN __aarch64_swpN_ORDER (iN val, iN *ptr)                  -> old
//   iN __aarch64_ldaddN_ORDER(iN val, iN *ptr)                -> old (old + val)
//   iN __aarch64_ldclrN_ORDER(iN val, iN *ptr)                -> old (old & ~val)
//   iN __aarch64_ldeorN_ORDER(iN val, iN *ptr)                -> old (old ^ val)
//   iN __aarch64_ldsetN_ORDER(iN val, iN *ptr)                -> old (old | val)
//
//   M in {1,2,4,8}, ORDER in {relax,acq,rel,acq_rel}
//
// (ABI reference: LLVM docs/Atomics.rst "External libcall names".)
// Neither bionic nor any Android system library exports this family, so a
// translated .so that carries them unresolved fails dlopen with
// "cannot locate symbol __aarch64_cas8_relax". Linking this object into every
// emitted .so makes the output fully self-contained.
//
// Semantics mirror compiler-rt's cas.c / swp.c / ldadd.c:
//   - acquire orderings  -> ldaxr (+ dmb ishld on the CAS early-exit path)
//   - release orderings  -> stlxr
//   - acq_rel            -> ldaxr + stlxr
//   - CAS returns the OLD value and stores DESIRED only when old == expected
//     (the caller infers success by comparing the return with expected).
//
// Register usage (all caller-saved; leaf functions, AAPCS64-clean):
//   old -> x16/w16, new -> x17/w17, stxr status -> w9, cmp/mask in place.
//   x18 (platform register) is never touched.
//
// Symbols are .hidden: resolved at static-link time inside the emitted .so,
// never exported — no dynamic-symbol collisions between sibling libraries.

    .text

// ==================== CAS ====================
// args: w0/x0 = expected, w1/x1 = desired, x2 = ptr; returns old.
// Narrow sizes mask the expected value first: AAPCS64 leaves upper bits of
// sub-word arguments unspecified, and ldxrb/ldxrh zero-extend.
.macro CAS s, o, l, t, rp
    .globl __aarch64_cas\s\()_\o
    .hidden __aarch64_cas\s\()_\o
    .type __aarch64_cas\s\()_\o, %function
__aarch64_cas\s\()_\o\():
    .ifc "\s","1"
    and  w0, w0, #0xff
    .endif
    .ifc "\s","2"
    and  w0, w0, #0xffff
    .endif
1:  \l   \rp\()16, [x2]          // old = exclusive-load(ptr)
    cmp  \rp\()16, \rp\()0
    b.ne 8f
    \t   w9, \rp\()1, [x2]        // exclusive-store(desired, ptr)
    cbnz w9, 1b                   // lost the exclusive -> retry
    mov  \rp\()0, \rp\()16        // return old
    ret
8:  .ifc "\o","acq"
    dmb  ishld
    .endif
    .ifc "\o","acq_rel"
    dmb  ishld
    .endif
    mov  \rp\()0, \rp\()16        // failed comparison: return old
    ret
    .size __aarch64_cas\s\()_\o, . - __aarch64_cas\s\()_\o
.endm

// ==================== SWP ====================
// args: w0/x0 = val, x1 = ptr; returns old.
.macro SWP s, o, l, t, rp
    .globl __aarch64_swp\s\()_\o
    .hidden __aarch64_swp\s\()_\o
    .type __aarch64_swp\s\()_\o, %function
__aarch64_swp\s\()_\o\():
1:  \l   \rp\()16, [x1]           // old
    \t   w9, \rp\()0, [x1]        // new = val
    cbnz w9, 1b
    mov  \rp\()0, \rp\()16
    ret
    .size __aarch64_swp\s\()_\o, . - __aarch64_swp\s\()_\o
.endm

// ==================== fetch-RMW ====================
// args: w0/x0 = val, x1 = ptr; returns old. new = op(old, val).
.macro RMW n, s, o, a, l, t, rp
    .globl __aarch64_\n\s\()_\o
    .hidden __aarch64_\n\s\()_\o
    .type __aarch64_\n\s\()_\o, %function
__aarch64_\n\s\()_\o\():
1:  \l   \rp\()16, [x1]           // old
    \a   \rp\()17, \rp\()16, \rp\()0
    \t   w9, \rp\()17, [x1]
    cbnz w9, 1b
    mov  \rp\()0, \rp\()16
    ret
    .size __aarch64_\n\s\()_\o, . - __aarch64_\n\s\()_\o
.endm

// ==================== CAS: sizes 8 (x) / 4 (w) ====================
CAS 8, relax,   ldxr,  stxr,  x
CAS 8, acq,     ldaxr, stxr,  x
CAS 8, rel,     ldxr,  stlxr, x
CAS 8, acq_rel, ldaxr, stlxr, x
CAS 4, relax,   ldxr,  stxr,  w
CAS 4, acq,     ldaxr, stxr,  w
CAS 4, rel,     ldxr,  stlxr, w
CAS 4, acq_rel, ldaxr, stlxr, w
// ==================== CAS: subword ====================
CAS 2, relax,   ldxrh, stxrh, w
CAS 2, acq,     ldaxrh, stxrh, w
CAS 2, rel,     ldxrh, stlxrh, w
CAS 2, acq_rel, ldaxrh, stlxrh, w
CAS 1, relax,   ldxrb, stxrb, w
CAS 1, acq,     ldaxrb, stxrb, w
CAS 1, rel,     ldxrb, stlxrb, w
CAS 1, acq_rel, ldaxrb, stlxrb, w

// ==================== SWP ====================
SWP 8, relax,   ldxr,  stxr,  x
SWP 8, acq,     ldaxr, stxr,  x
SWP 8, rel,     ldxr,  stlxr, x
SWP 8, acq_rel, ldaxr, stlxr, x
SWP 4, relax,   ldxr,  stxr,  w
SWP 4, acq,     ldaxr, stxr,  w
SWP 4, rel,     ldxr,  stlxr, w
SWP 4, acq_rel, ldaxr, stlxr, w
SWP 2, relax,   ldxrh, stxrh, w
SWP 2, acq,     ldaxrh, stxrh, w
SWP 2, rel,     ldxrh, stlxrh, w
SWP 2, acq_rel, ldaxrh, stlxrh, w
SWP 1, relax,   ldxrb, stxrb, w
SWP 1, acq,     ldaxrb, stxrb, w
SWP 1, rel,     ldxrb, stlxrb, w
SWP 1, acq_rel, ldaxrb, stlxrb, w

// ==================== ldadd ====================
RMW ldadd, 8, relax,   add, ldxr,  stxr,  x
RMW ldadd, 8, acq,     add, ldaxr, stxr,  x
RMW ldadd, 8, rel,     add, ldxr,  stlxr, x
RMW ldadd, 8, acq_rel, add, ldaxr, stlxr, x
RMW ldadd, 4, relax,   add, ldxr,  stxr,  w
RMW ldadd, 4, acq,     add, ldaxr, stxr,  w
RMW ldadd, 4, rel,     add, ldxr,  stlxr, w
RMW ldadd, 4, acq_rel, add, ldaxr, stlxr, w
RMW ldadd, 2, relax,   add, ldxrh, stxrh, w
RMW ldadd, 2, acq,     add, ldaxrh, stxrh, w
RMW ldadd, 2, rel,     add, ldxrh, stlxrh, w
RMW ldadd, 2, acq_rel, add, ldaxrh, stlxrh, w
RMW ldadd, 1, relax,   add, ldxrb, stxrb, w
RMW ldadd, 1, acq,     add, ldaxrb, stxrb, w
RMW ldadd, 1, rel,     add, ldxrb, stlxrb, w
RMW ldadd, 1, acq_rel, add, ldaxrb, stlxrb, w

// ==================== ldclr (old & ~val) ====================
RMW ldclr, 8, relax,   bic, ldxr,  stxr,  x
RMW ldclr, 8, acq,     bic, ldaxr, stxr,  x
RMW ldclr, 8, rel,     bic, ldxr,  stlxr, x
RMW ldclr, 8, acq_rel, bic, ldaxr, stlxr, x
RMW ldclr, 4, relax,   bic, ldxr,  stxr,  w
RMW ldclr, 4, acq,     bic, ldaxr, stxr,  w
RMW ldclr, 4, rel,     bic, ldxr,  stlxr, w
RMW ldclr, 4, acq_rel, bic, ldaxr, stlxr, w
RMW ldclr, 2, relax,   bic, ldxrh, stxrh, w
RMW ldclr, 2, acq,     bic, ldaxrh, stxrh, w
RMW ldclr, 2, rel,     bic, ldxrh, stlxrh, w
RMW ldclr, 2, acq_rel, bic, ldaxrh, stlxrh, w
RMW ldclr, 1, relax,   bic, ldxrb, stxrb, w
RMW ldclr, 1, acq,     bic, ldaxrb, stxrb, w
RMW ldclr, 1, rel,     bic, ldxrb, stlxrb, w
RMW ldclr, 1, acq_rel, bic, ldaxrb, stlxrb, w

// ==================== ldeor (old ^ val) ====================
RMW ldeor, 8, relax,   eor, ldxr,  stxr,  x
RMW ldeor, 8, acq,     eor, ldaxr, stxr,  x
RMW ldeor, 8, rel,     eor, ldxr,  stlxr, x
RMW ldeor, 8, acq_rel, eor, ldaxr, stlxr, x
RMW ldeor, 4, relax,   eor, ldxr,  stxr,  w
RMW ldeor, 4, acq,     eor, ldaxr, stxr,  w
RMW ldeor, 4, rel,     eor, ldxr,  stlxr, w
RMW ldeor, 4, acq_rel, eor, ldaxr, stlxr, w
RMW ldeor, 2, relax,   eor, ldxrh, stxrh, w
RMW ldeor, 2, acq,     eor, ldaxrh, stxrh, w
RMW ldeor, 2, rel,     eor, ldxrh, stlxrh, w
RMW ldeor, 2, acq_rel, eor, ldaxrh, stlxrh, w
RMW ldeor, 1, relax,   eor, ldxrb, stxrb, w
RMW ldeor, 1, acq,     eor, ldaxrb, stxrb, w
RMW ldeor, 1, rel,     eor, ldxrb, stlxrb, w
RMW ldeor, 1, acq_rel, eor, ldaxrb, stlxrb, w

// ==================== ldset (old | val) ====================
RMW ldset, 8, relax,   orr, ldxr,  stxr,  x
RMW ldset, 8, acq,     orr, ldaxr, stxr,  x
RMW ldset, 8, rel,     orr, ldxr,  stlxr, x
RMW ldset, 8, acq_rel, orr, ldaxr, stlxr, x
RMW ldset, 4, relax,   orr, ldxr,  stxr,  w
RMW ldset, 4, acq,     orr, ldaxr, stxr,  w
RMW ldset, 4, rel,     orr, ldxr,  stlxr, w
RMW ldset, 4, acq_rel, orr, ldaxr, stlxr, w
RMW ldset, 2, relax,   orr, ldxrh, stxrh, w
RMW ldset, 2, acq,     orr, ldaxrh, stxrh, w
RMW ldset, 2, rel,     orr, ldxrh, stlxrh, w
RMW ldset, 2, acq_rel, orr, ldaxrh, stlxrh, w
RMW ldset, 1, relax,   orr, ldxrb, stxrb, w
RMW ldset, 1, acq,     orr, ldaxrb, stxrb, w
RMW ldset, 1, rel,     orr, ldxrb, stlxrb, w
RMW ldset, 1, acq_rel, orr, ldaxrb, stlxrb, w
