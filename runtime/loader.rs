//! rearm runtime loader — lives inside every emitted .so (compiled once to
//! aarch64 relocatable code with `rustc --emit=obj --crate-type=lib`), linked
//! by `ld.lld -shared` together with the per-library trampolines and payload
//! blob. Runs from the .so's .init_array.
//!
//! Responsibilities:
//!  1. mmap the payload (translated code, RWX) at the build-time code window
//!     (absolute low address C — the payload's baked constants require it).
//!  2. mmap the guest image (shadow) at the guest window W (RW).
//!  3. Apply loader relocations (all pre-based absolute low 32-bit stores).
//!  4. Resolve imports via dlsym: fill GOT64[], and build bridge stubs in
//!     the low world for imported function pointers stored into guest data.
//!  5. Run DT_INIT / DT_INIT_ARRAY through the payload thunk.
//!  6. Provide `rearm_rt_enter` (per-thread low ARM stacks for trampolines)
//!     and low-arena allocators for the malloc-family imports.

#![no_std]
#![allow(clippy::missing_safety_doc)]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================ libc externs ============================

extern "C" {
    fn mmap(addr: u64, len: u64, prot: i32, flags: i32, fd: i32, off: u64) -> i64;
    fn dlsym(handle: *mut u8, name: *const u8) -> *mut u8;
    fn pthread_key_create(key: *mut u32, dtor: extern "C" fn(*mut u8)) -> i32;
    fn pthread_getspecific(key: u32) -> *mut u8;
    fn pthread_setspecific(key: u32, v: *mut u8) -> i32;
}

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_NORESERVE: i32 = 0x4000;
const MAP_FIXED_NOREPLACE: i32 = 0x100000;
const MAP_FAILED: i64 = -1;

// ============================ payload symbols ============================
// Provided by the per-library payload data object (link-time constants).

extern "C" {
    static payload_blob: u8; // payload byte 0 (length via header)
    // .data slot the trampolines read the payload base from (defined in the
    // generated trampolines object — keeps the reference GOT-free).
    static mut payload_base_slot: u64;
}

// ============================ low arena ============================
// [ARENA_BASE, 4 GiB): per-thread ARM stacks + guest-visible heap.
// Reserved once, RW, NORESERVE; committed on touch.

const ARENA_BASE: u64 = 0xC000_0000;
const ARENA_SIZE: u64 = 0x4000_0000;
const STACK_SIZE: u64 = 1 << 20; // 1 MiB per thread
const BRIDGE_BASE: u64 = 0xBF00_0000;
const BRIDGE_MAX: u64 = 0x0100_0000; // 16 MiB of bridge stubs (up to the arena)

static ARENA_NEXT: AtomicU64 = AtomicU64::new(ARENA_BASE + 0x10_000);
static BRIDGE_NEXT: AtomicU64 = AtomicU64::new(0);
static BRIDGE_MAPPED: AtomicU32 = AtomicU32::new(0);
static PTHREAD_KEY: AtomicU32 = AtomicU32::new(0);
static INIT_DONE: AtomicU32 = AtomicU32::new(0);

fn arena_alloc(size: u64, align: u64) -> u64 {
    let mut cur = ARENA_NEXT.load(Ordering::Relaxed);
    loop {
        let aligned = (cur + align - 1) & !(align - 1);
        let next = aligned.wrapping_add(size);
        if next > ARENA_BASE + ARENA_SIZE { return 0; } // out of low memory
        match ARENA_NEXT.compare_exchange_weak(
            cur, next, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => return aligned,
            Err(c) => cur = c,
        }
    }
}

// ============================ payload header ============================

#[repr(C, packed)]
struct Hdr {
    magic: [u8; 8],
    map_off: u32,
    map_count: u32,
    reloc_off: u32,
    reloc_count: u32,
    got64_off: u32,
    n_imports: u32,
    init: u32,
    init_array: u32,
    init_array_sz: u32,
    shadow_off: u32,
    shadow_len: u32,
    payload_size: u32,
    code_base: u32,
    window: u32,
    imports_off: u32,
    imports_len: u32,
}

fn hdr() -> &'static Hdr {
    unsafe { &*(ptr::addr_of!(payload_blob) as *const Hdr) }
}

// ============================ init ============================

#[no_mangle]
pub extern "C" fn rearm_rt_init() {
    if INIT_DONE.swap(1, Ordering::AcqRel) != 0 { return; }

    let h = hdr();
    if h.magic[0..7] != *b"REARM1\0" { die(b"rearm: bad payload magic\n"); }

    let c = h.code_base as u64;
    let w = h.window as u64;
    unsafe { payload_base_slot = c; } // bridges read this during step 3

    // ---- 0. reserve the low arena (stacks + guest heap) ----
    if mmap_exactly(ARENA_BASE, ARENA_SIZE, PROT_READ | PROT_WRITE).is_none() {
        die(b"rearm: arena mmap failed\n");
    }

    // ---- 1. payload (translated code) at C ----
    let pre_shadow = h.shadow_off as u64;
    if mmap_exactly(c, pre_shadow, PROT_READ | PROT_WRITE | PROT_EXEC).is_none() {
        die(b"rearm: code window mmap failed\n");
    }
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::addr_of!(payload_blob) as *const u8, c as *mut u8, pre_shadow as usize,
        );
    }

    // ---- 2. guest image at W (W is far above mmap_min_addr — no skip) ----
    if h.shadow_len > 0 {
        if mmap_exactly(w, h.shadow_len as u64, PROT_READ | PROT_WRITE).is_none() {
            die(b"rearm: guest window mmap failed\n");
        }
        unsafe {
            ptr::copy_nonoverlapping(
                (ptr::addr_of!(payload_blob) as *const u8).add(h.shadow_off as usize),
                w as *mut u8,
                h.shadow_len as usize,
            );
        }
    }

    // ---- 3. relocations (absolute low 32-bit stores) ----
    let base = ptr::addr_of!(payload_blob) as *const u8;
    let n = h.reloc_count as usize;
    for i in 0..n {
        let p = unsafe { base.add(h.reloc_off as usize + i * 12) };
        let (kind, off, aux) = unsafe {
            (ptr::read_unaligned(p as *const u32),
             ptr::read_unaligned(p.add(4) as *const u32),
             ptr::read_unaligned(p.add(8) as *const u32))
        };
        match kind {
            1 => unsafe { ptr::write_volatile(off as *mut u32, aux); },
            2 => {
                if aux != 0xFFFF_FFFF {
                    let b = bridge_for(aux as u64, c);
                    unsafe { ptr::write_volatile(off as *mut u32, b as u32); }
                }
            }
            _ => {}
        }
    }

    // ---- 4. imports: GOT64 (+ name-keyed wrappers) ----
    let nimp = h.n_imports as usize;
    let name_base = unsafe { base.add(h.imports_off as usize) };
    for i in 0..nimp {
        let noff = unsafe { ptr::read_unaligned(name_base.add(4 + i * 4) as *const u32) as usize };
        let name = unsafe {
            let p = name_base.add(4 + nimp * 4 + noff);
            let mut e = 0usize;
            while *p.add(e) != 0 { e += 1; }
            core::slice::from_raw_parts(p, e)
        };
        let mut res = dlsym_default(name);
        // name-keyed low-arena substitution
        match name {
            b"malloc" | b"__libc_malloc" => res = rearm_malloc as *mut u8,
            b"free" | b"__libc_free" => res = rearm_free as *mut u8,
            b"calloc" | b"__libc_calloc" => res = rearm_calloc as *mut u8,
            _ => {}
        }
        unsafe {
            ptr::write_volatile(
                (c + h.got64_off as u64 + (i as u64) * 8) as *mut u64,
                res as u64,
            );
        }
    }

    // ---- 5. pthread key for per-thread low stacks ----
    let mut key: u32 = 0;
    unsafe { pthread_key_create(&mut key, stack_dtor); }
    PTHREAD_KEY.store(key, Ordering::Relaxed);

    // ---- 6. DT_INIT / DT_INIT_ARRAY ----
    if h.init != 0 { call_guest(h.init as u64, c); }
    if h.init_array != 0 && h.init_array_sz > 0 {
        for i in 0..(h.init_array_sz / 4) {
            let f = unsafe {
                ptr::read_volatile((h.init_array as u64 + (i as u64) * 4) as *const u32)
            };
            if f != 0 { call_guest(f as u64, c); }
        }
    }

    // ---- 7. publish the base for the trampolines ----
    unsafe { payload_base_slot = c; }
}

#[panic_handler]
fn panic(_i: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn dlsym_default(name: &[u8]) -> *mut u8 {
    let mut buf = [0u8; 256];
    if name.len() >= 255 { return core::ptr::null_mut(); }
    unsafe { ptr::copy_nonoverlapping(name.as_ptr(), buf.as_mut_ptr(), name.len()); }
    unsafe { dlsym((-1isize) as usize as *mut u8, buf.as_ptr()) } // RTLD_DEFAULT
}

fn mmap_exactly(addr: u64, len: u64, prot: i32) -> Option<u64> {
    let r = unsafe {
        mmap(addr, len, prot,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
             -1, 0)
    };
    if r == MAP_FAILED || r as u64 != addr { None } else { Some(r as u64) }
}

fn die(msg: &[u8]) -> ! {
    unsafe {
        let _ = write2(2, msg);
    }
    unsafe { core::arch::asm!("brk #0xF00D", options(noreturn)); }
}

unsafe fn write2(fd: i32, b: &[u8]) -> i64 {
    let r: i64;
    asm!("svc #0",
         in("x8") 64u64, in("x0") fd as u64,
         in("x1") b.as_ptr(), in("x2") b.len() as u64,
         lateout("x0") r, options(nostack));
    r
}

// ============================ bridges ============================
// 24-byte stub per imported symbol whose address is written into guest data:
//   movz w15, #lo(idx); movk w15, #hi(idx), lsl 16
//   ldr x16, #16 ; br x16 ; .xword adapter
// Enters the payload PLT adapter with w15 = import idx (full AAPCS64
// marshaling; target read from GOT64[idx]).

fn bridge_for(import_idx: u64, _c: u64) -> u64 {
    if BRIDGE_MAPPED.swap(1, Ordering::Relaxed) == 0 {
        if mmap_exactly(BRIDGE_BASE, BRIDGE_MAX, PROT_READ | PROT_WRITE | PROT_EXEC).is_none() {
            die(b"rearm: bridge mmap failed\n");
        }
        BRIDGE_NEXT.store(BRIDGE_BASE, Ordering::Relaxed);
    }
    let b = BRIDGE_NEXT.fetch_add(24, Ordering::Relaxed);
    if b + 24 > BRIDGE_BASE + BRIDGE_MAX { die(b"rearm: bridge overflow\n"); }
    unsafe {
        let lo = (import_idx & 0xFFFF) as u32;
        let hi = (import_idx >> 16) as u32;
        let p = b as *mut u32;
        ptr::write_volatile(p.add(0), 0x5280_0000 | (lo << 5) | 15); // movz w15, #lo
        ptr::write_volatile(p.add(1), 0x72A0_0000 | (hi << 5) | 15); // movk w15, #hi, lsl 16
        ptr::write_volatile(p.add(2), 0x5800_0050);                 // ldr x16, [pc, #16] → literal at +16
        ptr::write_volatile(p.add(3), 0xD61F_0200);                 // br x16
        ptr::write_volatile(p.add(4), 0xD503_201F);                  // nop
        ptr::write_volatile(b as *mut u64, rearm_bridge_tail as u64);
    }
    b
}

/// Naked tail: entered with w15 = import idx (guest stack in x13 intact).
/// Computes the adapter address from the payload header and branches.
#[no_mangle]
pub extern "C" fn rearm_bridge_tail() {
    unsafe {
        let c = payload_base_slot;
        let p = c as *const u8;
        // adapter offset = 128 + offset of rearm_plt_adapter in rearm_rt.o.
        // The rt blob layout is fixed: glue(8) thunk(0x84-8=0x7c bytes?) —
        // hardcoding is fragile; instead locate via the thunk: the adapter
        // follows the thunk blob. Use the KNOWN constant from the build:
        // rt blob = glue(2 words) + thunk + adapter, thunk size fixed at
        // build. We pass it through the payload header? Field 52 is
        // payload_size... use the map: the adapter address equals
        // C + 128 + ADAPTER_OFF where ADAPTER_OFF was encoded in the PLT
        // stubs. Read it from the FIRST PLT stub's b instruction:
        // stub0 = C + 128 + rt_len — unknown. Fallback: scan? No —
        // use the value the build left at payload offset 124 (spare).
        let adapter_off = ptr::read_unaligned(p.add(124) as *const u32);
        let adapter = c + adapter_off as u64;
        asm!("br {0}", in(reg) adapter, options(noreturn));
    }
}

// ============================ per-thread stacks ============================

extern "C" fn stack_dtor(_p: *mut u8) {}

/// Called by every export trampoline with (x0 = current x13, x1 = original
/// x30). Returns the low stack top for this call (the trampoline builds the
/// fake frame). Nested calls descend by 1 MiB.
#[no_mangle]
pub extern "C" fn rearm_rt_enter(x13_in: u64, _x30: u64) -> u64 {
    let key = PTHREAD_KEY.load(Ordering::Relaxed);
    if x13_in >= ARENA_BASE && x13_in < ARENA_BASE + ARENA_SIZE {
        // nested: descend well below the caller's live frames
        return (x13_in & !0xF).saturating_sub(0x10_0000) & !0xF;
    }
    let top = unsafe { pthread_getspecific(key) } as u64;
    if top != 0 { return top; }
    let sp = arena_alloc(STACK_SIZE + 0x10_000, 0x10_000); // 64K-aligned chunk
    if sp == 0 { die(b"rearm: low stack arena exhausted\n"); }
    let base = sp + 0x10_000;
    unsafe { pthread_setspecific(key, base as *mut u8); }
    base
}

// ============================ guest calls ============================

/// Call a translated function by GUEST address (mapped through the payload
/// thunk). Used for DT_INIT / INIT_ARRAY.
fn call_guest(guest_addr: u64, c: u64) {
    unsafe {
        let thunk = c + 136; // 128 header + 8 glue
        let glue = c + 128;
        let sp = rearm_rt_enter(0, 0);
        asm!(
            "stp x29, x30, [sp, #-32]!",
            "mov x28, {c}",
            "mov x13, {sp}",
            "mov x15, {ga}",
            "mov x17, {glue}",
            "str x17, [x13]",
            "adr x17, 2f",
            "str x17, [x13, #8]",
            "blr {thunk}",
            "br x15",
            "2:",
            "ldp x29, x30, [sp], #32",
            c = in(reg) c,
            sp = in(reg) sp,
            ga = in(reg) guest_addr,
            glue = in(reg) glue,
            thunk = in(reg) thunk,
        );
    }
}

// ============================ wrapped imports ============================
// Guest-visible memory comes from the low arena.

#[no_mangle]
pub extern "C" fn rearm_malloc(size: u64) -> *mut u8 {
    let p = arena_alloc(size + 16, 16);
    if p == 0 { return core::ptr::null_mut(); }
    unsafe { ptr::write_volatile(p as *mut u64, size); }
    (p + 16) as *mut u8
}

#[no_mangle]
pub extern "C" fn rearm_free(_p: *mut u8) {
    // v1: arena bump — no reclamation. Documented limitation.
}

#[no_mangle]
pub extern "C" fn rearm_calloc(n: u64, sz: u64) -> *mut u8 {
    let total = n.wrapping_mul(sz);
    let p = rearm_malloc(total);
    if !p.is_null() {
        unsafe { ptr::write_bytes(p, 0, total as usize); }
    }
    p
}
