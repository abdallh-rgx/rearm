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
//!  4. Resolve imports via dlsym: fill GOT64[], and build bridge stubs in the
//!     low world for imported function pointers stored into guest data.
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
    fn pthread_self() -> u64;
    fn pthread_create(
        t: *mut u64, a: *mut u8,
        start: extern "C" fn(*mut u8) -> *mut u8,
        arg: *mut u8,
    ) -> i32;
    fn pthread_join(t: u64, rv: *mut *mut u8) -> i32;
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
}

// .data slot the trampolines read the payload base from.
#[no_mangle]
pub static mut payload_base_slot: u64 = 0;

// ============================ low arena ============================
// [ARENA_BASE, 4 GiB): per-thread ARM stacks + guest-visible heap. Reserved
// once, RW, NORESERVE; committed on touch.

const ARENA_BASE: u64 = 0xC000_0000;
const ARENA_SIZE: u64 = 0x4000_0000;
const STACK_SIZE: u64 = 1 << 20; // 1 MiB per thread
const BRIDGE_BASE: u64 = 0xBF00_0000;
const BRIDGE_MAX: u64 = 0x1000_0000; // 16 MiB of bridge stubs

static ARENA_NEXT: AtomicU64 = AtomicU64::new(ARENA_BASE + 0x1000);
static BRIDGE_NEXT: AtomicU64 = AtomicU64::new(BRIDGE_BASE);
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
    if &h.magic != b"REARM1\0" { die(b"rearm: bad payload magic\n"); }

    let c = h.code_base as u64;
    let w = h.window as u64;

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

    // ---- 2. guest image at W (skip the null-guard page(s) below 0x8000) ----
    if h.shadow_len > 0x8000 {
        let len = (h.shadow_len - 0x8000) as u64;
        if mmap_exactly(w + 0x8000, len, PROT_READ | PROT_WRITE).is_none() {
            die(b"rearm: guest window mmap failed\n");
        }
        unsafe {
            ptr::copy_nonoverlapping(
                (ptr::addr_of!(payload_blob) as *const u8).add(h.shadow_off as usize + 0x8000),
                (w + 0x8000) as *mut u8,
                len as usize,
            );
        }
    }

    // ---- 3. relocations ----
    let n = h.reloc_count as usize;
    for i in 0..n {
        let r = unsafe {
            let p = (ptr::addr_of!(payload_blob) as *const u8).add(h.reloc_off as usize + i * 12);
            (ptr::read_unaligned(p as *const u32),
             ptr::read_unaligned(p.add(4) as *const u32),
             ptr::read_unaligned(p.add(8) as *const u32))
        };
        match r.0 {
            1 => unsafe { ptr::write_volatile(r.1 as *mut u32, r.2); }, // MAP32: slot = W+addend
            2 => {
                // import slot: bridge stub so guest code can call it
                if r.2 != 0xFFFF_FFFF {
                    let b = bridge_for(r.2);
                    unsafe { ptr::write_volatile(r.1 as *mut u32, b as u32); }
                }
            }
            _ => {}
        }
    }

    // ---- 4. imports: GOT64 + bridges ----
    let nimp = h.n_imports as usize;
    let name_base = unsafe {
        (ptr::addr_of!(payload_blob) as *const u8).add(h.imports_off as usize)
    };
    for i in 0..nimp {
        let noff = unsafe {
            ptr::read_unaligned(name_base.add(4 + i * 4) as *const u32) as usize
        };
        let name = unsafe {
            let p = name_base.add(noff);
            let mut e = 0usize;
            while *p.add(e) != 0 { e += 1; }
            core::slice::from_raw_parts(p, e)
        };
        let res = unsafe { dlsham(name) };
        unsafe {
            ptr::write_volatile(
                (c + h.got64_off as u64 + (i as u64) * 8) as *mut u64,
                res as u64,
            );
        }
        let _ = res;
    }

    // ---- 5. pthread key for per-thread low stacks ----
    let mut key: u32 = 0;
    unsafe { pthread_key_create(&mut key, stack_dtor); }
    PTHREAD_KEY.store(key, Ordering::Relaxed);

    // ---- 6. DT_INIT / DT_INIT_ARRAY ----
    if h.init != 0 { call_guest(h.init as u64); }
    if h.init_array != 0 && h.init_array_sz > 0 {
        for i in 0..(h.init_array_sz / 4) {
            let f = unsafe {
                ptr::read_volatile((w + h.init_array as u64 + (i as u64) * 4) as *const u32)
            };
            if f != 0 { call_guest(f as u64); }
        }
    }

    // ---- 7. publish the base for the trampolines ----
    unsafe { payload_base_slot = c; }
}

fn dlsham(name: &[u8]) -> *mut u8 {
    // NUL-terminate into a stack buffer (names are short).
    let mut buf = [0u8; 256];
    if name.len() >= 255 { return core::ptr::null_mut(); }
    buf[..name.len()].copy_from_slice(name);
    unsafe { dlsham_call(buf.as_ptr()) }
}

unsafe fn dlsham_call(p: *const u8) -> *mut u8 {
    dlsym((-1isize) as usize as *mut u8, p) // RTLD_DEFAULT
}

fn mmap_exactly(addr: u64, len: u64, prot: i32) -> Option<u64> {
    let r = unsafe {
        mmap(addr, len, prot,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
             -1, 0)
    };
    if r == MAP_FAILED { None } else { Some(r as u64) }
}

fn die(msg: &[u8]) -> ! {
    unsafe {
        let _ = write2(2, msg);
        let _ = write2(2, b"\n");
    }
    core::arch::asm!("brk #0xF00D", options(noreturn));
}

unsafe fn write2(fd: i32, b: &[u8]) -> i64 {
    let r: i64;
    asm!("svc #0", inlateout("x8") 64u64 => _, in("x0") fd as u64,
         in("x1") b.as_ptr(), in("x2") b.len() as u64, lateout("x0") r);
    r
}

// ============================ bridges ============================
// One 16-byte stub per imported symbol whose address is written into guest
// data: `ldr x16, #8; br x16; .xword plt_stub`.
// The bridge enters the PLT stub which sets w15=idx and jumps to the adapter.

fn bridge_for(import_idx: u32) -> u64 {
    let h = hdr();
    let c = h.code_base as u64;
    // PLT stub address = C + 128 + rt_len + idx*12 — rt_len is not in the
    // header; use the thunk: bridge = movz/movk w15 + ldr/br via GOT64.
    // Simpler and layout-independent: load target directly from GOT64.
    let _ = c;
    let slot = c + h.got64_off as u64 + (import_idx as u64) * 8;
    let b = BRIDGE_NEXT.fetch_add(16, Ordering::Relaxed);
    if b + 16 > BRIDGE_BASE + BRIDGE_MAX { die(b"rearm: bridge overflow\n"); }
    if BRIDGE_NEXT.load(Ordering::Relaxed) == BRIDGE_BASE + 16 {
        // first bridge: make the bridge region executable+writable
        if mmap_exactly(BRIDGE_BASE, BRIDGE_MAX, PROT_READ | PROT_WRITE | PROT_EXEC).is_none() {
            die(b"rearm: bridge mmap failed\n");
        }
        BRIDGE_NEXT.store(BRIDGE_BASE + 0x1000, Ordering::Relaxed);
        return bridge_inner(b, slot);
    }
    bridge_inner(b, slot)
}

fn bridge_inner(b: u64, got_slot: u64) -> u64 {
    // ldr x16, #12 ; br x16 ; pad ; .xword <got slot address>
    // The stub loads the TARGET ADDRESS VALUE indirectly? No — it loads the
    // got SLOT ADDRESS and dereferences it, because the slot value changes
    // at load time. Instead: load the slot address once and deref:
    //   ldr x16, #20      ; x16 = &got_slot
    //   ldr x17, [x16]    ; x17 = target
    //   br x17
    //   .xword got_slot
    unsafe {
        let p = b as *mut u32;
        // ldr x16, #20  (pc-relative literal at +20)
        ptr::write_volatile(p, 0x5800_0A50u32 | ((20u32 / 4) << 5) as u32 & 0);
    }
    // Encoding ldr x16, label: 0x58 | imm19 — compute directly below instead.
    unsafe {
        let p = b as *mut u32;
        let imm19: u32 = 20 / 4; // word offset from this instruction
        ptr::write_volatile(p.add(0), 0x5800_0000 | (imm19 << 5) | 16); // ldr x16, [pc, #20]
        ptr::write_volatile(p.add(1), 0xF940_0211);                   // ldr x17, [x16]
        ptr::write_volatile(p.add(2), 0xD61F_0220);                    // br x17
        ptr::write_volatile(p.add(3), 0xD503_201F);                    // nop (pad)
        ptr::write_volatile(b as *mut u64, got_slot);                   // literal
    }
    b
}

// ============================ per-thread stacks ============================

extern "C" fn stack_dtor(_p: *mut u8) {}

/// Called by every export trampoline with (x0 = current x13, x1 = original
/// x30). Returns the low stack top for this call (fake frame at [x13..x13+16]
/// is built by the caller). Nested calls descend by 64 KiB.
#[no_mangle]
pub extern "C" fn rearm_rt_enter(x13_in: u64, _x30: u64) -> u64 {
    let key = PTHREAD_KEY.load(Ordering::Relaxed);
    if x13_in >= ARENA_BASE && x13_in < ARENA_BASE + ARENA_SIZE {
        // nested: the caller's ARM sp — descend well below its live frames
        return (x13_in & !0xF).saturating_sub(0x10_0000) & !0xF;
    }
    let top = unsafe { pthread_getspecific(key) } as u64;
    if top != 0 { return top; }
    let sp = arena_alloc(STACK_SIZE + 0x1000, 0x10_000); // 64K-aligned chunk
    if sp == 0 { die(b"rearm: low stack arena exhausted\n"); }
    let base = sp + 0x1000; // skip the guard page region
    unsafe { pthread_setspecific(key, base as *mut u8); }
    base
}

// ============================ guest calls ============================

/// Call a translated function by GUEST address (mapped through the payload
/// thunk). Used for DT_INIT / INIT_ARRAY.
fn call_guest(guest_addr: u64) {
    unsafe {
        let c = hdr().code_base as u64;
        let thunk = c + 136; // thunk_off: 128 + glue(8)
        let sp = rearm_rt_enter(0, 0);
        // [sp] = glue, [sp+8] = rearm_guest_ret
        let glue = c + 128;
        ptr::write_volatile(sp as *mut u64, glue);
        ptr::write_volatile((sp + 8) as *mut u64, rearm_guest_ret as u64);
        asm!(
            "blr {thunk}",          // x15 = mapped address
            in("x15") guest_addr as u64,
            in("x28") c,
            thunk = in(reg) thunk,
        );
        // set up the fake frame and call
        asm!(
            "mov x13, {sp}",
            "ldr x14, =rearm_guest_ret_thunk",
            "br x15",
            sp = in(reg) sp,
        );
    }
}

#[no_mangle]
extern "C" fn rearm_guest_ret() {}

// ============================ wrapped imports ============================
// Name-keyed import substitution: guest-visible memory comes from the low
// arena. (Currently pass-through for everything; extend as needed.)

#[no_mangle]
pub extern "C" fn rearm_malloc(size: u64) -> *mut u8 {
    let p = arena_alloc(size + 16, 16);
    if p == 0 { return core::ptr::null_mut(); }
    unsafe {
        ptr::write_volatile(p as *mut u64, size);
    }
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
