//! Execution-bias support for payload translation (rearm-elf v2).
//!
//! The corpus/Z3 mode of the translators materializes PC-derived values as
//! **source-space constants** — correct for symbolic verification, wrong for
//! execution. Payload mode ("bias") instead emits base-relative code:
//!
//! * Every source address `V` has a *payload offset*: code is re-laid-out,
//!   data (the "shadow image") keeps the original layout at `SHADOW_OFF + V`.
//! * The payload is mapped at a 4 KiB-aligned low base, so `adrp/add` with
//!   build-time page deltas is exact and needs **no runtime relocation**.
//! * Address-taking of code goes through the source→payload *code map*
//! (resolved statically by the driver where possible, otherwise by the
//!   runtime thunk that binary-searches the map table in the payload).

use crate::a64::encode::{A64, XR};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// `BIAS` — payload (execution) mode switch. `false` = const/verify mode.
pub static BIAS: AtomicBool = AtomicBool::new(false);
/// Guest-image window base W (absolute low-32 address where the source
/// image is mapped at runtime). All guest-space values are W + relative.
pub static W: AtomicU32 = AtomicU32::new(0);
/// Payload offset of the runtime code-map thunk entry, in bytes.
pub static THUNK: AtomicU32 = AtomicU32::new(0);

#[inline]
pub fn bias_on() -> bool { BIAS.load(Ordering::Relaxed) }
#[inline]
pub fn window() -> u32 { W.load(Ordering::Relaxed) }
#[inline]
pub fn thunk_off() -> u32 { THUNK.load(Ordering::Relaxed) }

/// `Xd = base + payload_offset` — adrp (+ add when lo12 ≠ 0).
///
/// `payload_offset` must be the offset within the translated code+shadow
/// image; the runtime base is 4 KiB-aligned so the adrp page delta is a
/// build-time constant (base cancels: page(B+T) − page(B+H) = page(T)−page(H)).
pub fn bias_addr(out: &mut A64, dst: XR, payload_off: u32) {
    let here = (out.len() * 4) as i64;
    let tgt = payload_off as i64;
    let dp = (((tgt & !0xFFF) - (here & !0xFFF)) >> 12) as i32;
    out.adrp(dst, dp);
    if payload_off & 0xFFF != 0 {
        out.add_imm(true, dst, dst, (payload_off & 0xFFF) as u16);
    }
}

/// `Xd = W + src_vaddr` — address of a source-space location (literal pools,
/// jump tables, PC reads) as an absolute low-world constant. The guest
/// image lives below 4 GB at a build-time window, so this is a plain
/// `movz/movk` — no base register, no adrp range limits, position-free.
pub fn bias_src(out: &mut A64, dst: XR, src: u32) {
    let v = window().wrapping_add(src);
    if v < 0x10000 {
        out.movz(true, 0, v as u16, dst);
    } else {
        out.movz(true, 0, (v & 0xFFFF) as u16, dst);
        out.movk(true, 1, (v >> 16) as u16, dst);
    }
}

/// `LDR Wrt, [W + src]` — load a (possibly relocated) word from the guest
/// image, e.g. a literal-pool entry. In const mode falls back to nothing
/// (the caller folds the constant instead).
#[inline]
pub fn bias_ldr_word(out: &mut A64, rt: XR, src: u32) {
    bias_src(out, 16, src);
    out.ldst_uimm(2, 1, 0, 16, rt); // ldr w(rt), [x16]
}

/// Load a 64-bit payload-relative address that is only known at run time in
/// **w15** into x17 (thunk/bridge helpers): `x17 = base + w15`.
pub fn bias_dyn_addr(out: &mut A64, scratch: XR) {
    // x(scratch) = base(=x28) + w15 : add x17, x28, w15, uxtw
    out.addsub_ext(true, 0, false, 15, 2, 0, 28, scratch);
}

/// Call the payload code-map thunk with the source-space address in **w15**
/// (overwritten with the mapped runtime address): `w15 = base + map(w15)`.
/// Used by TBB/TBH and any dynamic code-address the driver cannot resolve
/// statically. Clobbers x16/x17 only (safe at self-contained materialization
/// sites).
pub fn emit_thunk_call(out: &mut A64) {
    bias_addr(out, 17, thunk_off());
    out.blr(17);
}
