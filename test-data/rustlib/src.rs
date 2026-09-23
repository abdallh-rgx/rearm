// Rich A32/NEON test library: real compiler output
#![no_std]
use core::arch::{asm, global_asm};

#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }

global_asm!(r#"
.arch armv8-a
// integer DSP mix
add r0, r1, r2, lsl #3
mla r4, r5, r6, r7
smull r8, r9, r10, r11
smlad r0, r1, r2, r3
usad8 r4, r5, r6
rev r7, r8
rbit r9, r10
clz r11, r12
ssat r0, #31, r1, asr #3
usat r2, #30, r3
sbfx r4, r5, #3, #7
bfi r6, r7, #3, #7
sxtb r8, r9, ror #8
uxth r10, r11
qadd r12, r0, r1
sadd16 r2, r3, r4
sel r5, r6, r7
pkhbt r8, r9, r10, lsl #5
ldrex r0, [r1]
strexb r2, r0, [r1]
ldm r0, {{r1, r2, r3, r4, r5, r6, r7}}
push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}
pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}
movw r0, #0x5678
movt r0, #0x1234
div_marker:
sdiv r0, r1, r2
udiv r3, r4, r5
bx lr
"#);

#[unsafe(no_mangle)]
pub extern "C" fn rust_int(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b).wrapping_add(a >> 2)
}
