// Differential check: translate A32 → A64, dump words for llvm-objdump verification.
use rearm_core::a32::decode::decode_a32;
use rearm_core::a32::ins::Ins;
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;

fn main() {
    // (word, expected A64 text after llvm-objdump)
    let cases: Vec<(u32, &str)> = vec![
        (0xe1bc0f9f, "ldrexd r0, pc, [r12] → ldxp x0, x15, [x12]"),
        (0xe1bc0f91, "ldrexd r0, r1, [r12] → ldxp x0, x1, [x12]"),
        (0xe1ac6f94, "strexd r6, r4, r5, [r12] → stxp w6, x4, x5, [x12]"),
        (0xe7f3305b, "ubfx r3,r11,#0,#20"),
        (0xe7f000f0, "udf #0"),
        (0xe10f0000, "mrs r0, cpsr"),
        (0xe128f00c, "msr cpsr_f, r12"),
        (0xe328f202, "msr cpsr_f, #0x20000000"),
        (0xe1901f9f, "ldrex r1, [r0]"),
        (0xe1801f90, "strex r1, r0, [r0]"),
    ];
    for (w, desc) in cases {
        let ins = match decode_a32(w) {
            Ok(i) => i,
            Err(e) => { println!("{w:08x} DECODE-ERR {e} // {desc}"); continue; }
        };
        let mut out = A64::new();
        match translate_a32(&ins, 0, &mut out) {
            Ok(true) => {
                let words: Vec<String> = out.bytes().chunks_exact(4)
                    .map(|c| format!("{:08x}", u32::from_le_bytes([c[0],c[1],c[2],c[3]])))
                    .collect();
                println!("{} // {}", words.join(" "), desc);
                println!("   IR: {:?}", ins);
            }
            _ => println!("{w:08x} NOT-TRANSLATED ({:?}) // {}", ins, desc),
        }
    }
}
