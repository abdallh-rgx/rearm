use rearm_core::t32::decode::decode_t32;
fn main() {
    // The word reaching decode_t32_32: hw1=0xef01, hw2=0x0802
    // Test with direct function call bypassing the size check
    let hw1: u16 = 0xef01;
    let hw2: u16 = 0x0802;
    println!("hw1 >= 0xE800: {}", hw1 >= 0xE800);
    println!("hw1 >> 8 = {:#x}", hw1 >> 8);
    println!("NEON cond: {}", (hw1 >= 0xEF00 && hw1 < 0xF000) || hw1 >= 0xFF00);
    match decode_t32(hw1, hw2) {
        Ok(t) => println!("→ {} len={}", t.ins.mnemonic(), t.len),
        Err(e) => println!("ERR {}", e),
    }
}
