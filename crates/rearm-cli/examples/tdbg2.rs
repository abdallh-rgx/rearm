use rearm_core::t32::decode::decode_t32;
fn main() {
    match decode_t32(0xb020, 0) {
        Ok(t) => println!("ok: {:?} len={}", t.ins.mnemonic(), t.len),
        Err(e) => println!("err: {}", e),
    }
    match decode_t32(0x0088, 0) {
        Ok(t) => println!("ok: {:?} len={}", t.ins.mnemonic(), t.len),
        Err(e) => println!("err: {}", e),
    }
}
