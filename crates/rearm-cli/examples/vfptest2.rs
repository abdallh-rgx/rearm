use rearm_core::a32::decode::decode_a32;
fn main() {
    match decode_a32(0xf2010802) {
        Ok(ins) => println!("f2010802 → {}", ins.mnemonic()),
        Err(e) => println!("f2010802 ERR: {}", e),
    }
}
