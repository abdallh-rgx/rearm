use rearm_core::a32::decode::decode_a32;
fn main() {
    let w = 0xf2010802u32;
    match decode_a32(w) {
        Ok(ins) => {
            use rearm_core::a32::ins::Ins;
            let is_unsup = matches!(ins, Ins::Unsupported { .. });
            println!("decodes to: {} (Unsupported: {})", ins.mnemonic(), is_unsup);
        }
        Err(e) => println!("ERR: {}", e),
    }
}
