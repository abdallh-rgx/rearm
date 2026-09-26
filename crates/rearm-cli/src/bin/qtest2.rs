use rearm_core::a32::decode::decode_a32;
fn main() {
    for (name, w) in [
        ("vmla.i32 q0,q2,d4[1]", 0xf3a40064u32),
        ("vmul.i16 q0,q2,d4[3]", 0xf3a005a4u32),
    ] {
        match decode_a32(w) {
            Ok(ins) => println!("{}: -> {:?}", name, ins),
            Err(_) => println!("{}: decode error", name),
        }
    }
}
