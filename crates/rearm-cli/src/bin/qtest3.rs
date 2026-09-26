use rearm_core::a32::decode::decode_a32;
use rearm_core::translate::a32_to_a64::translate_a32;
use rearm_core::a64::encode::A64;
fn main() {
    for (name, w) in [
        ("vmla.i32 q0,q2,d4[1]", 0xf3a40064u32),
        ("vmul.i32 q0,q1,d2[1]", 0xf3a20862u32),
        ("vmla.f32 d0,d1,d2[0]", 0xf2a10942u32),
        ("vmul.i16 q0,q1,d2[2]", 0xf3920062u32),
    ] {
        match decode_a32(w) {
            Ok(ins) => {
                let mut out = A64::new();
                match translate_a32(&ins, 0x1000, &mut out) {
                    Ok(true) => {
                        print!("{}: ", name);
                        for w in out.words() { print!("{:08x} ", w); }
                        println!();
                    }
                    _ => println!("{}: unsupported/err", name),
                }
            }
            Err(_) => println!("{}: decode error", name),
        }
    }
}
