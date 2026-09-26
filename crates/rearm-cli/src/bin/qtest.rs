use rearm_core::a32::decode::decode_a32;
use rearm_core::translate::a32_to_a64::translate_a32;
use rearm_core::a64::encode::A64;
fn dis(out: &A64) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for w in out.words() { write!(s, "{:08x} ", w).unwrap(); }
    s
}
fn main() {
    for (name, w) in [
        ("vadd.i32 q2,q4,q6", 0xf228484cu32),
        ("vadd.i32 d2,d4,d6", 0xf2242806u32),
        ("vmov.i32 q1,#255", 0xf387205fu32),
        ("vmov.i32 d3,#255", 0xf387301fu32),
        ("vdup.32 q3,d5[1]", 0xf3bc6c45u32),
    ] {
        match decode_a32(w) {
            Ok(ins) => {
                println!("{}: {:08x} -> {:?}", name, w, &ins);
                let mut out = A64::new();
                match translate_a32(&ins, 0x1000, &mut out) {
                    Ok(true) => println!("   A64: {}", dis(&out)),
                    Ok(false) => println!("   unsupported"),
                    Err(e) => println!("   err: {}", e.0),
                }
            }
            Err(_) => println!("{}: decode error", name),
        }
    }
}
