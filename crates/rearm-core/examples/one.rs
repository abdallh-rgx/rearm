use rearm_core::a32::decode::decode_a32;
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;
fn main() {
    for w in [0xe750f110u32, 0xe750f130, 0xe7510f10, 0xe7550f10] {
        let ins = decode_a32(w).unwrap();
        let mut out = A64::new();
        let ok = translate_a32(&ins, 0, &mut out).is_ok();
        print!("{w:08x} ok={ok}: ");
        for c in out.bytes().chunks_exact(4) { print!("{:08x} ", u32::from_le_bytes([c[0],c[1],c[2],c[3]])); }
        println!();
    }
}
