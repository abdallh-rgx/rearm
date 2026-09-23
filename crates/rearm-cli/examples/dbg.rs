use rearm_core::a32::decode::decode_a32;
fn main() {
    let ins = decode_a32(0xe3b000ff).unwrap();
    let mut a64 = rearm_core::a64::encode::A64::new();
    rearm_core::translate::a32_to_a64::translate_a32(&ins, 0, &mut a64).unwrap();
    println!("{:08x?}", a64.words());
    let smt = rearm_verify::debug_smt(&ins, &a64).unwrap();
    std::fs::write("/tmp/movs.smt", &smt).unwrap();
}
