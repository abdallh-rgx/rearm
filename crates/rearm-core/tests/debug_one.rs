#[test]
fn debug_nop() {
    let w = 0xe320f000u32;
    let d = rearm_core::a32::decode::decode_a32(w);
    eprintln!("decode({:#010x}) = {:?}", w, d);
    let d2 = rearm_core::a32::decode::decode_a32(0xe12fff1e);
    eprintln!("decode(bx lr) = {:?}", d2);
    let d3 = rearm_core::a32::decode::decode_a32(0xe1d100d5);
    eprintln!("decode(ldrsb) = {:?}", d3);
    let d4 = rearm_core::a32::decode::decode_a32(0xf1010200);
    eprintln!("decode(setend be) = {:?}", d4);
    let d5 = rearm_core::a32::decode::decode_a32(0xf57ff05f);
    eprintln!("decode(dmb) = {:?}", d5);
}
