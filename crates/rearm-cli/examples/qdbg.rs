
use rearm_core::a32::decode::decode_a32;
fn main() {
    let words: Vec<u32> = [0x2a0103ef, 0x2a0203f0, 0x1200d9f1, 0x1200da12, 0x0b120231, 0x4a1001f2, 0x1207c252, 0x4a120231, 0x53077df3, 0x1200c273, 0x4a1101f2, 0x4a1001ef, 0x0a2f0252, 0x1207c252, 0x528feff0, 0x72afeff0, 0x0b100273, 0x53077e50, 0x2a100610, 0x2a100a10, 0x2a101210, 0x4a13022f, 0x0a1001ef, 0x4a0f0231, 0x5288102f, 0x72a0040f, 0x1b0f7e4f, 0x531c7def, 0x710001ff, 0x1a9f07f0, 0x2a100294, 0x2a1103e0].to_vec();
    let _ = decode_a32(0);
    let a64 = rearm_core::a64::encode::A64 { buf: words };
    let _ = std::fs::write("/tmp/words.bin", a64.bytes()).unwrap();
    let smt = rearm_verify::debug_smt(&decode_a32(0xe6210f92).unwrap(), &a64).unwrap();
    let _ = std::fs::write("/tmp/qadd8.smt", smt).unwrap();
    println!("ok");
}
