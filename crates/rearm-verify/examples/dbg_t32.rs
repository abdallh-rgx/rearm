use rearm_core::a64::encode::A64;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::t32_to_a64::translate_t32;
use rearm_verify::{debug_smt_at_t32, verify_one_at_t32};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // default: mvns r0, #0xff000000 (f06f 407f); arg: hex word (8 digits)
    let word = if args.len() > 1 { u32::from_str_radix(&args[1], 16).unwrap() } else { 0xf06f407f };
    let (hw1, hw2) = ((word >> 16) as u16, (word & 0xFFFF) as u16);
    let tins = decode_t32(hw1, hw2).unwrap();
    println!("decoded: {:?} (len {})", tins.ins, tins.len);
    let mut a64 = A64::new();
    translate_t32(&tins.ins, 0x1000, &mut a64, None).unwrap();
    println!("A64 words:");
    for w in a64.words() { println!("  {:08x}", w); }
    match verify_one_at_t32(&tins.ins, 0x1000) {
        Ok(true) => println!("PROVEN"),
        Ok(false) => {
            println!("COUNTEREXAMPLE");
            let smt = debug_smt_at_t32(&tins.ins, 0x1000, &a64).unwrap();
            std::fs::write("/tmp/ce.smt2", &smt).unwrap();
            println!("smt written to /tmp/ce.smt2");
        }
        Err(e) => println!("err: {}", e),
    }
}
