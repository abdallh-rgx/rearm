use rearm_core::a32::decode::decode_a32;
use rearm_core::translate::a32_to_a64::translate_a32;
use rearm_core::a64::encode::A64;

fn main() {
    let ins = decode_a32(u32::from_str_radix(std::env::args().nth(1).unwrap().trim(), 16).unwrap()).unwrap();
    let mut a64 = A64::new();
    translate_a32(&ins, 0, &mut a64).unwrap();
    let (decls, steps) = rearm_verify::trace_exec(&a64);
    // write full SMT queries evaluating x17 final + x18 + x19 at a concrete point
    let smt = format!(
        "{decls}(assert (and (= x14 #x0000000000000000) (= x10 #x0000000000000001) (= x8 #x0000000000000000)\
         (= N #b0) (= Z #b0) (= C #b1) (= V #b0) (= QF #x00000000) (= GF #x00000000)))\n(check-sat)\n");
    std::fs::write("/tmp/trace_eval.smt", &smt).unwrap();
    for s in &steps { println!("{}", s); }
}
