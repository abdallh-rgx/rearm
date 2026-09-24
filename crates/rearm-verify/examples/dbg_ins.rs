use rearm_core::a64::encode::A64;
use rearm_core::a32::ins::Ins;
use rearm_core::common::{Shift, ShiftAmount};
use rearm_core::a32::ins::DpOp;
use rearm_core::translate::t32_to_a64::translate_t32;
use rearm_verify::{debug_smt_at_t32, verify_one_at_t32};

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    let ins = if which == "1" {
        // 0x02505b94: movs.w r2, r2, lsr #14
        Ins::DpReg { op: DpOp::Mov, s: true, rn: 0, rd: 2, rm: 2, shift: Shift::Lsr, amount: ShiftAmount::Imm(14) }
    } else {
        // 0x0324090c: orns.w r3, r13, #0xB85
        Ins::DpImmT32 { op: DpOp::Orn, s: true, rn: 13, rd: 3, imm12: 2949, plain: false }
    };
    let addr: u32 = if which == "1" { 0x02505b94 } else { 0x0324090c };
    let mut a64 = A64::new();
    translate_t32(&ins, addr, &mut a64, None).unwrap();
    println!("A64 words:");
    for w in a64.words() { println!("  {:08x}", w); }
    match verify_one_at_t32(&ins, addr) {
        Ok(true) => println!("PROVEN"),
        Ok(false) => {
            println!("COUNTEREXAMPLE");
            std::fs::write("/tmp/ce.smt2", debug_smt_at_t32(&ins, addr, &a64).unwrap()).unwrap();
        }
        Err(e) => println!("err: {}", e),
    }
}
