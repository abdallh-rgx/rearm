use rearm_core::a64::encode::A64;
use rearm_core::a32::ins::*;
use rearm_core::a32::ins::{LdmMode, RegList};

fn main() {
    // push {r7, lr} = LdmStm Db
    let ins = Ins::LdmStm { load: false, rn: 13, mode: LdmMode::Db, wback: true, user: false, list: RegList::from_bitmap(0x4080) };
    let mut out = A64::new();
    match rearm_core::translate::a32_to_a64::translate_a32(&ins, 0x2a88, &mut out) {
        Ok(true) => println!("OK, {} words", out.len()),
        Ok(false) => println!("UNSUPPORTED (Ok(false))"),
        Err(e) => println!("ERR {}", e.0),
    }
    // also via translate_t32 (the payload path)
    let mut out2 = A64::new();
    match rearm_core::translate::t32_to_a64::translate_t32(&ins, 0x2a88, &mut out2, None) {
        Ok(true) => println!("t32 OK, {} words", out2.len()),
        Ok(false) => println!("t32 UNSUPPORTED (Ok(false))"),
        Err(e) => println!("t32 ERR {}", e.0),
    }
    // pop {r7, pc}
    let pop = Ins::LdmStm { load: true, rn: 13, mode: LdmMode::Ia, wback: true, user: false, list: RegList::from_bitmap(0x8080) };
    let mut out3 = A64::new();
    match rearm_core::translate::t32_to_a64::translate_t32(&pop, 0x2aa8, &mut out3, None) {
        Ok(true) => println!("pop OK, {} words", out3.len()),
        Ok(false) => println!("pop UNSUPPORTED"),
        Err(e) => println!("pop ERR {}", e.0),
    }
}
