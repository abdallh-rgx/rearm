use rearm_core::a32::decode::decode_a32;
fn main() {
    for h in ["e75032d1", "e75210f3"] {
        let w = u32::from_str_radix(h, 16).unwrap();
        match decode_a32(w) {
            Ok(i) => println!("{} -> {:?}", h, i),
            Err(e) => println!("{} -> ERR {}", h, e),
        }
    }
}
