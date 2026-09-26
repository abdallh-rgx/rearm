fn main() {
    use rearm_core::a32::decode::decode_a32;
    // addeq r0, r1, r2 = 0x00810002 ; addne = 0x12810002 ; add r0,r1,r2 (AL) = 0xE0810002
    for (name, w) in [("addeq", 0x00810002u32), ("addne", 0x12810002), ("add-al", 0xE0810002), ("ldrne", 0x15910000), ("bne", 0x1A000000)] {
        match decode_a32(w) {
            Ok(i) => println!("{name} ({w:08x}) -> {:?}", i),
            Err(_) => println!("{name} ({w:08x}) -> DECODE ERROR"),
        }
    }
}
