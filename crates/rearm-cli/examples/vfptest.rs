use rearm_core::a32::decode::decode_a32;
fn main() {
    // T32 VFP words — feed to A32 decoder (cond field = 1110 = always)
    for (w, name) in [
        (0xee300a81u32, "vadd.f32 s0,s1,s2"),
        (0xee300ac1, "vsub.f32 s0,s1,s2"),
        (0xee200a81, "vmul.f32 s0,s1,s2"),
        (0xee800a81, "vdiv.f32 s0,s1,s2"),
        (0xeeb00ae0, "vabs.f32 s0,s1"),
        (0xeeb10a60, "vneg.f32 s0,s1"),
        (0xee001a10, "vmov s0,r1"),
        (0xed900a00, "vldr s0,[r0]"),
        (0xec900a04, "vldmia r0,{s0-s3}"),
        (0xef010802, "vadd.i8 d0,d1,d2"),
    ] {
        match decode_a32(w) {
            Ok(ins) => println!("{:08x} {} → {}", w, name, ins.mnemonic()),
            Err(e) => println!("{:08x} {} → ERR {}", w, name, e),
        }
    }
}
