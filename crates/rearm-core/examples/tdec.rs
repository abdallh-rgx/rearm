use rearm_core::a64::encode::A64;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::t32_to_a64::{translate_t32, ItTracker};
use rearm_core::a32::ins::*;

fn main() {
    let data = std::fs::read("/home/z/my-project/pubg/lib/armeabi-v7a/libzlib.so").unwrap();
    // walk from deflateInit2_'s entry 0x2aac, like the sweep does
    let mut a: u32 = 0x2aac;
    let mut it: Option<ItTracker> = None;
    let mut out = A64::new();
    for _step in 0..16 {
        let hw1 = u16::from_le_bytes([data[0x2aac + (a-0x2aac) as usize], data[0x2aad + (a-0x2aac) as usize]]);
        let base = 0x2aac + (a-0x2aac) as usize;
        let hw1 = u16::from_le_bytes([data[base], data[base+1]]);
        let hw2 = u16::from_le_bytes([data[base+2], data[base+3]]);
        let t = decode_t32(hw1, hw2).unwrap();
        let len = t.len as u32;
        if let Ins::It { first_cond, mask } = &t.ins {
            println!("guest {a:#x}: IT {first_cond:?} mask={mask:#x} (len {len})");
            it = Some(ItTracker::new(*first_cond, *mask));
            a += len;
            continue;
        }
        let cond = match &mut it { Some(tr) => tr.next(), None => None };
        let start = out.len();
        let r = translate_t32(&t.ins, a, &mut out, cond);
        println!("guest {a:#x} (len {len}, cond={cond:?}) -> {} words, ok={:?} start_word_idx={}",
            out.len()-start, r, start);
        for i in start..out.len() {
            println!("   [{:#06x}] = {:#010x}", i*4, out.buf[i]);
        }
        a += len;
    }
}
