// emit new encodings to a binary for llvm-mc differential check
use rearm_core::a64::encode::A64;
fn main() {
    let mut out = A64::new();
    // fcvt/frinti variants
    out.fcvt_s_from_d(1, 0);   // fcvt s0, d1
    out.fcvt_d_from_s(1, 0);   // fcvt d0, s1
    out.frinti_s(1, 0);        // frinti s0, s1
    out.frinti_d(1, 0);        // frinti d0, d1
    // fixed-point conversions
    out.scvtf_fixed(false, 4, 0, 1);   // scvtf s1, w0, #4
    out.ucvtf_fixed(false, 4, 0, 1);   // ucvtf s1, w0, #4
    out.fcvtzs_fixed(false, 2, 1, 0);  // fcvtzs w0, s1, #2
    out.fcvtzu_fixed(false, 2, 1, 0); // fcvtzu w0, s1, #2
    out.scvtf_fixed(true, 16, 0, 1);  // scvtf d1, x0, #16
    out.fcvtzs_fixed(true, 8, 0, 1);  // fcvtzs x1, d0, #8
    // mrs/msr fpsr/fpcr
    out.mrs_fpsr(0); out.msr_fpsr(0); out.mrs_fpcr(0); out.msr_fpcr(0);
    // movi via enc_movi (fixed defgh<<5 check below)
    std::fs::write("/tmp/enccheck.bin", out.bytes()).unwrap();
    println!("{} words", out.buf.len());
    // print words for inspection
    for i in 0..out.buf.len() { println!("{:08x}", out.buf[i]); }
}
