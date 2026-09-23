//! # rearm-core
//!
//! Cross-architecture ARM recompiler core: A32/T32 decoders & encoders,
//! semantic IR lifting, and A64 translation.
//!
//! Pure Rust, no external dependencies, permissively licensed.
//! Encoding tables validated against an LLVM-generated golden corpus.

pub mod common;
pub mod ir;
pub mod a32;
pub mod t32;
pub mod a64;
pub mod translate;

pub use common::*;
