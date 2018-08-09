// Fail hard on warnings.  This will be automatically disabled when we're
// used as a dependency by other crates, thanks to Cargo magic.
#![deny(warnings)]
// Enable as many useful Rust warnings as we can stand.  We'd
// also enable `trivial_casts`, but we're waiting for
// https://github.com/rust-lang/rust/issues/23416.
#![warn(
    trivial_numeric_casts,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications
)]
// Disable for now
//#![warn(
//    missing_copy_implementations,
//    missing_debug_implementations,
//    missing_docs
//)]
// Enable i128 on nightly
#![cfg_attr(feature = "nightly", feature(i128_type))]

extern crate byteorder;
extern crate crypto;
extern crate num;
extern crate rand;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(test)]
extern crate primal;

mod math;
pub mod shamir;
pub use math::FE;
pub use math::PRIME_ORDER;

pub mod client;
pub mod data;
pub mod encrypt;
pub mod server;
