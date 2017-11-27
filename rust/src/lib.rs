#![cfg_attr(feature = "nightly", feature(i128_type))]

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

