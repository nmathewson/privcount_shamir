#![cfg_attr(feature = "nightly", feature(i128_type))]

extern crate num;
extern crate rand;
extern crate crypto;
extern crate byteorder;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(test)]
extern crate primal;

mod math;
pub mod shamir;
pub use math::FE;

pub mod data;
pub mod client;
mod encrypt;
