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

pub mod client;
pub mod data;
pub mod encrypt;
pub mod server;
