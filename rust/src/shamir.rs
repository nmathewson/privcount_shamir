//! Implementation of Shamir's K-of-N secret sharing over an aribtrary field.
//!
//! Shamir's secret sharing allows you to split a secret value into
//! `N` pieces such that any `K` pieces can be used to reconstruct the
//! original secret, but no information can be learned from any fewer
//! than `K` pieces.
//!
//! Math details: Shamir's scheme takes advantage of the fact that a
//! `K-1`-degree polynomial is fully determined by knowing `K`
//! distinct points on that polynomial. (Two points for a line, three
//! for a quadratic, etc.)  So we generate a random `K-1` degree
//! polynomial whose y-intercept is the secret, and then take the
//! value of that polynomial for `N` other values of the x coordiate.
//!
//! This module requires a numerical field that implements the
//! `NumRef` Trait; the maximum size of a secret that can be shared is
//! the size of the field.  For privcount, we use the FE type for our
//! field.
//!
//! (A field is, roughly, a mathematical object full of number-like
//! things that support addition, subtraction, multiplication, and
//! division, with the properties that you'd want.)
//!
//! # Examples
//! ```
//! extern crate rand;
//! extern crate privcount;
//! use privcount::{FE, shamir};
//! use rand::Rng;
//! # fn main() -> Result<(), &'static str> {
//!
//! // We need to use secure entropy for this, or we get no security.
//! let mut rng = rand::os::OsRng::new().unwrap();
//!
//! // First, you construct a parameters object that describes how you want to share
//! // secrets.  Each such parameters object can be used more than once.
//!
//! // Any 3 of 10 shares can retrieve the secret
//! let mut builder = shamir::ParamBuilder::new(3, 10)?;
//! builder.fill_x_coordinates(&mut rng); // Pick x coordinates randomly.
//!
//! let parameters = builder.finalize()?;
//!
//! // Now we can share a secret.  Let's share the number seven!
//! let shares_of_7 : Vec<_> = parameters.share_secret(FE::new(7), &mut rng);
//! assert_eq!(shares_of_7.len(), 10);
//!
//! // Finally, we can recover the secret from the shares.  Let's pick shares 2, 3, and 4.
//! let result = shamir::recover_secret(&shares_of_7[2..5]);
//!
//! assert_eq!(result.value(), 7);
//!
//! // But that's not all!  If we use the same parameters to share different values,
//! // the the sum of the shares is equal to the share of the sums!
//! let shares_of_100 : Vec<_> = parameters.share_secret(FE::new(100), &mut rng);
//!
//! let sum_of_shares : Vec<_> = shares_of_7.iter()
//!                                  .zip(shares_of_100.iter())
//!                                  .map(|(a,b)| privcount::shamir::Share {
//!                                        x : a.x, y: a.y + b.y })
//!                                  .collect();
//!
//! let result = shamir::recover_secret(&sum_of_shares[6..9]);
//!
//! assert_eq!(result.value(), 107);
//!
//! # Ok(())
//! # }

use num::traits::NumRef;
use rand::{Rand, Rng};
use std::iter::FromIterator;
use std::ops::Sub;

/// We don't support more than this many shares, although we could.
pub const MAX_SHARES : u32 = 1024;

/// A ParamBuilder is used to configure the secret-sharing
/// environment.
///
/// It gets filled in with the parts that will be used
/// to construct the parameters for secret-sharing.  Once you're done
/// filling it in, call `finalize()` on it to produce a `Params` object.
pub struct ParamBuilder<N> {
    p: Params<N>,
}

/// A Params structure encodes the K value (number of shares needed to
/// reconstruct secret), the N value (number of shares to generate),
/// and the X coordinates to use for the various shares.
pub struct Params<N> {
    k: u32,
    n: u32,
    x_coordinates: Vec<N>,
}

/// A Share: one of the N split shares of a secret.
#[derive(Clone, Debug)]
pub struct Share<N> {
    /// The X coordinate for this share.
    ///
    /// Every party needs a different X coordinate; no X coordinate can be zero.
    pub x: N,
    /// The Y coordinate for this share.
    pub y: N,
}

impl<N> ParamBuilder<N>
where
    N: NumRef + Clone + Rand,
{
    pub fn new(k: u32, n: u32) -> Result<Self, &'static str> {
        if k > n {
            return Err("Invalid parameters: k > n.");
        }
        if n > MAX_SHARES {
            return Err("Invalid parameters: n > MAX_SHARES.");
        }
        Ok(ParamBuilder {
            p: Params {
                k,
                n,
                x_coordinates: Vec::new(),
            },
        })
    }

    /// Add a single X coordinate manually.
    ///
    /// Most shamir implementations don't need to have configurable X
    /// coordinates, but they're needed for the kind of homomorphic
    /// shenanigans we have in mind for Privcount, where every TR gets its own
    /// X coordinate.
    pub fn add_x_coordinate(&mut self, x: &N) {
        self.p.x_coordinates.push(x.clone());
    }

    /// Fill in the X coordinates randomly
    pub fn fill_x_coordinates<R: Rng>(&mut self, rng: &mut R) {
        while self.p.x_coordinates.len() < self.p.n as usize {
            let n = rng.gen::<N>();
            if n != N::zero() {
                self.add_x_coordinate(&n);
            }
        }
    }

    /// Convert a ParamBuilder to a Params.
    ///
    /// Requires that the X coordinates have been filled with nonzero values.
    pub fn finalize(self) -> Result<Params<N>, &'static str> {
        if self.p.x_coordinates.contains(&N::zero()) {
            Err("No X coordinate may be zero.")
        } else if self.p.x_coordinates.len() != self.p.n as usize {
            Err("Length mismatch in finalize.")
        } else {
            Ok(self.p)
        }
    }
}

/// Helper: Given a polynomial's coefficients (from highest-order term
/// down to the 0th-order term), evaluate that polynomial at x.
fn evaluate_poly_at<N>(poly: &Vec<N>, x: &N) -> N
where
    N: NumRef,
{
    poly.iter().fold(N::zero(), |acc: N, t: &N| acc * x + t)
}

impl<N> Params<N>
where
    N: NumRef + Rand + Clone,
{
    /// Split a secret 'N' according to the given parameters.
    ///
    /// (The security of this scheme is only as good as the RNG you use.)
    pub fn share_secret<R: Rng>(
        &self,
        secret: N,
        rng: &mut R,
    ) -> Vec<Share<N>> {
        // Generate a random polynomial with Y intercept of secret.
        let mut poly = Vec::with_capacity(self.k as usize);
        for _ in 1..(self.k) {
            poly.push(rng.gen());
        }
        poly.push(secret);
        debug_assert_eq!(poly.len(), self.k as usize);

        // Evaluate this polynomial at each X coordinate.
        Vec::from_iter(self.x_coordinates.iter().map(|x| Share {
            x: x.clone(),
            y: evaluate_poly_at(&poly, &x),
        }))
    }
}

/// Reconstruct a secret from any K of its shares.
///
/// (If the number of shares is not the same K used to split the
/// secret, the output will be wrong.)
pub fn recover_secret<'a, N>(shares: &'a [Share<N>]) -> N
where
    &'a N: Sub<&'a N, Output = N>,
    N: NumRef + 'a,
{
    let mut accumulator = N::zero();
    for (i, sh) in shares.iter().enumerate() {
        let mut numerator = N::one();
        let mut denominator = N::one();
        for (j, sh2) in shares.iter().enumerate() {
            if i == j {
                continue;
            }

            numerator = numerator * &sh2.x;
            denominator = denominator * (&sh2.x - &sh.x);
        }
        accumulator = accumulator + (numerator * &sh.y) / denominator;
    }
    accumulator
}

#[cfg(test)]
mod tests {
    use math::*;
    use rand;
    use shamir::*;
    #[test]
    fn demo() {
        let mut pb = ParamBuilder::new(3, 5).unwrap();
        let mut rng = rand::thread_rng();
        pb.fill_x_coordinates(&mut rng);
        let p = pb.finalize().unwrap();
        let shares = p.share_secret(FE::new(12345), &mut rng);
        assert_eq!(shares.len(), 5);
        println!("{:?}", shares);
        let result = recover_secret(&shares[0..3]);
        assert_eq!(result, FE::new(12345));
    }
}
