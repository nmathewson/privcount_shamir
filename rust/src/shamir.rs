// Here's an implementation of Shamir's K-of-N secret sharing over an
// abitrary field.

use num::traits::NumRef;
use rand::{Rand, Rng};
use std::iter::FromIterator;
use std::ops::Sub;

// We don't support more than this many shares, although we could.
pub const MAX_SHARES : u32 = 1024;

// A parambuilder is used to configure the secret-sharing environment.
pub struct ParamBuilder<N> {
    p: Params<N>,
}

// A Params structure encodes the K, the N, and the X coordinates to use
// for the various shares
pub struct Params<N> {
    k: u32,
    n: u32,
    x_coordinates: Vec<N>,
}

// A Share one of the N split shares of a secret.
#[derive(Clone, Debug)]
pub struct Share<N> {
    pub x: N,
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

    // Add a single X coordinate manually.
    //
    // Most shamir implementations don't need to have configurable X
    // coordinates, but they're needed for the kind of homomorphic
    // shenanigans we have in mind for Privcount.
    pub fn add_x_coordinate(&mut self, x: &N) {
        self.p.x_coordinates.push(x.clone());
    }

    // Fill in the X coordinates randomly.
    pub fn fill_x_coordinates<R: Rng>(&mut self, rng: &mut R) {
        while self.p.x_coordinates.len() < self.p.n as usize {
            let n = rng.gen::<N>();
            self.add_x_coordinate(&n);
        }
    }

    // Convert a ParamBuilder to a Params.
    // Requires that the X coordinates have been filled.
    pub fn finalize(self) -> Result<Params<N>, &'static str> {
        if self.p.x_coordinates.len() == self.p.n as usize {
            Ok(self.p)
        } else {
            Err("Length mismatch in finalize.")
        }
    }
}

// Helper: Given a polynomial's coefficients (from highest-order term
// down to the 0th-order term), evaluate that polynomial at x.
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
    // Split a secret 'N' according to the given parameters.
    //
    // (The security of this scheme is only as good as the RNG you use.)
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

// Reconstruct a secret from any K of its shares.  (If the number of shares
// is not the same K used to split the secret, the output will be wrong.)
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
