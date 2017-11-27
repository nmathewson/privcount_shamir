// Implements a prime field modulo some prime of form 2^A - 2^B - 1.
//
// Tries to be fairly efficient, and to not have timing side-channels.
//
// Certain constraints are placed on A and B, see below.

use rand::{Rand,Rng};
use std::cmp::{Eq,PartialEq};
use std::convert::From;
use std::fmt::{Display,Formatter,UpperHex,LowerHex,self};
use std::ops::{Add,Sub,Neg,Mul,Div,Rem};
use std::ops::{AddAssign,SubAssign,MulAssign,DivAssign,RemAssign};
use num::traits::{Zero,One,Num};
use std::hash::{Hash,Hasher};

// 2^N_BITS - (2^OFFSET_BIT + 1) must be prime; we do all of our
//   arithmetic modulo this prime.
// Choose OFFSET_BIT low, and less than N_BITS/2.
// Our recip() implementation requires OFFSET_BIT != 2.
// Choose N_BITS even, and no more than 64 - 2, and no less than 34.

// number of bits in our field elements
const N_BITS : u64 = 62;
// Which bit (other than bit 0) do we clear in our prime?
const OFFSET_BIT : u64 = 30;
// order of the prime field
const PRIME_ORDER : u64 = (1<<N_BITS) - (1<<OFFSET_BIT) - 1;
// Mask to mask off all bits that aren't used in the field elements.
const FULL_BITS_MASK : u64 = (1 << N_BITS) - 1;

// We use these macros to check invariants.

// Number of bits in a u64 which we don't use.
const REMAINING_BITS : u64 = 64 - N_BITS;
// Largest remaining value after we take a u64 and get rid of the
// bits that we want to use in our field.
const MAX_EXCESS : u64 = (1<<REMAINING_BITS) - 1;
// Largest value to use in our field elements.  This will spill
// over our regular bit mask by a littke, since we don't store stuff
// in a fully bit-reduced form.
const FE_VAL_MAX : u64 =
    FULL_BITS_MASK + (MAX_EXCESS << OFFSET_BIT) + MAX_EXCESS;

#[derive(Debug,Copy,Clone)]
pub struct FE {
    // This value is stored in a bit-reduced form: it will be in range
    // 0..FE_VAL_MAX.  It is equivalent modulo PRIME_ORDER to the
    // actual value of this field element
    val : u64
}

// Given a value in range 0..U64_MAX, returns a value in range 0..FE_VAL_MAX.
//
// (Given a value in range 0..FE_VAL_MAX, the output is in range
// 0..FULL_BITS_MASK.)
fn bit_reduce_once(v : u64) -> u64 {
    // Excess is in range 0..MAX_EXCESS
    let excess = v >> N_BITS;
    // Lowpart is in range 0..FULL_BITS_MASK
    let lowpart = v & FULL_BITS_MASK;
    // Result is at most FE_VAL_MAX
    let result = lowpart + excess + (excess << OFFSET_BIT);
    debug_assert!(result <= FE_VAL_MAX);
    result
}

// Returns "if v > PRIME_ORDER { v - PRIME_ORDER } else { v }".
//
// We only call this when it will produce a value in range 0..PRIME_ORDER-1.
fn reduce_by_p(v : u64) -> u64 {
    debug_assert!(v < PRIME_ORDER * 2);
    let difference = v.wrapping_sub(PRIME_ORDER);
    let overflow_bit = difference & (1<<63);
    let mask =
        ( (overflow_bit as i64) >> 63 ) as u64;

    (mask & v ) | ((!mask) & difference)
}

impl FE {
    pub fn new(v : u64) -> Self {
        FE { val : bit_reduce_once(v) }
    }
    // Internal use only: requires that v is already bit-reduced.
    fn new_raw(v : u64) -> Self {
        FE { val : v }
    }
    pub fn value(self) -> u64 {
        // self.val is already bit-reduced, so only bit-reduce it once more.
        reduce_by_p(bit_reduce_once(self.val))
    }
    // Compute the reciprocal of this value.
    pub fn recip(self) -> Self {
        debug_assert_ne!(self, FE::new_raw(0));

        // To compute the reciprical, we need to compute
        // self^E where E = (PRIME_ORDER-2).
        //
        // Since OFFSET_BIT != 2, E has every bit in (0..N_BITS-1)
        // set, except for bits 1 and OFFSET_BIT.  In other words,
        // it looks like 0b11111111..11101111..01

        // Simple version of exponention-by-squaring algorithm.
        let mut x = self;
        let mut y = FE::new(1);

        // Bit 0 is set.
        y = x * y;
        x = x * x;
        // Bit 1 is clear.
        x = x * x;
        // Bits 2 through offset_bit-1 are set.
        for _ in 2..(OFFSET_BIT) {
            y = x * y;
            x = x * x;
        }
        // OFFSET_BIT is clear
        x = x * x;
        // OFFSET_BIT + 1 through N_BITS-2
        for _ in (OFFSET_BIT+1)..(N_BITS-1) {
            y = x * y;
            x = x * x;
        }
        x * y
    }
}

// From implementations: these values are always in-range.
impl From<u8> for FE {
    fn from(v : u8) -> FE {
        FE::new_raw(v as u64)
    }
}
impl From<u16> for FE {
    fn from(v : u16) -> FE {
        FE::new_raw(v as u64)
    }
}
impl From<u32> for FE {
    fn from(v : u32) -> FE {
        FE::new_raw(v as u64)
    }
}
impl From<FE> for u64 {
    fn from(v : FE) -> u64 {
        v.value()
    }
}
impl Zero for FE {
    fn zero() -> FE {
        FE::new_raw(0)
    }
    fn is_zero(&self) -> bool {
        self.value() == 0
    }
}
impl One for FE {
    fn one() -> FE {
        FE::new_raw(1)
    }
}

impl Add for FE {
    type Output = Self;
    fn add(self, rhs : Self) -> Self {
        // This sum stay in range, since FE_MAX_VAL * 2 < U64_MAX.
        // The FE::new call will bit-reduce the result.
        FE::new(self.val + rhs.val)
    }
}

impl Neg for FE {
    type Output = Self;
    fn neg(self) -> Self {
        FE::new(PRIME_ORDER * 2 - self.val)
    }
}

impl Sub for FE {
    type Output = Self;
    fn sub(self, rhs : Self) -> Self {
        self + (-rhs)
    }
}

impl PartialEq for FE {
    fn eq(&self, rhs : &Self) -> bool {
        self.value() == rhs.value()
    }
}
impl Eq for FE { }

impl Hash for FE {
    fn hash<H:Hasher>(&self,hasher : &mut H) {
        hasher.write_u64(self.value())
    }
}

impl AddAssign for FE {
    fn add_assign(&mut self, other : Self) {
        *self = *self + other;
    }
}
impl SubAssign for FE {
    fn sub_assign(&mut self, other : Self) {
        *self = *self - other;
    }
}

impl Display for FE {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        Display::fmt(&self.value(), f)
    }
}

impl UpperHex for FE {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        UpperHex::fmt(&self.value(), f)
    }
}

impl LowerHex for FE {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        LowerHex::fmt(&self.value(), f)
    }
}

impl Default for FE {
    fn default() -> Self {
        FE::new_raw(0)
    }
}

impl Mul for FE {
    type Output = Self;

    // Implement multiplication. We have separate implementations
    // depending on whether we have u128 support or not.

    #[cfg(not(feature = "nightly"))]
    fn mul(self, rhs : Self) -> Self {
        // This is the version of multiplication without u128 support:
        // we have to a few 32x32 multiplies rather than a full 64x64
        // multiply.

        // We require below that HALF_BITS <= 31
        const HALF_BITS : u64 = N_BITS / 2;
        const MASK : u64 = (1<<HALF_BITS) - 1;

        // Reduce the input values an extra time, so that they are in
        // range 0..FULL_BITS_MASK.
        let a = bit_reduce_once(self.val);
        let b = bit_reduce_once(rhs.val);

        // The 'lo' values and 'hi' values here are in range 0..MASK.
        let a_lo = a & MASK;
        let a_hi = a >> HALF_BITS;
        let b_lo = b & MASK;
        let b_hi = b >> HALF_BITS;

        // Okay, it's Karatsuba multiplication time.
        // We want to compute
        //        (a_lo+Base*a_hi) * (b_lo+Base*b_hi)
        //      = z0 + z1 * Base + z2 * Base * Base
        // for Base == 2^HALF_BITS.
        //  So we compute z0 = a_lo * b_lo,
        //                z2 = a_hi * b_hi,
        //                z1 = (a_lo + a_hi) * (b_lo + b_hi) - z0 - z2
        //
        // Let's show this doesn't overflow.  We will have:
        //   z0 <= MASK^2.
        //   z2 <= MASK^2
        //   a_lo + a_hi <= 2 * MASK == 2^(HALF_BITS+1) - 2
        //   b_lo + b_hi <= 2 * MASK == 2^(HALF_BITS+1) - 2
        // And given P = (a_lo + a_hi) * (b_lo + b_hi),
        //   P <= 2^(2*HALF_BITS + 2) - 2^(HALF_BITS+2) + 4
        // Since HALF_BITS <= 31, we have:
        //   P <= 2^64 - 2^34 + 4,
        // so, the multiplication in z1 does not overflow.
        let z0 = a_lo * b_lo;
        let z2 = a_hi * b_hi;
        let z1 = (a_lo + a_hi) * (b_lo + b_hi) - z0 - z2;

        // Split z1 into high and low parts.
        let z1_lo = z1 & MASK;
        let z1_hi = z1 >> HALF_BITS;

        // The product is now given by:
        //      z0 + Base * z1 + Base2^2 * z2 ==
        //      (z0 + z1_lo * Base) + (z2 + z1_hi) * Base^2

        // (XXX Do we really need to bit-reduce z1_lo and z1_hi here?)

        // z0 is already < 2^N_BITS, so we don't need to bit-reduce it before
        // we add.
        let product_low = z0 + bit_reduce_once(z1_lo << HALF_BITS);
        // z2 is already < 2^N_BITS, so we don't need to bit-reduce it before
        // we add.  z1_hi is less than 2^HALF_BITS.
        let product_hi = bit_reduce_once(z2 + bit_reduce_once(z1_hi));

        // Now the product is product_low + 2^N_BITS * product_hi.
        // Modulo PRIME_GROUP, we have 2^N_BITS === 2^OFFSET_BIT + 1,
        // so the final product is:
        //     product_low + product_hi + product_hi << OFFSET_BIT.
        //
        // Computing product_hi << OFFSET_BIT could overflow, so we're
        // splitting it again.

        const NB : u64 = N_BITS - OFFSET_BIT;
        let product_hi_lo = product_hi & ((1<<NB)-1);
        let product_hi_hi = product_hi >> NB;

        // There are some redundant reductions here, maybe? XXXX
        FE::new(product_low) +
            FE::new(product_hi) +
            FE::new(product_hi_lo << OFFSET_BIT) +
            FE::new(product_hi_hi) +
            FE::new(product_hi_hi << OFFSET_BIT)
    }

    #[cfg(feature = "nightly")]
    fn mul(self, rhs : Self) -> Self {
        // If we have u128, we are much happier.

        // Here's our bit-reduction algorithm again:
        fn bit_reduce_once_128(v : u128) -> u128 {
            let low = v & (FULL_BITS_MASK as u128);
            let high = v >> N_BITS;
            low + (high << OFFSET_BIT) + high
        }

        // Reduce the inputs again to make sure they are in range
        // 0..FULL_BITS_MASK.
        let a = bit_reduce_once(self.val) as u128;
        let b = bit_reduce_once(rhs.val) as u128;

        // The product is is most FULL_BITS_MASK^2, and so is less
        // than 2^(N_BITS*2).  No overflow here!
        let product = a * b ;

        // XXXX Is this is too much reduction?  Too little?
        let result = bit_reduce_once_128(bit_reduce_once_128(product));
        debug_assert!(result < (1<<64));
        FE::new(result as u64)
    }
}

impl Div for FE {
    type Output = Self;
    fn div(self, rhs : Self) -> Self {
        self * rhs.recip()
    }
}

impl Rem for FE {
    type Output = Self;
    // not sure why you would want this.... XXXX
    // .... but it makes the Num trait work out.
    fn rem(self, rhs : Self) -> Self {
        self - ( self / rhs )
    }
}

impl MulAssign for FE {
    fn mul_assign(&mut self, other : Self) {
        *self = *self * other;
    }
}
impl DivAssign for FE {
    fn div_assign(&mut self, other : Self) {
        *self = *self / other;
    }
}
impl RemAssign for FE {
    fn rem_assign(&mut self, other : Self) {
        *self = *self % other;
    }
}

impl Rand for FE {
    fn rand<R: Rng>(rng: &mut R) -> FE {
        loop {
            let v = rng.next_u64() & FULL_BITS_MASK;
            if v < PRIME_ORDER {
                return FE::new_raw(v);
            }
        }
    }
}

impl<'a> Add<&'a FE> for FE {
    type Output = Self;
    fn add(self, rhs : &Self) -> FE {
        self + *rhs
    }
}
impl<'a> Sub<&'a FE> for FE {
    type Output = Self;
    fn sub(self, rhs : &Self) -> FE {
        self - *rhs
    }
}
impl<'a> Mul<&'a FE> for FE {
    type Output = Self;
    fn mul(self, rhs : &Self) -> FE {
        self * *rhs
    }
}
impl<'a> Div<&'a FE> for FE {
    type Output = Self;
    fn div(self, rhs : &Self) -> FE {
        self / *rhs
    }
}
impl<'a> Rem<&'a FE> for FE {
    type Output = Self;
    fn rem(self, rhs : &Self) -> FE {
        self % *rhs
    }
}


impl Num for FE {
    type FromStrRadixErr = &'static str;
    fn from_str_radix(s: &str, radix: u32) ->
        Result<Self, &'static str> {
            let u = u64::from_str_radix(s, radix).map_err(|_|"Bad num")?;
            if u < PRIME_ORDER {
                Ok(FE::new_raw(u))
            } else {
                Err("Too big")
            }
        }
}

#[cfg(test)]
mod tests {
    use math::*;

    fn maxrep() -> FE {
        FE::new_raw(FE_VAL_MAX)
    }
    fn fullbits() -> FE {
        FE::new_raw(FULL_BITS_MASK)
    }

    #[test]
    fn constants_in_range() {
        assert!(N_BITS % 2 == 0);
        assert!(N_BITS <= 62);
        assert!(OFFSET_BIT < N_BITS / 2);
        assert!(OFFSET_BIT != 2);
    }
    #[test]
    fn prime_is_prime() {
        use primal;
        assert!(primal::is_prime(PRIME_ORDER));
    }
    #[test]
    fn test_values() {
        assert_eq!(FE::new(0).value(), 0);
        assert_eq!(FE::new(1337).value(), 1337);
        assert_eq!(FE::new(PRIME_ORDER).value(), 0);
        assert_eq!(FE::new(PRIME_ORDER+1).value(), 1);
        assert_eq!(FE::new(PRIME_ORDER-1).value(), PRIME_ORDER - 1);
        assert_eq!(FE::new(PRIME_ORDER).value(), 0);
        assert_eq!(FE::new(!0u64).value(), (!0u64) % PRIME_ORDER);
        assert_eq!(maxrep().value(), FE_VAL_MAX - PRIME_ORDER);
    }
    #[test]
    fn test_equivalence() {
        assert_eq!(FE::new(0), FE::new(PRIME_ORDER));
        assert_eq!(FE::new(1), FE::new(PRIME_ORDER+1));
        assert_eq!(FE::new(1), FE::new(PRIME_ORDER*2+1));
        assert_eq!(FE::new(PRIME_ORDER-50), FE::new(PRIME_ORDER*4 - 50));
        assert_eq!(maxrep(), FE::new(FE_VAL_MAX - PRIME_ORDER));
    }
    #[test]
    fn test_add_sub() {
        assert_eq!(FE::new(0) - FE::new(100), FE::new(PRIME_ORDER-100));
        assert_eq!(FE::new(100) - FE::new(5), FE::new(95));
        assert_eq!(FE::new(100) - FE::new(105), FE::new(PRIME_ORDER-5));
        assert_eq!(FE::new(300) - FE::new(PRIME_ORDER+1), FE::new(299));
        assert_eq!(FE::new(1050) + FE::new(1337), FE::new(2387));
        assert_eq!(FE::new(1337) + FE::new(PRIME_ORDER-37), FE::new(1300));
        assert_eq!(-FE::new(10) + (- FE::new(15)),
                   -FE::new(25));

        assert_eq!(-maxrep(), FE::new(PRIME_ORDER * 2 - FE_VAL_MAX));
        assert_eq!(maxrep() + maxrep(),
                   FE::new((FE_VAL_MAX - PRIME_ORDER)*2));
        assert_eq!(maxrep() - maxrep(), FE::zero());
        assert_eq!(FE::zero() - maxrep(), -maxrep());

        assert_eq!(FE::new(1000) - maxrep(),
                   FE::new(PRIME_ORDER * 2 - FE_VAL_MAX + 1000));

        assert_eq!(-fullbits(), FE::new(PRIME_ORDER * 2 - FULL_BITS_MASK));
        assert_eq!(FE::zero() - fullbits(), -fullbits());
    }
    #[test]
    fn mult() {
        assert_eq!(FE::new(0) * FE::new(1000), FE::new(0));
        assert_eq!(FE::new(999) * FE::new(1000), FE::new(999000));
        assert_eq!(FE::new(PRIME_ORDER) * FE::new(PRIME_ORDER),
                   FE::new(0));
        assert_eq!(FE::new(PRIME_ORDER-1) * FE::new(PRIME_ORDER-1),
                   FE::new(1));
        assert_eq!(FE::new(PRIME_ORDER-2) * FE::new(PRIME_ORDER-2),
                   FE::new(4));

        assert_eq!(maxrep() * maxrep(),
                   FE::new(FE_VAL_MAX % PRIME_ORDER) *
                   FE::new(FE_VAL_MAX % PRIME_ORDER));
        assert_eq!(fullbits() * fullbits(),
                   FE::new(FULL_BITS_MASK % PRIME_ORDER) *
                   FE::new(FULL_BITS_MASK % PRIME_ORDER))
    }
    #[test]
    fn recip() {
        assert_eq!(FE::new(1).recip(), FE::new(1));
        assert_eq!(FE::new(999).recip() * FE::new(999), FE::new(1));
        assert_eq!(FE::new(999).recip(), FE::new(2885188949795824624));
        assert_eq!(FE::new(999), FE::new(2885188949795824624).recip());
    }

    fn mul_slow(a : FE, b : FE) -> FE {
        use num::bigint::BigUint;
        use num::traits::cast::FromPrimitive;
        use num::traits::cast::ToPrimitive;
        let a_big = BigUint::from_u64(a.val).unwrap();
        let b_big = BigUint::from_u64(b.val).unwrap();
        let product = (a_big * b_big) % PRIME_ORDER;
        FE::new(product.to_u64().unwrap())
    }

    use quickcheck::{Arbitrary, Gen};
    impl Arbitrary for FE
    {
        fn arbitrary<G: Gen>(g: &mut G) -> FE {
            g.gen()
        }
    }
    quickcheck! {
        fn p_multiply(a : FE, b : FE) -> bool {
            // println!("{:?} * {:?}", a, b);
            a * b == mul_slow(a,b)
        }

        fn p_recip(a : FE) -> bool {
            // println!("1 / {:?}", a);
            a * a.recip() == FE::new(1)
        }

        fn p_div(a : FE, b : FE) -> bool {
            (a / b) * b == a
        }
    }
}

