// Copyright 2017 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// https://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Xoshiro256 generators

use core::num::Wrapping as w;
use core::{fmt, slice};
use rand_core::{impls, le, Error, RngCore, SeedableRng};

const JUMP: [u64; 4] = [
    0x180EC6D3_3CFD0ABAu64,
    0xD5A61266_F0C9392Cu64,
    0xA9582618_E03FC9AAu64,
    0x39ABDC45_29B1661Cu64,
];

/// A Xoshiro256**[1] random number generator.
///
/// The xoshiro256** algorithm is not suitable for cryptographic purposes
/// but is very fast. If you do not know for sure that it fits your
/// requirements, use a more secure one such as `IsaacRng` or `OsRng`.
///
/// [1]: xoshiro / xoroshiro generators and the PRNG shootout. ["Xorshift
/// RNGs"](http://xoshiro.di.unimi.it).
#[derive(Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct Xoshiro256AARng {
    s0: w<u64>,
    s1: w<u64>,
    s2: w<u64>,
    s3: w<u64>,
}

// Custom Debug implementation that does not expose the internal state
impl fmt::Debug for Xoshiro256AARng {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Xoshiro256Rng {{}}")
    }
}

impl Xoshiro256AARng {
    /// This is the jump function for the generator.
    /// It is equivalent to 2^128 calls to next_u64();
    pub fn jump(&mut self) {
        let mut s0 = w(0u64);
        let mut s1 = w(0u64);
        let mut s2 = w(0u64);
        let mut s3 = w(0u64);

        for &i in &JUMP {
            for b in 0..64 {
                if (i & (1u64 << b)) > 0 {
                    s0 ^= self.s0;
                    s1 ^= self.s1;
                    s2 ^= self.s2;
                    s3 ^= self.s3;
                }
                self.next_u64();
            }
        }

        self.s0 = s0;
        self.s1 = s1;
        self.s2 = s2;
        self.s3 = s3;
    }
}

impl RngCore for Xoshiro256AARng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let result = w((self.s1 * w(5)).0.rotate_left(7)) * w(9);

        let t = self.s1 << 17;

        self.s2 ^= self.s0;
        self.s3 ^= self.s1;
        self.s1 ^= self.s2;
        self.s0 ^= self.s3;

        self.s2 ^= t;
        self.s3 = w(self.s3.0.rotate_left(45));

        result.0
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl SeedableRng for Xoshiro256AARng {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_u64 = [0u64; 4];
        le::read_u64_into(&seed, &mut seed_u64);

        // xoshiro256 cannot be seeded with 0 and we cannot return an Error, but
        // also do not wish to panic (because a random seed can legitimately be
        // 0); our only option is therefore to use a preset value.
        if seed_u64.iter().all(|&x| x == 0) {
            seed_u64 = [
                0xBAD5EED_BAD533D,
                0xBAD5EED_BAD511D,
                0xBAD5EED_BAD533D,
                0xBAD5EED_BAD511D,
            ];
        }

        Self {
            s0: w(seed_u64[0]),
            s1: w(seed_u64[1]),
            s2: w(seed_u64[2]),
            s3: w(seed_u64[3]),
        }
    }

    fn from_rng<R: RngCore>(mut rng: R) -> Result<Self, Error> {
        let mut seed_u64 = [0u64; 4];

        loop {
            unsafe {
                let ptr = seed_u64.as_mut_ptr() as *mut u8;

                let slice = slice::from_raw_parts_mut(ptr, 4 * 8);
                rng.try_fill_bytes(slice)?;
            }
            if !seed_u64.iter().all(|&x| x == 0) {
                break;
            }
        }

        Ok(Self {
            s0: w(seed_u64[0]),
            s1: w(seed_u64[1]),
            s2: w(seed_u64[2]),
            s3: w(seed_u64[3]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Xoshiro256AARng;
    use {RngCore, SeedableRng};

    #[test]
    fn test_xoshiro256aa_construction() {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = i as u8;
        }

        let mut rng = Xoshiro256AARng::from_seed(seed);
        assert_eq!(rng.next_u64(), 13557399450712487245);
        assert_eq!(rng.next_u64(), 2706373525000986293);
    }

    #[test]
    fn test_xoshiro256aa_jump() {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = i as u8;
        }

        let mut rng = Xoshiro256AARng::from_seed(seed);
        rng.jump();

        assert_eq!(rng.next_u64(), 13745676184895872781);
        assert_eq!(rng.next_u64(), 6558318295426599200);
    }

    #[test]
    fn test_xoshiro256aa_true_values() {

    }
}
