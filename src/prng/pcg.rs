// Copyright 2017 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// https://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Pcg generators

use core::num::Wrapping as w;
use core::{fmt, slice};
use rand_core::{impls, le, Error, RngCore, SeedableRng};

const PCG_DEFAULT_MULTIPLIER_64: w<u64> = w(6364136223846793005u64);

/// A Pcg-32[1] random number generator.
///
/// The Pcg algorithm is not suitable for cryptographic purposes
/// but is very fast. If you do not know for sure that it fits your
/// requirements, use a more secure one such as `IsaacRng` or `OsRng`.
///
/// [1]: PCG is a family of simple fast space-efficient statistically good algorithms for random number generation. Unlike many general-purpose RNGs, they are also hard to predict. ["PCG"](http://www.pcg-random.org/).
#[derive(Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct PcgRng {
    state: w<u64>,
    inc: w<u64>,
}

// Custom Debug implementation that does not expose the internal state
impl fmt::Debug for PcgRng {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PcgRng {{}}")
    }
}

impl PcgRng {
    #[inline]
    fn new(state: u64, seq: u64) -> Self {
        let mut rng = Self {
            state: w(0),
            inc: w(0),
        };

        rng.inc = (w(seq) << 1) | w(1);
        rng.next_u32();
        rng.state += w(state);
        rng.next_u32();

        rng
    }

    /// Advances the state with delta
    pub fn advance(&mut self, delta: u64) {
        let mut cur_plus = self.inc;
        let mut cur_mult = PCG_DEFAULT_MULTIPLIER_64;

        let mut acc_mult = w(1u64);
        let mut acc_plus = w(0u64);

        let mut delta = delta;

        while delta > 0 {
            if delta & 1 > 0 {
                acc_mult *= cur_mult;
                acc_plus = acc_plus * cur_mult + cur_plus;
            }
            cur_plus = (cur_mult + w(1)) * cur_plus;
            cur_mult *= cur_mult;
            delta /= 2;
        }

        self.state = acc_mult * self.state + acc_plus
    }
}

impl RngCore for PcgRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let s = self.state;

        self.state = s * PCG_DEFAULT_MULTIPLIER_64 + self.inc;

        let p = (((s >> 18) ^ s) >> 27).0 as u32;
        p.rotate_right((s >> 59).0 as u32)
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl SeedableRng for PcgRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_u64 = [0u64; 2];
        le::read_u64_into(&seed, &mut seed_u64);

        Self::new(seed_u64[0], seed_u64[1])
    }

    fn from_rng<R: RngCore>(mut rng: R) -> Result<Self, Error> {
        let mut seed_u64 = [0u64; 2];

        unsafe {
            let ptr = seed_u64.as_mut_ptr() as *mut u8;

            let slice = slice::from_raw_parts_mut(ptr, 2 * 8);
            rng.try_fill_bytes(slice)?;
        }

        Ok(Self::new(seed_u64[0], seed_u64[1]))
    }
}
