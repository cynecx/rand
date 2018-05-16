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
        (self.next_u64() & 0xFFFFFFFFu64) as u32
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
                0x28EF3C47_A831FD1C,
                0x8E975A11_78A024DB,
                0x84770776_5ECFACC4,
                0xB35F3DAC_565901B4,
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
        let seed: [u8; 32] = [
            2, 3, 5, 6, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
            67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
        ];

        let mut rng = Xoshiro256AARng::from_seed(seed);
        rng.jump();

        let mut results = [0u64; 9];
        for i in results.iter_mut() {
            *i = rng.next_u64();
        }
        let expected: [u64; 9] = [
            6448501676107297803,
            13631813502479173302,
            6922221365153641841,
            3914411535044074158,
            8169050191151619992,
            565265129322444892,
            15411982277416092712,
            16385527767248928421,
            16449547130297894689,
        ];
        assert_eq!(results, expected);

        let mut results = [0u32; 9];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected: [u32; 9] = [
            704897, 316721737, 3933319170, 226300084, 4248520878, 1605962826,
            3870272192, 1796601862, 33520231,
        ];
        assert_eq!(results, expected);

        let mut results = [0u8; 32];
        rng.fill_bytes(&mut results);
        let expected: [u8; 32] = [
            234, 93, 36, 132, 88, 54, 90, 61, 215, 87, 142, 42, 146, 55, 33,
            93, 48, 15, 56, 145, 162, 113, 180, 131, 101, 62, 104, 64, 184,
            149, 10, 181,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_xoshiro256aa_zero_seed() {
        // xoshiro256 does not work with an all zero seed.
        // Instead we set use a hardcoded seed.
        // Assert it does not panic.
        let mut rng = Xoshiro256AARng::from_seed([0u8; 32]);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert!(a != 0);
        assert!(b != a);
    }

    #[test]
    fn test_xoshiro256aa_clone() {
        let seed: [u8; 32] = [
            2, 3, 5, 6, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
            67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
        ];
        let mut rng1 = Xoshiro256AARng::from_seed(seed);
        let mut rng2 = rng1.clone();
        for _ in 0..16 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[cfg(all(feature = "serde1", feature = "std"))]
    #[test]
    fn test_xoshiro256aa_serde() {
        use bincode;
        use std::io::{BufReader, BufWriter};

        let seed: [u8; 32] = [
            2, 3, 5, 6, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
            67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
        ];
        let mut rng = Xoshiro256AARng::from_seed(seed);

        let buf: Vec<u8> = Vec::new();
        let mut buf = BufWriter::new(buf);
        bincode::serialize_into(&mut buf, &rng).expect("Could not serialize");

        let buf = buf.into_inner().unwrap();
        let mut read = BufReader::new(&buf[..]);
        let mut deserialized: Xoshiro256AARng =
            bincode::deserialize_from(&mut read)
                .expect("Could not deserialize");

        assert_eq!(rng.s0, deserialized.s0);
        assert_eq!(rng.s1, deserialized.s1);
        assert_eq!(rng.s2, deserialized.s2);
        assert_eq!(rng.s3, deserialized.s3);

        for _ in 0..16 {
            assert_eq!(rng.next_u64(), deserialized.next_u64());
        }
    }
}
