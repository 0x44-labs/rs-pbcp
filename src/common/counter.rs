use std::ops::AddAssign;

use num_traits::{FromBytes, ToBytes};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::common::unix_now;

/// A `u128` counter value.
///
/// Holds a count in the low 64 bits and a Unix timestamp (in seconds) in the
/// high 64 bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Counter(u128);

impl Counter {
    /// Create a new `Counter` holding the given `u64` count in the low 64 bits
    /// and the current Unix timestamp (in seconds) in the high 64 bits.
    pub fn new(count: u64) -> Self {
        let time = unix_now();

        Self(Self::pack(count, time))
    }

    /// Returns the count held in the low 64 bits.
    pub fn count(&self) -> u64 {
        let (count, _) = self.unpack();
        count
    }

    /// Returns the Unix timestamp (in seconds) held in the high 64 bits.
    pub fn time(&self) -> u64 {
        let (_, time) = self.unpack();
        time
    }

    fn pack(count: u64, time: u64) -> u128 {
        (time as u128) << 64 | (count as u128)
    }

    fn unpack(&self) -> (u64, u64) {
        let count = self.0 as u64;
        let time = (self.0 >> 64) as u64;

        (count, time)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new(0u64)
    }
}

impl core::fmt::Debug for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (count, time) = self.unpack();

        f.debug_struct("Counter")
            .field("count", &count)
            .field("time", &time)
            .finish()
    }
}

impl ToBytes for Counter {
    type Bytes = [u8; 16];

    fn to_be_bytes(&self) -> Self::Bytes {
        self.0.to_be_bytes()
    }

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn to_ne_bytes(&self) -> Self::Bytes {
        self.0.to_ne_bytes()
    }
}

impl FromBytes for Counter {
    type Bytes = [u8; 16];

    fn from_be_bytes(bytes: &Self::Bytes) -> Self {
        let inner = u128::from_be_bytes(*bytes);
        Self(inner)
    }

    fn from_le_bytes(bytes: &Self::Bytes) -> Self {
        let inner = u128::from_le_bytes(*bytes);
        Self(inner)
    }

    fn from_ne_bytes(bytes: &Self::Bytes) -> Self {
        let inner = u128::from_ne_bytes(*bytes);
        Self(inner)
    }
}

impl AddAssign<u64> for Counter {
    /// Performs the `+=` operation on the `u64` count stored in the low 64
    /// bits of this [Counter], leaving its timestamp in the high 64 bits
    /// unchanged.
    ///
    /// If the addition would overflow, the `u64` count restarts at zero under
    /// a fresh timestamp instead of wrapping.
    fn add_assign(&mut self, rhs: u64) {
        let (mut count, time) = self.unpack();

        if count <= u64::MAX - rhs {
            count += rhs;
            self.0 = Self::pack(count, time);
        } else {
            let time = unix_now();
            let count = 0u64;
            self.0 = Self::pack(count, time);
        }
    }
}

impl From<u128> for Counter {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Counter> for u128 {
    fn from(value: Counter) -> Self {
        value.0
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Counter {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIME: u64 = 1786558105;

    fn pack_values(count: u64, time: u64) -> Counter {
        Counter::from((u128::from(time) << 64) | u128::from(count))
    }

    fn unpack_counter(counter: Counter) -> (u64, u64) {
        let value = u128::from(counter);
        (value as u64, (value >> 64) as u64)
    }

    #[test]
    fn new_packs_count_low_time_high() {
        for count in [0, 1, u64::MAX] {
            let before = unix_now();
            let counter = Counter::new(count);
            let after = unix_now();

            let unpacked = unpack_counter(counter);
            assert_eq!(unpacked.0, count);
            assert!((before..=after).contains(&unpacked.1));
        }
    }

    #[test]
    fn accessors_return_their_own_field() {
        let before = unix_now();
        let counter = Counter::default();
        let after = unix_now();

        assert_eq!(counter.count(), 0);
        assert!((before..=after).contains(&counter.time()));
    }

    #[test]
    fn default_zero_count_current_time() {
        let before = unix_now();
        let counter = Counter::default();
        let after = unix_now();

        let unpacked = unpack_counter(counter);
        assert_eq!(unpacked.0, 0);
        assert!((before..=after).contains(&unpacked.1));
    }

    #[test]
    fn debug_shows_count_and_time() {
        let counter = pack_values(0, TIME);
        assert_eq!(
            format!("{:?}", counter),
            format!("Counter {{ count: 0, time: {} }}", TIME)
        );
    }

    #[test]
    fn to_bytes_byte_order() {
        let count = 16u64;
        let counter = pack_values(count, TIME);

        // Build the expected byte orders from the two u64 halves.
        let be: [u8; 16] = [TIME.to_be_bytes(), count.to_be_bytes()]
            .concat()
            .try_into()
            .expect("two 64-bit values fit in 16 bytes");
        let le: [u8; 16] = [count.to_le_bytes(), TIME.to_le_bytes()]
            .concat()
            .try_into()
            .expect("two 64-bit values fit in 16 bytes");

        assert_eq!(counter.to_be_bytes(), be);
        assert_eq!(counter.to_le_bytes(), le);
        assert_eq!(
            counter.to_ne_bytes(),
            if cfg!(target_endian = "little") {
                le
            } else {
                be
            }
        );
    }

    #[test]
    fn from_bytes_byte_order() {
        let count = 16u64;
        let expected = pack_values(count, TIME);

        // Build the expected byte orders from the two u64 halves.
        let be: [u8; 16] = [TIME.to_be_bytes(), count.to_be_bytes()]
            .concat()
            .try_into()
            .expect("two 64-bit values fit in 16 bytes");
        let le: [u8; 16] = [count.to_le_bytes(), TIME.to_le_bytes()]
            .concat()
            .try_into()
            .expect("two 64-bit values fit in 16 bytes");

        assert_eq!(Counter::from_be_bytes(&be), expected);
        assert_eq!(Counter::from_le_bytes(&le), expected);
        assert_eq!(
            Counter::from_ne_bytes(&if cfg!(target_endian = "little") {
                le
            } else {
                be
            }),
            expected
        );
    }

    #[test]
    fn add_assign_increments_count() {
        let mut counter = pack_values(0, TIME);
        counter += 16;

        let unpacked = unpack_counter(counter);
        assert_eq!(unpacked.0, 16);
    }

    #[test]
    fn add_assign_max_no_refresh() {
        for (count, rhs) in [(0, u64::MAX), (u64::MAX - 1, 1), (u64::MAX, 0)] {
            let mut counter = pack_values(count, TIME);
            counter += rhs;

            let unpacked = unpack_counter(counter);
            assert_eq!(unpacked.0, u64::MAX);
            assert_eq!(unpacked.1, TIME);
        }
    }

    #[test]
    fn add_assign_overflow_refreshes_time() {
        for (count, rhs) in [(1, u64::MAX), (u64::MAX, 1)] {
            let mut counter = pack_values(count, TIME);
            let before = unix_now();
            counter += rhs;
            let after = unix_now();

            let unpacked = unpack_counter(counter);
            assert_eq!(unpacked.0, 0);
            assert!((before..=after).contains(&unpacked.1));
        }
    }

    #[test]
    fn u128_round_trip() {
        for value in [0, 1, u128::MAX] {
            assert_eq!(u128::from(Counter::from(value)), value);
        }
    }
}
