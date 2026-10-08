use num_traits::ToBytes;
use std::{
    ops::AddAssign,
    time::{SystemTime, UNIX_EPOCH},
};

/// A `u128` value packing a count in the low 64 bits with a Unix timestamp
/// (in seconds) in the high 64 bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Counter(u128);

impl Counter {
    /// Create a new `Counter` holding the given `u64` count in the low 64 bits
    /// and the current Unix timestamp (in seconds) in the high 64 bits.
    pub fn new(count: u64) -> Self {
        let time = Self::now();

        Self(Self::pack(count, time))
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("")
            .as_secs()
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
            let time = Self::now();
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
